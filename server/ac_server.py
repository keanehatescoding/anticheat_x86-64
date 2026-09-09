#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
ac_server.py -- minimal report-ingestion + ban-lookup server for the
hypranticheat daemon's ban pipeline.

Two things this deliberately is NOT:

  - An enforcement point. This project has no game or matchmaking server
    to integrate with, so there is nothing here that kicks or blocks a
    player. GET /banned/<client_id> is the API a real game server would
    call before letting someone connect; calling it is left to that
    (nonexistent, in this project) system.

  - An auto-ban system. A report is a client-side daemon's unverified
    claim about itself -- and the daemon runs on the exact machine a
    cheat author controls, so a report can be wrong, spoofed, or replayed
    by an attacker probing for false positives. Reports only accumulate;
    a human decides whether to actually ban via POST /ban after reviewing
    GET /reports/<client_id>. Auto-banning on unverified client input
    would turn a bug or a spoofed report into a banned real player, which
    is a worse failure mode than a slower human-in-the-loop pipeline.

Storage is a single SQLite file (zero extra services to run). Auth is two
static bearer tokens: a report key (used by daemon instances, via
AC_REPORT_KEY) and an admin key (used by whoever reviews/bans/queries).
Each tier optionally accepts one additional "-old" key
(AC_SERVER_REPORT_KEY_OLD / AC_SERVER_ADMIN_KEY_OLD) for a zero-downtime
rotation window -- see --report-key-old/--admin-key-old below. There is no
built-in TLS -- run this behind a reverse proxy for anything reachable
over an untrusted network, or keep it LAN/localhost-only, which is the
deployment this was actually built and tested against.

Alternatively, pass --unix-socket PATH to listen on an AF_UNIX
SOCK_STREAM socket instead of TCP (--host/--port are ignored when this is
set) -- the matching daemon-side option is AC_REPORT_URL=unix://PATH (see
ac_report() in src/anticheat_daemon.c). This removes the plaintext-
network-credential exposure noted above for a daemon and server
co-located on the same host: filesystem permissions on the socket become
the trust boundary instead of network reachability. The socket is
created 0600 (owner-only) to match Store's own DB-file permissions, and
that mode is reapplied on every start -- a daemon connecting to it must
run as this server's own user (or root). There's no durable way to widen
that for a different-user daemon: any group/ACL change made after the
fact is undone the next time this process (re)starts and rebinds.
"""
import argparse
import hmac
import http.server
import ipaddress
import json
import os
import re
import signal
import socket
import socketserver
import sqlite3
import stat
import sys
import threading
import time
import traceback
import urllib.parse
import collections
import functools

CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
MAX_BODY_BYTES = 4096


class RateLimiter:
    """Sliding-window limiter: at most `limit` requests per `window` seconds,
    per key (source IP here). Replaces the previous fixed-window scheme
    which allowed a brief double-rate burst at the window boundary (up to
    2*limit in one window's worth of time straddling two fixed windows).
    Sliding window prunes timestamps older than `window` on every `allow()`
    and counts only those still inside the window. Not built for distributed
    scale -- enough to bound abuse against a single small process, which is
    the actual deployment this is for. Applied to every endpoint, not just
    /report: unauthenticated attempts against /banned or /ban are exactly
    the kind of thing worth throttling too (ID enumeration, admin-key
    brute-forcing), not just report flooding."""

    def __init__(self, limit, window):
        self.limit = limit
        self.window = window
        self._lock = threading.Lock()
        self._hits = {}  # key -> deque[monotonic timestamps]
        self._buckets = self._hits  # compat alias for older tests inspecting _buckets
        self._last_prune = time.monotonic()

    def allow(self, key):
        now = time.monotonic()
        with self._lock:
            dq = self._hits.get(key)
            if dq is None:
                dq = collections.deque()
                self._hits[key] = dq
            # prune outside window
            while dq and now - dq[0] >= self.window:
                dq.popleft()
            if len(dq) >= self.limit:
                # still need occasional prune of stale keys even on deny
                if now - self._last_prune >= self.window:
                    self._prune(now)
                return False
            dq.append(now)
            if now - self._last_prune >= self.window:
                self._prune(now)
            return True

    def _prune(self, now):
        """Drop keys whose deque is empty or whose newest entry is already
        outside the window. Keeps _hits bounded in a long-running process
        with many distinct source IPs, same purpose as before but adapted
        to deque storage."""
        stale = [k for k, dq in self._hits.items()
                 if not dq or now - dq[-1] >= self.window]
        for k in stale:
            del self._hits[k]
        self._last_prune = now


def now_ts():
    return int(time.time())


UNIX_CLIENT_ADDRESS = ("unix", 0)

DEFAULT_MAX_CONNECTIONS = 50


class BoundedThreadingMixIn(socketserver.ThreadingMixIn):
    """Cap concurrent handler threads so a burst of slow-trickling
    connections can't unboundedly grow the thread count (#100).

    ThreadingHTTPServer spawns one OS thread per accepted connection with
    no cap: each connection already has a per-read `timeout` plus an
    absolute CONNECTION_DEADLINE_SEC watchdog, but a client opening many
    connections at once and trickling bytes just under those bounds can
    still force one thread per connection for the full deadline window.
    Bounding here also bounds clean-shutdown latency, since
    daemon_threads=False makes server_close() join every handler thread.

    Rejects excess connections with an immediate 503 + close instead of
    queueing: queueing in the accept loop would stall legitimate clients
    behind attacker-held slots, and the daemon client already retries
    report POSTs. The semaphore is per-server-instance (created in
    __init__, before any accept loop runs), so separate test instances
    in the same process don't share a budget."""

    def __init__(self, *args, max_connections=DEFAULT_MAX_CONNECTIONS,
                 **kwargs):
        self._conn_semaphore = threading.Semaphore(max_connections)
        self.max_connections = max_connections
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        # Non-blocking: never park the accept loop behind attacker-held
        # slots. An accepted-but-unhandled connection still holds its fd,
        # so prompt close (not a wait with timeout) is what actually
        # bounds fd/thread pressure under a many-connection burst.
        if not self._conn_semaphore.acquire(blocking=False):
            self._reject_overloaded(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            # ThreadingMixIn.process_request() spawns a thread and start()
            # itself can raise (thread/resource limit): then
            # process_request_thread() never runs, so its finally-release
            # never fires. Release here and re-raise so the caller's
            # handle_error/shutdown_request path still runs -- otherwise
            # repeated failures leak the semaphore to zero and every later
            # connection gets 503 even after load drops.
            self._conn_semaphore.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            # Released even if finish_request() raises: handle_error() is
            # inside ThreadingMixIn.process_request_thread, but a bug in
            # shutdown_request() itself must still not leak a slot forever.
            self._conn_semaphore.release()

    def _reject_overloaded(self, request):
        # Best-effort 503 so a legitimate daemon bursting past the cap
        # gets a retryable signal instead of a bare reset; failures here
        # (peer already gone, unix-socket edge) just fall through to the
        # close -- the point is bounding, not the status line.
        try:
            request.settimeout(2)
            body = b'{"error": "server busy"}'
            request.sendall(
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii")
                + b"\r\nConnection: close\r\nRetry-After: 5\r\n\r\n"
                + body
            )
        except OSError:
            pass
        finally:
            # shutdown(SHUT_WR) before close: closing a socket with unread
            # request bytes still queued can RST and discard the 503 we
            # just sent. shutdown_request() does the SHUT_WR-then-close
            # sequence so the client actually receives the retryable
            # response.
            try:
                self.shutdown_request(request)
            except OSError:
                pass


class BoundedThreadingHTTPServer(BoundedThreadingMixIn,
                                 http.server.HTTPServer):
    """TCP variant of the bounded mixin above -- the direct replacement
    for http.server.ThreadingHTTPServer at the call site in main()."""

    pass


class ThreadingUnixHTTPServer(BoundedThreadingMixIn, http.server.HTTPServer):
    """The --unix-socket transport: same request handling as
    ThreadingHTTPServer, just over an AF_UNIX SOCK_STREAM socket bound to
    a filesystem path instead of a TCP (host, port). http.server.HTTPServer
    itself is transport-agnostic (it only calls socket.socket(self.address_family,
    self.socket_type) and self.socket.bind(self.server_address)) -- the two
    overrides below are the only AF_UNIX-specific behavior needed."""

    address_family = socket.AF_UNIX

    def server_bind(self):
        # Binding an AF_UNIX SOCK_STREAM socket fails outright if a file
        # already exists at that path -- unlike a TCP port, which is free
        # again as soon as the previous listener closes it (modulo
        # TIME_WAIT, which allow_reuse_address already handles). Without
        # this, every restart after the very first one would fail with
        # "address already in use" against the stale socket file the
        # previous run left behind. But blindly unlinking whatever is
        # there would (a) delete a regular file someone accidentally
        # pointed --unix-socket at, and (b) steal the path out from under
        # a still-running previous instance (e.g. a second `ac_server.py
        # --unix-socket` invocation against the same path), silently
        # diverting new connections to this process while the old one
        # keeps running unaware its socket file is gone. Guard both: only
        # ever remove a path that's actually a socket, and only after
        # confirming nothing is listening on it.
        try:
            st = os.lstat(self.server_address)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISSOCK(st.st_mode):
                raise RuntimeError(
                    "ac_server: --unix-socket path %r exists and is not a "
                    "socket -- refusing to remove it" % (self.server_address,)
                )
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.connect(self.server_address)
            except OSError:
                pass  # nothing listening -- a stale socket file, safe to reclaim
            else:
                raise RuntimeError(
                    "ac_server: --unix-socket path %r already has an "
                    "active listener -- refusing to steal it"
                    % (self.server_address,)
                )
            finally:
                probe.close()
            os.unlink(self.server_address)
        # Deliberately socketserver.TCPServer.server_bind(), not
        # http.server.HTTPServer.server_bind(): the latter does
        # `host, port = self.server_address[:2]` afterward, assuming a TCP
        # (host, port) tuple -- for AF_UNIX, server_address is a path
        # string, and slicing a 2+ char string still "unpacks" into two
        # single-character strings without raising, silently assigning
        # garbage (e.g. the path's first two characters) to
        # server_name/server_port instead of failing loudly. Nothing here
        # actually uses those two attributes, but there's no reason to let
        # them hold nonsense when a real placeholder is just as cheap.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "unix"
        self.server_port = 0
        # Match Store's own DB-file permissions (0600, see Store.__init__):
        # filesystem permissions on this socket are the trust boundary for
        # the --unix-socket transport (see the module docstring's "No TLS"
        # / unix-socket note), not whatever the process umask happens to
        # be at bind time.
        os.chmod(self.server_address, 0o600)
        # Recorded so a later cleanup unlink (see main()'s shutdown path)
        # can confirm the path still names *this* socket before removing
        # it -- not, say, a replacement another process created at the
        # same path after this one closed it.
        self._bound_stat = os.stat(self.server_address)

    def get_request(self):
        # accept()'s peer address for AF_UNIX is '' (the client end is
        # usually unbound), not the (host, port) tuple BaseHTTPRequestHandler
        # expects -- address_string()/log_message() and _client_ip() below
        # all index self.client_address[0] assuming that shape. Every
        # connection on this transport is already trust-boundary-gated by
        # the socket's own filesystem permissions (see server_bind above),
        # so a single fixed placeholder identifying "some client over the
        # unix socket" is all that's meaningful here -- there is no
        # per-peer network address to report or rate-limit on separately.
        request, _client_address = super().get_request()
        return request, UNIX_CLIENT_ADDRESS


def _requires_auth(keys):
    """Method decorator for a Handler._handle_*() method: send 401 and
    skip the wrapped handler if the request's bearer token isn't in
    `keys`. The decorator marks the wrapper with `_ac_auth_keys` so the
    dispatcher (_route_guarded) can tell an intentionally-authed handler
    apart from a new endpoint that merely forgot this decorator -- see
    PUBLIC_HANDLERS below."""

    def deco(fn):
        @functools.wraps(fn)
        def wrapper(self, *args, **kwargs):
            if not self._authed(keys):
                return self._send_json(401, {"error": "unauthorized"})
            return fn(self, *args, **kwargs)

        wrapper._ac_auth_keys = frozenset(keys)
        return wrapper

    return deco


# Handler names (the _handle_* method's __name__) explicitly allowed to
# serve without auth, enforced deny-by-default by _route_guarded(): every
# routed handler must either carry @_requires_auth (marked above) or be
# named here, else the dispatcher 401s instead of serving. Empty today --
# every endpoint needs a key tier -- so this is purely the explicit
# allow-list a future public endpoint (health check, version probe) would
# have to be added to deliberately, rather than becoming public by
# forgetting a decorator. test_auth_dispatch_unit.py asserts the
# invariant over every registered route.
PUBLIC_HANDLERS = frozenset()


class Store:
    """One SQLite connection per request (see handler) -- simplest way to
    be correct under ThreadingHTTPServer without sharing a connection
    across threads."""

    def __init__(self, db_path, max_reports_per_client=1000):
        self.db_path = db_path
        # Bounds how many rows a single client_id can hold in `reports`,
        # trimmed on every insert (see add_report). Without this, a single
        # spammy or misbehaving daemon has no limit on how much it can grow
        # the SQLite file, since `list_reports`'s LIMIT only bounds what a
        # query returns, not what accumulates on disk (#60). 0/None disables
        # the cap.
        self.max_reports_per_client = max_reports_per_client
        # SQLite only ever allows one writer at a time, even in WAL mode --
        # under ThreadingHTTPServer, every write-handling thread opens its
        # own connection and would otherwise all race for that single
        # writer lock at once, each polling/blocking inside SQLite's own
        # busy_timeout. Under sustained high concurrency that busy-wait can
        # still lose (a real stress run: 30 threads x 300s produced 36
        # "database is locked" OperationalErrors past a 5s busy_timeout).
        # Serializing writes through this lock instead means at most one
        # thread ever has a write in flight against SQLite, so there is
        # never any lock contention for busy_timeout to time out on --
        # every writer just queues fairly in Python instead.
        self._write_lock = threading.Lock()
        # The DB (and its -wal/-shm siblings, recreated on every checkpoint)
        # hold raw report detail text, source IPs, and ban reasons -- private
        # regardless of the launching environment's umask, not just under the
        # exact systemd unit that happens to set UMask=0077. Deliberately no
        # os.umask() call here: umask is process-wide with no thread-local or
        # context-manager scoping in the stdlib, so a constructor that sets it
        # permanently mutates every future file creation in the importing
        # process (#99) -- surprising for anything using Store as a library
        # (tests, admin scripts). The daemon entry point (main() below) sets
        # a restrictive umask once at startup, before any handler thread
        # exists, which covers every file SQLite creates afterwards without
        # racing. A per-_connect() scoped umask would close the later-file
        # gap for library users too, but umask races process-wide under
        # ThreadingHTTPServer concurrency, so explicit chmod (per-file,
        # thread-safe) is used here instead. Normalize any pre-existing
        # files: an upgrade from a pre-fix deployment can already have a
        # world-readable DB (and -wal/-shm) on disk that sqlite3.connect()
        # would otherwise reuse as-is.
        with self._write_lock:
            self._ensure_private()
            conn = self._connect()
            conn.execute(
                """CREATE TABLE IF NOT EXISTS reports (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       client_id TEXT NOT NULL,
                       event_type TEXT NOT NULL,
                       detail TEXT NOT NULL,
                       client_ts INTEGER,
                       received_at INTEGER NOT NULL,
                       source_addr TEXT NOT NULL
                   )"""
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_reports_client ON reports(client_id)"
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS bans (
                       client_id TEXT PRIMARY KEY,
                       reason TEXT NOT NULL,
                       banned_at INTEGER NOT NULL
                   )"""
            )
            conn.commit()
            conn.close()
            # Fresh files (or -wal/-shm siblings checkpoint-created above) may
            # have been created under the importer's own umask when Store is
            # used as a library (no main() umask in effect) -- lock them down
            # explicitly so library use still lands at 0600 without touching
            # the process-wide umask to get there.
            self._ensure_private()

    def _ensure_private(self):
        """chmod any existing DB/-wal/-shm files to 0600. Per-file and
        thread-safe, unlike umask -- safe to call from __init__ (both
        before table creation for the upgrade case and after, for the
        fresh-creation-as-library case) and after writes (SQLite can
        recreate -wal/-shm on any checkpoint, including well after
        __init__ when Store is used as a library without main()'s umask).
        A vanishing file between the exists check and the chmod (another
        thread's connection checkpointing the WAL away) just means there
        is nothing left to lock down."""
        for suffix in ("", "-wal", "-shm"):
            path = self.db_path + suffix
            if os.path.exists(path):
                try:
                    os.chmod(path, 0o600)
                except FileNotFoundError:
                    pass

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        # Explicit busy_timeout as defense-in-depth: timeout=5 above is the
        # Python-level busy handler, but setting the SQLite-level pragma
        # ensures the same 5s bound even if the connection is used via raw
        # sqlite3 APIs that bypass Python's wrapper. Synchronous=NORMAL is
        # safe in WAL mode and reduces fsync pressure under concurrent writes
        # without sacrificing durability guarantees needed here.
        try:
            conn.execute("PRAGMA busy_timeout=5000")
        except Exception:
            pass
        return conn

    def add_report(self, client_id, event_type, detail, client_ts, source_addr):
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO reports (client_id, event_type, detail, "
                    "client_ts, received_at, source_addr) VALUES (?,?,?,?,?,?)",
                    (client_id, event_type, detail, client_ts, now_ts(), source_addr),
                )
                if self.max_reports_per_client:
                    conn.execute(
                        "DELETE FROM reports WHERE client_id = ? AND id NOT IN ("
                        "SELECT id FROM reports WHERE client_id = ? "
                        "ORDER BY id DESC LIMIT ?)",
                        (client_id, client_id, self.max_reports_per_client),
                    )
                conn.commit()
                # SQLite may have (re)created -wal/-shm on this write; lock
                # them down while the connection is still open (they exist
                # now, not just at __init__ time). Harmless under the daemon
                # (main()'s umask already made them 0600); what actually
                # needs it is Store-as-library use with no such umask.
                self._ensure_private()
            finally:
                conn.close()

    def list_reports(self, client_id, limit=200):
        conn = self._connect()
        try:
            cur = conn.execute(
                "SELECT event_type, detail, client_ts, received_at, source_addr "
                "FROM reports WHERE client_id = ? ORDER BY id DESC LIMIT ?",
                (client_id, limit),
            )
            return [
                {
                    "event_type": r[0],
                    "detail": r[1],
                    "client_ts": r[2],
                    "received_at": r[3],
                    "source_addr": r[4],
                }
                for r in cur.fetchall()
            ]
        finally:
            conn.close()

    def ban(self, client_id, reason):
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO bans (client_id, reason, banned_at) VALUES (?,?,?) "
                    "ON CONFLICT(client_id) DO UPDATE SET reason=excluded.reason, "
                    "banned_at=excluded.banned_at",
                    (client_id, reason, now_ts()),
                )
                conn.commit()
                self._ensure_private()
            finally:
                conn.close()

    def unban(self, client_id):
        with self._write_lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM bans WHERE client_id = ?", (client_id,))
                conn.commit()
                self._ensure_private()
                return cur.rowcount > 0
            finally:
                conn.close()

    def ban_status(self, client_id):
        conn = self._connect()
        try:
            cur = conn.execute(
                "SELECT reason, banned_at FROM bans WHERE client_id = ?",
                (client_id,),
            )
            row = cur.fetchone()
            if not row:
                return {"banned": False}
            return {"banned": True, "reason": row[0], "banned_at": row[1]}
        finally:
            conn.close()


def _parse_proxy_cidrs(values):
    """Parse --trusted-proxy-cidr values into ipaddress networks.
    Raises ValueError naming the first bad entry -- main() turns that
    into a startup refusal, and the unit test asserts on it directly.
    Strict: host bits are rejected (10.0.0.1/8 does NOT silently become
    10.0.0.0/8 and trust 16M peers the operator never named) -- write
    the network address itself, or a single host as /32."""
    nets = []
    for v in values or []:
        try:
            nets.append(ipaddress.ip_network(v, strict=True))
        except ValueError:
            raise ValueError("invalid --trusted-proxy-cidr %r: use a "
                             "network address (e.g. 10.0.0.0/8) or a "
                             "single host (e.g. 10.0.0.5/32), with no "
                             "host bits set" % (v,)) from None
    return nets


def make_handler(store, report_keys, admin_keys, rate_limiter, trust_proxy=False,
                 trusted_proxy_cidrs=()):
    # Tuple of ipaddress._BaseNetwork parsed once in main(): X-Forwarded-For
    # is only honored for TCP peers inside one of these (see
    # _peer_is_trusted_proxy). main() refuses --trust-proxy without at
    # least one --trusted-proxy-cidr, so a non-empty tuple here whenever
    # trust_proxy is True is a startup guarantee, not a per-request check.
    trusted_proxy_nets = tuple(trusted_proxy_cidrs)
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "ac_server/1"
        # Bounds every INDIVIDUAL blocking socket read on this connection
        # (one request-line/header readline(), or one _read_json_body()
        # rfile.read()) via StreamRequestHandler.setup(). This alone is not
        # enough: it resets on every call, so a client sending one byte
        # every N < timeout seconds keeps each read individually within
        # bounds while never completing a request -- see
        # CONNECTION_DEADLINE_SEC below for the absolute bound that closes
        # that gap.
        timeout = 10

        # Absolute wall-clock bound on one connection's total lifetime,
        # covering every request-line/header/body read across a keep-alive
        # connection -- not just a single blocking read the way `timeout`
        # above does. Without this, a client trickling bytes just under the
        # per-read timeout keeps a worker thread parked indefinitely, and
        # since daemon_threads=False below (see main()), an attacker doing
        # this could also block clean shutdown indefinitely: server_close()
        # waits for every handler thread, including this stuck one.
        CONNECTION_DEADLINE_SEC = 30

        def handle(self):
            watchdog = threading.Timer(
                self.CONNECTION_DEADLINE_SEC, self._deadline_exceeded
            )
            watchdog.daemon = True
            watchdog.start()
            try:
                super().handle()
            finally:
                watchdog.cancel()

        def _deadline_exceeded(self):
            # Runs on the watchdog's own thread, not the handler thread.
            # Shutting down the raw socket from here unblocks whatever
            # blocking read the handler thread is currently stuck in (it
            # raises ConnectionError/OSError there, the same as a peer
            # disconnecting would), so the handler thread -- and therefore
            # server_close()'s join -- actually finishes instead of hanging
            # on a slow-trickling client forever.
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        def log_message(self, fmt, *args):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

        def _log_exception(self):
            # Distinct from the normal per-request access log line above,
            # so a real bug is grep-able instead of blending into traffic.
            self.log_message(
                "ERROR %s %s -> %r", self.command, self.path, sys.exc_info()[1]
            )
            traceback.print_exc(file=sys.stderr)

        def _dispatch(self, inner):
            self._response_started = False
            try:
                inner()
            except (BrokenPipeError, ConnectionResetError):
                # Client hung up mid-response -- routine for any HTTP
                # server, not worth a stack trace per occurrence.
                pass
            except Exception:
                self._log_exception()
                if not self._response_started:
                    try:
                        self._send_json(500, {"error": "internal error"})
                    except Exception:
                        pass  # connection's already in a bad state; give up

        def _send_json(self, code, obj, extra_headers=None):
            # Set before any bytes go out, so a failure partway through
            # this call never causes _dispatch to attempt a second,
            # malformed response on the same connection.
            self._response_started = True
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _peer_is_trusted_proxy(self):
            # --trust-proxy alone used to honor X-Forwarded-For from ANY
            # direct connection, so a client reaching the server itself
            # could forge its own rate-limit bucket and source_addr (#14).
            # Only peers inside a configured --trusted-proxy-cidr count as
            # the reverse proxy; everyone else falls back to the raw peer
            # exactly as if the header were absent. An unparseable peer
            # (including the "unix" placeholder on the unix-socket
            # transport, where --trust-proxy is refused at startup anyway)
            # is untrusted by definition.
            try:
                peer = ipaddress.ip_address(self.client_address[0])
            except ValueError:
                return False
            return any(peer in net for net in trusted_proxy_nets)

        def _client_ip(self):
            if not trust_proxy or not self._peer_is_trusted_proxy():
                return self.client_address[0]
            # self.headers.get() returns only the FIRST occurrence of a
            # repeated header -- a client could send its own
            # X-Forwarded-For line ahead of the one the proxy adds and
            # win outright, since .get() would return the attacker's
            # value and never even see the proxy's. get_all() returns
            # every occurrence; RFC 9110 SS5.3 treats repeated instances
            # of the same field as equivalent to one field joined by
            # commas in order, so joining them before re-splitting
            # handles both a proxy that appends to an existing header
            # (the common case, e.g. nginx's proxy_add_x_forwarded_for)
            # and one that adds a second, separate header line.
            xff_all = self.headers.get_all("X-Forwarded-For")
            if not xff_all:
                # Flag on but header absent: fall back to the raw peer --
                # if a direct connection somehow bypasses the proxy, the
                # raw peer IS the real source, so this is the safe/more
                # correct direction, not less.
                return self.client_address[0]
            xff = ",".join(xff_all)
            # The LAST entry is the one the trusted proxy itself appended
            # (its own view of its immediate peer); everything before
            # that is attacker-controlled request-header content. Taking
            # the first entry would let any client bypass rate limiting
            # and forge source_addr just by sending its own header.
            candidate = xff.rsplit(",", 1)[-1].strip()
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                return self.client_address[0]
            return candidate

        def _rate_limited(self):
            if rate_limiter.allow(self._client_ip()):
                return False
            self._send_json(
                429,
                {"error": "rate limited"},
                {"Retry-After": str(rate_limiter.window)},
            )
            return True

        def _bearer(self):
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return None
            return auth[len("Bearer "):]

        def _authed(self, expected_keys):
            got = self._bearer()
            if got is None:
                return False
            # hmac.compare_digest is constant-time; a naive == here would
            # leak key-prefix-match timing to anyone who can hit this
            # endpoint repeatedly. expected_keys is at most 2 (current +
            # one still-valid-during-rotation previous key), so comparing
            # against each candidate doesn't turn this into a meaningful
            # timing side channel between candidates either.
            return any(hmac.compare_digest(got, k) for k in expected_keys)

        def _read_json_body(self):
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
            except ValueError:
                # A client sending a garbage Content-Length (not
                # necessarily malicious -- could just be buggy) shouldn't
                # take the request handler down with an uncaught
                # exception; treat it the same as any other bad request.
                return None
            if length <= 0 or length > MAX_BODY_BYTES:
                return None
            raw = self.rfile.read(length)
            # event_type/detail ultimately derive from process comm names
            # and kernel file paths -- raw bytes with no UTF-8 guarantee
            # (see ac_json_escape() on the daemon side). Rejecting the
            # whole report over a decode error would let a process simply
            # name itself with invalid UTF-8 to suppress its own reports
            # from ever reaching the ban pipeline; replacing the bad
            # bytes keeps the report (and everything else in it) intact.
            try:
                return json.loads(raw.decode("utf-8", errors="replace"))
            except ValueError:
                return None

        @staticmethod
        def _valid_client_id(v):
            return isinstance(v, str) and CLIENT_ID_RE.fullmatch(v) is not None

        def _require_valid_client_id(self, v):
            """Shared by every handler below that takes a client_id
            (whether from a JSON body or a URL path segment): sends the
            400 response and returns False if it isn't valid."""
            if not self._valid_client_id(v):
                self._send_json(400, {"error": "invalid client_id"})
                return False
            return True

        def _require_body_client_id(self):
            """Shared by every POST handler below: read+parse the JSON
            body and pull out a valid client_id, sending the appropriate
            400 response and returning None if either step fails."""
            body = self._read_json_body()
            if not isinstance(body, dict) or not body:
                self._send_json(400, {"error": "bad request"})
                return None
            if not self._require_valid_client_id(body.get("client_id")):
                return None
            return body

        def _route_guarded(self, handler_fn, *args):
            # Deny-by-default dispatch (#13): auth used to be opt-in per
            # handler via @_requires_auth, so a future endpoint that forgot
            # the decorator would have served unauthenticated with nothing
            # to catch the omission. Every routed handler must now either
            # carry the decorator's `_ac_auth_keys` marker (the decorator
            # itself still performs the actual key check) or be named in
            # PUBLIC_HANDLERS -- anything else 401s here instead of ever
            # running. The log line names the handler so the omission shows
            # up in stderr during development rather than silently 401ing
            # in production.
            name = getattr(handler_fn, "__name__", "?")
            if name in PUBLIC_HANDLERS:
                return handler_fn(*args)
            if getattr(handler_fn, "_ac_auth_keys", None) is None:
                self.log_message(
                    "denying unmarked handler %s (missing @_requires_auth "
                    "and not in PUBLIC_HANDLERS)",
                    name,
                )
                return self._send_json(401, {"error": "unauthorized"})
            return handler_fn(*args)

        def do_POST(self):
            self._dispatch(self._do_POST)

        def _do_POST(self):
            if self._rate_limited():
                return
            parsed = urllib.parse.urlparse(self.path)
            path = urllib.parse.unquote(parsed.path)
            if not path:
                return self._send_json(404, {"error": "not found"})
            if path == "/report":
                return self._route_guarded(self._handle_report)
            if path == "/ban":
                return self._route_guarded(self._handle_ban)
            if path == "/unban":
                return self._route_guarded(self._handle_unban)
            self._send_json(404, {"error": "not found"})

        def do_GET(self):
            self._dispatch(self._do_GET)

        def _do_GET(self):
            if self._rate_limited():
                return
            parsed = urllib.parse.urlparse(self.path)
            path = urllib.parse.unquote(parsed.path)
            if not path:
                return self._send_json(404, {"error": "not found"})
            if path.startswith("/banned/"):
                return self._route_guarded(
                    self._handle_banned, path[len("/banned/"):])
            if path.startswith("/reports/"):
                return self._route_guarded(
                    self._handle_reports, path[len("/reports/"):])
            self._send_json(404, {"error": "not found"})

        @_requires_auth(report_keys)
        def _handle_report(self):
            body = self._require_body_client_id()
            if body is None:
                return
            client_id = body["client_id"]
            event_type = body.get("event_type")
            detail = body.get("detail")
            client_ts = body.get("ts")
            if not isinstance(event_type, str) or len(event_type) > 64:
                return self._send_json(400, {"error": "invalid event_type"})
            if not isinstance(detail, str) or len(detail) > 2000:
                return self._send_json(400, {"error": "invalid detail"})
            if not isinstance(client_ts, (int, float)):
                client_ts = None
            store.add_report(
                client_id, event_type, detail, client_ts, self._client_ip()
            )
            self._send_json(201, {"ok": True})

        @_requires_auth(admin_keys)
        def _handle_ban(self):
            body = self._require_body_client_id()
            if body is None:
                return
            client_id = body["client_id"]
            reason = body.get("reason")
            if not isinstance(reason, str) or not (0 < len(reason) <= 500):
                return self._send_json(400, {"error": "invalid reason"})
            store.ban(client_id, reason)
            self._send_json(200, {"ok": True})

        @_requires_auth(admin_keys)
        def _handle_unban(self):
            body = self._require_body_client_id()
            if body is None:
                return
            existed = store.unban(body["client_id"])
            self._send_json(200, {"ok": True, "was_banned": existed})

        @_requires_auth(admin_keys)
        def _handle_banned(self, client_id):
            if not self._require_valid_client_id(client_id):
                return
            self._send_json(200, store.ban_status(client_id))

        @_requires_auth(admin_keys)
        def _handle_reports(self, client_id):
            if not self._require_valid_client_id(client_id):
                return
            self._send_json(200, {"reports": store.list_reports(client_id)})

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument(
        "--unix-socket",
        default=None,
        metavar="PATH",
        help="listen on an AF_UNIX SOCK_STREAM socket at PATH instead of "
        "TCP -- --host/--port are ignored when this is set. The matching "
        "daemon-side option is AC_REPORT_URL=unix://PATH. The socket is "
        "created 0600 (owner-only); filesystem permissions on it are the "
        "trust boundary for this transport, same role network exposure "
        "plays for the default TCP one (default: off, use TCP)",
    )
    ap.add_argument("--db", default="ac_server.db")
    ap.add_argument(
        "--max-reports-per-client",
        type=int,
        default=1000,
        help="cap on stored rows in `reports` per client_id, oldest "
        "trimmed on insert; keeps a single spammy or misbehaving daemon "
        "from growing the SQLite file without bound (default: 1000, "
        "0 disables the cap)",
    )
    ap.add_argument(
        "--report-key",
        default=None,
        help="bearer token daemons use for POST /report "
        "(default: $AC_SERVER_REPORT_KEY)",
    )
    ap.add_argument(
        "--admin-key",
        default=None,
        help="bearer token for ban/unban/query endpoints "
        "(default: $AC_SERVER_ADMIN_KEY)",
    )
    ap.add_argument(
        "--report-key-old",
        default=None,
        help="a previous report key still accepted alongside --report-key, "
        "for a zero-downtime rotation window: start the server with both "
        "the new --report-key and the old one here, roll every daemon "
        "over to the new key, then restart once more without this flag "
        "to finish the rotation (default: $AC_SERVER_REPORT_KEY_OLD)",
    )
    ap.add_argument(
        "--admin-key-old",
        default=None,
        help="a previous admin key still accepted alongside --admin-key, "
        "same rotation-window purpose as --report-key-old "
        "(default: $AC_SERVER_ADMIN_KEY_OLD)",
    )
    ap.add_argument(
        "--rate-limit",
        type=int,
        default=60,
        help="max requests per --rate-window seconds, per source IP, "
        "across every endpoint (default: 60)",
    )
    ap.add_argument(
        "--rate-window",
        type=int,
        default=60,
        help="rate-limit window in seconds (default: 60)",
    )
    ap.add_argument(
        "--max-connections",
        type=int,
        default=DEFAULT_MAX_CONNECTIONS,
        help="cap on concurrent connections (handler threads); excess "
        "connections are refused with an immediate 503 + close instead of "
        "spawning unbounded threads under a many-slow-connection burst "
        "(default: %d)" % DEFAULT_MAX_CONNECTIONS,
    )
    ap.add_argument(
        "--trust-proxy",
        action="store_true",
        help="trust the last hop of the X-Forwarded-For header as the "
        "real client IP for rate limiting and report source_addr, "
        "instead of the raw TCP peer -- but ONLY for TCP peers inside "
        "a --trusted-proxy-cidr (below). Requires at least one "
        "--trusted-proxy-cidr; without it the server refuses to start, "
        "since trusting the header from any direct connection would let "
        "a client spoof its rate-limit bucket and the audit trail. The "
        "upstream proxy must be configured to APPEND to any existing "
        "X-Forwarded-For, e.g. nginx's proxy_add_x_forwarded_for "
        "(default: off, use the raw TCP peer)",
    )
    ap.add_argument(
        "--trusted-proxy-cidr",
        action="append",
        default=[],
        metavar="CIDR",
        help="IPv4/IPv6 CIDR whose TCP peers are trusted reverse proxies "
        "when --trust-proxy is on (repeatable; e.g. --trusted-proxy-cidr "
        "10.0.0.5/32 for one proxy host). Name the smallest range "
        "containing only your proxies -- every reachable peer inside "
        "these ranges can forge X-Forwarded-For outright, so a broad "
        "subnet shared with untrusted clients defeats the allowlist. "
        "X-Forwarded-For from any peer outside these ranges is ignored "
        "and the raw TCP peer is used instead, exactly as if the header "
        "were absent",
    )
    args = ap.parse_args()

    import os

    def _key_arg(cli_value, env_name, flag_name):
        # `cli_value or os.environ.get(...)` would treat an explicitly
        # passed `--report-key ""` the same as not passing the flag at
        # all (empty string is falsy), silently falling through to the
        # env var instead of honoring what was actually typed. Checking
        # `is not None` respects an explicit value, including an empty
        # one -- argparse's own default for these flags is None, so this
        # still falls through to the env var exactly when the flag was
        # never passed.
        if cli_value is not None:
            # Anything passed on argv sits in /proc/<pid>/cmdline, readable
            # by any local user on the same host (even without ptrace
            # permission) for as long as this process lives. The env var
            # form isn't perfectly hidden either, but it doesn't linger in
            # a world-readable proc file, so steer people there instead.
            sys.stderr.write(
                "ac_server: warning: %s was passed on the command line -- "
                "it is visible to any local user via /proc/<pid>/cmdline "
                "for the life of this process; prefer the %s environment "
                "variable instead\n" % (flag_name, env_name)
            )
            return cli_value
        return os.environ.get(env_name)

    # A bearer key this short/uniform is brute-forceable outright, so it's
    # rejected outright rather than merely warned about -- unlike the
    # argv-exposure check above, there's no legitimate reason to allow it.
    MIN_KEY_LENGTH = 16

    def _check_key_strength(key, flag_name):
        if key is None:
            return
        if len(key) < MIN_KEY_LENGTH:
            sys.stderr.write(
                "ac_server: %s is only %d character(s) long -- keys must "
                "be at least %d characters (e.g. `python3 -c \"import "
                "secrets; print(secrets.token_urlsafe(32))\"`) -- refusing "
                "to start with a brute-forceable bearer key\n"
                % (flag_name, len(key), MIN_KEY_LENGTH)
            )
            sys.exit(1)
        # Cheap entropy floor: a key drawn from only a handful of distinct
        # characters (all-same, "aaaa...b", a short repeated pattern) can
        # pad out to MIN_KEY_LENGTH while still being trivially guessable.
        # This isn't a real entropy estimate, just a sanity floor on
        # character variety.
        distinct = len(set(key))
        if distinct < 8:
            sys.stderr.write(
                "ac_server: %s uses only %d distinct character(s) across "
                "%d characters -- too predictable to be a real secret -- "
                "refusing to start\n" % (flag_name, distinct, len(key))
            )
            sys.exit(1)

    report_key = _key_arg(args.report_key, "AC_SERVER_REPORT_KEY", "--report-key")
    admin_key = _key_arg(args.admin_key, "AC_SERVER_ADMIN_KEY", "--admin-key")
    if not report_key or not admin_key:
        sys.stderr.write(
            "ac_server: --report-key/--admin-key (or AC_SERVER_REPORT_KEY/"
            "AC_SERVER_ADMIN_KEY) are required -- refusing to start with no "
            "auth configured\n"
        )
        sys.exit(1)
    _check_key_strength(report_key, "--report-key/AC_SERVER_REPORT_KEY")
    _check_key_strength(admin_key, "--admin-key/AC_SERVER_ADMIN_KEY")

    report_key_old = _key_arg(
        args.report_key_old, "AC_SERVER_REPORT_KEY_OLD", "--report-key-old"
    )
    admin_key_old = _key_arg(
        args.admin_key_old, "AC_SERVER_ADMIN_KEY_OLD", "--admin-key-old"
    )
    _check_key_strength(report_key_old, "--report-key-old/AC_SERVER_REPORT_KEY_OLD")
    _check_key_strength(admin_key_old, "--admin-key-old/AC_SERVER_ADMIN_KEY_OLD")
    report_keys = frozenset({report_key} | ({report_key_old} if report_key_old else set()))
    admin_keys = frozenset({admin_key} | ({admin_key_old} if admin_key_old else set()))

    # Any key valid for one tier must not also be valid for the other --
    # otherwise a daemon holding a report key (or an old one still in its
    # rotation window) could authenticate to the admin-only ban/unban/query
    # endpoints. This generalizes the original report_key == admin_key
    # check to cover the old keys too.
    if report_keys & admin_keys:
        sys.stderr.write(
            "ac_server: a report key and an admin key (current or "
            "-old) are identical -- report and admin tiers must not "
            "overlap\n"
        )
        sys.exit(1)

    if args.rate_limit <= 0 or args.rate_window <= 0:
        sys.stderr.write("ac_server: --rate-limit/--rate-window must be positive\n")
        sys.exit(1)

    if args.max_reports_per_client < 0:
        sys.stderr.write(
            "ac_server: --max-reports-per-client must be >= 0 (0 disables the cap)\n"
        )
        sys.exit(1)

    if args.max_connections <= 0:
        sys.stderr.write("ac_server: --max-connections must be positive\n")
        sys.exit(1)

    try:
        trusted_proxy_cidrs = _parse_proxy_cidrs(args.trusted_proxy_cidr)
    except ValueError as e:
        sys.stderr.write("ac_server: %s -- refusing to start\n" % (e,))
        sys.exit(1)
    if args.trust_proxy and not trusted_proxy_cidrs:
        # Fail closed: without a CIDR allowlist _client_ip() would trust
        # X-Forwarded-For from ANY direct connection, letting a client
        # that can reach this process forge its rate-limit bucket and
        # source_addr (#14). Refusing to start beats silently running
        # either open (old behavior) or with XFF dead (a --trust-proxy
        # that trusts nothing would just confuse the operator).
        sys.stderr.write(
            "ac_server: --trust-proxy requires at least one "
            "--trusted-proxy-cidr naming only your reverse proxies "
            "(e.g. --trusted-proxy-cidr 10.0.0.5/32) -- refusing to "
            "start with X-Forwarded-For trusted from any peer\n"
        )
        sys.exit(1)
    if trusted_proxy_cidrs and not args.trust_proxy:
        # Fail-safe direction (header stays ignored, raw peer used), but
        # almost certainly not what the operator meant -- say so instead
        # of silently running a CIDR list that does nothing.
        sys.stderr.write(
            "ac_server: warning: --trusted-proxy-cidr given without "
            "--trust-proxy -- the allowlist has no effect unless the "
            "header is actually trusted\n"
        )

    if args.trust_proxy and args.unix_socket:
        # --trust-proxy makes the handler take X-Forwarded-For at face
        # value for rate limiting and source_addr. Over the unix-socket
        # transport every peer is already collapsed to one fixed
        # placeholder address (see ThreadingUnixHTTPServer.get_request),
        # so honoring a client-supplied header here wouldn't disambiguate
        # real peers -- it would let any client on the socket forge an
        # arbitrary source_addr and dodge the shared rate-limit bucket.
        sys.stderr.write(
            "ac_server: --trust-proxy has no meaningful effect over "
            "--unix-socket and only lets a client forge its source_addr "
            "-- drop one of the two flags\n"
        )
        sys.exit(1)

    # Restrictive umask for the daemon's own lifetime, set once here while
    # still single-threaded (before Store() creates any file and before the
    # accept loop spawns handler threads). This is what keeps every file
    # SQLite creates afterwards -- DB plus -wal/-shm siblings recreated on
    # every checkpoint -- at 0600 regardless of the launching environment.
    # It lives here, not in Store.__init__, precisely so importing Store as
    # a library never mutates the importer's process-wide umask (#99).
    os.umask(0o077)
    store = Store(args.db, max_reports_per_client=args.max_reports_per_client)
    rate_limiter = RateLimiter(args.rate_limit, args.rate_window)
    handler = make_handler(
        store, report_keys, admin_keys, rate_limiter, args.trust_proxy,
        tuple(trusted_proxy_cidrs),
    )
    if args.unix_socket:
        httpd = ThreadingUnixHTTPServer(
            args.unix_socket, handler, max_connections=args.max_connections
        )
    else:
        httpd = BoundedThreadingHTTPServer(
            (args.host, args.port), handler,
            max_connections=args.max_connections,
        )
    # Drain in-flight requests on shutdown instead of abandoning them.
    # ThreadingHTTPServer defaults daemon_threads=True, under which
    # server_close() below does NOT wait for handler threads still running
    # when serve_forever() returns (see socketserver.ThreadingMixIn) -- a
    # request accepted just before SIGTERM/systemctl-stop would have its
    # connection torn down mid-handling with no response ever sent. Setting
    # this False makes server_close() join every still-running handler
    # thread first; each handler's own worst-case latency is bounded by
    # Store's 5s SQLite busy-timeout, so this can't hang indefinitely.
    httpd.daemon_threads = False

    def _handle_sigterm(signum, frame):
        sys.stderr.write("ac_server: received SIGTERM, shutting down\n")
        # shutdown() blocks until serve_forever()'s loop notices and
        # exits, and must be called from a thread OTHER than the one
        # running serve_forever() or it deadlocks -- this signal handler
        # runs in that same (main) thread, so hand it off.
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _handle_sigterm)

    accepted_old_keys = []
    if report_key_old:
        accepted_old_keys.append("report-key-old")
    if admin_key_old:
        accepted_old_keys.append("admin-key-old")
    rotation_note = ""
    if accepted_old_keys:
        rotation_note = (
            " (key rotation in progress: %s accepted)\n"
            % ", ".join(accepted_old_keys)
        )
    if args.unix_socket:
        listen_desc = (
            "unix socket %s (0600, filesystem permissions are the trust "
            "boundary -- see --unix-socket's help)" % args.unix_socket
        )
    else:
        listen_desc = (
            "%s:%d (plain HTTP -- put a TLS reverse proxy in front for "
            "anything beyond localhost/LAN)" % (args.host, args.port)
        )
    sys.stderr.write(
        "ac_server: listening on %s, db=%s, rate limit %d req/%ds per IP\n"
        % (listen_desc, args.db, args.rate_limit, args.rate_window)
    )
    if rotation_note:
        sys.stderr.write("ac_server:%s" % rotation_note)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()      # no-op/near-instant if SIGTERM already did this
        httpd.server_close()
        if args.unix_socket:
            # Tidy up the socket file on a clean exit -- not required for
            # correctness (server_bind() above unlinks a stale one on the
            # next start regardless), just avoids leaving a dead socket
            # file lying around after a normal shutdown. Only remove it if
            # it's still the same socket this process bound: if another
            # process has since reclaimed the path (e.g. a fresh instance
            # started while this one was draining in-flight requests),
            # unlinking here would pull the path out from under it.
            try:
                cur_stat = os.stat(args.unix_socket)
            except FileNotFoundError:
                pass
            else:
                if (cur_stat.st_dev, cur_stat.st_ino) == (
                    httpd._bound_stat.st_dev,
                    httpd._bound_stat.st_ino,
                ):
                    os.unlink(args.unix_socket)


if __name__ == "__main__":
    main()
