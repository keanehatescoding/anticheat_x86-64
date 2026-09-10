#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""test_logging_hygiene_unit.py -- fast, deterministic test of two
server logging-hygiene fixes (both from the consolidated server audit
checklist, issue #30):

- Handler.address_string() no longer calls socket.getfqdn() per log
  line. BaseHTTPRequestHandler resolves the peer on EVERY log_message /
  log_request / log_error call -- a reverse-DNS lookup per request
  against attacker-influenced source IPs, plus a pointless
  getfqdn("unix") on every unix-socket request. The override returns
  the client_address literal directly.
- BoundedThreadingMixIn.process_request() now emits a server-side log
  line when it rejects a connection over --max-connections. The client
  already got its 503 + Retry-After; without this, stderr showed
  nothing, so a rejection burst was indistinguishable from a quiet
  server in the logs.

No server/network -- handler and mixin instances are built via __new__
with fakes, matching this project's existing unit-test style (see
test_ratelimiter_unit.py).
"""
import contextlib
import importlib.util
import io
import pathlib
import socket
import sys
import threading

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ac_server", HERE / "ac_server.py")
ac_server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ac_server)

FAIL = 0


def check(name, cond):
    global FAIL
    status = "\033[1;32mPASS\033[0m" if cond else "\033[1;31mFAIL\033[0m"
    print(f"  {status}  {name}")
    if not cond:
        FAIL = 1


def make_handler():
    handler_cls = ac_server.make_handler(
        None,
        frozenset({"report-key-12345678"}),
        frozenset({"admin-key-12345678"}),
        ac_server.RateLimiter(limit=1000, window=60),
    )
    inst = handler_cls.__new__(handler_cls)
    return inst


print("=== Logging hygiene unit test (issue #30) ===")
print()

# --- address_string() never touches reverse DNS ---
real_getfqdn = socket.getfqdn


def exploding_getfqdn(_name):
    raise AssertionError("address_string() must not call socket.getfqdn()")


socket.getfqdn = exploding_getfqdn
try:
    h = make_handler()
    h.client_address = ("203.0.113.7", 41234)
    check("TCP peer logs as bare IP literal", h.address_string() == "203.0.113.7")

    h_unix = make_handler()
    h_unix.client_address = ("unix", 0)
    check("unix-socket peer logs as placeholder", h_unix.address_string() == "unix")

    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        h.log_message("hello %s", "world")
    check(
        "log_message line carries the literal peer",
        buf.getvalue() == "203.0.113.7 - hello world\n",
    )
finally:
    socket.getfqdn = real_getfqdn

check("socket.getfqdn restored after test", socket.getfqdn is real_getfqdn)


# --- over-capacity 503 rejection leaves a server-side log line ---
class FakeRequest:
    def __init__(self):
        self.sent = b""
        self.shutdown_called = False

    def settimeout(self, _timeout):
        pass

    def sendall(self, data):
        self.sent += data


mixin = ac_server.BoundedThreadingMixIn.__new__(ac_server.BoundedThreadingMixIn)
mixin._conn_semaphore = threading.Semaphore(0)  # every acquire fails
mixin.max_connections = 0
fake = FakeRequest()
mixin.shutdown_request = lambda _request: setattr(fake, "shutdown_called", True)

buf = io.StringIO()
with contextlib.redirect_stderr(buf):
    result = mixin.process_request(fake, ("198.51.100.9", 9999))
logged = buf.getvalue()

check("rejected connection returns without a handler thread", result is None)
check("client still gets its 503 + Retry-After", b"503 Service Unavailable" in fake.sent
      and b"Retry-After: 5" in fake.sent)
check("rejected socket is still shut down", fake.shutdown_called)
check(
    "rejection is logged server-side with peer and cap",
    "198.51.100.9" in logged and "--max-connections" in logged,
)

# --- rejection log is throttled: a flood coalesces, accept loop never
# --- blocks on stderr per connection ---
def reject_once(peer):
    f = FakeRequest()
    mixin.shutdown_request = lambda _request: setattr(f, "shutdown_called", True)
    out = io.StringIO()
    with contextlib.redirect_stderr(out):
        mixin.process_request(f, peer)
    return f, out.getvalue()

fake2, logged2 = reject_once(("198.51.100.10", 9998))
check("client still gets its 503 during a burst", b"503 Service Unavailable" in fake2.sent)
check("burst rejection inside the window logs nothing", logged2 == "")

# Force the window to expire, then the next rejection must flush the
# suppressed count in a single line.
mixin._overload_log_last -= (
    ac_server.BoundedThreadingMixIn.OVERLOAD_LOG_INTERVAL_SEC + 1.0)
fake3, logged3 = reject_once(("198.51.100.11", 9997))
check(
    "post-window rejection logs once with suppressed count",
    "--max-connections" in logged3 and "+1 similar suppressed" in logged3
    and logged3.count("rejected: over") == 1,
)

print()
if FAIL:
    print("\033[1;31mSOME LOGGING HYGIENE UNIT TESTS FAILED\033[0m")
else:
    print("\033[1;32mALL LOGGING HYGIENE UNIT TESTS PASSED\033[0m")
sys.exit(FAIL)
