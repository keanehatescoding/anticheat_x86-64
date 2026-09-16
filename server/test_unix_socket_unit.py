#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""test_unix_socket_unit.py -- fast, deterministic test of the server's
--unix-socket-mode/--unix-socket-group options (#33), without root.

- _parse_socket_mode() accepts the usual octal spellings ("0600", "600",
  "0o600") and rejects non-octal/out-of-range input at startup instead of
  binding a socket with unintended permissions.
- _resolve_socket_group() resolves a real group and rejects an unknown
  one, so a typo fails at startup instead of binding with the wrong
  ownership.
- ThreadingUnixHTTPServer applies the given mode (and group) on bind and
  keeps the 0600 default when nothing is passed -- binding real AF_UNIX
  sockets in a temp dir, no serve_forever, no network. Permissions go
  through the socket descriptor (pre-bind fchmod seed, post-bind fchown),
  never the pathname, and the temporarily cleared umask is restored.

No unittest framework, no pytest -- matches this project's existing
test-script style (plain assert-and-report, see
test_reports_pagination_quota_unit.py).
"""
import grp
import http.server
import importlib.util
import os
import pathlib
import stat
import sys
import tempfile

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


print("=== Unix-socket mode/group unit test (#33) ===")

# Octal spellings all land on the same numeric mode.
check("0600 parses to 0o600", ac_server._parse_socket_mode("0600") == 0o600)
check("600 parses to 0o600", ac_server._parse_socket_mode("600") == 0o600)
check("0o600 parses to 0o600", ac_server._parse_socket_mode("0o600") == 0o600)
check("0660 parses to 0o660", ac_server._parse_socket_mode("0660") == 0o660)
check("0770 parses to 0o770", ac_server._parse_socket_mode("0770") == 0o770)

# Anything that is not a 0..0o777 octal mode is refused at startup.
bad_modes = ["", "abc", "06000", "888", "08", "-1", "0o", "6x0", "  "]
rejected = 0
for bad in bad_modes:
    try:
        ac_server._parse_socket_mode(bad)
    except ValueError:
        rejected += 1
    else:
        check("mode %r is rejected" % (bad,), False)
check("all %d invalid modes rejected" % len(bad_modes), rejected == len(bad_modes))

# Group resolution: the current group resolves, a bogus one fails loudly.
own_group = grp.getgrgid(os.getgid()).gr_name
check(
    "own group resolves to own gid",
    ac_server._resolve_socket_group(own_group) == os.getgid(),
)
try:
    ac_server._resolve_socket_group("definitely-no-such-group-xyz")
except ValueError:
    check("unknown group is rejected", True)
else:
    check("unknown group is rejected", False)


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass


def _bind(path, **kwargs):
    return ac_server.ThreadingUnixHTTPServer(path, _QuietHandler, **kwargs)


def _sock_mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


with tempfile.TemporaryDirectory() as tmp:
    # Default bind keeps the owner-only 0600 the DB file itself uses.
    default_sock = os.path.join(tmp, "default.sock")
    srv = _bind(default_sock)
    try:
        check("default socket mode is 0600", _sock_mode(default_sock) == 0o600)
    finally:
        srv.server_close()
        try:
            os.unlink(default_sock)
        except FileNotFoundError:
            pass

    # An explicit mode + group is applied durably at bind time, onto the
    # bound path's own filesystem inode (a bound AF_UNIX path is
    # mknod-created, distinct from the sockfs descriptor, so fchown(fd)
    # would retarget the wrong inode -- the server chowns through the
    # socket directory fd instead). Exercise a group other than the
    # process's own: any supplementary group the process already belongs
    # to (no root, no new groups created).
    custom_sock = os.path.join(tmp, "custom.sock")
    other_gids = sorted(set(os.getgroups()) - {os.getgid()})
    check("a supplementary group exists for the group test", bool(other_gids))
    gid = other_gids[0] if other_gids else os.getgid()
    srv = _bind(custom_sock, mode=0o660, group=gid)
    try:
        check("custom socket mode is 0660", _sock_mode(custom_sock) == 0o660)
        check(
            "custom socket group applied to the path inode",
            os.stat(custom_sock).st_gid == gid,
        )
    finally:
        srv.server_close()
        try:
            os.unlink(custom_sock)
        except FileNotFoundError:
            pass

    # Keep a restrictive umask active through the bind: server_bind()
    # clears it only around its own bind (pre-bind fchmod seed lands at
    # seed & ~umask) and must restore it, so read it back while still in
    # effect and restore prev_umask only in the finally block.
    prev_umask = os.umask(0o077)
    umask_sock = os.path.join(tmp, "umask.sock")
    srv = _bind(umask_sock)
    try:
        cur_umask = os.umask(0o077)
        check("server_bind leaves the process umask unchanged", cur_umask == 0o077)
    finally:
        os.umask(prev_umask)
        srv.server_close()
        try:
            os.unlink(umask_sock)
        except FileNotFoundError:
            pass

    ww_dir = os.path.join(tmp, "wwdir")
    os.mkdir(ww_dir)
    # mkdir is umask-filtered, so force the mode: the refusal must fire
    # on the actual directory bits, not on what umask happened to allow.
    os.chmod(ww_dir, 0o777)
    try:
        _bind(os.path.join(ww_dir, "x.sock"))
    except RuntimeError:
        check("group/other-writable socket directory is refused", True)
    else:
        check("group/other-writable socket directory is refused", False)
