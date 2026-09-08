#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""test_auth_dispatch_unit.py -- fast, deterministic test of the server's
two request-trust boundaries (#13, #14), without any network or root.

- #13: dispatch is deny-by-default. Every _handle_* method on the
  Handler class must either carry the @_requires_auth marker or be named
  in PUBLIC_HANDLERS, and _route_guarded() must 401 anything else instead
  of running it -- so a future endpoint that forgets the decorator fails
  closed. The live HTTP suite (test_server.sh) proves each *current*
  endpoint 401s without a key; only this test can observe the *dispatch
  invariant* itself, which is what stops the *next* endpoint from going
  out open by omission.
- #14: X-Forwarded-For is only honored for TCP peers inside a configured
  --trusted-proxy-cidr. _parse_proxy_cidrs() rejects garbage at startup
  (fail closed, not silently untrusted), and _client_ip() falls back to
  the raw peer for anyone outside the allowlist.

No unittest framework, no pytest -- matches this project's existing
test-script style (plain assert-and-report, see test_server.sh).
"""
import importlib.util
import pathlib
import sys
from email.message import Message

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


print("=== Auth dispatch unit test: deny-by-default (#13) ===")

REPORT_KEYS = frozenset({"test-report-key-0123456789"})
ADMIN_KEYS = frozenset({"test-admin-key-0123456789"})
Handler = ac_server.make_handler(
    object(), REPORT_KEYS, ADMIN_KEYS, ac_server.RateLimiter(1000, 60)
)

handlers = sorted(
    name for name in vars(Handler) if name.startswith("_handle_")
)
check("handler set is non-empty (test would be vacuous otherwise)", bool(handlers))

# The invariant itself: no routed handler may be reachable without either
# an explicit auth marking or an explicit public allow-listing. A future
# undecorated endpoint fails this test before it can fail open in prod.
unmarked = [
    name for name in handlers
    if getattr(getattr(Handler, name), "_ac_auth_keys", None) is None
    and name not in ac_server.PUBLIC_HANDLERS
]
check(
    "every _handle_* is authed or explicitly public "
    f"(violations: {unmarked})",
    not unmarked,
)

# The allow-list must not rot either: a name in PUBLIC_HANDLERS with no
# such handler would be a stale entry nobody re-examines, and a typo'd
# name would silently not-exempt the handler it meant to cover.
stale = [n for n in ac_server.PUBLIC_HANDLERS if n not in handlers]
check(
    f"PUBLIC_HANDLERS names real handlers (stale: {stale})",
    not stale,
)

# The decorator marks with the exact key tier it enforces, so the
# dispatcher's marker check and the decorator's 401 can't drift apart
# (e.g. report-tier handler accidentally marked with admin keys).
check(
    "report handler marked with the report tier",
    getattr(Handler._handle_report, "_ac_auth_keys", None) == REPORT_KEYS,
)
check(
    "admin handlers marked with the admin tier",
    all(
        getattr(getattr(Handler, name), "_ac_auth_keys", None) == ADMIN_KEYS
        for name in ("_handle_ban", "_handle_unban",
                     "_handle_banned", "_handle_reports")
    ),
)


def bare_handler(cls=None, **stub):
    """A Handler with no socket: only the pure-logic methods under test
    (_route_guarded, _client_ip) are callable; anything touching the
    connection would raise, which is fine -- these tests never do.
    `cls` selects which make_handler parameterization to instantiate,
    since trust_proxy/trusted_proxy_nets live in the defining closure."""
    h = (cls or Handler).__new__(cls or Handler)
    h.client_address = ("127.0.0.1", 9999)
    h.headers = Message()
    calls = {}

    def _send_json(code, obj, extra_headers=None):
        calls["code"] = code
        calls["obj"] = obj
        return None

    h._send_json = _send_json
    h.log_message = lambda *a: calls.setdefault("logged", []).append(a)
    h.__dict__.update(stub)
    return h, calls


# An unmarked handler must 401 through the dispatcher, never run.
ran = []
h, calls = bare_handler()


def _forgotten_endpoint():
    ran.append(True)


h._route_guarded(_forgotten_endpoint)
check("unmarked handler denied with 401", calls.get("code") == 401)
check("unmarked handler never ran", not ran)


# A marked handler passes the guard through and actually runs (a bare
# function with the marker stands in for a decorated _handle_* here).
def _marked():
    return "reached"


_marked._ac_auth_keys = frozenset({"k"})
h2, calls2 = bare_handler()
h2._route_guarded(_marked)
check(
    "marked handler passes the dispatcher guard "
    f"(got {calls2.get('code')})",
    "code" not in calls2,
)

# A PUBLIC_HANDLERS entry passes the guard without any marker.
h3, calls3 = bare_handler()


def _healthz():
    return "ok"


_healthz.__name__ = "_healthz_for_test_only"
old_public = ac_server.PUBLIC_HANDLERS
ac_server.PUBLIC_HANDLERS = frozenset({"_healthz_for_test_only"})
try:
    h3._route_guarded(_healthz)
finally:
    ac_server.PUBLIC_HANDLERS = old_public
check("explicitly public handler passes the guard", "code" not in calls3)

print()
print("=== Trusted-proxy CIDR unit test (#14) ===")


def client_ip(trust_proxy, cidrs, peer, xff=None):
    H = ac_server.make_handler(
        object(), REPORT_KEYS, ADMIN_KEYS, ac_server.RateLimiter(1000, 60),
        trust_proxy, ac_server._parse_proxy_cidrs(cidrs),
    )
    # Instantiate the parameterized class itself: trust_proxy and
    # trusted_proxy_nets live in make_handler's closure, so the
    # instance must come from H, not the module-global Handler.
    h, _ = bare_handler(H)
    h.client_address = (peer, 9999)
    if xff is not None:
        h.headers["X-Forwarded-For"] = xff
    return h._client_ip()


TRUSTED_XFF = "9.9.9.9, 10.0.0.5"
check(
    "trusted peer: last (proxy-authored) XFF hop used",
    client_ip(True, ["127.0.0.0/8"], "127.0.0.1", TRUSTED_XFF) == "10.0.0.5",
)
check(
    "untrusted peer: XFF ignored, raw peer used",
    client_ip(True, ["10.0.0.0/8"], "127.0.0.1", TRUSTED_XFF) == "127.0.0.1",
)
check(
    "trust off: XFF ignored even for an allowlisted peer",
    client_ip(False, ["127.0.0.0/8"], "127.0.0.1", TRUSTED_XFF) == "127.0.0.1",
)
check(
    "trusted peer, malformed XFF: raw peer used",
    client_ip(True, ["127.0.0.0/8"], "127.0.0.1", "not-an-ip") == "127.0.0.1",
)
check(
    "trusted peer, no XFF: raw peer used",
    client_ip(True, ["127.0.0.0/8"], "127.0.0.1") == "127.0.0.1",
)
check(
    "v4 peer vs v6-only allowlist: no match, no crash, raw peer used",
    client_ip(True, ["::/0"], "127.0.0.1", TRUSTED_XFF) == "127.0.0.1",
)
check(
    "v6 peer inside v6 allowlist: XFF honored",
    client_ip(True, ["::1/128"], "::1", "2001:db8::9, ::1") == "::1",
)
check(
    "unix-socket placeholder peer: untrusted, raw value used, no crash",
    client_ip(True, ["127.0.0.0/8"], "unix", TRUSTED_XFF) == "unix",
)

check(
    "parses single + repeated + v6 CIDRs",
    [str(n) for n in ac_server._parse_proxy_cidrs(
        ["10.0.0.0/8", "192.168.0.1/32", "fd00::/8"])]
    == ["10.0.0.0/8", "192.168.0.1/32", "fd00::/8"],
)
check(
    "empty/None input parses to no networks",
    ac_server._parse_proxy_cidrs([]) == []
    and ac_server._parse_proxy_cidrs(None) == [],
)
try:
    ac_server._parse_proxy_cidrs(["10.0.0.0/8", "not-a-cidr"])
    bad_rejected = False
except ValueError:
    bad_rejected = True
check("garbage CIDR raises ValueError (startup refuses)", bad_rejected)

print()
if FAIL:
    print("\033[1;31mSOME AUTH DISPATCH UNIT TESTS FAILED\033[0m")
else:
    print("\033[1;32mALL AUTH DISPATCH UNIT TESTS PASSED\033[0m")
sys.exit(FAIL)
