#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""test_request_framing_unit.py -- fast, deterministic test of three related
issue-#30 request-framing findings in server/ac_server.py: oversized bodies
must get a clean 413 (not a generic 400), chunked Transfer-Encoding must be
rejected outright (the server never decodes it, so falling back to
Content-Length beside it is request-smuggling-adjacent), and duplicate
Content-Length headers must be rejected (headers.get() would return only the
first, desyncing the body read from what the sender meant).

No network, no server process: drives Handler._require_body_client_id()
directly with stubbed headers/rfile and captures the sent status. Follows
the same pattern as the other server/*_unit.py tests.
"""
import importlib.util
import io
import pathlib
import sys

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


class StubHeaders:
    """Minimal email.message.Message surface the handler touches: get()
    returns the FIRST value (matching real semantics), get_all() returns
    every occurrence."""

    def __init__(self, pairs):
        self._pairs = list(pairs)

    def get(self, name, default=None):
        lname = name.lower()
        for k, v in self._pairs:
            if k.lower() == lname:
                return v
        return default

    def get_all(self, name):
        lname = name.lower()
        vals = [v for k, v in self._pairs if k.lower() == lname]
        return vals or None


class ExplodingReader:
    """rfile stub that fails the test if the handler touches the body --
    framing rejections must happen header-only, without reading."""

    def read(self, _n=-1):
        raise AssertionError("framing rejection must not read the body")


def make_handler(headers, rfile):
    handler_cls = ac_server.make_handler(
        None,
        frozenset({"report-key-12345678"}),
        frozenset({"admin-key-12345678"}),
        ac_server.RateLimiter(limit=1000, window=60),
    )
    inst = handler_cls.__new__(handler_cls)
    inst.headers = headers
    inst.rfile = rfile
    sent = {}

    def fake_send(code, obj, extra_headers=None):
        sent["code"] = code
        sent["obj"] = obj

    inst._send_json = fake_send
    return inst, sent


def body_bytes(payload):
    return payload.encode("utf-8")


print("=== Request framing unit test (issue #30) ===")
print()

# --- happy path: single sane Content-Length still parses ---
payload = '{"client_id": "desk-01"}'
h, sent = make_handler(
    StubHeaders([("Content-Length", str(len(body_bytes(payload))))]),
    io.BytesIO(body_bytes(payload)),
)
got = h._require_body_client_id()
check("sane request parses and returns the body",
      got == {"client_id": "desk-01"} and sent == {})

# --- oversized body: clean 413, body never read ---
h, sent = make_handler(
    StubHeaders([("Content-Length", str(ac_server.MAX_BODY_BYTES + 1))]),
    ExplodingReader(),
)
check("oversized body returns None",
      h._require_body_client_id() is None)
check("oversized body gets 413 (not generic 400)",
      sent.get("code") == 413)
check("oversized body error names the problem",
      sent.get("obj", {}).get("error") == "payload too large")

# --- 5000-digit Content-Length: beyond int()'s conversion limit, must
# --- still be a header-only 413, never a 500 via _dispatch (review #58) ---
h, sent = make_handler(
    StubHeaders([("Content-Length", "9" * 5000)]),
    ExplodingReader(),
)
check("gigantic Content-Length gets 413, body unread",
      h._require_body_client_id() is None and sent.get("code") == 413)

# --- exactly MAX_BODY_BYTES still passes framing AND parses: build a
# --- serialized body of precisely that size and run the full funnel ---
edge_prefix = b'{"client_id": "desk-01", "pad": "'
edge_suffix = b'"}'
edge_raw = (edge_prefix + b"x" * (
    ac_server.MAX_BODY_BYTES - len(edge_prefix) - len(edge_suffix))
    + edge_suffix)
assert len(edge_raw) == ac_server.MAX_BODY_BYTES
h, sent = make_handler(
    StubHeaders([("Content-Length", str(len(edge_raw)))]),
    io.BytesIO(edge_raw),
)
check("body exactly at the limit parses with no error sent",
      h._require_body_client_id() == {"client_id": "desk-01",
                                      "pad": "x" * (
                                          ac_server.MAX_BODY_BYTES
                                          - len(edge_prefix)
                                          - len(edge_suffix))}
      and sent == {})

# --- chunked Transfer-Encoding rejected even with no Content-Length ---
h, sent = make_handler(
    StubHeaders([("Transfer-Encoding", "chunked")]),
    ExplodingReader(),
)
check("chunked body returns None",
      h._require_body_client_id() is None)
check("chunked body gets 400", sent.get("code") == 400)
check("chunked error names the problem",
      sent.get("obj", {}).get("error")
      == "chunked transfer-encoding not supported")

# --- chunked + Content-Length together (smuggling shape) rejected ---
h, sent = make_handler(
    StubHeaders([("Transfer-Encoding", "chunked"),
                 ("Content-Length", str(len(body_bytes(payload))))]),
    ExplodingReader(),
)
check("chunked + Content-Length returns None",
      h._require_body_client_id() is None)
check("chunked + Content-Length gets 400, not a guessed read",
      sent.get("code") == 400)

# --- duplicate Content-Length rejected (differing values) ---
h, sent = make_handler(
    StubHeaders([("Content-Length", "5"), ("Content-Length", "5000")]),
    ExplodingReader(),
)
check("duplicate Content-Length returns None",
      h._require_body_client_id() is None)
check("duplicate Content-Length gets 400", sent.get("code") == 400)
check("duplicate error names the problem",
      sent.get("obj", {}).get("error") == "duplicate content-length")

# --- duplicate Content-Length rejected even when identical (strict:
# --- the daemon never sends these, so a duplicate is always a buggy or
# --- hostile client, and .get() would silently honor only the first) ---
h, sent = make_handler(
    StubHeaders([("Content-Length", "5"), ("Content-Length", "5")]),
    ExplodingReader(),
)
check("identical duplicate Content-Length still 400s",
      h._require_body_client_id() is None and sent.get("code") == 400)

# --- non-decimal Content-Length syntax rejected: int() alone would accept
# --- "+16" or "1_6" as 16, letting a framing no downstream parser agrees
# --- on slip through (review on #58). Only optional whitespace around
# --- plain ASCII digits is valid. ---
for weird in ("+16", "1_6", "0x10", "-5", "1.5", "١٦"):
    h, sent = make_handler(
        StubHeaders([("Content-Length", weird)]),
        ExplodingReader(),
    )
    check(f"Content-Length {weird!r} gets 400, body unread",
          h._require_body_client_id() is None and sent.get("code") == 400)

h, sent = make_handler(
    StubHeaders([("Content-Length", "  %d  " % len(body_bytes(payload)))]),
    io.BytesIO(body_bytes(payload)),
)
check("OWS-padded decimal Content-Length still parses",
      h._require_body_client_id() == {"client_id": "desk-01"})

# --- regression pins: pre-existing behavior unchanged ---
h, sent = make_handler(
    StubHeaders([("Content-Length", "garbage")]),
    ExplodingReader(),
)
check("garbage Content-Length still 400s",
      h._require_body_client_id() is None and sent.get("code") == 400)

h, sent = make_handler(StubHeaders([]), ExplodingReader())
check("missing Content-Length still 400s",
      h._require_body_client_id() is None and sent.get("code") == 400)

h, sent = make_handler(
    StubHeaders([("Content-Length", str(len(body_bytes(payload))))]),
    io.BytesIO(b"not json{{{"),
)
check("malformed JSON still 400s",
      h._require_body_client_id() is None and sent.get("code") == 400)

print()
if FAIL:
    print("\033[1;31mSOME REQUEST FRAMING UNIT TESTS FAILED\033[0m")
else:
    print("\033[1;32mALL REQUEST FRAMING UNIT TESTS PASSED\033[0m")
sys.exit(FAIL)
