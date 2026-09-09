#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""test_ratelimiter_unit.py -- fast, deterministic test of
RateLimiter._prune()'s bucket-cleanup behavior.

RateLimiter._buckets grows one entry per distinct key (source IP) ever
seen, with nothing to evict them but _prune() (see the class's own
docstring in ac_server.py). The live HTTP suite (test_server.sh)
thoroughly exercises the *rate-limiting* behavior this class provides,
but has no way to observe its *internal* memory behavior under many
distinct keys -- that's what this test is for, isolated from any server/
network/root, and fast enough (~1s) to run on every push rather than
only in the nightly stress job (see stress_test.sh for the live,
concurrent, sustained-load counterpart to this).

No unittest framework, no pytest -- matches this project's existing
test-script style (plain assert-and-report, see test_server.sh).
"""
import importlib.util
import pathlib
import sys
import time

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


print("=== RateLimiter unit test: bucket pruning ===")
print()

WINDOW = 1  # seconds -- short so this test stays fast
N_KEYS = 500

rl = ac_server.RateLimiter(limit=1_000_000, window=WINDOW)

# Populate _buckets with many distinct keys, the same shape a burst of
# traffic from many distinct source IPs produces.
for i in range(N_KEYS):
    rl.allow(f"203.0.113.{i % 256}-{i}")

check(f"buckets populated ({N_KEYS} distinct keys)", len(rl._buckets) == N_KEYS)

# _prune() only runs opportunistically from inside allow() (roughly once
# per window -- see allow()'s "now - self._last_prune >= self.window"
# check), so an actual elapsed window plus one more allow() call is what
# it takes to trigger it for real, not a mocked clock. Captured before
# the sleep so the assertion below can prove _prune() actually moved
# this value forward, not just that it happens to already be recent --
# _last_prune is set at construction time too, so comparing only against
# a fixed time.time()-derived threshold would pass even if _prune()
# silently never ran at all.
last_prune_before = rl._last_prune
time.sleep(WINDOW + 0.1)
rl.allow("trigger-prune")

# Every one of the N_KEYS buckets was first touched before the sleep, so
# all of them are stale by now and should have been evicted -- only the
# just-added "trigger-prune" key (and possibly nothing else) should
# remain. A real leak (a _prune() that silently stopped evicting
# anything) would instead leave this at N_KEYS + 1.
check(
    "stale buckets evicted after their window elapses "
    f"(before={N_KEYS}, after={len(rl._buckets)})",
    len(rl._buckets) <= 2,
)

# _prune() itself should also have advanced _last_prune -- otherwise
# every single allow() call after the window would re-scan the (by now
# empty) dict for no reason forever, which isn't a correctness bug but
# would be a silent perf regression from the "roughly once per window"
# design this class documents for itself. Compared against the captured
# before-value, not a fixed time-based threshold, so this actually
# fails if _prune() didn't run rather than passing by coincidence.
check(
    "_last_prune advanced past the window (prune isn't re-scanning every call)",
    rl._last_prune > last_prune_before,
)

print("=== RateLimiter unit test: max_keys hard cap (#25) ===")
print()

# No sleep here on purpose: _prune() only runs ~once per window, so a
# burst of distinct keys inside a single window is exactly the shape that
# used to grow _hits without bound. Window is 60s so nothing goes stale
# mid-test; only the hard cap can keep this bounded.
CAP = 64
rl_cap = ac_server.RateLimiter(limit=1_000_000, window=60, max_keys=CAP)
for i in range(200):
    rl_cap.allow(f"198.51.100.{i % 256}-{i}")

check(
    f"distinct-key burst stays bounded without waiting for prune (cap={CAP}, after={len(rl_cap._buckets)})",
    len(rl_cap._buckets) <= CAP,
)
check(
    "oldest keys evicted first, newest retained",
    "198.51.100.0-0" not in rl_cap._buckets
    and "198.51.100.199-199" in rl_cap._buckets,
)

# Recently-used keys survive eviction (LRU, not FIFO): with cap 3 holding
# a, b, c, re-touching a then adding d must evict b, not a.
rl_lru = ac_server.RateLimiter(limit=1_000_000, window=60, max_keys=3)
for k in ("a", "b", "c"):
    rl_lru.allow(k)
rl_lru.allow("a")
rl_lru.allow("d")
check(
    "recently-used key survives eviction (LRU order)",
    "a" in rl_lru._buckets and "b" not in rl_lru._buckets and "d" in rl_lru._buckets,
)

# The cap must not break per-key limiting for retained keys, and an
# evicted key restarts with a fresh (generous) budget on its next request.
rl_lim = ac_server.RateLimiter(limit=2, window=60, max_keys=2)
check("within limit allowed", rl_lim.allow("victim") and rl_lim.allow("victim"))
check("over limit denied", not rl_lim.allow("victim"))
rl_lim.allow("other")
rl_lim.allow("evictor")  # exceeds cap, evicts least-recently-seen ("victim")
check(
    "evicted key restarts with a fresh budget (fail-open, not stuck denied)",
    rl_lim.allow("victim"),
)

for bad in (0, -1, True, False, 1.5, float("inf"), float("nan"), "64", None):
    try:
        ac_server.RateLimiter(limit=1, window=1, max_keys=bad)
        check(f"max_keys={bad!r} rejected", False)
    except ValueError:
        check(f"max_keys={bad!r} rejected", True)

print()
if FAIL:
    print("\033[1;31mSOME RATELIMITER UNIT TESTS FAILED\033[0m")
else:
    print("\033[1;32mALL RATELIMITER UNIT TESTS PASSED\033[0m")
sys.exit(FAIL)
