#!/bin/bash
# stress_test.sh -- sustained concurrent load against a real ac_server.py
# instance: $STRESS_CONCURRENCY workers hammering /report in parallel for
# $STRESS_DURATION seconds, verifying the server survives (no crash, no
# unexpected errors) and that every successfully-201'd report is actually
# durably recorded -- something test_server.sh's short, mostly-sequential
# suite doesn't exercise. Complements test_ratelimiter_unit.py: that one
# proves RateLimiter._buckets doesn't grow unboundedly in isolation; this
# one proves the server as a whole holds up under real concurrent
# ThreadingHTTPServer + one-SQLite-connection-per-request load.
#
# No root, no kernel module -- pure HTTP against a throwaway SQLite DB,
# same as test_server.sh. Deliberately NOT part of the fast per-push CI
# job (see .github/workflows/stress.yml) -- this is meant to run for
# minutes, not seconds.
#
# Override via environment: STRESS_DURATION=1800 STRESS_CONCURRENCY=50
# ./server/stress_test.sh for a real extended soak run locally.
set -u

cd "$(dirname "$0")" || exit 1

DURATION="${STRESS_DURATION:-90}"
CONCURRENCY="${STRESS_CONCURRENCY:-20}"
# A zero/negative/non-numeric value here wouldn't fail loudly -- $end
# below could equal or precede "now", so every worker's while-loop would
# run zero times and this script would still report success on zero
# actual load, and `seq 1 "$CONCURRENCY"` with a bad value fails
# unpredictably rather than cleanly. Reject both explicitly up front.
if ! [[ "$DURATION" =~ ^[1-9][0-9]*$ && "$CONCURRENCY" =~ ^[1-9][0-9]*$ ]]; then
    printf 'STRESS_DURATION and STRESS_CONCURRENCY must be positive integers (got DURATION=%s CONCURRENCY=%s)\n' \
        "$DURATION" "$CONCURRENCY" >&2
    exit 2
fi
PORT=18900
TESTDIR="$(mktemp -d /tmp/ac_server_stress.XXXXXXXX)"
DB="$TESTDIR/ac_server.db"
# cleanup() below always rm -rf's $TESTDIR, including server.log and every
# worker's errlog -- exactly the files needed to diagnose a failure. On
# FAIL, copy them here (relative to this script's own dir, i.e.
# server/stress-failure-artifacts/) before that happens, so CI can upload
# them as a build artifact instead of the failure reason being lost the
# moment this script exits.
ARTIFACT_DIR="$(pwd)/stress-failure-artifacts"
REPORT_KEY="stress-report-key-$$"
ADMIN_KEY="stress-admin-key-$$"
BASE="http://127.0.0.1:$PORT"
# Every curl call below uses this: without a bound, a stalled connection
# or response could block a worker past $DURATION, and the top-level
# `wait` would then block indefinitely too -- the same class of hang
# this script's cleanup()/trap handling already exists to guard against,
# just from the opposite direction (a stuck request instead of a killed
# process). --max-time was originally 5s; raised to 20s after a real run
# (30 workers, 300s, both in CI and reproduced locally) showed that value
# was too tight for this architecture under sustained 30-way contention --
# every one of those "failures" was curl code 000 (client gave up) for a
# request the server log showed as a clean 201 moments later, not a
# server-side error. 20s still firmly bounds a genuine indefinite hang;
# it just stops manufacturing false failures out of ordinary queueing
# delay under load. See the worker loop and durability check below for
# how a 000 is now told apart from an actual error.
CURL_CONNECT_TIMEOUT=2
CURL_MAX_TIME=20
CURL_TIMEOUT=(--connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME")

FAIL=0
pass() { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; FAIL=1; }

SERVER_PID=""
WORKER_PIDS=""
# shellcheck disable=SC2317,SC2329
cleanup() {
    # Worker PIDs first: each runs its own while-loop for the full
    # $DURATION independently of the server, so on any early/abnormal
    # exit (Ctrl-C, a CI job timeout sending SIGTERM, a failure earlier
    # in this script) they must be killed explicitly -- they are NOT
    # children of $SERVER_PID and killing only that PID leaves every
    # worker's loop running for the rest of its original $DURATION,
    # orphaned, still hammering $PORT.
    # shellcheck disable=SC2086
    [ -n "$WORKER_PIDS" ] && kill $WORKER_PIDS 2>/dev/null
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    # shellcheck disable=SC2086
    [ -n "$WORKER_PIDS" ] && wait $WORKER_PIDS 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    if [ "$FAIL" -ne 0 ]; then
        mkdir -p "$ARTIFACT_DIR"
        cp "$TESTDIR/server.log" "$ARTIFACT_DIR/" 2>/dev/null
        cp "$TESTDIR"/worker-*.errlog "$ARTIFACT_DIR/" 2>/dev/null
    fi
    rm -rf "$TESTDIR"
}
trap cleanup EXIT
# EXIT alone does not reliably run on every signal-terminated shell in
# every context -- explicit traps make cleanup unconditional rather than
# incidental, which matters here specifically because leftover workers
# are a real, previously-hit failure mode (see the comment above), not
# a hypothetical one.
trap 'FAIL=1; cleanup; exit 130' INT
trap 'FAIL=1; cleanup; exit 143' TERM

echo "=== server stress test: $CONCURRENCY workers x ${DURATION}s ==="
echo

# Rate limit set far above anything this run could plausibly trip --
# rate-limiting correctness itself is test_server.sh's job; this run is
# about concurrency/durability, and a 429 here would just be noise
# obscuring that signal.
AC_SERVER_REPORT_KEY="$REPORT_KEY" AC_SERVER_ADMIN_KEY="$ADMIN_KEY" \
    python3 ./ac_server.py --host 127.0.0.1 --port "$PORT" --db "$DB" \
    --rate-limit 1000000 --rate-window 60 \
    >"$TESTDIR/server.log" 2>&1 &
SERVER_PID=$!

READY=0
for _ in $(seq 1 50); do
    if curl -s "${CURL_TIMEOUT[@]}" "$BASE/banned/x" -H "Authorization: Bearer $ADMIN_KEY" 2>/dev/null \
        | grep -q '"banned"'; then
        READY=1
        break
    fi
    sleep 0.1
done
if [ "$READY" -ne 1 ]; then
    fail "server never became ready on $BASE (port collision with another service?)"
    exit 1
fi

# Each worker hammers /report with its own client_id for the full
# duration, recording how many 201s, client-side timeouts, and other
# (genuinely unexpected) codes it saw. Result written to a file rather
# than a shared variable -- these run as separate background processes,
# nothing else crosses that boundary.
#
# curl reports "000" for %{http_code} whenever it never received a
# complete response -- both for --max-time firing (a request the server
# may well have actually completed) AND for a genuine transport failure
# like connection-refused or a reset connection (a real error, not
# ordinary load-induced latency). %{http_code} alone can't tell those
# apart; curl's own exit status can -- 28 is specifically "operation
# timeout" (this call's own --connect-timeout/--max-time firing), while
# every other nonzero exit is a real transport failure. Classified on
# that instead of the code string, so a connection failure doesn't get
# silently miscounted as the same benign "server was just slow" bucket a
# --max-time timeout belongs in.
worker() {
    local id="$1"
    local cid="stress-worker-$id-$$"
    local ok=0
    local timeouts=0
    local errors=0
    local n=0
    local bodyfile="$TESTDIR/worker-$id.lastbody"
    local end=$(( $(date +%s) + DURATION ))
    while [ "$(date +%s)" -lt "$end" ]; do
        n=$((n + 1))
        code=$(curl -s "${CURL_TIMEOUT[@]}" -o "$bodyfile" -w '%{http_code}' -X POST "$BASE/report" \
            -H "Authorization: Bearer $REPORT_KEY" -H 'Content-Type: application/json' \
            -d "{\"client_id\":\"$cid\",\"event_type\":\"X\",\"detail\":\"n=$n\",\"ts\":$n}")
        rc=$?
        if [ "$rc" -eq 0 ] && [ "$code" = "201" ]; then
            ok=$((ok + 1))
        elif [ "$rc" -eq 28 ]; then
            timeouts=$((timeouts + 1))
            printf 'n=%d rc=%d (timeout, response unavailable)\n' "$n" "$rc" >> "$TESTDIR/worker-$id.errlog"
        else
            errors=$((errors + 1))
            # Only rc=0 means curl actually got a complete response to show
            # a body/code for; a nonzero, non-28 rc is a transport failure
            # (connection refused/reset) where $bodyfile is stale or empty
            # from a prior iteration, not useful/attributable to this one.
            {
                if [ "$rc" -eq 0 ]; then
                    printf 'n=%d rc=%d code=%s body=%s\n' "$n" "$rc" "$code" "$(head -c 300 "$bodyfile" 2>/dev/null)"
                else
                    printf 'n=%d rc=%d (transport failure, no response)\n' "$n" "$rc"
                fi
            } >> "$TESTDIR/worker-$id.errlog"
        fi
    done
    printf '%s %d %d %d\n' "$cid" "$ok" "$timeouts" "$errors" > "$TESTDIR/worker-$id.result"
}

for i in $(seq 1 "$CONCURRENCY"); do
    worker "$i" &
    WORKER_PIDS="$WORKER_PIDS $!"
done
# shellcheck disable=SC2086
wait $WORKER_PIDS
WORKER_PIDS=""  # all reaped normally -- nothing left for cleanup() to kill

echo "-- checking every worker's successful reports landed durably --"
TOTAL_OK=0
TOTAL_TIMEOUTS=0
TOTAL_ERRORS=0
DB_MISMATCH=0
# Page size for the API durability walk below: one DEFAULT_LIST_LIMIT page
# at a time (see Store.DEFAULT_LIST_LIMIT in ac_server.py), so any worker
# that stored more than a page forces the walk past offset=0 and actually
# exercises multi-page pagination rather than a single full-store fetch.
API_PAGE=200
for i in $(seq 1 "$CONCURRENCY"); do
    read -r CID OK TIMEOUTS ERRORS < "$TESTDIR/worker-$i.result"
    TOTAL_OK=$((TOTAL_OK + OK))
    TOTAL_TIMEOUTS=$((TOTAL_TIMEOUTS + TIMEOUTS))
    TOTAL_ERRORS=$((TOTAL_ERRORS + ERRORS))
    # COUNT(*) against the DB file is the ground truth for what is
    # actually stored -- but on its own it bypasses the API contract an
    # operator reviews reports through (#30). The paginated walk below
    # proves the same rows are reachable via ?limit=&offset=? (#27); both
    # halves have to agree before this check passes.
    #
    # That agreement is reached by convergence, never by a single
    # immediate compare: wait $WORKER_PIDS above only reaps the
    # client-side curl loops, while the server keeps running. A request
    # curl gave up on (client-side 000, counted in TIMEOUTS rather than
    # OK) can still be sitting in the server's write queue and commit
    # after this check starts. A commit landing between the COUNT(*) read
    # and the walk -- or mid-walk, shifting ORDER BY id DESC offsets so a
    # row is skipped or double-counted across a page boundary -- would
    # fail an exact one-shot match even though the server behaved
    # correctly. So each walk is retried until its total equals a fresh
    # COUNT(*): every worker is reaped, so only already-received requests
    # can still commit -- a finite tail, meaning the readings must
    # converge. Disagreement that survives the retries is a real listing
    # bug, and fails.
    STABLE=0
    DB_COUNT=0
    API_COUNT=""
    API_RC=0
    for _ in $(seq 1 6); do
        DB_COUNT=$(python3 -c "
import sqlite3
con = sqlite3.connect('$DB')
print(con.execute('SELECT COUNT(*) FROM reports WHERE client_id = ?', ('$CID',)).fetchone()[0])
")
        API_COUNT="$(python3 - "$BASE" "$CID" "$ADMIN_KEY" "$API_PAGE" <<'EOF'
import json
import sys
import urllib.request
base, cid, key, page = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
total = 0
offset = 0
# Stored rows here are bounded by the per-client retention cap (1000 by
# default, 5 pages at this page size), so this loop is short -- the guard
# is only against looping forever if the server ever misbehaves.
for _ in range(1000):
    url = "%s/reports/%s?limit=%d&offset=%d" % (base, cid, page, offset)
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + key})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            rows = json.load(r).get("reports", [])
    except Exception as e:  # noqa: BLE001 -- any fetch failure fails the check below
        sys.stderr.write("page fetch failed at offset %d: %r\n" % (offset, e))
        sys.exit(2)
    total += len(rows)
    if len(rows) < page:
        break
    offset += len(rows)
else:
    sys.stderr.write("pagination walk did not terminate\n")
    sys.exit(3)
print(total)
EOF
)"
        API_RC=$?
        if [ "$API_RC" -eq 0 ] && [ "$API_COUNT" = "$DB_COUNT" ]; then
            STABLE=1
            break
        fi
        sleep 2
    done
    if [ "$STABLE" -ne 1 ]; then
        if [ "$API_RC" -ne 0 ]; then
            fail "worker $i: paginated /reports walk failed for $CID (rc=$API_RC, 6 attempts)"
        else
            fail "worker $i: paginated API lists $API_COUNT reports for $CID but DB stores $DB_COUNT after 6 walks -- listing diverged from ground truth"
        fi
        DB_MISMATCH=1
        continue
    fi
    # Retention-aware durability floor: the server trims each client to
    # --max-reports-per-client (this run uses the default, 1000, newest
    # win -- see Store.__init__ in ac_server.py), so a worker that 201'd
    # more than that legitimately stores only the newest 1000. (The global
    # --max-total-reports default of 100000 needs ~100 full clients to
    # bite; with one client per worker it can't trim here, so the
    # per-client cap is the only trimming this floor accounts for.)
    if [ "$OK" -gt 1000 ]; then
        FLOOR=1000
    else
        FLOOR="$OK"
    fi
    # Beyond that trimming, the real durability question is "did the DB
    # lose anything the client saw succeed" (DB_COUNT < FLOOR) -- NOT
    # exact equality. A client-side timeout (curl gave up, counted above,
    # not in $OK) for a request the server actually completed makes
    # DB_COUNT > OK perfectly legitimately; treating that as a failure
    # was itself a bug in this check, not a sign of one in the server
    # (verified directly: every DB_COUNT > OK case traced back to a 000
    # in that worker's timeout count, and the server log showed a clean
    # 201 for it, not an error).
    if [ "$DB_COUNT" -lt "$FLOOR" ]; then
        fail "worker $i: sent $OK successful reports but DB only has $DB_COUNT rows for $CID (floor $FLOOR)"
        DB_MISMATCH=1
    fi
done
[ "$DB_MISMATCH" -eq 0 ] && pass "no worker's successful reports went missing from the DB, and the paginated API listed every stored row"

pass "sustained load: $TOTAL_OK total successful reports across $CONCURRENCY workers in ${DURATION}s"
if [ "$TOTAL_TIMEOUTS" -gt 0 ]; then
    pass "$TOTAL_TIMEOUTS request(s) exceeded the client's ${CURL_MAX_TIME}s wait under load (curl 000) -- informational, not a failure on its own; the durability check above is what proves whether any of them actually failed server-side"
fi
if [ "$TOTAL_ERRORS" -gt 0 ]; then
    fail "$TOTAL_ERRORS requests failed with an unexpected non-201, non-timeout status (rate limit was set high enough that none of this should be rate-limiting)"
else
    pass "zero unexpected-error responses during the run"
fi

if grep -q "Traceback" "$TESTDIR/server.log"; then
    fail "server logged an unhandled exception during the stress run"
else
    pass "no unhandled exceptions logged during the stress run"
fi

echo "-- confirming the server is still responsive after sustained load --"
CODE=$(curl -s "${CURL_TIMEOUT[@]}" -o /dev/null -w '%{http_code}' "$BASE/banned/x" -H "Authorization: Bearer $ADMIN_KEY")
if [ "$CODE" = "200" ]; then
    pass "server still responsive after sustained load"
else
    fail "server not responsive after sustained load (got $CODE)"
fi

echo
if [ "$FAIL" -eq 0 ]; then
    printf '\033[1;32mALL STRESS CHECKS PASSED\033[0m\n'
else
    printf '\033[1;31mSOME STRESS CHECKS FAILED\033[0m\n'
fi
exit "$FAIL"
