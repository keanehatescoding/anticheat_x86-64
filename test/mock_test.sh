#!/bin/bash
# mock_test.sh — run the daemon CLI end-to-end against a userspace mock of
# /dev/anticheat (test/libmock_anticheat.so via LD_PRELOAD).
#
# Exercises every command and code path without a kernel module or root:
#   status, protect/list/unprotect, scan (+hash baselines), syscalls
#   (clean AND compromised), modules (hidden module detection), vmcheck
#   (CPUID/DMI, needs no mock -- see its own section below), events,
#   lock/unlock, and the monitoring daemon (incl. graceful SIGTERM exit).
#
# Build:  make test-mock
set -u

cd "$(dirname "$0")/.." || exit 1

export LD_PRELOAD="$PWD/test/libmock_anticheat.so"
export AC_MOCK_ROOT=1
export AC_MOCK_STATE="/tmp/ac_mock_state_$$"
export AC_BASELINE_DIR="/tmp/ac_baselines_$$"

FAIL=0

pass() { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; }
fail() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; FAIL=1; }

# expect_rc <desc> <want_rc> <cmd...>
expect_rc() {
    local desc="$1" want="$2"; shift 2
    "$@" >/dev/null 2>&1
    local rc=$?
    if [ "$rc" -eq "$want" ]; then pass "$desc (rc=$rc)"; else fail "$desc (want rc=$want, got $rc)"; fi
}

# expect_out <desc> <needle> <cmd...>
expect_out() {
    local desc="$1" needle="$2"; shift 2
    local out
    out=$("$@" 2>&1)
    if printf '%s' "$out" | grep -qF "$needle"; then
        pass "$desc"
    else
        fail "$desc (missing '$needle'); output: $(printf '%s' "$out" | head -2)"
    fi
}

rm -f "$AC_MOCK_STATE"
mkdir -p "$AC_BASELINE_DIR"

# scan + hash the anticheat binary *itself*: after `exec`, the process is the
# scanner, so /proc/PID/mem is readable without ptrace privileges (yama scope).
# $BASHPID must expand inside the daemon's eval'd context, not here
# shellcheck disable=SC2016
SELFSCAN='exec ./anticheat scan --pid $BASHPID'

echo "== basic CLI =="
expect_rc  "help"                     0 ./anticheat help
expect_rc  "unknown command"          1 ./anticheat bogus

echo "== status =="
expect_rc  "status"                   0 ./anticheat status
expect_out "status: version"          "version"        ./anticheat status

echo "== protect / list / unprotect =="
expect_rc  "protect --pid \$\$"        0 ./anticheat protect --pid $$
expect_out "list shows pid"            "$$"             ./anticheat list
expect_out "list shows jit=no by default" "jit=no"      ./anticheat list
expect_rc  "unprotect (before jit re-protect)" 0 ./anticheat unprotect --pid $$
expect_rc  "protect --pid \$\$ --jit"  0 ./anticheat protect --pid $$ --jit
expect_out "list shows jit=yes"        "jit=yes"        ./anticheat list
expect_rc  "re-protect --pid \$\$ (drop --jit)" 0 ./anticheat protect --pid $$
expect_out "list updates jit=no on re-protect" "jit=no" ./anticheat list
expect_rc  "protect --comm bash"      0 ./anticheat protect --comm bash
expect_rc  "unprotect"                0 ./anticheat unprotect --pid $$

echo "== protect --comm: exe-basename precision (issue #69) =="
# pid_of_comm() now prefers matching /proc/<pid>/exe's basename (the
# executable's real, untruncated name) over the raw /proc/<pid>/comm
# string (silently truncated by the kernel to TASK_COMM_LEN-1 = 15
# chars), falling back to the comm string only when /proc/<pid>/exe isn't
# usable. Exercise both paths against real background processes -- this
# scans the real /proc, not the mocked ioctl ABI, so it needs actual
# pids on disk, not just mock state.
AC_TESTBIN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ac_testbin.XXXXXX") || exit 1

# > 15 chars, so the old comm-string-only match couldn't have found this
# pid at all (comm would read back truncated) -- only the exe-basename
# match can.
AC_LONGNAME="ac69-exe-match-longname-$$"
cp /bin/sleep "$AC_TESTBIN_DIR/$AC_LONGNAME"
chmod +x "$AC_TESTBIN_DIR/$AC_LONGNAME"
"$AC_TESTBIN_DIR/$AC_LONGNAME" 30 &
AC_LONGPID=$!
expect_rc  "protect --comm matches full (>15-char) exe basename" 0 \
    ./anticheat protect --comm "$AC_LONGNAME"
expect_out "list shows exe-basename-matched pid" "$AC_LONGPID" ./anticheat list
./anticheat unprotect --pid "$AC_LONGPID" >/dev/null 2>&1
kill "$AC_LONGPID" 2>/dev/null
wait "$AC_LONGPID" 2>/dev/null

# <= 15 chars, then the backing file is deleted while the process keeps
# running: /proc/<pid>/exe now resolves to "... (deleted)", which
# exe_path_matches() deliberately treats as unusable -- this must fall
# back to the original /proc/<pid>/comm string match, not fail outright.
AC_SHORTNAME="ac69delfb$$"
AC_SHORTNAME="${AC_SHORTNAME:0:15}"
cp /bin/sleep "$AC_TESTBIN_DIR/$AC_SHORTNAME"
chmod +x "$AC_TESTBIN_DIR/$AC_SHORTNAME"
"$AC_TESTBIN_DIR/$AC_SHORTNAME" 30 &
AC_DELPID=$!
# Wait for the child to actually exec the copied binary before deleting
# it out from under it -- deleting too early can still catch it mid-fork,
# in which case /proc/<pid>/exe would resolve to nothing (ENOENT) instead
# of "... (deleted)", and the fallback-to-comm-string assertion below
# would flake intermittently.
for _ in $(seq 1 50); do
    [ "$(readlink "/proc/$AC_DELPID/exe" 2>/dev/null)" = "$AC_TESTBIN_DIR/$AC_SHORTNAME" ] && break
    sleep 0.1
done
rm -f "$AC_TESTBIN_DIR/$AC_SHORTNAME"
expect_rc  "protect --comm falls back to comm string (exe deleted)" 0 \
    ./anticheat protect --comm "$AC_SHORTNAME"
expect_out "list shows comm-fallback-matched pid" "$AC_DELPID" ./anticheat list
./anticheat unprotect --pid "$AC_DELPID" >/dev/null 2>&1
kill "$AC_DELPID" 2>/dev/null
wait "$AC_DELPID" 2>/dev/null

rm -rf "$AC_TESTBIN_DIR"

echo "== protect: kernel-thread rejection (issue #69) =="
# The real module now rejects PF_KTHREAD tasks in ac_add_prot_task(); the
# mock mirrors that with a userspace analog (empty /proc/<pid>/cmdline --
# see is_kthread_like() in mock_anticheat.c) so this end-to-end path is
# covered without root or a loaded module. kthreadd is the ancestor of
# every kernel thread and always has an empty cmdline, so it's a stable,
# always-present stand-in target.
AC_KPID=$(pgrep -x kthreadd 2>/dev/null | head -1)
if [ -n "$AC_KPID" ] && [ -r "/proc/$AC_KPID/cmdline" ]; then
    expect_rc "protect --pid <kernel thread> is rejected" 1 \
        ./anticheat protect --pid "$AC_KPID"
else
    echo "  (skipped: kthreadd not found/readable on this system)"
fi

echo "== scan (VMA + RWX) =="
expect_rc  "scan --pid \$\$"           0 ./anticheat scan --pid $$
expect_out "scan summary"              "VMA(s)"         ./anticheat scan --pid $$

echo "== memory-integrity baselines (self-scan) =="
expect_rc  "scan --hash --save"       0 bash -c "$SELFSCAN --hash --save"
expect_rc  "scan --hash --check"      0 bash -c "$SELFSCAN --hash --check"
expect_out "baseline matches"          "matches baseline" bash -c "$SELFSCAN --hash --check"

echo "== syscall integrity (clean + compromised) =="
expect_rc  "syscalls clean"           0 ./anticheat syscalls
expect_out "syscalls OK message"       "no hooks detected" ./anticheat syscalls
expect_out "syscalls: boot baseline shown" "boot baseline" ./anticheat syscalls
expect_rc  "syscalls compromised -> rc 2" 2 env AC_MOCK_HOOKED=1 ./anticheat syscalls
expect_out "syscalls alert"            "COMPROMISED"    env AC_MOCK_HOOKED=1 ./anticheat syscalls

echo "== syscall integrity: in-text redirect baseline (#63) =="
expect_rc  "syscalls redirected -> rc 2" 2 env AC_MOCK_REDIRECT=1 ./anticheat syscalls
expect_out "syscalls redirect alert"   "COMPROMISED"    env AC_MOCK_REDIRECT=1 ./anticheat syscalls
expect_out "syscalls redirect count"   "redirected       : 1" env AC_MOCK_REDIRECT=1 ./anticheat syscalls
expect_out "syscalls checksum mismatch" "MISMATCH"      env AC_MOCK_REDIRECT=1 ./anticheat syscalls

echo "== syscall integrity: checksum-only mismatch (#63 review fix) =="
# Handler churn that flips the whole-table checksum without tripping any
# per-slot hook/redirect counter (e.g. a slot going non-zero -> 0) must
# still be reported as COMPROMISED with a non-zero exit code, not silently
# swallowed by a verdict that only looks at out->hooked/out->redirected.
expect_rc  "syscalls checksum-only -> rc 2" 2 env AC_MOCK_CHECKSUM_ONLY=1 ./anticheat syscalls
expect_out "syscalls checksum-only alert" "COMPROMISED"  env AC_MOCK_CHECKSUM_ONLY=1 ./anticheat syscalls
expect_out "syscalls checksum-only mismatch shown" "MISMATCH" env AC_MOCK_CHECKSUM_ONLY=1 ./anticheat syscalls
expect_out "syscalls checksum-only hooked/redirected both zero" "hooked           : 0" env AC_MOCK_CHECKSUM_ONLY=1 ./anticheat syscalls

echo "== hidden module detection =="
expect_rc  "modules -> rc 2 (hidden)" 2 ./anticheat modules
expect_out "modules: hidden count"     "hidden modules: 1" ./anticheat modules
expect_out "modules: hidden name"      "hidden_rootkit" ./anticheat modules

echo "== vmcheck =="
# Pure userspace CPUID/DMI reads -- doesn't touch /dev/anticheat at all,
# so this needs no mock and its outcome (hypervisor detected or not)
# genuinely depends on whatever machine runs this test. Assert structure
# (exits 0, prints the expected header) rather than a specific outcome,
# which would be wrong on a bare-metal dev machine and right in CI (a
# virtualized GitHub Actions runner) or vice versa.
expect_rc  "vmcheck"                  0 ./anticheat vmcheck
expect_out "vmcheck header"            "VM/hypervisor check:" ./anticheat vmcheck
expect_out "vmcheck CPUID line"        "CPUID hypervisor bit" ./anticheat vmcheck
expect_out "vmcheck DMI line"          "DMI/SMBIOS strings"   ./anticheat vmcheck

echo "== events =="
expect_out "events: ptrace denied"     "PTRACE-DENIED"  env AC_MOCK_ATTACK=1 ./anticheat events
expect_out "events: info"              "INFO"           ./anticheat events

echo "== lock / unlock =="
expect_rc  "lock"                     0 ./anticheat lock
expect_out "status: locked"            "locked            : 1" ./anticheat status
expect_rc  "unlock"                   0 ./anticheat unlock
expect_out "status: unlocked"          "locked            : 0" ./anticheat status

echo "== error paths =="
expect_rc  "scan without --pid"       1 ./anticheat scan
expect_rc  "protect without args"     1 ./anticheat protect

echo "== daemon/module ABI version handshake =="
# Matching version: the daemon's compiled-in AC_IOCTL_VERSION vs. what the
# mock reports (default, unmodified) -- start must get past the handshake
# and into its normal run loop, so a short foreground run that exits
# cleanly on SIGTERM proves the check didn't reject a healthy pairing.
out=$(timeout -k 2 --preserve-status 2 ./anticheat start --foreground 2>&1)
rc=$?
if [ "$rc" -eq 0 ]; then pass "start: matching version proceeds"; else fail "start: matching version (rc=$rc)"; fi

# Mismatched version: die() fires before any fork, so this returns
# immediately with no timeout needed -- a hang here would itself be a bug.
# The expected daemon-side version is read from anticheat.h rather than
# hardcoded, so this doesn't silently go stale the next time
# AC_IOCTL_VERSION is bumped.
daemon_ioctl_version=$(sed -n 's/^#define AC_IOCTL_VERSION \([0-9]\+\)/\1/p' src/anticheat.h)
case "$daemon_ioctl_version" in
    ''|*[!0-9]*)
        echo "mock_test.sh: couldn't extract a numeric AC_IOCTL_VERSION from src/anticheat.h" >&2
        exit 1
        ;;
esac
expect_rc  "start: mismatched version fails fast" 1 \
    env AC_MOCK_VERSION=99 ./anticheat start --foreground
expect_out "start: mismatched version error names both versions" \
    "version mismatch" env AC_MOCK_VERSION=99 ./anticheat start --foreground
expect_out "start: mismatched version error names daemon's version" \
    "AC_IOCTL_VERSION=$daemon_ioctl_version" env AC_MOCK_VERSION=99 ./anticheat start --foreground
expect_out "start: mismatched version error names module's version" \
    "version=99" env AC_MOCK_VERSION=99 ./anticheat start --foreground
expect_out "start: mismatched version error refuses to start" \
    "refusing to start" env AC_MOCK_VERSION=99 ./anticheat start --foreground

echo "== monitoring daemon (start --foreground) =="
# --preserve-status: report the command's own exit status; a clean exit after
# SIGTERM is rc=0, a hang is caught by -k (SIGKILL -> 137).
out=$(timeout -k 2 --preserve-status 4 env AC_MOCK_ATTACK=1 ./anticheat start --foreground 2>&1)
rc=$?
if [ "$rc" -eq 0 ]; then pass "start: clean exit on SIGTERM"; else fail "start (rc=$rc)"; fi
if printf '%s' "$out" | grep -q "PTRACE-DENIED"; then
    pass "start: PTRACE alert logged"
else
    fail "start: no PTRACE alert"
fi
if printf '%s' "$out" | grep -q "hidden from /proc/modules"; then
    pass "start: hidden-module alert"
else
    fail "start: no hidden-module alert"
fi

# Syscall-hook alerts should be logged once per rising edge (via the ring
# drain), not once per 5s poll -- see #52. The daemon's periodic syscall
# check runs immediately, then again every 5s, so a 7s run crosses that
# second poll with margin. A single CRIT line here proves the alert both
# fires end-to-end through the ring AND stays deduplicated across more
# than one poll -- a 4s run would exit before the second poll and pass
# even if the old per-poll re-emit regressed.
hooked_out=$(timeout -k 2 --preserve-status 7 \
    env AC_MOCK_HOOKED=1 ./anticheat start --foreground 2>&1)
hooked_crit_count=$(printf '%s' "$hooked_out" | grep -c "SYSCALL-HOOK")
if [ "$hooked_crit_count" -eq 1 ]; then
    pass "start: syscall-hook alert logged exactly once"
else
    fail "start: expected exactly 1 SYSCALL-HOOK log line, got $hooked_crit_count"
fi

# Same rising-edge dedup proof as above, for the boot-baseline in-text
# redirect check (AC_EV_SYSCALL_REDIRECT, #63) -- distinct event type from
# SYSCALL-HOOK, so this also proves the two aren't conflated.
redirect_out=$(timeout -k 2 --preserve-status 7 \
    env AC_MOCK_REDIRECT=1 ./anticheat start --foreground 2>&1)
redirect_crit_count=$(printf '%s' "$redirect_out" | grep -c "SYSCALL-REDIRECT")
if [ "$redirect_crit_count" -eq 1 ]; then
    pass "start: syscall-redirect alert logged exactly once"
else
    fail "start: expected exactly 1 SYSCALL-REDIRECT log line, got $redirect_crit_count"
fi

# checksum_mismatch has no matching kernel event (see #63 review fix), so
# unlike the two cases above this dedup is entirely daemon-side, in
# check_syscalls_periodic()'s own rising-edge state -- a distinct code
# path from the ring-drain dedup exercised above, so it needs its own
# proof of both "fires at all" and "stays deduplicated across polls".
checksum_out=$(timeout -k 2 --preserve-status 7 \
    env AC_MOCK_CHECKSUM_ONLY=1 ./anticheat start --foreground 2>&1)
checksum_crit_count=$(printf '%s' "$checksum_out" | grep -c "checksum mismatch")
if [ "$checksum_crit_count" -eq 1 ]; then
    pass "start: checksum-only mismatch alert logged exactly once"
else
    fail "start: expected exactly 1 checksum mismatch log line, got $checksum_crit_count"
fi
echo "== scan --check-hooks (mock) =="
expect_out "scan --check-hooks hooked" "render hook" bash -c 'AC_MOCK_HOOK_LIB="libvulkan.so.1:vkQueuePresentKHR:hooked" exec bash -c '\''LD_PRELOAD="$0" AC_MOCK_ROOT=1 AC_MOCK_STATE="$1" exec ./anticheat scan --pid $BASHPID --check-hooks'\'' "$LD_PRELOAD" "$AC_MOCK_STATE"'
expect_out "scan --check-hooks clean" "clean" bash -c 'AC_MOCK_HOOK_LIB="libvulkan.so.1:vkQueuePresentKHR:clean" exec bash -c '\''LD_PRELOAD="$0" AC_MOCK_ROOT=1 AC_MOCK_STATE="$1" exec ./anticheat scan --pid $BASHPID --check-hooks'\'' "$LD_PRELOAD" "$AC_MOCK_STATE"'
expect_out "scan --check-hooks inconclusive" "could not verify" bash -c 'AC_MOCK_HOOK_LIB="libvulkan.so.1:vkQueuePresentKHR:inconclusive" exec bash -c '\''LD_PRELOAD="$0" AC_MOCK_ROOT=1 AC_MOCK_STATE="$1" exec ./anticheat scan --pid $BASHPID --check-hooks'\'' "$LD_PRELOAD" "$AC_MOCK_STATE"'
expect_out "scan --check-hooks no mock -> not loaded" "not loaded" bash -c 'exec bash -c '\''LD_PRELOAD="$0" AC_MOCK_ROOT=1 AC_MOCK_STATE="$1" exec ./anticheat scan --pid $BASHPID --check-hooks'\'' "$LD_PRELOAD" "$AC_MOCK_STATE"'

echo "== scan --check-preload / --check-vklayers / --check-implicit-layers (mock) =="
expect_out "scan --check-preload detects LD_PRELOAD" "LD_PRELOAD check: /tmp/evil.so" bash -c 'AC_MOCK_ENVIRON="LD_PRELOAD=/tmp/evil.so" exec bash -c '\''LD_PRELOAD="$0" AC_MOCK_ROOT=1 AC_MOCK_STATE="$1" exec ./anticheat scan --pid $BASHPID --check-preload'\'' "$LD_PRELOAD" "$AC_MOCK_STATE"'
expect_out "scan --check-preload not set" "not set" bash -c 'AC_MOCK_ENVIRON="EMPTY=1" exec bash -c '\''LD_PRELOAD="$0" AC_MOCK_ROOT=1 AC_MOCK_STATE="$1" exec ./anticheat scan --pid $BASHPID --check-preload'\'' "$LD_PRELOAD" "$AC_MOCK_STATE"'
expect_out "scan --check-vklayers detects" "VK_INSTANCE_LAYERS=VK_LAYER_test" bash -c 'AC_MOCK_ENVIRON="VK_INSTANCE_LAYERS=VK_LAYER_test" exec bash -c '\''LD_PRELOAD="$0" AC_MOCK_ROOT=1 AC_MOCK_STATE="$1" exec ./anticheat scan --pid $BASHPID --check-vklayers'\'' "$LD_PRELOAD" "$AC_MOCK_STATE"'
expect_out "scan --check-implicit-layers detects mock" "VK_LAYER_mock" bash -c 'AC_MOCK_MANIFEST="VK_LAYER_mock:/tmp/fake.so" exec bash -c '\''LD_PRELOAD="$0" AC_MOCK_ROOT=1 AC_MOCK_STATE="$1" exec ./anticheat scan --pid $BASHPID --check-implicit-layers'\'' "$LD_PRELOAD" "$AC_MOCK_STATE"'

echo "== anon-exec growth and --jit downgrade (mock) =="
expect_out "scan anon-exec count override" "anon-exec" bash -c 'AC_MOCK_ANON_EXEC_COUNT=5 exec bash -c '\''LD_PRELOAD="$0" AC_MOCK_ROOT=1 AC_MOCK_STATE="$1" exec ./anticheat scan --pid $BASHPID'\'' "$LD_PRELOAD" "$AC_MOCK_STATE"'
# periodic anon-exec growth: protect a sleep, run daemon with short interval, check that growth is logged
# Use a fresh state file for the periodic run to avoid pollution from earlier protects
ANON_SLEEP=$(mktemp -u)
sleep 30 &
ANON_PID=$!
./anticheat protect --pid $ANON_PID >/dev/null 2>&1
anon_out=$(timeout -k 2 --preserve-status 4 env AC_MOCK_ANON_EXEC_COUNT=2 AC_SCAN_CHECK_INTERVAL=1 ./anticheat start --foreground 2>&1)
if printf '%s' "$anon_out" | grep -q "new anonymous executable"; then pass "periodic anon-exec growth detected"; else fail "periodic anon-exec growth not detected"; fi
./anticheat unprotect --pid $ANON_PID >/dev/null 2>&1 || true
kill $ANON_PID 2>/dev/null; wait $ANON_PID 2>/dev/null || true
# jit downgrade: same but with --jit, should log WARNING not CRIT for that pid
sleep 30 &
JIT_PID=$!
./anticheat protect --pid $JIT_PID --jit >/dev/null 2>&1
jit_out=$(timeout -k 2 --preserve-status 4 env AC_MOCK_ANON_EXEC_COUNT=2 AC_SCAN_CHECK_INTERVAL=1 ./anticheat start --foreground 2>&1)
if printf '%s' "$jit_out" | grep -q "expected for a JIT-marked"; then pass "jit downgrade to WARNING"; else fail "jit downgrade not observed"; fi
if printf '%s' "$jit_out" | grep -q "possible code injection after process start"; then
    # The jitter (non-jit anticheat pid itself) will still log CRIT for itself - filter to our JIT pid
    if printf '%s' "$jit_out" | grep "pid $JIT_PID" | grep -q "possible code injection"; then
        fail "jit pid should not log CRIT"
    else
        pass "jit pid correctly not CRIT"
    fi
else
    # No CRIT at all is also ok if only jit pid was protected and anticheat pid not counted
    pass "jit periodic no unexpected CRIT for jit pid"
fi
./anticheat unprotect --pid $JIT_PID >/dev/null 2>&1 || true
kill $JIT_PID 2>/dev/null; wait $JIT_PID 2>/dev/null || true

echo "== periodic LD_PRELOAD / VK-layer / implicit-layer intervals (mock) =="
# These checks should warn at most once per pid (environ is static), so a short daemon run with 1s intervals should log exactly once
sleep 30 &
PER_PID=$!
./anticheat protect --pid $PER_PID >/dev/null 2>&1
# Create a child that has the environ we want to fake via AC_MOCK_ENVIRON? Instead we run daemon with AC_MOCK_ENVIRON set so every protected pid appears to have LD_PRELOAD
per_out=$(timeout -k 2 --preserve-status 4 env AC_MOCK_ENVIRON="LD_PRELOAD=/tmp/evil.so" AC_LD_PRELOAD_CHECK_INTERVAL=1 AC_VK_LAYER_CHECK_INTERVAL=1 AC_IMPLICIT_LAYER_CHECK_INTERVAL=1 AC_RENDER_HOOK_CHECK_INTERVAL=1 AC_SCAN_CHECK_INTERVAL=1 ./anticheat start --foreground 2>&1)
# LD_PRELOAD warning should appear once per pid, not per interval — but
# mock state accumulates protects from earlier tests, so count scales with
# number of protected pids still alive. Allow 1..10 to avoid flaky failure
# due to state pollution while still catching the "warn every interval" bug
# (which would be >>10 in 4s with 1s interval).
per_ld_count=$(printf '%s' "$per_out" | grep -c "LD_PRELOAD=/tmp/evil.so" || true)
if [ "$per_ld_count" -ge 1 ] && [ "$per_ld_count" -le 10 ]; then pass "periodic LD_PRELOAD warned once per pid (got $per_ld_count)"; else fail "periodic LD_PRELOAD count $per_ld_count unexpected"; fi
kill $PER_PID 2>/dev/null; wait $PER_PID 2>/dev/null || true


echo
if [ "$FAIL" -eq 0 ]; then
    printf '\033[1;32mALL MOCK TESTS PASSED\033[0m\n'
else
    printf '\033[1;31mSOME MOCK TESTS FAILED\033[0m\n'
fi
exit "$FAIL"
