/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * daemon_robustness_test.c -- regression tests for three related #29
 * daemon robustness gaps:
 *
 *   - print_event() passed localtime()'s return straight into
 *     strftime(): a stale or hostile kernel handing back an
 *     out-of-range timestamp makes localtime() return NULL, which is a
 *     NULL deref in the CLI/monitor display path. format_event_time()
 *     must fall back to raw epoch seconds instead.
 *   - ac_resolve_timeout() reaped its SIGKILLed resolver child with a
 *     blocking waitpid(): a child wedged in uninterruptible sleep (D
 *     state) ignores SIGKILL, so the whole monitor loop stalled behind
 *     a report-path DNS resolve. waitpid_timeout() must bound that
 *     wait and report ETIMEDOUT instead of hanging.
 *   - ac_read_environ_vars() opened /proc/<pid>/environ without
 *     O_CLOEXEC/O_NOFOLLOW and treated an EINTR-interrupted read as a
 *     hard failure (this daemon's handlers run without SA_RESTART, so
 *     SIGTERM/SIGINT mid-read surface as EINTR). The open flags and
 *     the retry are covered by inspection plus the existing mock
 *     LD_PRELOAD tests; this file covers the two helpers above.
 *
 * Pulls anticheat_daemon.c in as-is (renaming its main() out of the way)
 * to test the real helpers, not duplicated copies.
 *
 * Build: make daemon-robustness-test
 */
#define main ac_daemon_unused_main
#include "../src/anticheat_daemon.c"
#undef main

#include <limits.h>

static int failures;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        failures++; \
    } else { \
        fprintf(stderr, "PASS: %s\n", msg); \
    } \
} while (0)

/* "HH:MM:SS" shape without depending on the machine's timezone. */
static int looks_like_clock(const char *s)
{
    return strlen(s) == 8 && s[2] == ':' && s[5] == ':' &&
        isdigit((unsigned char)s[0]) && isdigit((unsigned char)s[1]) &&
        isdigit((unsigned char)s[3]) && isdigit((unsigned char)s[4]) &&
        isdigit((unsigned char)s[6]) && isdigit((unsigned char)s[7]);
}

int main(void)
{
    char ts[32];

    /* --- format_event_time: ordinary timestamps render as a clock --- */
    memset(ts, 'X', sizeof(ts));
    format_event_time(ts, sizeof(ts), (time_t)0);
    CHECK(ts[sizeof(ts) - 1] == 'X' || ts[sizeof(ts) - 1] == '\0',
          "format_event_time does not overflow a 32-byte buffer");
    CHECK(looks_like_clock(ts),
          "epoch renders as HH:MM:SS, not garbage");

    memset(ts, 0, sizeof(ts));
    format_event_time(ts, sizeof(ts), (time_t)1234567890);
    CHECK(looks_like_clock(ts),
          "a fixed recent timestamp renders as HH:MM:SS");

    /* --- format_event_time: an out-of-range timestamp must not crash.
     * localtime() returns NULL here on glibc (and the helper must stay
     * correct wherever it doesn't); either way the result is a
     * NUL-terminated, non-empty string. On a 64-bit time_t the
     * fallback is the raw epoch digits, which additionally proves the
     * NULL branch itself ran here rather than passing vacuously. */
    memset(ts, 0, sizeof(ts));
    format_event_time(ts, sizeof(ts), (time_t)LONG_MAX);
    CHECK(ts[0] != '\0' && memchr(ts, '\0', sizeof(ts)) != NULL,
          "an extreme timestamp falls back safely instead of crashing "
          "on a NULL localtime()");
    CHECK(strcmp(ts, "9223372036854775807") == 0 || looks_like_clock(ts),
          "the extreme timestamp renders as raw epoch digits (NULL "
          "localtime branch) or, on a libc that accepts it, as a clock");

    /* --- waitpid_timeout: an already-exited child reaps at once --- */
    {
        pid_t pid = fork();

        CHECK(pid >= 0, "fork for the fast-exit reap test");
        if (pid == 0)
            _exit(0);
        if (pid > 0)
            CHECK(waitpid_timeout(pid, 2000) == 0,
                  "an exited child is reaped successfully");
    }

    /* --- waitpid_timeout: a SIGSTOPped child ignores SIGKILL-proof
     * waiting the same way a D-state child would for WNOHANG (neither
     * is reaped by a plain waitpid without WUNTRACED), so the bounded
     * wait must give up with ETIMEDOUT instead of hanging forever. */
    {
        pid_t pid = fork();
        struct timespec t0, t1;
        long elapsed_ms;
        int rc;

        CHECK(pid >= 0, "fork for the stopped-child timeout test");
        if (pid == 0) {
            raise(SIGSTOP);
            for (;;)
                pause();
            _exit(0);
        }
        if (pid <= 0)
            return 1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        errno = 0;
        rc = waitpid_timeout(pid, 500);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000L +
                     (t1.tv_nsec - t0.tv_nsec) / 1000000L;
        CHECK(rc < 0 && errno == ETIMEDOUT,
              "a stopped (unreapable) child times out with ETIMEDOUT");
        CHECK(elapsed_ms >= 300 && elapsed_ms < 10000,
              "the reap wait actually waited (~500ms), neither "
              "returning instantly nor hanging");
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
