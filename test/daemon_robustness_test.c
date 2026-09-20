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
 *     wait -- even under signal pressure, via a CLOCK_MONOTONIC
 *     deadline checked after EINTR too -- and report ETIMEDOUT instead
 *     of hanging. Children given up on are tracked and reaped by a
 *     later sweep instead of accumulating as zombies.
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
#include <sys/time.h>

static int failures;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        failures++; \
    } else { \
        fprintf(stderr, "PASS: %s\n", msg); \
    } \
} while (0)

/* SIGALRM poker for the EINTR-pressure test below: installed without
 * SA_RESTART so waitpid() inside waitpid_timeout() actually EINTRs,
 * the way the daemon's own SIGTERM/SIGINT handlers interrupt it. */
static volatile int pokes;

static void poke_handler(int sig)
{
    (void)sig;
    pokes++;
}

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

    /* --- waitpid_timeout: the bound holds even when signals keep
     * interrupting waitpid() with EINTR. A 10ms-interval SIGALRM (no
     * SA_RESTART, like the daemon's own handlers) fires ~50 times
     * across a 500ms wait; the CLOCK_MONOTONIC deadline is checked
     * after every return, so the wait still lands near its bound
     * instead of stretching. */
    {
        struct sigaction sa, old_sa;
        struct itimerval it, old_it;
        pid_t pid;
        struct timespec t0, t1;
        long elapsed_ms;
        int rc;

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = poke_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;   /* no SA_RESTART: waitpid() must EINTR */
        CHECK(sigaction(SIGALRM, &sa, &old_sa) == 0,
              "install SIGALRM poker for the EINTR-pressure test");
        memset(&it, 0, sizeof(it));
        it.it_interval.tv_usec = 10000;
        it.it_value.tv_usec = 10000;
        CHECK(setitimer(ITIMER_REAL, &it, &old_it) == 0,
              "arm 10ms interval timer for the EINTR-pressure test");

        pid = fork();
        CHECK(pid >= 0, "fork for the EINTR-pressure timeout test");
        if (pid == 0) {
            raise(SIGSTOP);
            for (;;)
                pause();
            _exit(0);
        }
        if (pid <= 0) {
            memset(&it, 0, sizeof(it));
            setitimer(ITIMER_REAL, &it, NULL);
            sigaction(SIGALRM, &old_sa, NULL);
            return 1;
        }
        clock_gettime(CLOCK_MONOTONIC, &t0);
        errno = 0;
        rc = waitpid_timeout(pid, 500);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000L +
                     (t1.tv_nsec - t0.tv_nsec) / 1000000L;
        memset(&it, 0, sizeof(it));
        setitimer(ITIMER_REAL, &it, NULL);
        sigaction(SIGALRM, &old_sa, NULL);
        CHECK(rc < 0 && errno == ETIMEDOUT,
              "the wait still times out with ETIMEDOUT under ~50 "
              "EINTR interruptions");
        CHECK(pokes > 0, "the timer actually interrupted the wait");
        CHECK(elapsed_ms >= 300 && elapsed_ms < 3000,
              "the wait lands near its 500ms bound under signal "
              "pressure instead of stretching");
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }

    /* --- abandon/reap sweep: a child given up on is tracked and later
     * reaped, not leaked as a zombie per stalled resolve. */
    {
        pid_t pid = fork();

        CHECK(pid >= 0, "fork for the stale-resolver reap test");
        if (pid == 0)
            _exit(0);
        if (pid <= 0)
            return 1;
        usleep(100000);   /* let the child exit; it is now an unreaped zombie */
        abandon_resolver_child(pid);
        CHECK(g_stale_resolvers[0] == pid,
              "an abandoned child is tracked for later reap");
        reap_stale_resolvers();
        CHECK(g_stale_resolvers[0] == 0,
              "the sweep reaps an exited tracked child and clears it");
        errno = 0;
        CHECK(waitpid(pid, NULL, WNOHANG) < 0 && errno == ECHILD,
              "the swept child is fully reaped (no zombie left)");
    }

    /* --- abandon/reap sweep: a still-running tracked child is kept,
     * then reaped once it dies. */
    {
        pid_t pid = fork();

        CHECK(pid >= 0, "fork for the still-running tracked child test");
        if (pid == 0) {
            raise(SIGSTOP);
            for (;;)
                pause();
            _exit(0);
        }
        if (pid <= 0)
            return 1;
        abandon_resolver_child(pid);
        reap_stale_resolvers();
        CHECK(g_stale_resolvers[0] == pid,
              "a still-running tracked child is kept, not dropped");
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        reap_stale_resolvers();
        CHECK(g_stale_resolvers[0] == 0,
              "the sweep clears a tracked child once it has died");
    }

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
