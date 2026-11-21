/*
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
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
 * Plus the environ parsing gaps from the same checklist:
 *
 *   - ac_parse_environ_buf() kept the first LD_PRELOAD= entry where ld.so
 *     acts on the last, so a benign entry in front hid the real one; and
 *     a value longer than the buffer was cut off without saying so.
 *   - an empty /proc/<pid>/environ (an exited process) was reported as
 *     "nothing set" rather than inconclusive.
 *
 * Pulls anticheat_daemon.c in as-is (renaming its main() out of the way)
 * to test the real helpers, not duplicated copies.
 *
 * Build: make daemon-robustness-test
 */
/* _GNU_SOURCE for RTLD_DEFAULT/dlsym in the fault-injection section
 * below; must precede every libc header, including those pulled in via
 * anticheat_daemon.c. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define main ac_daemon_unused_main
#include "../src/anticheat_daemon.c"
#undef main

#include <dlfcn.h>
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

/* Runs the #29 robustness checks against the daemon's own helpers (the .c
 * is #included above): event-time formatting, the bounded resolver-child
 * reap, and environ parsing -- repeated names, value truncation, an empty
 * environ, and an environ past the read buffer. Exits 1 if any check
 * failed. */
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

    /* --- EINTR fault injection: prove waitpid() itself returned EINTR
     * during the bounded wait, not just that a signal fired somewhere.
     * Runs only under AC_WAITPID_FAULT_TEST=1 with the fault injector
     * preloaded (see the Makefile target): arming it faults 100% of
     * the wait's WNOHANG waitpids, and the injector's counter -- read
     * back via dlsym, so this asserts against the injector's own
     * records rather than assuming -- must be nonzero afterwards. */
    if (getenv("AC_WAITPID_FAULT_TEST")) {
        int (*fault_count)(void) =
            dlsym(RTLD_DEFAULT, "waitpid_fault_count");
        pid_t pid;

        CHECK(fault_count != NULL,
              "fault injector present for the EINTR-proof test");
        if (!fault_count)
            return 1;
        CHECK(fault_count() == 0,
              "no faults injected before the armed wait");
        pid = fork();
        CHECK(pid >= 0, "fork for the EINTR-proof timeout test");
        if (pid == 0) {
            raise(SIGSTOP);
            for (;;)
                pause();
            _exit(0);
        }
        if (pid <= 0)
            return 1;
        setenv("AC_WAITPID_FAULT_ARMED", "1", 1);
        errno = 0;
        {
            int rc = waitpid_timeout(pid, 500);

            setenv("AC_WAITPID_FAULT_ARMED", "0", 1);
            CHECK(rc < 0 && errno == ETIMEDOUT,
                  "the armed wait still times out with ETIMEDOUT");
            CHECK(fault_count() > 0,
                  "waitpid() returned EINTR during the wait "
                  "(injector fired, so the retry branch ran)");
        }
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }

    /* --- resolve gate: with every stale slot occupied by a live child,
     * ac_resolve_timeout() refuses to fork (EAGAIN) instead of risking
     * an untrackable zombie. */
    {
        pid_t stuck[AC_MAX_STALE_RESOLVERS] = { 0 };
        struct ac_resolved_addr addrs[1];
        int i, all_forked = 1;

        for (i = 0; i < AC_MAX_STALE_RESOLVERS; i++) {
            stuck[i] = fork();
            if (stuck[i] == 0) {
                raise(SIGSTOP);
                for (;;)
                    pause();
                _exit(0);
            }
            if (stuck[i] < 0) {
                all_forked = 0;
                break;
            }
        }
        CHECK(all_forked,
              "fork eight stuck children for the full-table test");
        if (all_forked) {
            for (i = 0; i < AC_MAX_STALE_RESOLVERS; i++)
                abandon_resolver_child(stuck[i]);
            CHECK(!stale_resolver_slot_free(),
                  "eight live children fill the stale table");
            errno = 0;
            CHECK(ac_resolve_timeout("localhost", "80", addrs, 1, 5) < 0 &&
                  errno == EAGAIN,
                  "resolve with a full stale table fails fast with "
                  "EAGAIN, forking nothing");
            for (i = 0; i < AC_MAX_STALE_RESOLVERS; i++) {
                kill(stuck[i], SIGKILL);
                waitpid(stuck[i], NULL, 0);
            }
            reap_stale_resolvers();
            CHECK(stale_resolver_slot_free(),
                  "slots free again after the stuck children die");
        } else {
            for (i = 0; i < AC_MAX_STALE_RESOLVERS; i++) {
                if (stuck[i] > 0) {
                    kill(stuck[i], SIGKILL);
                    waitpid(stuck[i], NULL, 0);
                }
            }
        }
    }

    /* --- environ: a repeated name resolves the way its consumer does --- */
    {
        static const char env[] =
            "LD_PRELOAD=libMangoHud.so\0A=1\0VK_LAYER_PATH=/first\0"
            "LD_PRELOAD=/tmp/cheat.so\0VK_LAYER_PATH=/second\0"
            "LD_PRELOADX=/not/this\0";
        struct ac_environ_query q[3];

        memset(q, 0, sizeof(q));
        q[0].name = "LD_PRELOAD";
        q[0].last_wins = 1;
        q[1].name = "VK_LAYER_PATH";
        q[2].name = "LD_AUDIT";
        q[2].last_wins = 1;
        ac_parse_environ_buf(env, sizeof(env) - 1, q, 3);
        CHECK(q[0].found && strcmp(q[0].value, "/tmp/cheat.so") == 0,
              "the last LD_PRELOAD= entry wins, as it does for ld.so");
        CHECK(q[1].found && strcmp(q[1].value, "/first") == 0,
              "the first entry still wins for a getenv()-style variable");
        CHECK(!q[2].found, "a variable that isn't there is not found");
        CHECK(!q[0].truncated && !q[1].truncated,
              "values that fit are not flagged truncated");
    }

    /* --- environ: every LD_AUDIT= entry is a loader input --- */
    {
        static const char env[] =
            "LD_AUDIT=/tmp/evil.so\0A=1\0LD_PRELOAD=/first.so\0"
            "LD_AUDIT=/tmp/benign.so\0LD_PRELOAD=/second.so\0"
            "LD_AUDIT=\0LD_AUDITX=/not/this\0";
        struct ac_environ_query q[2];

        memset(q, 0, sizeof(q));
        q[0].name = "LD_AUDIT";
        q[0].collect_all = 1;
        q[1].name = "LD_PRELOAD";
        q[1].last_wins = 1;
        ac_parse_environ_buf(env, sizeof(env) - 1, q, 2);
        CHECK(q[0].found && q[0].occurrences == 3 &&
              strcmp(q[0].value, "/tmp/evil.so:/tmp/benign.so") == 0,
              "repeated LD_AUDIT= entries are all kept, an empty one adds "
              "nothing, and an LD_AUDITX= lookalike is ignored");
        CHECK(!q[0].truncated, "an LD_AUDIT list that fits is not flagged");
        CHECK(q[1].found && strcmp(q[1].value, "/second.so") == 0,
              "LD_PRELOAD keeps last-wins selection beside a collect_all "
              "variable");
    }
    {
        /* Occurrences that don't all fit: bounded, flagged, still counted. */
        static char env[AC_ENVIRON_VAL_LEN * 4];
        struct ac_environ_query q;
        size_t pos = 0;
        int k;

        enum { ENTRY_LEN = sizeof("LD_AUDIT=") - 1 + AC_ENVIRON_VAL_LEN / 2 + 1 };

        /* Three fixed-size entries: provably within env[], no
         * return-value-derived sizes. */
        _Static_assert(3 * ENTRY_LEN <= AC_ENVIRON_VAL_LEN * 4,
                       "the three entries fit in env[]");
        for (k = 0; k < 3; k++) {
            memcpy(env + pos, "LD_AUDIT=", sizeof("LD_AUDIT=") - 1);
            pos += sizeof("LD_AUDIT=") - 1;
            memset(env + pos, 'a' + k, AC_ENVIRON_VAL_LEN / 2);
            pos += AC_ENVIRON_VAL_LEN / 2;
            env[pos++] = '\0';
        }
        memset(&q, 0, sizeof(q));
        q.name = "LD_AUDIT";
        q.collect_all = 1;
        ac_parse_environ_buf(env, pos, &q, 1);
        CHECK(q.found && q.truncated && q.occurrences == 3 &&
              strlen(q.value) < AC_ENVIRON_VAL_LEN &&
              q.value[0] == 'a',
              "a collected LD_AUDIT list past the cap stays in bounds, is "
              "flagged truncated, and still counts every occurrence");
    }
    {
        /* Through the real reader, from a real /proc/<pid>/environ. */
        char *envp[] = { "LD_AUDIT=/tmp/evil.so", "LD_AUDIT=/tmp/benign.so",
                         "LD_PRELOAD=/p1.so", "LD_PRELOAD=/p2.so", NULL };
        char *argv_sleep[] = { "sleep", "10", NULL };
        pid_t pid = fork();

        CHECK(pid >= 0, "fork for the repeated-LD_AUDIT environ test");
        if (pid == 0) {
            execve("/bin/sleep", argv_sleep, envp);
            _exit(127);
        }
        if (pid > 0) {
            struct ac_environ_query vars[AC_LD_INJECT_ENV_VARS_COUNT];
            char comm[32] = "";
            int tries, rc;

            for (tries = 0; tries < 200; tries++) {
                char p[64];
                FILE *f;

                snprintf(p, sizeof(p), "/proc/%d/comm", (int)pid);
                f = fopen(p, "r");
                if (f) {
                    if (fgets(comm, sizeof(comm), f) &&
                        strncmp(comm, "sleep", 5) == 0) {
                        fclose(f);
                        break;
                    }
                    fclose(f);
                }
                usleep(10 * 1000);
            }
            rc = ac_read_ld_inject_vars((int)pid, vars);
            CHECK(rc == 0 && vars[1].found &&
                  strcmp(vars[1].value,
                         "/tmp/evil.so:/tmp/benign.so") == 0,
                  "ac_read_ld_inject_vars() reports both repeated LD_AUDIT "
                  "libraries, not only the last");
            CHECK(vars[0].found && strcmp(vars[0].value, "/p2.so") == 0,
                  "ac_read_ld_inject_vars() still reports the last "
                  "LD_PRELOAD");
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }
    }

    /* --- log line: the qualifiers survive a maximum-length value --- */
    {
        struct ac_environ_query q;
        char line[AC_LOG_LINE_MAX];

        memset(&q, 0, sizeof(q));
        q.name = "LD_PRELOAD";
        memset(q.value, 'x', sizeof(q.value) - 1);
        q.found = 1;
        q.truncated = 1;
        ac_fmt_environ_warning(line, sizeof(line), 2147483647,
                               "0123456789abcde", &q, 1, AC_LD_WARN_TAIL);
        CHECK(strlen(line) <= sizeof(line) - 1 &&
              strlen(line) > strlen(AC_LD_WARN_TAIL) &&
              strcmp(line + strlen(line) - strlen(AC_LD_WARN_TAIL),
                     AC_LD_WARN_TAIL) == 0 &&
              strstr(line, "[value truncated]") != NULL &&
              strstr(line, AC_ENVIRON_LOG_CUT_NOTE) != NULL &&
              strstr(line, AC_ENVIRON_INCOMPLETE_NOTE) != NULL &&
              strstr(line, "not a verdict on its own") != NULL,
              "a full-length LD_* value keeps its truncation qualifiers, "
              "marks the extra log cut, and ends with the usual tail");

        memset(&q, 0, sizeof(q));
        q.name = "VK_LAYER_PATH";
        memset(q.value, 'y', sizeof(q.value) - 1);
        q.found = 1;
        q.truncated = 1;
        ac_fmt_environ_warning(line, sizeof(line), 1, "game", &q, 0,
                               AC_VK_WARN_TAIL);
        CHECK(strstr(line, "[value truncated]") != NULL &&
              strstr(line, "not a verdict on its own") != NULL,
              "the same holds for the Vulkan-layer warning");

        /* A collected LD_AUDIT list reports its entry count, and that
         * qualifier is reserved before the value is shortened. */
        memset(&q, 0, sizeof(q));
        q.name = "LD_AUDIT";
        q.collect_all = 1;
        memset(q.value, 'z', sizeof(q.value) - 1);
        q.found = 1;
        q.truncated = 1;
        q.occurrences = 4294967295u;
        ac_fmt_environ_warning(line, sizeof(line), 2147483647,
                               "0123456789abcde", &q, 1, AC_LD_WARN_TAIL);
        CHECK(strlen(line) <= sizeof(line) - 1 &&
              strcmp(line + strlen(line) - strlen(AC_LD_WARN_TAIL),
                     AC_LD_WARN_TAIL) == 0 &&
              strstr(line, " [4294967295 entries]") != NULL &&
              strstr(line, "[value truncated]") != NULL &&
              strstr(line, AC_ENVIRON_LOG_CUT_NOTE) != NULL &&
              strstr(line, AC_ENVIRON_INCOMPLETE_NOTE) != NULL,
              "a truncated, incomplete LD_AUDIT list still reports its "
              "entry count beside every other qualifier");

        memset(&q, 0, sizeof(q));
        q.name = "LD_AUDIT";
        q.collect_all = 1;
        snprintf(q.value, sizeof(q.value), "/a.so:/b.so");
        q.found = 1;
        q.occurrences = 2;
        ac_fmt_environ_warning(line, sizeof(line), 42, "game", &q, 0,
                               AC_LD_WARN_TAIL);
        CHECK(strncmp(line, "pid 42 (game): LD_AUDIT=/a.so:/b.so [2 entries]"
                      " set at exec -- ",
                      sizeof("pid 42 (game): LD_AUDIT=/a.so:/b.so [2 entries]"
                             " set at exec -- ") - 1) == 0,
              "a short LD_AUDIT list shows its entry count");
        q.occurrences = 1;
        snprintf(q.value, sizeof(q.value), "/a.so");
        ac_fmt_environ_warning(line, sizeof(line), 42, "game", &q, 0,
                               AC_LD_WARN_TAIL);
        CHECK(strstr(line, "LD_AUDIT=/a.so [1 entry] set at exec") != NULL,
              "a single LD_AUDIT entry is reported as 1 entry");

        memset(&q, 0, sizeof(q));
        q.name = "LD_PRELOAD";
        snprintf(q.value, sizeof(q.value), "/tmp/cheat.so");
        q.found = 1;
        ac_fmt_environ_warning(line, sizeof(line), 42, "game", &q, 0,
                               AC_LD_WARN_TAIL);
        CHECK(strncmp(line, "pid 42 (game): LD_PRELOAD=/tmp/cheat.so set at "
                      "exec -- ", 55) == 0 &&
              strstr(line, AC_ENVIRON_LOG_CUT_NOTE) == NULL &&
              strstr(line, "[value truncated]") == NULL,
              "a short value is logged whole with no qualifiers");
    }

    /* --- environ: a value too long for the buffer says so --- */
    {
        static char env[AC_ENVIRON_VAL_LEN * 2];
        struct ac_environ_query q;
        size_t fits = sizeof("LD_PRELOAD=") - 1 + AC_ENVIRON_VAL_LEN - 1;

        memset(env, 'x', sizeof(env) - 1);
        memcpy(env, "LD_PRELOAD=", sizeof("LD_PRELOAD=") - 1);
        memset(&q, 0, sizeof(q));
        q.name = "LD_PRELOAD";
        ac_parse_environ_buf(env, sizeof(env) - 1, &q, 1);
        CHECK(q.found && q.truncated &&
              strlen(q.value) == AC_ENVIRON_VAL_LEN - 1,
              "an over-long value is cut at the buffer and flagged");

        env[fits] = '\0';
        memset(&q, 0, sizeof(q));
        q.name = "LD_PRELOAD";
        ac_parse_environ_buf(env, fits, &q, 1);
        CHECK(q.found && !q.truncated &&
              strlen(q.value) == AC_ENVIRON_VAL_LEN - 1,
              "a value that exactly fills the buffer is not flagged");
    }

    /* --- environ: an exited process's empty environ is inconclusive --- */
    {
        pid_t pid = fork();

        CHECK(pid >= 0, "fork for the empty-environ test");
        if (pid == 0)
            _exit(0);
        if (pid > 0) {
            struct ac_environ_query q;
            siginfo_t si;
            int rc;

            /* Wait for the exit without reaping: the zombie keeps its
             * /proc entry, with no mm left behind it. */
            CHECK(waitid(P_PID, (id_t)pid, &si, WEXITED | WNOWAIT) == 0,
                  "child for the empty-environ test has exited");
            memset(&q, 0, sizeof(q));
            q.name = "LD_PRELOAD";
            errno = 0;
            rc = ac_read_environ_vars((int)pid, &q, 1);
            CHECK(rc == -1 && !q.found,
                  "an empty environ is reported as inconclusive, not as "
                  "nothing set");
            waitpid(pid, NULL, 0);
        }
    }

    /* --- environ: an environ past the read buffer keeps its matches --- */
    {
        /* Each execve() string is capped at 128 KiB, so three of them put
         * the total past AC_ENVIRON_BUF. LD_PRELOAD sits first, inside
         * the part that is read. */
        enum { PAD_LEN = 100 * 1024 };
        char *pad[3] = { NULL, NULL, NULL };
        char *envp[6];
        char *argv_sleep[] = { "sleep", "10", NULL };
        pid_t pid;
        unsigned int k;

        for (k = 0; k < 3; k++) {
            pad[k] = malloc(PAD_LEN + 1);
            CHECK(pad[k] != NULL, "allocate environ padding");
            if (!pad[k])
                break;
            memset(pad[k], 'p', PAD_LEN);
            pad[k][PAD_LEN] = '\0';
            memcpy(pad[k], "PAD=", 4);
        }
        envp[0] = "LD_PRELOAD=/tmp/cheat.so";
        envp[1] = pad[0];
        envp[2] = pad[1];
        envp[3] = pad[2];
        envp[4] = "LD_AUDIT=/tmp/audit.so";   /* past the buffer: unseen */
        envp[5] = NULL;
        if (pad[0] && pad[1] && pad[2]) {
            pid = fork();
            CHECK(pid >= 0, "fork for the oversized-environ test");
            if (pid == 0) {
                execve("/bin/sleep", argv_sleep, envp);
                _exit(127);
            }
            if (pid > 0) {
                struct ac_environ_query vars[AC_LD_INJECT_ENV_VARS_COUNT];
                char comm[32] = "";
                int tries, rc, err;

                /* Until the exec lands, /proc/<pid>/environ is still the
                 * forked copy of ours; wait for the new comm. */
                for (tries = 0; tries < 200; tries++) {
                    char p[64];
                    FILE *f;

                    snprintf(p, sizeof(p), "/proc/%d/comm", (int)pid);
                    f = fopen(p, "r");
                    if (f) {
                        if (fgets(comm, sizeof(comm), f) &&
                            strncmp(comm, "sleep", 5) == 0) {
                            fclose(f);
                            break;
                        }
                        fclose(f);
                    }
                    usleep(10 * 1000);
                }
                CHECK(strncmp(comm, "sleep", 5) == 0,
                      "child for the oversized-environ test has exec'd");
                errno = 0;
                rc = ac_read_ld_inject_vars((int)pid, vars);
                err = errno;
                CHECK(rc == -1 && err == EMSGSIZE,
                      "an environ past the buffer reports EMSGSIZE");
                CHECK(vars[0].found &&
                      strcmp(vars[0].value, "/tmp/cheat.so") == 0,
                      "a match in the readable part survives the EMSGSIZE");
                CHECK(!vars[1].found,
                      "an entry past the buffer is not claimed as found");
                kill(pid, SIGKILL);
                waitpid(pid, NULL, 0);
            }
        }
        for (k = 0; k < 3; k++)
            free(pad[k]);
    }

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
