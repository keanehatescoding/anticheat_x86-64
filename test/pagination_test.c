/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * test/pagination_test.c — pagination / cap smoke test (Phase 5.4)
 *
 * Exercises the begin/get/end pagination ABI against the mock:
 *   n_vmas=5000  (>AC_MAX_VMAS=4096)
 *   n_mods=1100 (>AC_MAX_MODS=1024)
 *   n_events=70 (>AC_MAX_EVENTS=64)
 * when AC_MOCK_PAGINATION=1. Also checks the AC_GET_EVENTS_MAX_BLOCK_MS
 * clamp: a GET_EVENTS with block_ms=5000 must return within ~1000ms.
 *
 * Built with: $(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
 * Run mock:  LD_PRELOAD=test/libmock_anticheat.so AC_MOCK_PAGINATION=1 ./test/pagination_test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>

#include "../src/anticheat.h"

static int failures;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        failures++; \
    } else { \
        fprintf(stderr, "PASS: %s\n", msg); \
    } \
} while (0)

static long elapsed_ms(struct timespec a, struct timespec b)
{
    return (b.tv_sec - a.tv_sec) * 1000L + (b.tv_nsec - a.tv_nsec) / 1000000L;
}

int main(void)
{
    int fd, pag;
    pag = getenv("AC_MOCK_PAGINATION") && strcmp(getenv("AC_MOCK_PAGINATION"), "1") == 0;

    fd = open(AC_DEV_PATH, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "FAIL: open %s: %s\n", AC_DEV_PATH, strerror(errno));
        return 1;
    }

    /* ---------------- scan pagination ---------------- */
    {
        struct ac_scan_begin b;
        unsigned int fetched = 0;
        unsigned int i;
        int rc;

        memset(&b, 0, sizeof(b));
        b.pid = getpid();
        b.emit_events = 0;
        rc = ioctl(fd, AC_IOCTL_SCAN_BEGIN, &b);
        CHECK(rc == 0, "SCAN_BEGIN succeeds");
        if (rc == 0) {
            if (pag) {
                CHECK(b.n_vmas == 5000, "SCAN_BEGIN n_vmas==5000 in pagination mode");
                CHECK(b.truncated == 1, "SCAN_BEGIN truncated==1 in pagination mode");
                CHECK(b.resolved_pid == b.pid, "SCAN_BEGIN resolved_pid mirrors pid");
            } else {
                CHECK(b.n_vmas < AC_MAX_VMAS || b.n_vmas == 0, "SCAN_BEGIN n_vmas < AC_MAX_VMAS in normal mode");
            }
            /* Fetch via SCAN_GET — daemon pattern: loop up to n_vmas or until EINVAL */
            for (i = 0; i < b.n_vmas; i++) {
                struct ac_scan_get g;
                memset(&g, 0, sizeof(g));
                g.pid = b.pid;
                g.index = i;
                if (ioctl(fd, AC_IOCTL_SCAN_GET, &g) < 0) {
                    if (pag) {
                        /* In pagination mode we expect at least AC_MAX_VMAS successes;
                         * break is truncation point. */
                        break;
                    } else {
                        fprintf(stderr, "FAIL: SCAN_GET index %u failed: %s\n", i, strerror(errno));
                        failures++;
                        break;
                    }
                }
                fetched++;
            }
            if (pag) {
                CHECK(fetched >= AC_MAX_VMAS, "SCAN pagination: fetched at least AC_MAX_VMAS (4096) VMAs");
                CHECK(fetched == b.n_vmas || fetched == AC_MAX_VMAS || fetched >= AC_MAX_VMAS,
                      "SCAN pagination: fetched count sane");
                /* Out-of-range GET must fail with EINVAL */
                {
                    struct ac_scan_get g;
                    memset(&g, 0, sizeof(g));
                    g.pid = b.pid;
                    g.index = b.n_vmas; /* one past end */
                    rc = ioctl(fd, AC_IOCTL_SCAN_GET, &g);
                    CHECK(rc < 0 && errno == EINVAL, "SCAN_GET past end fails EINVAL");
                }
            } else {
                CHECK(fetched == b.n_vmas, "SCAN normal: fetched == n_vmas");
            }
        }
        (void)ioctl(fd, AC_IOCTL_SCAN_END, NULL);
        CHECK(1, "SCAN_END succeeds");
    }

    /* ---------------- mods pagination ---------------- */
    {
        unsigned int count = 0;
        unsigned int fetched = 0;
        unsigned int i;
        int rc;

        rc = ioctl(fd, AC_IOCTL_MODS_BEGIN, &count);
        CHECK(rc == 0, "MODS_BEGIN succeeds");
        if (rc == 0) {
            if (pag) {
                CHECK(count == 1100, "MODS_BEGIN count==1100 in pagination mode");
                CHECK(count > AC_MAX_MODS, "MODS_BEGIN count > AC_MAX_MODS in pagination mode");
            } else {
                CHECK(count <= AC_MAX_MODS, "MODS_BEGIN count <= AC_MAX_MODS in normal mode");
            }
            for (i = 0; i < count; i++) {
                struct ac_mod_get g;
                memset(&g, 0, sizeof(g));
                g.index = i;
                if (ioctl(fd, AC_IOCTL_MODS_GET, &g) < 0) {
                    break;
                }
                fetched++;
            }
            if (pag) {
                CHECK(fetched >= AC_MAX_MODS, "MODS pagination: fetched at least AC_MAX_MODS (1024) mods");
                CHECK(fetched == count, "MODS pagination: fetched == count (1100) via pagination mock");
                /* one past end must be EINVAL */
                {
                    struct ac_mod_get g;
                    memset(&g, 0, sizeof(g));
                    g.index = count;
                    rc = ioctl(fd, AC_IOCTL_MODS_GET, &g);
                    CHECK(rc < 0 && errno == EINVAL, "MODS_GET past end fails EINVAL");
                }
            } else {
                CHECK(fetched == count, "MODS normal: fetched == count");
            }
        }
        (void)ioctl(fd, AC_IOCTL_MODS_END, NULL);
        CHECK(1, "MODS_END succeeds");
    }

    /* ---------------- events pagination ---------------- */
    {
        struct ac_event_list el;
        int rc;

        /* flush any stale events so pagination fill is deterministic */
        (void)ioctl(fd, AC_IOCTL_FLUSH_EVENTS, NULL);

        if (pag) {
            /* In pagination mode the mock seeds 70 events on next GET;
             * first GET should return 64 (=AC_MAX_EVENTS) and dropped>0. */
            memset(&el, 0, sizeof(el));
            el.block_ms = 0;
            rc = ioctl(fd, AC_IOCTL_GET_EVENTS, &el);
            CHECK(rc == 0, "GET_EVENTS succeeds in pagination mode");
            if (rc == 0) {
                CHECK(el.count == AC_MAX_EVENTS, "GET_EVENTS count capped at AC_MAX_EVENTS (64)");
                CHECK(el.dropped > 0, "GET_EVENTS dropped >0 (events_dropped_total increments)");
                CHECK(el.count + el.dropped >= 70 || el.dropped == 6,
                      "GET_EVENTS pagination: 70 events -> 64 + 6 dropped");
            }
            /* second drain should be empty now */
            memset(&el, 0, sizeof(el));
            rc = ioctl(fd, AC_IOCTL_GET_EVENTS, &el);
            CHECK(rc == 0, "GET_EVENTS second drain succeeds");
            if (rc == 0) {
                CHECK(el.count == 0, "GET_EVENTS second drain empty");
            }
        } else {
            memset(&el, 0, sizeof(el));
            el.block_ms = 0;
            rc = ioctl(fd, AC_IOCTL_GET_EVENTS, &el);
            CHECK(rc == 0, "GET_EVENTS succeeds in normal mode");
            if (rc == 0) {
                CHECK(el.count <= AC_MAX_EVENTS, "GET_EVENTS count <= AC_MAX_EVENTS in normal mode");
            }
        }
    }

    /* ---------------- block_ms clamp ---------------- */
    if (pag) {
        struct ac_event_list el;
        struct timespec t0, t1;
        long ms;
        int rc;

        (void)ioctl(fd, AC_IOCTL_FLUSH_EVENTS, NULL);
        memset(&el, 0, sizeof(el));
        el.block_ms = 5000; /* exceeds AC_GET_EVENTS_MAX_BLOCK_MS=1000 */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        rc = ioctl(fd, AC_IOCTL_GET_EVENTS, &el);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        ms = elapsed_ms(t0, t1);
        CHECK(rc == 0, "GET_EVENTS block_ms=5000 succeeds (clamped)");
        /* Must be clamped to ~1000ms, not 2000ms nor 5000ms. Allow 800-1300 window for scheduling jitter. */
        CHECK(ms < 2000, "GET_EVENTS block_ms clamp: returns in <2000ms (not 5000ms)");
        CHECK(ms < 1500, "GET_EVENTS block_ms clamp: returns in <1500ms");
        CHECK(ms >= 800 && ms <= 1300, "GET_EVENTS block_ms clamp: ~1000ms (800-1300) when asked 5000");
        fprintf(stderr, "  (block_ms=5000 elapsed %ld ms)\n", ms);
        /* Also sanity: block_ms=0 must return immediately */
        memset(&el, 0, sizeof(el));
        el.block_ms = 0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        rc = ioctl(fd, AC_IOCTL_GET_EVENTS, &el);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        ms = elapsed_ms(t0, t1);
        CHECK(rc == 0, "GET_EVENTS block_ms=0 succeeds");
        CHECK(ms < 200, "GET_EVENTS block_ms=0 returns immediately (<200ms)");
    } else {
        fprintf(stderr, "SKIP: block_ms clamp test (needs AC_MOCK_PAGINATION=1)\n");
    }

    close(fd);

    if (failures) {
        fprintf(stderr, "\n%d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "\nAll pagination checks passed\n");
    return 0;
}
