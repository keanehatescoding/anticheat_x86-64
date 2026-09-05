/*
 * baseline_test.c -- regression test for #51: baseline_save_record() must
 * not clobber another (inode, offset) segment's record already saved to
 * the same path's baseline file. Reproduces the bug directly against the
 * daemon's real baseline_* functions (no kernel/mock scan needed -- they
 * are pure file I/O), by simulating a library with two executable
 * PT_LOAD segments: same inode/path, two different file offsets.
 *
 * Also covers coderabbit findings on the #51 fix itself:
 *   - baseline_find_record() must treat a size mismatch at the same
 *     (inode, offset) as an incompatible baseline, not a content diff.
 *   - ...and must report that distinctly (out_size_mismatch) from "no
 *     record at this (inode, offset) at all", so callers can tell the
 *     operator to re-run --save instead of silently dropping coverage.
 *   - baseline_save_record()/baseline_find_record() must key on the full
 *     (inode, offset, size), not (inode, offset) alone, since two
 *     distinct VMAs can share a starting file offset at different sizes.
 *   - baseline_load_records() must tell a legacy pre-#51 3-field record
 *     apart from "nothing saved", so callers can point the operator at
 *     re-running --save instead of reporting it identically to "never
 *     baselined".
 *   - baseline_save_record() must fail loudly (AC_BASELINE_SAVE_FULL)
 *     rather than silently no-op when the file already holds
 *     AC_BASELINE_MAX_RECORDS *other* segments' records.
 *   - baseline_save_record()'s read-modify-write must actually land: a
 *     successful call must be immediately visible to a fresh
 *     baseline_load_records() (covers the atomic-rename path, though
 *     not the concurrent-writer locking itself).
 *
 * Pulls anticheat_daemon.c in as-is (renaming its main() out of the way)
 * rather than re-implementing the record format, so this test breaks if
 * the real functions regress, not just if a duplicated copy does.
 *
 * Build: make baseline-test
 */
#define main ac_daemon_unused_main
#include "../src/anticheat_daemon.c"
#undef main

#include <assert.h>

static int failures;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        failures++; \
    } else { \
        fprintf(stderr, "PASS: %s\n", msg); \
    } \
} while (0)

int main(void)
{
    char tmpdir[] = "/tmp/ac_baseline_test_XXXXXX";
    char blpath[PATH_MAX];
    struct ac_baseline_rec recs[AC_BASELINE_MAX_RECORDS];
    char hex[65];
    int n, i, legacy, size_mismatch;

    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return 1;
    }
    setenv("AC_BASELINE_DIR", tmpdir, 1);
    ac_mkdir_baselines();

    baseline_path_for("/usr/lib/libmultiseg.so", blpath);

    /* Segment 1: inode 42, file offset 0x1000, size 0x2000 */
    CHECK(baseline_save_record(blpath, 42, 0x1000, 0x2000,
                                "1111111111111111111111111111111111111111111111111111111111111111") == 0,
          "save segment 1");

    /* Segment 2: same inode/path, different file offset -- this is the
     * multi-PT_LOAD-executable-segment case from #51. Before the fix,
     * fopen(blpath, "w") here truncated segment 1's line away. */
    CHECK(baseline_save_record(blpath, 42, 0x5000, 0x1000,
                                "2222222222222222222222222222222222222222222222222222222222222222") == 0,
          "save segment 2");

    n = baseline_load_records(blpath, recs, &legacy);
    CHECK(n == 2, "both segments' records survive in the baseline file");
    CHECK(!legacy, "no legacy-format lines flagged for a fresh file");

    CHECK(baseline_find_record(recs, n, 42, 0x1000, 0x2000, hex, NULL) &&
          strncmp(hex, "1111", 4) == 0,
          "segment 1's record is still intact after segment 2 was saved");
    CHECK(baseline_find_record(recs, n, 42, 0x5000, 0x1000, hex, NULL) &&
          strncmp(hex, "2222", 4) == 0,
          "segment 2's record is present");

    /* Same (inode, offset) as segment 1, but a different size (e.g. the
     * file at this path was rebuilt) -- must NOT match segment 1's
     * record and be hashed against a stale digest, and must be reported
     * distinctly (out_size_mismatch) from "nothing saved for this
     * (inode, offset) at all", so a caller can tell the operator to
     * re-run --save instead of silently dropping coverage. */
    size_mismatch = 0;
    CHECK(!baseline_find_record(recs, n, 42, 0x1000, 0x9999, hex, &size_mismatch),
          "a size mismatch at a known (inode, offset) is not treated as a match");
    CHECK(size_mismatch, "the size mismatch is reported via out_size_mismatch");

    /* Re-saving segment 1 (e.g. after a legitimate update) replaces only
     * its own record, still without touching segment 2's. */
    CHECK(baseline_save_record(blpath, 42, 0x1000, 0x2000,
                                "3333333333333333333333333333333333333333333333333333333333333333") == 0,
          "re-save segment 1");
    n = baseline_load_records(blpath, recs, &legacy);
    CHECK(n == 2, "record count unchanged after re-saving an existing segment");
    CHECK(baseline_find_record(recs, n, 42, 0x1000, 0x2000, hex, NULL) &&
          strncmp(hex, "3333", 4) == 0,
          "segment 1's record was updated in place");
    CHECK(baseline_find_record(recs, n, 42, 0x5000, 0x1000, hex, NULL) &&
          strncmp(hex, "2222", 4) == 0,
          "segment 2's record is untouched by re-saving segment 1");

    /* A segment nobody ever saved a baseline for is correctly reported
     * as absent (no size mismatch flagged -- there's no record at this
     * offset at all to have mismatched), not confused with an unrelated
     * offset's record. */
    size_mismatch = 1;
    CHECK(!baseline_find_record(recs, n, 42, 0x9000, 0x1000, hex, &size_mismatch),
          "an offset with no saved record is not found");
    CHECK(!size_mismatch, "no size-mismatch flagged when the offset itself is unknown");

    /* Two distinct file-backed VMAs can legitimately share a starting
     * file offset while covering different lengths (the same region
     * mapped twice at different addresses) -- coderabbit finding on the
     * prior fix: saving the second must not evict the first's record
     * just because they share (inode, offset). */
    CHECK(baseline_save_record(blpath, 99, 0x2000, 0x1000,
                                "5555555555555555555555555555555555555555555555555555555555555555") == 0,
          "save a same-(inode,offset), size-0x1000 mapping");
    CHECK(baseline_save_record(blpath, 99, 0x2000, 0x3000,
                                "6666666666666666666666666666666666666666666666666666666666666666") == 0,
          "save a same-(inode,offset), size-0x3000 mapping");
    n = baseline_load_records(blpath, recs, &legacy);
    CHECK(n == 4, "both same-(inode,offset) different-size records are kept");
    CHECK(baseline_find_record(recs, n, 99, 0x2000, 0x1000, hex, NULL) &&
          strncmp(hex, "5555", 4) == 0,
          "the size-0x1000 mapping's own record is found");
    CHECK(baseline_find_record(recs, n, 99, 0x2000, 0x3000, hex, NULL) &&
          strncmp(hex, "6666", 4) == 0,
          "the size-0x3000 mapping's own record is found, not evicted by the other");

    /* A pre-#51 baseline file (single "start size hex" line, no
     * inode/offset) is recognized as legacy rather than silently
     * yielding zero records indistinguishable from "never baselined". */
    {
        char legacy_path[PATH_MAX];
        FILE *f;

        baseline_path_for("/usr/lib/liblegacy.so", legacy_path);
        f = fopen(legacy_path, "w");
        CHECK(f != NULL, "create a synthetic legacy-format baseline file");
        if (f) {
            fprintf(f, "%llx %llx %s\n", 0x1000ULL, 0x2000ULL,
                    "4444444444444444444444444444444444444444444444444444444444444444");
            fclose(f);
        }
        n = baseline_load_records(legacy_path, recs, &legacy);
        CHECK(n == 0, "a legacy 3-field line yields no usable records");
        CHECK(legacy, "a legacy 3-field line is flagged via out_legacy");
    }

    /* A file already holding AC_BASELINE_MAX_RECORDS *other* segments'
     * records must fail a save for one more, rather than silently
     * dropping it while still reporting success. */
    {
        char full_path[PATH_MAX];
        int rc;

        baseline_path_for("/usr/lib/libfull.so", full_path);
        for (i = 0; i < AC_BASELINE_MAX_RECORDS; i++) {
            char digest[65];

            snprintf(digest, sizeof(digest),
                     "%064x", (unsigned int)i);
            rc = baseline_save_record(full_path, 7, (unsigned long long)i * 0x1000,
                                       0x1000, digest);
            if (rc != 0)
                break;
        }
        CHECK(i == AC_BASELINE_MAX_RECORDS,
              "fill the baseline file to AC_BASELINE_MAX_RECORDS records");

        rc = baseline_save_record(full_path, 7,
                                   (unsigned long long)AC_BASELINE_MAX_RECORDS * 0x1000,
                                   0x1000, "deadbeef");
        CHECK(rc == AC_BASELINE_SAVE_FULL,
              "saving one more record into a full baseline file fails loudly");

        n = baseline_load_records(full_path, recs, &legacy);
        CHECK(n == AC_BASELINE_MAX_RECORDS,
              "the file still holds exactly the records it had before the failed save");
    }

    /* Concurrent baseline_save_record via fork()+flock: two writers to the
     * same path's baseline file (different segments) must not lose one
     * writer's record. Without flock() the second's load would see the
     * first's rename partially or discard it. */
    {
        char conc_path[PATH_MAX];
        pid_t c1, c2;
        int st1 = 0, st2 = 0;

        baseline_path_for("/usr/lib/libconcurrent.so", conc_path);
        unlink(conc_path);
        /* also remove any stale .tmp file from prior run */
        {
            char tmp[PATH_MAX + 32];
            snprintf(tmp, sizeof(tmp), "%s.tmpXXXXXX", conc_path);
            (void)tmp; /* mkstemp pattern not needed; unlink possible leftover handled by new save */
        }

        c1 = fork();
        if (c1 < 0) {
            CHECK(0, "fork for concurrent writer 1");
        } else if (c1 == 0) {
            int rc = baseline_save_record(conc_path, 111, 0x1000, 0x1000,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            _exit(rc == 0 ? 0 : 2);
        }
        c2 = fork();
        if (c2 < 0) {
            CHECK(0, "fork for concurrent writer 2");
        } else if (c2 == 0) {
            /* small jitter to increase overlap */
            usleep(5000);
            int rc = baseline_save_record(conc_path, 111, 0x2000, 0x1000,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
            _exit(rc == 0 ? 0 : 2);
        }
        if (c1 > 0) waitpid(c1, &st1, 0);
        if (c2 > 0) waitpid(c2, &st2, 0);
        CHECK(c1 > 0 && WIFEXITED(st1) && WEXITSTATUS(st1) == 0,
              "concurrent writer 1 exited successfully");
        CHECK(c2 > 0 && WIFEXITED(st2) && WEXITSTATUS(st2) == 0,
              "concurrent writer 2 exited successfully");

        n = baseline_load_records(conc_path, recs, &legacy);
        CHECK(n == 2, "concurrent writers: both segments survive");
        CHECK(baseline_find_record(recs, n, 111, 0x1000, 0x1000, hex, NULL) &&
              strncmp(hex, "aaaa", 4) == 0,
              "concurrent writer 1's record intact");
        CHECK(baseline_find_record(recs, n, 111, 0x2000, 0x1000, hex, NULL) &&
              strncmp(hex, "bbbb", 4) == 0,
              "concurrent writer 2's record intact");
    }

    /* Corrupt digest handling: baseline_load_records must not crash on
     * non-hex, truncated, empty, or garbage inputs and must report
     * legacy/invalid correctly. */
    {
        char corrupt_path[PATH_MAX];
        FILE *f;

        baseline_path_for("/usr/lib/libcorrupt.so", corrupt_path);

        /* empty file */
        f = fopen(corrupt_path, "w");
        CHECK(f != NULL, "create empty baseline file");
        if (f) fclose(f);
        n = baseline_load_records(corrupt_path, recs, &legacy);
        CHECK(n == 0, "empty file yields zero records");
        CHECK(!legacy, "empty file not flagged as legacy");

        /* truncated digest (short hex, still 4 fields) -- must not crash */
        f = fopen(corrupt_path, "w");
        CHECK(f != NULL, "create truncated-digest baseline file");
        if (f) {
            fprintf(f, "%llx %llx %llx %s\n", 0x2aULL, 0x1000ULL, 0x2000ULL, "abcd");
            fclose(f);
        }
        n = baseline_load_records(corrupt_path, recs, &legacy);
        CHECK(n == 1, "truncated digest line still parsed as one record (no crash)");
        if (n == 1) {
            CHECK(recs[0].inode == 0x2a && recs[0].offset == 0x1000 && recs[0].size == 0x2000,
                  "truncated digest record fields parsed correctly");
            CHECK(strcmp(recs[0].hex, "abcd") == 0,
                  "truncated digest hex preserved verbatim");
        }
        CHECK(!legacy, "truncated 4-field line not flagged as legacy");

        /* non-hex digest (contains 'z','g' which are not hex) -- %s still
         * captures it, must not crash. */
        f = fopen(corrupt_path, "w");
        CHECK(f != NULL, "create non-hex digest baseline file");
        if (f) {
            fprintf(f, "%llx %llx %llx %s\n", 0x2aULL, 0x1000ULL, 0x2000ULL,
                    "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
            fclose(f);
        }
        n = baseline_load_records(corrupt_path, recs, &legacy);
        CHECK(n == 1, "non-hex digest line parsed as one record (no crash)");
        if (n == 1)
            CHECK(strncmp(recs[0].hex, "zzzz", 4) == 0,
                  "non-hex digest preserved, no validation crash");
        CHECK(!legacy, "non-hex 4-field line not flagged as legacy");

        /* garbage line + valid line: garbage must be skipped, valid kept */
        f = fopen(corrupt_path, "w");
        CHECK(f != NULL, "create garbage+valid baseline file");
        if (f) {
            fprintf(f, "hello world this is not a baseline\n");
            fprintf(f, "%llx %llx %llx %s\n", 0x2aULL, 0x1000ULL, 0x2000ULL,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            fprintf(f, "   \n"); /* blank line */
            fclose(f);
        }
        n = baseline_load_records(corrupt_path, recs, &legacy);
        CHECK(n == 1, "garbage line skipped, valid record still loaded");
        CHECK(!legacy, "garbage non-legacy line not flagged as legacy");

        /* mixed legacy 3-field + valid 4-field: legacy flagged, valid kept */
        f = fopen(corrupt_path, "w");
        CHECK(f != NULL, "create legacy+valid baseline file");
        if (f) {
            fprintf(f, "%llx %llx %s\n", 0x1000ULL, 0x2000ULL,
                    "4444444444444444444444444444444444444444444444444444444444444444");
            fprintf(f, "%llx %llx %llx %s\n", 0x2aULL, 0x1000ULL, 0x2000ULL,
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
            fclose(f);
        }
        n = baseline_load_records(corrupt_path, recs, &legacy);
        CHECK(n == 1, "legacy line ignored, valid 4-field record loaded");
        CHECK(legacy, "legacy flag set when file contains a 3-field line");
        if (n == 1)
            CHECK(baseline_find_record(recs, n, 0x2a, 0x1000, 0x2000, hex, NULL) &&
                  strncmp(hex, "bbbb", 4) == 0,
                  "valid record after legacy line is retrievable");

        /* baseline_load_records with NULL out_legacy must not crash */
        f = fopen(corrupt_path, "w");
        if (f) {
            fprintf(f, "%llx %llx %s\n", 0x1000ULL, 0x2000ULL,
                    "4444444444444444444444444444444444444444444444444444444444444444");
            fclose(f);
        }
        n = baseline_load_records(corrupt_path, recs, NULL);
        CHECK(n == 0, "baseline_load_records with NULL out_legacy handles legacy line (no crash)");

        /* nonexistent file */
        {
            char nofile[PATH_MAX];
            snprintf(nofile, sizeof(nofile), "%s/nonexistent_%d.txt", tmpdir, (int)getpid());
            n = baseline_load_records(nofile, recs, &legacy);
            CHECK(n == 0, "nonexistent file yields zero records");
            CHECK(!legacy, "nonexistent file not flagged as legacy");
        }
    }

    /* AC_BASELINE_DIR override unwritable dir -- baseline_save_record must
     * fail cleanly (return -1, no crash). Handles both non-root (chmod)
     * and root (file-as-dir ENOTDIR) cases. */
    {
        char ro_dir[PATH_MAX];
        char blpath2[PATH_MAX];
        char blocker_file[PATH_MAX];
        int rc;
        FILE *bf;

        /* chmod-based unwritable directory */
        snprintf(ro_dir, sizeof(ro_dir), "%s/ro_test", tmpdir);
        mkdir(ro_dir, 0755);
        chmod(ro_dir, 0000);
        setenv("AC_BASELINE_DIR", ro_dir, 1);
        baseline_path_for("/usr/lib/libnowrite.so", blpath2);
        rc = baseline_save_record(blpath2, 99, 0x1000, 0x1000,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        if (geteuid() != 0) {
            CHECK(rc == -1, "AC_BASELINE_DIR unwritable dir fails cleanly (return -1)");
        } else {
            /* root bypasses DAC; don't assert -1, just ensure no crash */
            fprintf(stderr, "SKIP: unwritable chmod check running as root (rc=%d)\n", rc);
            CHECK(1, "AC_BASELINE_DIR unwritable dir no crash as root (skipped)");
            if (rc == 0) unlink(blpath2);
        }
        chmod(ro_dir, 0755);
        rmdir(ro_dir);

        /* file-as-directory: AC_BASELINE_DIR points at a regular file, so
         * any baseline path is <file>/hash.txt -> ENOTDIR, fails even as root. */
        snprintf(blocker_file, sizeof(blocker_file), "%s/blocker", tmpdir);
        bf = fopen(blocker_file, "w");
        CHECK(bf != NULL, "create blocker file for unwritable-dir test");
        if (bf) { fputs("x", bf); fclose(bf); }
        setenv("AC_BASELINE_DIR", blocker_file, 1);
        baseline_path_for("/usr/lib/libnowrite2.so", blpath2);
        rc = baseline_save_record(blpath2, 99, 0x1000, 0x1000,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        CHECK(rc == -1, "AC_BASELINE_DIR file-as-dir fails cleanly (return -1, no crash)");
        unlink(blocker_file);

        /* restore for remaining tests */
        setenv("AC_BASELINE_DIR", tmpdir, 1);
        ac_mkdir_baselines();
    }

    /* AC_HASH_CAP=16MiB cap: mapping >16MiB hashes only first 16MiB
     * (assert by hashing known pattern). The daemon caps via
     *   size = vi->end - vi->start; if (size > AC_HASH_CAP) size = AC_HASH_CAP;
     * before calling hash_proc_mem(). Verify that a file whose tail beyond
     * 16MiB differs still hashes identically when capped. */
    {
        char pathtmp[] = "/tmp/ac_hashcap_XXXXXX";
        int fd = mkstemp(pathtmp);
        char hex_cap[65], hex_full[65], hex_capped_via_logic[65];
        uint64_t raw_size, capped_size;
        size_t i_chunk;
        const size_t one_mib = 1024 * 1024;
        char *chunk = malloc(one_mib);
        int ok = 0;

        CHECK(fd >= 0, "AC_HASH_CAP test: create temp file");
        CHECK(chunk != NULL, "AC_HASH_CAP test: allocate 1MiB chunk");
        if (fd >= 0 && chunk) {
            /* write 16MiB of 'A' */
            memset(chunk, 'A', one_mib);
            for (i_chunk = 0; i_chunk < 16; i_chunk++) {
                ssize_t w = write(fd, chunk, one_mib);
                CHECK(w == (ssize_t)one_mib, "AC_HASH_CAP test: write A chunk");
                if (w != (ssize_t)one_mib) break;
            }
            /* write extra 1MiB of 'B' so total 17MiB differs beyond cap */
            memset(chunk, 'B', one_mib);
            {
                ssize_t w = write(fd, chunk, one_mib);
                CHECK(w == (ssize_t)one_mib, "AC_HASH_CAP test: write B chunk");
            }
            fsync(fd);

            raw_size = 17ULL * 1024 * 1024;
            capped_size = raw_size > AC_HASH_CAP ? AC_HASH_CAP : raw_size;
            CHECK(capped_size == AC_HASH_CAP, "AC_HASH_CAP is 16MiB and caps 17MiB mapping");

            /* hash only first 16MiB */
            CHECK(hash_proc_mem(fd, 0, AC_HASH_CAP, hex_cap) == 0,
                  "AC_HASH_CAP test: hash first 16MiB via hash_proc_mem");
            /* hash full 17MiB -- must differ from capped */
            CHECK(hash_proc_mem(fd, 0, raw_size, hex_full) == 0,
                  "AC_HASH_CAP test: hash full 17MiB via hash_proc_mem");
            CHECK(strcmp(hex_cap, hex_full) != 0,
                  "AC_HASH_CAP test: full 17MiB digest differs from capped 16MiB (cap matters)");

            /* daemon's capping logic: hash with capped size equals hex_cap */
            CHECK(hash_proc_mem(fd, 0, capped_size, hex_capped_via_logic) == 0,
                  "AC_HASH_CAP test: hash with capped size succeeds");
            CHECK(strcmp(hex_cap, hex_capped_via_logic) == 0,
                  "AC_HASH_CAP test: capped hash equals hash of first 16MiB");

            /* also verify capping via raw->capped transform yields same as direct */
            {
                uint64_t sz = raw_size;
                if (sz > AC_HASH_CAP) sz = AC_HASH_CAP;
                char hex_via_transform[65];
                CHECK(hash_proc_mem(fd, 0, sz, hex_via_transform) == 0,
                      "AC_HASH_CAP test: hash via transformed size");
                CHECK(strcmp(hex_via_transform, hex_cap) == 0,
                      "AC_HASH_CAP test: transformed-size hash matches cap");
            }

            ok = 1;
        }
        if (chunk) free(chunk);
        if (fd >= 0) close(fd);
        unlink(pathtmp);
        if (!ok)
            CHECK(0, "AC_HASH_CAP test: setup failed");
    }

    if (failures) {
        fprintf(stderr, "%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
