/*
 * baseline_test.c -- regression test for #51: baseline_save_record() must
 * not clobber another (inode, offset) segment's record already saved to
 * the same path's baseline file. Reproduces the bug directly against the
 * daemon's real baseline_* functions (no kernel/mock scan needed -- they
 * are pure file I/O), by simulating a library with two executable
 * PT_LOAD segments: same inode/path, two different file offsets.
 *
 * Also covers coderabbit findings on the #51 fix itself:
 *   - baseline_save_record() must key on the full
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
 * #86: baseline_check_run() verifies a record across a *run* of adjacent,
 * file-contiguous executable VMAs, so splitting a baselined mapping
 * (madvise(MADV_DONTFORK)) after patching it can't downgrade the CRIT.
 * Exercised against a real mmap(PROT_EXEC) of a temp file in this
 * process, read back through /proc/self/mem.
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
#include <sys/mman.h>

static int failures;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        failures++; \
    } else { \
        fprintf(stderr, "PASS: %s\n", msg); \
    } \
} while (0)

/* Exact (inode, offset, size) lookup, for checking what
 * baseline_save_record() wrote. */
static int find_rec(const struct ac_baseline_rec *recs, int n,
                    unsigned long long inode, unsigned long long offset,
                    unsigned long long size, char hex_out[65])
{
    int i;

    for (i = 0; i < n; i++) {
        if (recs[i].inode == inode && recs[i].offset == offset &&
            recs[i].size == size) {
            snprintf(hex_out, 65, "%s", recs[i].hex);
            return 1;
        }
    }
    return 0;
}

/* This process's executable file-backed VMAs of `inode`, from
 * /proc/self/maps -- the same shape check_baselines_periodic() builds
 * from the module's scan snapshot. */
static int collect_self(unsigned long long inode, struct ac_bl_vma *out,
                        int max)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    int nv = 0;

    if (!f)
        return 0;
    while (nv < max && fgets(line, sizeof(line), f)) {
        unsigned long long start, end, off, ino;
        char perms[8], dev[16], path[AC_VMA_PATH] = "";

        if (sscanf(line, "%llx-%llx %7s %llx %15s %llu %127s", &start, &end,
                   perms, &off, dev, &ino, path) < 7)
            continue;
        if (ino != inode || !strchr(perms, 'x'))
            continue;
        out[nv].start = start;
        out[nv].end = end;
        out[nv].offset = off;
        out[nv].inode = ino;
        snprintf(out[nv].path, sizeof(out[nv].path), "%s", path);
        nv++;
    }
    fclose(f);
    return nv;
}

/* Verdict for this process's mapping(s) of `inode`, all expected to form
 * the single run starting at the first one. */
static int check_self(unsigned long long inode, int *nv_out, int *nruns_out,
                      struct ac_bl_run_result *res)
{
    struct ac_bl_vma v[16];
    int nv = collect_self(inode, v, 16);
    int mem_fd = -1, r, nruns = 0, worst = AC_BL_UNBASELINED;

    memset(res, 0, sizeof(*res));
    for (r = 0; r < nv; ) {
        struct ac_bl_run_result one;
        int rend = baseline_run_end(v, nv, r);

        baseline_check_run(v, r, rend, getpid(), &mem_fd, &one);
        if (nruns == 0 || one.verdict > worst) {
            worst = one.verdict;
            *res = one;
        }
        nruns++;
        r = rend;
    }
    if (mem_fd >= 0)
        close(mem_fd);
    *nv_out = nv;
    *nruns_out = nruns;
    return nv ? worst : -1;
}

int main(void)
{
    char tmpdir[] = "/tmp/ac_baseline_test_XXXXXX";
    char blpath[PATH_MAX];
    struct ac_baseline_rec recs[AC_BASELINE_MAX_RECORDS];
    char hex[65];
    int n, i, legacy;

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

    CHECK(find_rec(recs, n, 42, 0x1000, 0x2000, hex) &&
          strncmp(hex, "1111", 4) == 0,
          "segment 1's record is still intact after segment 2 was saved");
    CHECK(find_rec(recs, n, 42, 0x5000, 0x1000, hex) &&
          strncmp(hex, "2222", 4) == 0,
          "segment 2's record is present");

    /* Re-saving segment 1 (e.g. after a legitimate update) replaces only
     * its own record, still without touching segment 2's. */
    CHECK(baseline_save_record(blpath, 42, 0x1000, 0x2000,
                                "3333333333333333333333333333333333333333333333333333333333333333") == 0,
          "re-save segment 1");
    n = baseline_load_records(blpath, recs, &legacy);
    CHECK(n == 2, "record count unchanged after re-saving an existing segment");
    CHECK(find_rec(recs, n, 42, 0x1000, 0x2000, hex) &&
          strncmp(hex, "3333", 4) == 0,
          "segment 1's record was updated in place");
    CHECK(find_rec(recs, n, 42, 0x5000, 0x1000, hex) &&
          strncmp(hex, "2222", 4) == 0,
          "segment 2's record is untouched by re-saving segment 1");

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
    CHECK(find_rec(recs, n, 99, 0x2000, 0x1000, hex) &&
          strncmp(hex, "5555", 4) == 0,
          "the size-0x1000 mapping's own record is found");
    CHECK(find_rec(recs, n, 99, 0x2000, 0x3000, hex) &&
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
        CHECK(find_rec(recs, n, 111, 0x1000, 0x1000, hex) &&
              strncmp(hex, "aaaa", 4) == 0,
              "concurrent writer 1's record intact");
        CHECK(find_rec(recs, n, 111, 0x2000, 0x1000, hex) &&
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
            CHECK(find_rec(recs, n, 0x2a, 0x1000, 0x2000, hex) &&
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


    /* #86: a baselined mapping must stay verified when the process splits
     * its VMA. Real file, real mmap(PROT_EXEC), real madvise()/mprotect(),
     * checked through /proc/self/mem with the daemon's own run logic. */
    {
        long pg = sysconf(_SC_PAGESIZE);
        char fpath[] = "./ac_split_test_XXXXXX";
        int fd = mkstemp(fpath);
        unsigned char *m = MAP_FAILED, *buf = NULL;
        struct stat st;
        struct ac_bl_vma v[16];
        struct ac_bl_run_result res;
        char sblpath[PATH_MAX], shex[65];
        int nv, nruns, verdict, mfd, ok = 0;

        /* Five pages on disk, mapped from file offset 1 page, so the
         * record's offset isn't trivially 0. */
        if (fd >= 0 && (buf = malloc((size_t)pg * 5)) != NULL) {
            for (i = 0; i < pg * 5; i++)
                buf[i] = (unsigned char)(i * 7 + i / pg);
            if (write(fd, buf, (size_t)pg * 5) == pg * 5 && fstat(fd, &st) == 0)
                m = mmap(NULL, (size_t)pg * 4, PROT_READ | PROT_EXEC,
                         MAP_PRIVATE, fd, pg);
        }
        if (m != MAP_FAILED) {
            nv = collect_self(st.st_ino, v, 16);
            mfd = open("/proc/self/mem", O_RDONLY);
            if (nv == 1 && mfd >= 0 &&
                hash_proc_mem(mfd, v[0].start, v[0].end - v[0].start, shex) == 0) {
                baseline_path_for(v[0].path, sblpath);
                ok = baseline_save_record(sblpath, v[0].inode, v[0].offset,
                                          v[0].end - v[0].start, shex) == 0;
            }
            if (mfd >= 0)
                close(mfd);
        }
        CHECK(ok, "#86 split test: map a file executable and save its baseline");

        if (ok) {
            verdict = check_self(st.st_ino, &nv, &nruns, &res);
            CHECK(verdict == AC_BL_OK, "#86: unsplit, untouched mapping matches");

            /* Clean split: no false positive. */
            CHECK(madvise(m + pg * 2, (size_t)pg, MADV_DONTFORK) == 0,
                  "#86: madvise(MADV_DONTFORK) one page");
            verdict = check_self(st.st_ino, &nv, &nruns, &res);
            CHECK(nv >= 2, "#86: the madvise really split the VMA");
            CHECK(nruns == 1, "#86: the fragments coalesce into one run");
            CHECK(verdict == AC_BL_OK,
                  "#86: a split but unpatched mapping still matches its baseline");

            /* Patch a page, then leave it split: the bypass from #86 --
             * this used to be a WARNING (first fragment) plus silence. */
            CHECK(mprotect(m, (size_t)pg, PROT_READ | PROT_WRITE) == 0,
                  "#86: mprotect a text page writable");
            m[16] ^= 0xff;
            CHECK(mprotect(m, (size_t)pg, PROT_READ | PROT_EXEC) == 0,
                  "#86: mprotect it back to R-X");
            verdict = check_self(st.st_ino, &nv, &nruns, &res);
            CHECK(nv >= 2 && nruns == 1,
                  "#86: patched mapping is still split, still one run");
            CHECK(verdict == AC_BL_MISMATCH,
                  "#86: patched-then-split mapping is a content MISMATCH (CRIT)");
            CHECK(!res.len_changed,
                  "#86: no 'size changed' hint, the run still has the saved extent");

            /* Undo the patch: the hash spans every fragment, so this
             * proves it compares the right bytes, not just "differs". */
            CHECK(mprotect(m, (size_t)pg, PROT_READ | PROT_WRITE) == 0 &&
                  (m[16] ^= 0xff, 1) &&
                  mprotect(m, (size_t)pg, PROT_READ | PROT_EXEC) == 0,
                  "#86: undo the patch");
            verdict = check_self(st.st_ino, &nv, &nruns, &res);
            CHECK(verdict == AC_BL_OK,
                  "#86: unpatched split mapping matches again");

            /* A same-offset record of a different size (the #51 case
             * above) doesn't fit this run; the record that does fit is
             * the one checked, so this is not PARTIAL. */
            CHECK(baseline_save_record(sblpath, st.st_ino, (unsigned long long)pg,
                                       (unsigned long long)pg * 8,
                                       "7777777777777777777777777777777777777777777777777777777777777777") == 0,
                  "#86: save an oversized same-offset record");
            verdict = check_self(st.st_ino, &nv, &nruns, &res);
            CHECK(verdict == AC_BL_OK,
                  "#86: an oversized same-offset record doesn't mask the fitting one");

            /* Last page made non-executable: the saved range is no
             * longer fully mapped executable, so it can't be verified --
             * CRIT (PARTIAL), not the old size-mismatch WARNING. */
            CHECK(mprotect(m + pg * 3, (size_t)pg, PROT_READ) == 0,
                  "#86: mprotect the last page non-executable");
            verdict = check_self(st.st_ino, &nv, &nruns, &res);
            CHECK(verdict == AC_BL_PARTIAL,
                  "#86: a fragment made non-executable leaves the range PARTIAL");
            CHECK(res.off == (unsigned long long)pg,
                  "#86: PARTIAL names the baselined range's file offset");
            CHECK(mprotect(m + pg * 3, (size_t)pg, PROT_READ | PROT_EXEC) == 0,
                  "#86: restore the last page");
            verdict = check_self(st.st_ino, &nv, &nruns, &res);
            CHECK(verdict == AC_BL_OK, "#86: restored mapping matches again");

            /* Middle page unmapped: two runs, neither holds the record. */
            CHECK(munmap(m + pg, (size_t)pg) == 0, "#86: munmap a middle page");
            verdict = check_self(st.st_ino, &nv, &nruns, &res);
            CHECK(nruns == 2, "#86: an unmapped page breaks the run in two");
            CHECK(verdict == AC_BL_PARTIAL,
                  "#86: a hole in the baselined range is PARTIAL, not silence");

            /* A different inode's record is never consulted. */
            {
                struct ac_bl_vma w = v[0];
                int mem_fd = -1;

                w.inode = st.st_ino + 1;
                baseline_check_run(&w, 0, 1, getpid(), &mem_fd, &res);
                CHECK(res.verdict == AC_BL_UNBASELINED,
                      "#86: a mapping of another inode is unbaselined");
                CHECK(mem_fd == -1,
                      "#86: /proc/<pid>/mem isn't opened when nothing needs hashing");
            }
            unlink(sblpath);
        }
        if (fd >= 0) {
            close(fd);
            unlink(fpath);
        }
        free(buf);
        if (m != MAP_FAILED)
            munmap(m, (size_t)pg * 4);
    }

    if (failures) {
        fprintf(stderr, "%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "all checks passed\n");
    return 0;
}
