/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * anticheat_daemon.c — userspace front-end for the kernel anticheat module.
 *
 * Commands:
 *   status                 module status
 *   protect --pid N        protect a running process
 *   protect --pid N --ns-of REFPID   protect a pid as seen inside the
 *                           pid namespace that host-pid REFPID lives in
 *                           (e.g. a sandboxed/containerized game whose
 *                           in-namespace pid is known but its host pid
 *                           isn't -- --comm below is usually simpler
 *                           when a comm name is available)
 *   protect --pid N --jit  mark this pid as a known JIT-using binary
 *                           (Mono/JVM/V8/...) -- anon-exec growth still
 *                           logs, at reduced severity, but isn't
 *                           auto-reported to the ban pipeline (also
 *                           works combined with --comm)
 *   protect --comm NAME    protect all processes matching NAME -- prefers
 *                           an exact /proc/<pid>/exe basename match
 *                           (untruncated), falling back to the raw,
 *                           15-char-truncated /proc/<pid>/comm string
 *                           when /proc/<pid>/exe isn't usable
 *   unprotect --pid N      remove protection
 *   unprotect --pid N --ns-of REFPID   remove protection from a pid as
 *                           seen inside the pid namespace that host-pid
 *                           REFPID lives in (same targeting as protect)
 *   list                   list protected processes
 *   scan --pid N           VMA scan (RWX detection)
 *   scan --pid N --ns-of REFPID   scan a pid as seen inside the pid
 *                           namespace that host-pid REFPID lives in
 *   scan --pid N --hash [--save|--check]   memory integrity baselines
 *   scan --pid N --check-hooks             Vulkan present-call hook check
 *   scan --pid N --check-preload           LD_PRELOAD check (heuristic)
 *   scan --pid N --check-vklayers          Vulkan-layer env var check (heuristic)
 *   scan --pid N --check-implicit-layers   implicit Vulkan-layer manifest check (heuristic)
 *   syscalls               verify syscall table integrity
 *   modules                list modules + detect hidden modules
 *   vmcheck                VM/hypervisor detection (heuristic, CPUID + DMI)
 *   events [--watch]       dump pending security events (--watch: poll)
 *   lock | unlock          pin / unpin the kernel module
 *   start [--foreground]   monitoring daemon (poll events + periodic checks)
 *
 * Requires root (the kernel device only opens for CAP_SYS_ADMIN).
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>
#include <cpuid.h>
#include <elf.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syslog.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <linux/limits.h>

#include "anticheat.h"
#include "sha256.h"

#define AC_BASELINE_DIR "/var/lib/anticheat/baselines"
#define AC_HASH_CAP      (16UL * 1024 * 1024)   /* max bytes hashed per mapping */
#define AC_READ_CHUNK    (1024 * 1024)

static int dev_fd = -1;
static int g_verbose = 0;
static volatile sig_atomic_t g_stop = 0;

/* Ban-pipeline reporting (see the "server-side reporting" section below
 * for the actual implementation). Forward-declared so logmsg() -- defined
 * early, used everywhere -- can call it without moving the networking code
 * up here. */
static void ac_report(const char *event_type, const char *detail);

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */
static void die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void logmsg(int pri, const char *fmt, ...)
{
    va_list ap;
    char buf[512];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    syslog(pri, "%s", buf);
    if (pri <= LOG_WARNING || g_verbose)
        fprintf(stderr, "%s\n", buf);
    /* LOG_ALERT/LOG_CRIT are exactly the severities this file already uses
     * for genuine detections (ptrace deny, syscall hook, hidden module,
     * baseline tamper, anon-exec growth) -- LOG_WARNING/LOG_INFO are
     * operational messages (self-protect failures, startup/shutdown), not
     * violations. Reusing that existing severity split as the report
     * trigger avoids touching every call site individually. */
    if (pri <= LOG_CRIT)
        ac_report(pri <= LOG_ALERT ? "ALERT" : "CRITICAL", buf);
}

static int ac_open(void)
{
    dev_fd = open(AC_DEV_PATH, O_RDWR | O_CLOEXEC);
    if (dev_fd < 0)
        die("cannot open %s: %s (is the module loaded? try: sudo insmod anticheat.ko)",
            AC_DEV_PATH, strerror(errno));
    /* O_CLOEXEC atomically sets FD_CLOEXEC, but set it explicitly too for
     * kernels that ignore the flag and as defense in depth after the open. */
    fcntl(dev_fd, F_SETFD, FD_CLOEXEC);
    return dev_fd;
}

static void ac_close(void)
{
    if (dev_fd >= 0) {
        close(dev_fd);
        dev_fd = -1;
    }
}

static int ioctl_ok(unsigned long req, void *arg)
{
    int r = ioctl(dev_fd, req, arg);

    if (r < 0)
        fprintf(stderr, "ioctl %#lx failed: %s\n", req, strerror(errno));
    return r;
}

static const char *ev_type_str(unsigned int t)
{
    switch (t) {
    case AC_EV_FORK:        return "FORK";
    case AC_EV_EXEC:        return "EXEC";
    case AC_EV_EXIT:        return "EXIT";
    case AC_EV_PTRACE:      return "PTRACE-DENIED";
    case AC_EV_PROCESS_VM:  return "PROCESS-VM-DENIED";
    case AC_EV_SYSCALL_HOOK:return "SYSCALL-HOOK";
    case AC_EV_SYSCALL_REDIRECT: return "SYSCALL-REDIRECT";
    case AC_EV_RWX:         return "RWX";
    case AC_EV_ANON_EXEC:   return "ANON-EXEC";
    case AC_EV_INFO:        return "INFO";
    default:                return "UNKNOWN";
    }
}

static void print_event(const struct ac_event *e)
{
    time_t t = (time_t)(e->ts / 1000000000ULL);
    char ts[32];

    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&t));
    printf("%s [%s] pid=%d comm=%s %s\n",
           ts, ev_type_str(e->type), e->pid, e->comm, e->data);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/* command: status                                                     */
/* ------------------------------------------------------------------ */
static int cmd_status(void)
{
    struct ac_status st;

    ac_open();
    if (ioctl_ok(AC_IOCTL_STATUS, &st) < 0)
        return 1;
    printf("anticheat kernel module\n");
    printf("  version           : %llu\n", st.version);
    printf("  syscall table     : %#llx\n", st.syscall_table_addr);
    printf("  protected procs   : %u\n", st.active_procs);
    printf("  events dropped    : %u\n", st.events_dropped);
    printf("  locked            : %u\n", st.locked);
    printf("  syscall hooks     : %u (last check)\n", st.syscall_hook_count);
    ac_close();
    return 0;
}

/* ------------------------------------------------------------------ */
/* command: protect / unprotect / list                                */
/* ------------------------------------------------------------------ */
/* Returns the trimmed contents of /proc/pid/comm in buf (bufsz >=
 * AC_MAX_COMM + 1), or -1 if the pid doesn't exist / isn't readable. */
static int read_comm(int pid, char *buf, size_t bufsz)
{
    char path[64];
    int fd;
    ssize_t r;

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    r = read(fd, buf, bufsz - 1);
    close(fd);
    if (r <= 0)
        return -1;
    buf[r] = '\0';
    while (r > 0 && (buf[r - 1] == '\n' || buf[r - 1] == ' '))
        buf[--r] = '\0';
    return (int)r;
}

/* Defined further down (the scan command's helpers); forward-declared here
 * so pid_of_comm() can reuse it instead of duplicating the readlink. */
static char *proc_exe_path(int pid);

/* Returns 1 if /proc/<pid>/exe's basename exactly equals `comm`, 0 if
 * /proc/<pid>/exe is readable but definitively doesn't match, or -1 if it
 * can't be used to decide at all (process gone, EACCES reading another
 * user's /proc/<pid>/exe, or a deleted/replaced binary) -- the last case
 * is the caller's cue to fall back to the /proc/<pid>/comm string
 * heuristic instead, same as before this function existed.
 *
 * /proc/<pid>/exe resolves to the executable's real, untruncated
 * basename, unlike /proc/<pid>/comm which the kernel silently truncates
 * to TASK_COMM_LEN-1 (15) characters. That's the precision win from
 * issue #69: two differently-named binaries whose comm happens to
 * truncate to the same 15 characters are indistinguishable via comm
 * alone, but not via their exe basenames -- so preferring this check
 * avoids matching and protecting an unrelated helper process that merely
 * shares a truncated comm with the intended target. */
static int exe_path_matches(int pid, const char *comm)
{
    char *link = proc_exe_path(pid);
    const char *base;
    size_t n;

    if (!link)
        return -1;

    /* The kernel suffixes a deleted or replaced backing file's target
     * with " (deleted)"; that path no longer reliably identifies what's
     * actually running (the on-disk file may be a totally different
     * binary now, or gone outright), so don't treat it as authoritative
     * -- fall back to the comm heuristic instead of risking a wrong
     * match. */
    n = strlen(link);
    if (n > 10 && strcmp(link + n - 10, " (deleted)") == 0)
        return -1;

    base = strrchr(link, '/');
    base = base ? base + 1 : link;
    return strcmp(base, comm) == 0;
}

/* Single source of truth for "does pid identify as target name `comm`",
 * shared by pid_of_comm()'s initial /proc scan and cmd_protect()'s
 * immediately-before-the-ioctl TOCTOU re-check below -- both need the
 * exact same exe-basename-preferred, comm-string-fallback logic, and
 * having the re-check apply only the old plain comm compare would silently
 * reject every pid the exe-based match found (since that match exists
 * precisely for names whose truncated comm does *not* equal `comm`).
 *
 * Returns 1 on a match (and, if comm_out is non-NULL, copies pid's current
 * /proc/<pid>/comm string into it -- the same value that's always been
 * stored in the kernel registry's informational comm field, even when the
 * match itself was made via exe basename). Returns 0 otherwise. */
static int pid_identifies_as(int pid, const char *comm, char *comm_out,
                              size_t comm_out_sz)
{
    int exe_match = exe_path_matches(pid, comm);
    char buf[AC_MAX_COMM + 1];

    if (exe_match == 0)
        return 0;   /* exe readable and definitively not this target */

    if (exe_match < 0) {
        /* exe unusable (gone, permission denied on another user's
         * process, or a deleted/replaced binary) -- fall back to the
         * original comm-string match so this doesn't regress any case
         * the old code used to handle. */
        if (read_comm(pid, buf, sizeof(buf)) < 0 || strcmp(buf, comm) != 0)
            return 0;
    } else {
        /* exe_match == 1: matched via exe basename; still fetch the
         * (possibly truncated) comm string purely for display/registry
         * purposes, same field the kernel has always stored. */
        if (read_comm(pid, buf, sizeof(buf)) < 0)
            buf[0] = '\0';
    }
    if (comm_out)
        snprintf(comm_out, comm_out_sz, "%s", buf);
    return 1;
}

static int pid_of_comm(const char *comm, int *pids, int max)
{
    DIR *d;
    struct dirent *de;
    int n = 0;

    d = opendir("/proc");
    if (!d)
        die("opendir /proc: %s", strerror(errno));
    while ((de = readdir(d)) != NULL) {
        int pid;

        if (de->d_name[0] < '0' || de->d_name[0] > '9')
            continue;
        pid = atoi(de->d_name);
        if (pid <= 0)
            continue;

        /* Top-level /proc/[N] entries are always keyed by tgid: a
         * non-leader thread only ever shows up under
         * /proc/[tgid]/task/[tid], never as its own top-level /proc
         * entry. So every pid this loop collects is already the
         * thread-group leader -- "tgid-stable" per issue #69 -- with no
         * extra lookup needed. */

        if (pid_identifies_as(pid, comm, NULL, 0) && n < max)
            pids[n++] = pid;
    }
    closedir(d);
    return n;
}

/* Strict positive-pid parse for --pid/--ns-of CLI arguments, same
 * rationale as ac_env_interval() above: atoi() silently truncates
 * trailing garbage ("12foo" -> 12) instead of rejecting it, so an
 * operator typo acts on the wrong pid with no error at all. Unlike
 * ac_env_interval()'s env-var fallback-to-default behavior, a bad CLI
 * argument is fatal -- die() rather than silently substituting a
 * default pid. */
static int ac_parse_pid(const char *s, const char *what)
{
    char *end;
    long v;

    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v <= 0 || v > INT_MAX)
        die("invalid %s '%s': must be a positive integer pid", what, s);
    return (int)v;
}

static int cmd_protect(int argc, char **argv)
{
    struct ac_proc_id id;
    int pid = -1, ref_pid = -1, jit = 0, i, n;
    const char *comm = NULL;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0) {
            if (i + 1 >= argc)
                die("usage: --pid requires a value");
            pid = ac_parse_pid(argv[++i], "--pid");
        } else if (strcmp(argv[i], "--comm") == 0) {
            if (i + 1 >= argc)
                die("usage: --comm requires a value");
            comm = argv[++i];
        } else if (strcmp(argv[i], "--ns-of") == 0) {
            if (i + 1 >= argc)
                die("usage: --ns-of requires a value");
            ref_pid = ac_parse_pid(argv[++i], "--ns-of");
        } else if (strcmp(argv[i], "--jit") == 0)
            jit = 1;
    }
    if (pid < 0 && !comm)
        die("usage: anticheat protect --pid N [--ns-of REFPID] [--jit] | "
            "--comm NAME [--jit]");
    if (ref_pid >= 0 && comm)
        die("usage: --ns-of cannot be combined with --comm");
    if (ref_pid >= 0 && pid < 0)
        die("usage: --ns-of requires --pid");

    ac_open();
    if (comm) {
        int pids[256];
        int protected_count = 0;

        n = pid_of_comm(comm, pids, 256);
        if (n == 0) {
            fprintf(stderr, "no process with comm '%s'\n", comm);
            return 1;
        }
        for (i = 0; i < n; i++) {
            char cur_comm[AC_MAX_COMM + 1];

            /* Re-check right before the ioctl, not just at scan time:
             * pids[i] may have exited and been reused by an unrelated
             * process in between, and this is our last chance to catch
             * that before silently protecting the wrong process. Uses the
             * same exe-basename-preferred match pid_of_comm() used to find
             * pids[i] in the first place -- re-checking via the plain comm
             * string alone would reject every pid that was only found via
             * its exe basename. */
            if (!pid_identifies_as(pids[i], comm, cur_comm, sizeof(cur_comm))) {
                fprintf(stderr,
                        "skipping pid %d: no longer matches '%s' (exited/reused?)\n",
                        pids[i], comm);
                continue;
            }
            memset(&id, 0, sizeof(id));
            id.pid = pids[i];
            id.jit_allowed = jit;
            snprintf(id.comm, sizeof(id.comm), "%.*s",
                     (int)sizeof(id.comm) - 1, cur_comm);
            if (ioctl_ok(AC_IOCTL_ADD_PROC, &id) == 0) {
                printf("protected pid %d (%s)\n", pids[i], id.comm);
                protected_count++;
            }
        }
        printf("%d process(es) protected\n", protected_count);
    } else {
        memset(&id, 0, sizeof(id));
        id.pid = pid;
        id.ref_pid = ref_pid;
        id.jit_allowed = jit;
        if (ioctl_ok(AC_IOCTL_ADD_PROC, &id) < 0)
            return 1;
        printf("protected pid %d (%s)\n", pid, id.comm);
    }
    ac_close();
    return 0;
}

static int cmd_unprotect(int argc, char **argv)
{
    struct ac_proc_id id;
    int pid = -1, ref_pid = -1, i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0) {
            if (i + 1 >= argc)
                die("usage: --pid requires a value");
            pid = ac_parse_pid(argv[++i], "--pid");
        } else if (strcmp(argv[i], "--ns-of") == 0) {
            if (i + 1 >= argc)
                die("usage: --ns-of requires a value");
            ref_pid = ac_parse_pid(argv[++i], "--ns-of");
        }
    }
    if (pid < 0)
        die("usage: anticheat unprotect --pid N [--ns-of REFPID]");

    ac_open();
    memset(&id, 0, sizeof(id));
    id.pid = pid;
    id.ref_pid = ref_pid;
    if (ioctl_ok(AC_IOCTL_DEL_PROC, &id) < 0)
        return 1;
    printf("protection removed from pid %d\n", pid);
    ac_close();
    return 0;
}

static int cmd_list(void)
{
    struct ac_prot_list pl;
    unsigned int i;

    ac_open();
    memset(&pl, 0, sizeof(pl));
    if (ioctl_ok(AC_IOCTL_LIST_PROTECTED, &pl) < 0)
        return 1;
    printf("%u protected process(es):\n", pl.count);
    for (i = 0; i < pl.count; i++)
        printf("  pid %-8d %-16s jit=%s\n", pl.items[i].pid,
               pl.items[i].comm, pl.items[i].jit_allowed ? "yes" : "no");
    ac_close();
    return 0;
}

/* ------------------------------------------------------------------ */
/* command: scan (VMA + optional hash baseline)                        */
/* ------------------------------------------------------------------ */
static char *proc_exe_path(int pid)
{
    static char link[PATH_MAX];
    ssize_t n;
    char p[64];

    snprintf(p, sizeof(p), "/proc/%d/exe", pid);
    n = readlink(p, link, sizeof(link) - 1);
    if (n < 0)
        return NULL;
    link[n] = '\0';
    return link;
}

/* hash [start, start+size) as read through `mem_fd`, an already-open
 * /proc/<pid>/mem fd; returns 0 on success. Takes an fd rather than a pid
 * so callers hashing several VMAs of the same process open it once
 * instead of once per VMA. */
static int hash_proc_mem(int mem_fd, uint64_t start, uint64_t size,
                         char out_hex[65])
{
    ac_sha256_ctx ctx;
    uint64_t done = 0;
    uint8_t buf[AC_READ_CHUNK];

    ac_sha256_init(&ctx);
    while (done < size) {
        uint64_t want = size - done;
        ssize_t r;

        if (want > sizeof(buf))
            want = sizeof(buf);
        do {
            r = pread(mem_fd, buf, want, (off_t)(start + done));
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            /* Part of the range is unreadable (swapped, a hole, or made
             * unreadable on purpose): the digest would silently cover only
             * part of the range, so fail the whole hash instead of
             * reporting a false match/mismatch against the baseline. */
            return -1;
        }
        if (r == 0)
            break;   /* short read: handled below, same as any other gap */
        ac_sha256_update(&ctx, buf, (size_t)r);
        done += (uint64_t)r;
    }
    if (done < size) {
        /* pread() hit EOF before covering the whole requested range --
         * the same silent-partial-coverage case as the r < 0 branch
         * above, just via a short read instead of an error. */
        return -1;
    }
    {
        uint8_t d[32];
        static const char hexd[] = "0123456789abcdef";
        int i;
        ac_sha256_final(&ctx, d);
        for (i = 0; i < 32; i++) {
            out_hex[i * 2] = hexd[d[i] >> 4];
            out_hex[i * 2 + 1] = hexd[d[i] & 0xf];
        }
        out_hex[64] = '\0';
    }
    return 0;
}

static const char *ac_baseline_dir(void)
{
    const char *e = getenv("AC_BASELINE_DIR");

    return (e && *e) ? e : AC_BASELINE_DIR;
}

/* Strict positive-integer parse for interval-override env vars, shared by
 * every ac_*_check_interval() below. atoi() (the previous implementation,
 * used identically six times over) can't tell "unset/garbage" apart from
 * an explicit 0 and has no overflow bound; strtol() lets us reject both a
 * malformed value (trailing garbage, non-numeric, empty) and one that
 * over/underflows int, falling back to the caller's default in either
 * case instead of silently misbehaving on operator typos. */
static int ac_env_interval(const char *envname, int default_secs)
{
    const char *e = getenv(envname);
    char *end;
    long v;

    if (!e || !*e)
        return default_secs;
    errno = 0;
    v = strtol(e, &end, 10);
    if (errno != 0 || *end != '\0' || end == e || v <= 0 || v > INT_MAX)
        return default_secs;
    return (int)v;
}

/* How often the daemon re-hashes protected processes' executables against
 * saved baselines. Overridable via AC_BASELINE_CHECK_INTERVAL (seconds) so
 * test.sh can exercise this on a live kernel without a real 60s wait. */
static int ac_baseline_check_interval(void)
{
    return ac_env_interval("AC_BASELINE_CHECK_INTERVAL", 60);
}

/* How often scan_protected_periodic() re-scans every protected process's
 * VMAs (RWX + anon-exec growth). Overridable via AC_SCAN_CHECK_INTERVAL
 * (seconds), mirroring ac_baseline_check_interval() above, so test.sh can
 * exercise two consecutive anon-exec scan cycles without a real 60s+
 * wait for the default 30s interval. */
static int ac_scan_check_interval(void)
{
    return ac_env_interval("AC_SCAN_CHECK_INTERVAL", 30);
}

static void ac_mkdir_baselines(void)
{
    const char *d = ac_baseline_dir();
    const char *slash = strrchr(d, '/');
    char parent[PATH_MAX];

    if (slash && slash != d) {
        snprintf(parent, sizeof(parent), "%.*s", (int)(slash - d), d);
        mkdir(parent, 0755);
    }
    mkdir(d, 0755);
}

static void baseline_path_for(const char *path, char out[PATH_MAX])
{
    char hex[65];

    ac_sha256_hex(path, strlen(path), hex);
    snprintf(out, PATH_MAX, "%s/%s.txt", ac_baseline_dir(), hex);
}

/* One baseline file per path (see baseline_path_for()) can hold multiple
 * records: a shared library with more than one executable PT_LOAD segment
 * maps as several distinct file-backed VMAs of the same path, each at its
 * own file offset. Keying/matching on (inode, offset) rather than path
 * alone -- and appending instead of truncating on --save -- keeps every
 * segment's baseline independent instead of the last --save silently
 * overwriting the others (#51). inode is redundant with the path hash in
 * the filename but is cheap to double check and free from path/rename
 * ambiguity within a single file's records. */
#define AC_BASELINE_MAX_RECORDS 256

struct ac_baseline_rec {
    unsigned long long inode;
    unsigned long long offset;
    unsigned long long size;
    char hex[65];
};

/* out_legacy (may be NULL) is set to 1 if a line failed the current
 * 4-field (inode, offset, size, hex) parse but matches the pre-#51
 * 3-field (start, size, hex) format -- i.e. a baseline saved by a daemon
 * build predating per-segment records. Those lines are otherwise
 * silently unreadable now (they carry no inode/offset to match against),
 * so callers use this to tell "never baselined" apart from "baselined by
 * an old daemon build, needs --save again" instead of reporting both
 * identically. NULL when the caller is about to overwrite the file
 * anyway (baseline_save_record()'s own reload below) since a legacy line
 * there just needs dropping, not reporting. */
static int baseline_load_records(const char *blpath, struct ac_baseline_rec *out,
                                  int *out_legacy)
{
    FILE *f = fopen(blpath, "r");
    char line[512];
    int n = 0;

    if (out_legacy)
        *out_legacy = 0;
    if (!f)
        return 0;
    while (n < AC_BASELINE_MAX_RECORDS && fgets(line, sizeof(line), f)) {
        struct ac_baseline_rec *r = &out[n];

        if (sscanf(line, "%llx %llx %llx %64s",
                   &r->inode, &r->offset, &r->size, r->hex) == 4) {
            n++;
            continue;
        }
        if (out_legacy) {
            unsigned long long a, b;
            char hex[65];

            if (sscanf(line, "%llx %llx %64s", &a, &b, hex) == 3)
                *out_legacy = 1;
        }
    }
    fclose(f);
    return n;
}

/* size must be the same capped hash length the caller is about to hash
 * (or already hashed) -- a mapping that keeps the same (inode, offset)
 * but changes size (e.g. a rebuilt library at the same install path,
 * loaded before its updated baseline was saved) would otherwise have its
 * *old* record matched by inode/offset alone and hashed over a different
 * byte range than what was saved, reporting a content-mismatch ALERT for
 * what is really just a stale/incompatible baseline.
 *
 * out_size_mismatch (may be NULL) is set to 1 on a "not found" return if
 * some record at this exact (inode, offset) exists but none of them match
 * `size` -- as opposed to no record at this (inode, offset) at all.
 * Without this, "never baselined" and "baselined, but for a size that no
 * longer matches (rebuilt/remapped since)" would be indistinguishable to
 * the caller, silently dropping integrity coverage after a rebuild
 * without ever telling the operator to re-run --save. */
static int baseline_find_record(const struct ac_baseline_rec *recs, int n,
                                 unsigned long long inode, unsigned long long offset,
                                 unsigned long long size, char hex_out[65],
                                 int *out_size_mismatch)
{
    int i;
    int saw_offset_match = 0;

    if (out_size_mismatch)
        *out_size_mismatch = 0;
    for (i = 0; i < n; i++) {
        if (recs[i].inode != inode || recs[i].offset != offset)
            continue;
        if (recs[i].size != size) {
            saw_offset_match = 1;  /* keep looking -- a same-(inode,offset)
                                     * different-sized segment's record is
                                     * not this segment's, just stale */
            continue;
        }
        snprintf(hex_out, 65, "%s", recs[i].hex);
        return 1;
    }
    if (out_size_mismatch)
        *out_size_mismatch = saw_offset_match;
    return 0;
}

/* baseline_save_record()'s "file already holds AC_BASELINE_MAX_RECORDS
 * *other* segments' records" case -- distinct from a plain I/O failure
 * (errno-bearing, return -1) so cmd_scan can tell the operator what
 * actually happened instead of a generic "cannot write baseline". */
#define AC_BASELINE_SAVE_FULL (-2)

/* Replaces this (inode, offset, size) segment's record in place, leaving
 * every other segment's record already saved for this path untouched --
 * including one at the same (inode, offset) but a different size, since
 * two distinct file-backed VMAs can legitimately share a starting file
 * offset while covering different lengths (e.g. the same region mapped
 * twice at different addresses).
 *
 * The whole read-modify-write is done under an flock() held on blpath
 * itself, and written out via a same-directory temp file + rename()
 * rather than truncating blpath in place: without the lock, two
 * concurrent `scan --hash --save` runs against the same path (e.g. two
 * segments of one library scanned back to back mid-race) could each
 * load the same old contents and have the second's rename silently
 * discard the first's new record; without the temp file, a write error
 * or a process killed mid-fprintf() loop leaves blpath truncated with
 * only some of the previously-valid records rewritten -- exactly the
 * kind of silent baseline-coverage loss this file exists to prevent
 * (#51). rename() within the same directory is atomic, so a reader
 * (baseline_load_records()) never observes a half-written file. */
static int baseline_save_record(const char *blpath, unsigned long long inode,
                                 unsigned long long offset, unsigned long long size,
                                 const char *hex)
{
    struct ac_baseline_rec recs[AC_BASELINE_MAX_RECORDS];
    char tmp_path[PATH_MAX];
    int i, kept = 0, n, lock_fd, tmp_fd, saved_errno;
    FILE *f;
    struct stat lst;

    /* Reject symlink baseline files: blpath is derived from SHA256(path)
     * under AC_BASELINE_DIR, which should never be a symlink. An attacker
     * with write access to the baseline dir could otherwise swap it for a
     * symlink to an arbitrary file and have the daemon overwrite it via the
     * save path. O_NOFOLLOW alone on the open below would give ELOOP,
     * but lstat lets us fail closed explicitly before flock. */
    if (lstat(blpath, &lst) == 0 && S_ISLNK(lst.st_mode)) {
        errno = ELOOP;
        return -1;
    }

    lock_fd = open(blpath, O_RDWR | O_CREAT | O_NOFOLLOW, 0644);
    if (lock_fd < 0)
        return -1;
    if (flock(lock_fd, LOCK_EX) < 0) {
        saved_errno = errno;
        close(lock_fd);
        errno = saved_errno;
        return -1;
    }

    n = baseline_load_records(blpath, recs, NULL);
    for (i = 0; i < n; i++)
        if (recs[i].inode != inode || recs[i].offset != offset ||
            recs[i].size != size)
            recs[kept++] = recs[i];

    if (kept == AC_BASELINE_MAX_RECORDS) {
        /* Every slot already belongs to some other segment of this same
         * path -- there's no room for this one without dropping one of
         * them. Fail loudly rather than quietly writing back the same
         * `kept` records and claiming success while this segment ends
         * up with no baseline at all. */
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return AC_BASELINE_SAVE_FULL;
    }

    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmpXXXXXX", blpath) >=
        (int)sizeof(tmp_path)) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    tmp_fd = mkstemp(tmp_path);
    if (tmp_fd < 0) {
        saved_errno = errno;
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        errno = saved_errno;
        return -1;
    }
    fchmod(tmp_fd, 0644);
    f = fdopen(tmp_fd, "w");
    if (!f) {
        saved_errno = errno;
        close(tmp_fd);
        unlink(tmp_path);
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        errno = saved_errno;
        return -1;
    }

    for (i = 0; i < kept; i++)
        fprintf(f, "%llx %llx %llx %s\n", recs[i].inode, recs[i].offset,
                recs[i].size, recs[i].hex);
    fprintf(f, "%llx %llx %llx %s\n", inode, offset, size, hex);

    if (fflush(f) != 0 || fsync(tmp_fd) != 0 || fclose(f) != 0) {
        saved_errno = errno;
        unlink(tmp_path);
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        errno = saved_errno;
        return -1;
    }
    if (rename(tmp_path, blpath) < 0) {
        saved_errno = errno;
        unlink(tmp_path);
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        errno = saved_errno;
        return -1;
    }

    flock(lock_fd, LOCK_UN);
    close(lock_fd);
    return 0;
}

/* ------------------------------------------------------------------ */
/* render-hook detection (frame-present-call inline-hook check)        */
/*                                                                      */
/* ESP/wallhack/aimbot overlays typically work by hooking the graphics */
/* API's frame-present call. On Linux this check targets three:        */
/* vkQueuePresentKHR in libvulkan.so covers native Vulkan games AND    */
/* Proton D3D9/10/11/12 titles, since DXVK/VKD3D-Proton translate D3D  */
/* down to Vulkan; glXSwapBuffers in libGL.so covers native OpenGL     */
/* games and older Proton titles still on wined3d's GL backend instead */
/* of DXVK; eglSwapBuffers in libEGL.so covers anything using EGL      */
/* instead of GLX to create its GL/GLES context, increasingly common   */
/* under Wayland and for GLES-based engines. A process only using one  */
/* or two of the three cleanly reports the rest as "not loaded", not   */
/* an error -- see check_render_hooks() below.                         */
/*                                                                      */
/* Detection needs no signature database: we read the exact same       */
/* on-disk file the target has mapped, parse out the target symbol's   */
/* file-relative offset and its first bytes there, and compare against */
/* the same bytes read from the target's memory at the equivalent      */
/* runtime address. A classic inline/trampoline hook (redirecting the  */
/* function to a jmp into injected code) changes those leading bytes;  */
/* a clean process matches byte-for-byte. The "known good" copy can't  */
/* go stale across distros or loader versions since it's whatever the  */
/* target itself is using, read fresh at check time.                   */
/*                                                                      */
/* Deliberately never dlopen()s that file: it's resolved through the   */
/* *target's own* mount namespace (see compare_render_symbol() below), */
/* which is not a trusted input -- a process can be set up so an       */
/* attacker controls what's mounted at the path the kernel reports for */
/* it. dlopen()ing an attacker-chosen file means running its           */
/* constructors (DT_INIT/.init_array) as root. The ELF section headers */
/* and symbol table are parsed directly with plain pread() instead --  */
/* pure data reads, no code from that file is ever executed.           */
/*                                                                      */
/* Known blind spot, documented rather than silently missed: a cheat   */
/* that hooks via LD_PRELOAD interposition or a malicious Vulkan layer */
/* (VK_LAYER_*) rather than patching vkQueuePresentKHR's bytes in      */
/* place is not caught by this check -- see README.                    */
/* ------------------------------------------------------------------ */
/* Fallback comparison length when the ELF symbol table doesn't carry a
 * usable st_size (0, or absurdly large -- that field is read from the
 * same attacker-influenceable file as everything else here, see the
 * mount-namespace block comment above, so it's bounded, never trusted
 * outright). AC_HOOK_CHECK_MIN_BYTES/MAX_BYTES clamp whatever st_size
 * *does* say to a sane range either way. */
#define AC_HOOK_CHECK_DEFAULT_BYTES 32
#define AC_HOOK_CHECK_MIN_BYTES 8
#define AC_HOOK_CHECK_MAX_BYTES 512
#define AC_ELF_MAX_SHNUM    2048           /* generous; real .so files have <100 */
#define AC_ELF_MAX_STRTAB   (4 * 1024 * 1024)
#define AC_ELF_MAX_SYMS     500000

/* Parses fd's ELF64 section headers to find `symbol` in .dynsym, using
 * only plain pread() -- never dlopen(), see the block comment above.
 * Returns 0 on success (fills *offset_out with the symbol's
 * file-relative offset, which for the ET_DYN shared libraries this
 * checks is the same value as its runtime offset from the load base,
 * and *size_out with its declared st_size, 0 if the symbol table
 * doesn't carry one), -1 on any parse/read/bounds failure. Every
 * failure is inconclusive, never a positive detection -- a malformed or
 * unexpected-shape ELF file is a skip, same as an unreadable one.
 * x86-64 only (ELFCLASS64 / little-endian), matching the rest of this
 * project's scope. */
static int elf_find_symbol_offset(int fd, const char *symbol, uint64_t *offset_out,
                                   uint64_t *size_out)
{
    Elf64_Ehdr eh;
    Elf64_Shdr *shdrs = NULL;
    char *shstrtab = NULL;
    Elf64_Sym *syms = NULL;
    char *dynstrtab = NULL;
    Elf64_Shdr *dynsym = NULL, *dynstr = NULL;
    unsigned int i, nsyms;
    int ret = -1;

    if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh))
        return -1;
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0)
        return -1;
    if (eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_ident[EI_DATA] != ELFDATA2LSB)
        return -1;
    if (eh.e_shentsize != sizeof(Elf64_Shdr) || eh.e_shnum == 0 ||
        eh.e_shnum > AC_ELF_MAX_SHNUM || eh.e_shstrndx >= eh.e_shnum)
        return -1;

    shdrs = malloc((size_t)eh.e_shnum * sizeof(Elf64_Shdr));
    if (!shdrs)
        return -1;
    if (pread(fd, shdrs, (size_t)eh.e_shnum * sizeof(Elf64_Shdr),
              (off_t)eh.e_shoff) != (ssize_t)((size_t)eh.e_shnum * sizeof(Elf64_Shdr)))
        goto out;

    {
        Elf64_Shdr *shstr = &shdrs[eh.e_shstrndx];

        if (shstr->sh_size == 0 || shstr->sh_size > AC_ELF_MAX_STRTAB)
            goto out;
        shstrtab = malloc(shstr->sh_size);
        if (!shstrtab)
            goto out;
        if (pread(fd, shstrtab, shstr->sh_size, (off_t)shstr->sh_offset) !=
            (ssize_t)shstr->sh_size)
            goto out;

        for (i = 0; i < eh.e_shnum; i++) {
            const char *name;

            if (shdrs[i].sh_name >= shstr->sh_size)
                continue;
            name = shstrtab + shdrs[i].sh_name;
            if (shdrs[i].sh_type == SHT_DYNSYM && strcmp(name, ".dynsym") == 0)
                dynsym = &shdrs[i];
            else if (shdrs[i].sh_type == SHT_STRTAB && strcmp(name, ".dynstr") == 0)
                dynstr = &shdrs[i];
        }
    }
    if (!dynsym || !dynstr || dynsym->sh_entsize != sizeof(Elf64_Sym) ||
        dynstr->sh_size == 0 || dynstr->sh_size > AC_ELF_MAX_STRTAB)
        goto out;

    nsyms = (unsigned int)(dynsym->sh_size / sizeof(Elf64_Sym));
    if (nsyms == 0 || nsyms > AC_ELF_MAX_SYMS)
        goto out;

    syms = malloc(dynsym->sh_size);
    dynstrtab = malloc(dynstr->sh_size);
    if (!syms || !dynstrtab)
        goto out;
    if (pread(fd, syms, dynsym->sh_size, (off_t)dynsym->sh_offset) !=
        (ssize_t)dynsym->sh_size)
        goto out;
    if (pread(fd, dynstrtab, dynstr->sh_size, (off_t)dynstr->sh_offset) !=
        (ssize_t)dynstr->sh_size)
        goto out;

    for (i = 0; i < nsyms; i++) {
        if (syms[i].st_name == 0 || syms[i].st_name >= dynstr->sh_size ||
            syms[i].st_value == 0)
            continue;
        if (strcmp(dynstrtab + syms[i].st_name, symbol) == 0) {
            *offset_out = syms[i].st_value;
            *size_out = syms[i].st_size;
            ret = 0;
            break;
        }
    }

out:
    free(shdrs);
    free(shstrtab);
    free(syms);
    free(dynstrtab);
    return ret;
}

/* Reads `symbol` from libpath (resolved via the target's own
 * /proc/<pid>/root/ -- see below) and compares against the same offset
 * in the target pid's live memory (lib_base = that mapping's lowest VMA
 * start, i.e. its file-offset-0 load address). Compares the symbol's
 * *entire* declared length (its ELF st_size, clamped to
 * [AC_HOOK_CHECK_MIN_BYTES, AC_HOOK_CHECK_MAX_BYTES], or
 * AC_HOOK_CHECK_DEFAULT_BYTES if the symbol table has no usable size for
 * it) rather than a fixed guess -- a "detour"-style hook patching
 * further into the function body than a small fixed window would still
 * be inside the function's own real bytes, and would still be caught.
 * Empirically, real present-call functions are tiny (glXSwapBuffers is
 * 17 bytes on a real system, smaller than the old fixed 32-byte
 * window -- meaning that window used to read a few bytes *past* the
 * real function into whatever follows it, which this also fixes).
 * Returns 1 if hooked, 0 if clean, -1 if inconclusive (never treated as
 * a positive detection -- an unreadable/unparseable library is a skip,
 * not an alert). Silent by design -- callers decide how (or whether) to
 * surface the result, since the CLI's one-shot `scan --check-hooks` and
 * the daemon's silent-unless-hooked periodic check want very different
 * presentation of the same underlying check. */
static int compare_render_symbol(int pid, const char *libpath,
                                  unsigned long long lib_base,
                                  const char *symbol)
{
    unsigned char expected[AC_HOOK_CHECK_MAX_BYTES];
    unsigned char actual[AC_HOOK_CHECK_MAX_BYTES];
    char memp[64];
    char nspath[AC_VMA_PATH + 32];
    uint64_t offset, size;
    size_t checklen;
    int fd;
    ssize_t r;

    /* TOCTOU: pid may have been reused between SCAN_BEGIN and this check.
     * Verify it still exists before opening control files. kill(pid,0)
     * is the cheapest liveness probe; ESRCH means the pid is gone. */
    if (kill(pid, 0) < 0 && errno == ESRCH)
        return -1;

    /* libpath came from the kernel's d_path() on the target's VMA, which
     * is just a string -- opening it directly from the daemon's own
     * mount namespace trusts that whatever exists at that path here is
     * the same file the target actually has mapped. For a process in a
     * container/sandbox with a private bind-mount at that path, it can
     * be a different file entirely (or nothing), and reading it as the
     * reference would compare against the wrong bytes. Going through
     * /proc/<pid>/root/ instead resolves the path exactly as the target
     * process itself sees it -- for the common case of a target sharing
     * the daemon's own namespace, /proc/<pid>/root is just "/", so this
     * is a strict correctness fix with no downside there. Verified
     * empirically (not assumed): a plain path collides with an unrelated
     * host-side file across a private bind mount and silently returns
     * the wrong content, while /proc/<pid>/root/<path> resolves to the
     * real target-visible file, as root, via ordinary open()+read() --
     * no setns() or any persistent namespace switch needed. */
    snprintf(nspath, sizeof(nspath), "/proc/%d/root%s", pid, libpath);

    fd = open(nspath, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (elf_find_symbol_offset(fd, symbol, &offset, &size) != 0) {
        close(fd);
        return -1;
    }
    if (size == 0)
        checklen = AC_HOOK_CHECK_DEFAULT_BYTES;
    else if (size < AC_HOOK_CHECK_MIN_BYTES)
        checklen = AC_HOOK_CHECK_MIN_BYTES;
    else if (size > AC_HOOK_CHECK_MAX_BYTES)
        checklen = AC_HOOK_CHECK_MAX_BYTES;
    else
        checklen = (size_t)size;

    r = pread(fd, expected, checklen, (off_t)offset);
    close(fd);
    if (r != (ssize_t)checklen)
        return -1;

    snprintf(memp, sizeof(memp), "/proc/%d/mem", pid);
    fd = open(memp, O_RDONLY);
    if (fd < 0)
        return -1;
    r = pread(fd, actual, checklen, (off_t)(lib_base + offset));
    close(fd);
    if (r != (ssize_t)checklen)
        return -1;

    return memcmp(expected, actual, checklen) != 0 ? 1 : 0;
}

/* Every rendering API a Linux game is realistically using -- native
 * Vulkan (and Proton D3D9/10/11/12 via DXVK/VKD3D, which translate down
 * to Vulkan too) via vkQueuePresentKHR; native OpenGL or older Proton
 * titles still on wined3d's GL backend via glXSwapBuffers; and anything
 * using EGL instead of GLX to create its GL/GLES context (increasingly
 * common under Wayland, and for GLES-based engines) via eglSwapBuffers.
 * Single source of truth for both check_render_hooks() and its periodic
 * counterpart below, so the two can't drift on which APIs/symbols they
 * check. */
static const struct {
    const char *lib_prefix;
    const char *symbol;
    const char *label;
} AC_RENDER_APIS[] = {
    { "libvulkan.so", "vkQueuePresentKHR", "Vulkan" },
    { "libGL.so",     "glXSwapBuffers",    "GLX/OpenGL" },
    { "libEGL.so",    "eglSwapBuffers",    "EGL" },
};
#define AC_RENDER_APIS_COUNT \
    (sizeof(AC_RENDER_APIS) / sizeof(AC_RENDER_APIS[0]))

struct ac_lib_result {
    int found;                    /* 1 = located, 0 = not loaded */
    unsigned long long lib_base;
    char libpath[AC_VMA_PATH];
};

/* Single streaming pass over the target's VMAs that locates the load
 * base of every AC_RENDER_APIS[] library at once -- one
 * SCAN_BEGIN/SCAN_GET/SCAN_END cycle for all n prefixes instead of one
 * per prefix, without collecting the (potentially thousands-of-entries)
 * VMA list into memory -- same "don't build a big buffer you don't
 * need" discipline as the rest of this file. results[] must have n
 * entries, index-aligned with prefixes[]/prefix_lens[]. Returns 0 on
 * success (each results[k].found reports whether that prefix matched
 * anything), -1 on ioctl failure. */
static int find_libs_by_basenames(int pid, const char *const *prefixes,
                                   const size_t *prefix_lens, unsigned int n,
                                   struct ac_lib_result *results)
{
    struct ac_scan_begin b;
    unsigned int v, k;

    for (k = 0; k < n; k++) {
        results[k].found = 0;
        results[k].lib_base = 0;
        results[k].libpath[0] = '\0';
    }

    memset(&b, 0, sizeof(b));
    b.pid = pid;
    b.emit_events = 0;
    if (ioctl(dev_fd, AC_IOCTL_SCAN_BEGIN, &b) < 0)
        return -1;
    for (v = 0; v < b.n_vmas; v++) {
        struct ac_scan_get g;
        struct ac_vma_info *vi;
        const char *base;

        memset(&g, 0, sizeof(g));
        g.pid = pid;
        g.index = v;
        if (ioctl(dev_fd, AC_IOCTL_SCAN_GET, &g) < 0)
            break;
        vi = &g.vma;
        if (!vi->is_file || !vi->path[0])
            continue;
        base = strrchr(vi->path, '/');
        base = base ? base + 1 : vi->path;
        for (k = 0; k < n; k++) {
            if (strncmp(base, prefixes[k], prefix_lens[k]) != 0)
                continue;
            if (!results[k].found || vi->start < results[k].lib_base) {
                results[k].lib_base = vi->start;
                snprintf(results[k].libpath, sizeof(results[k].libpath),
                         "%s", vi->path);
                results[k].found = 1;
            }
        }
    }
    (void)ioctl(dev_fd, AC_IOCTL_SCAN_END, NULL); /* END only frees snapshot; failure is non-fatal */
    return 0;
}

/* render_hook_statuses_for(): the single source of truth both the
 * one-shot CLI check and the periodic daemon check build on -- locates
 * every AC_RENDER_APIS[] library in one VMA pass via
 * find_libs_by_basenames(), then compares each one that's actually
 * loaded against a freshly-loaded reference copy. statuses[] must have
 * AC_RENDER_APIS_COUNT entries. Each status is -2 (that library not
 * loaded in this process -- not an error, most processes only use one
 * rendering API), -1 (inconclusive), 0 (clean), or 1 (hooked); libpaths[]
 * (same length, each AC_VMA_PATH bytes) is filled on any non-(-2)
 * status. */
static void render_hook_statuses_for(int pid, int *statuses,
                                      char libpaths[][AC_VMA_PATH])
{
    struct ac_lib_result results[AC_RENDER_APIS_COUNT];
    const char *prefixes[AC_RENDER_APIS_COUNT];
    size_t prefix_lens[AC_RENDER_APIS_COUNT];
    unsigned int k;
    int rc;

    for (k = 0; k < AC_RENDER_APIS_COUNT; k++) {
        prefixes[k] = AC_RENDER_APIS[k].lib_prefix;
        prefix_lens[k] = strlen(AC_RENDER_APIS[k].lib_prefix);
    }
    rc = find_libs_by_basenames(pid, prefixes, prefix_lens,
                                 AC_RENDER_APIS_COUNT, results);
    for (k = 0; k < AC_RENDER_APIS_COUNT; k++) {
        libpaths[k][0] = '\0';
        if (rc < 0) {
            statuses[k] = -1;
        } else if (!results[k].found) {
            statuses[k] = -2;
        } else {
            snprintf(libpaths[k], AC_VMA_PATH, "%s", results[k].libpath);
            statuses[k] = compare_render_symbol(pid, results[k].libpath,
                                                 results[k].lib_base,
                                                 AC_RENDER_APIS[k].symbol);
        }
    }
}

/* Shared presentation for one (api, symbol) check's result -- used by
 * both check_render_hooks() below (each call prints its own line) so
 * the Vulkan and GLX/OpenGL checks don't duplicate this switch twice.
 * Returns 1 if hooked (so the caller can track "any hook found"), 0
 * otherwise (clean, skipped, or inconclusive -- none of those are a
 * positive detection). */
static int print_render_hook_result(int pid, const char *api_label,
                                     const char *symbol, const char *libpath,
                                     int status)
{
    switch (status) {
    case -2:
        printf("  render-hook check (%s): not loaded in this process, skipping\n",
               api_label);
        return 0;
    case -1:
        printf("  render-hook check (%s): could not verify %s in %s, skipping\n",
               api_label, symbol, libpath);
        return 0;
    case 1:
        printf("  [!] render hook (%s): %s in %s (target pid %d) differs\n"
               "      from a freshly-loaded reference copy of the same file --\n"
               "      possible ESP/overlay/render hijack\n",
               api_label, symbol, libpath, pid);
        return 1;
    default:
        printf("  render-hook check (%s): %s clean (%s)\n", api_label, symbol, libpath);
        return 0;
    }
}

/* CLI-facing wrapper for `scan --check-hooks`. A process only using one
 * or two of the APIs above cleanly reports the rest as "not loaded", not
 * an error. */
static int check_render_hooks(int pid)
{
    int statuses[AC_RENDER_APIS_COUNT];
    char libpaths[AC_RENDER_APIS_COUNT][AC_VMA_PATH];
    int hooked = 0;
    unsigned int i;

    render_hook_statuses_for(pid, statuses, libpaths);
    for (i = 0; i < AC_RENDER_APIS_COUNT; i++) {
        if (print_render_hook_result(pid, AC_RENDER_APIS[i].label,
                                      AC_RENDER_APIS[i].symbol,
                                      libpaths[i], statuses[i]))
            hooked = 1;
    }

    return hooked;
}

/* Periodic daemon-loop counterpart: silent unless a hook is actually
 * found (matching anon_baseline_check()/check_baselines_periodic()'s
 * style -- a clean or skipped check every cycle for every protected
 * process would be log noise, not signal). A detection here flows
 * through logmsg() at LOG_CRIT, which -- via the ban-pipeline reporting
 * hook in logmsg() -- also reports it if AC_REPORT_URL is configured,
 * with no separate wiring needed. */
static void check_render_hooks_periodic(void)
{
    struct ac_prot_list pl;
    unsigned int i, j;

    memset(&pl, 0, sizeof(pl));
    if (ioctl(dev_fd, AC_IOCTL_LIST_PROTECTED, &pl) < 0)
        return;
    for (i = 0; i < pl.count; i++) {
        int statuses[AC_RENDER_APIS_COUNT];
        char libpaths[AC_RENDER_APIS_COUNT][AC_VMA_PATH];

        render_hook_statuses_for(pl.items[i].pid, statuses, libpaths);
        for (j = 0; j < AC_RENDER_APIS_COUNT; j++) {
            if (statuses[j] == 1)
                logmsg(LOG_CRIT, "pid %d (%s): render hook detected in %s "
                       "(%s differs from a freshly-loaded reference copy -- "
                       "possible ESP/overlay/render hijack)",
                       pl.items[i].pid, pl.items[i].comm, libpaths[j],
                       AC_RENDER_APIS[j].symbol);
        }
    }
}

/* Overridable the same way AC_BASELINE_CHECK_INTERVAL is, so test.sh can
 * exercise this on a live kernel without a long real wait. Longer default
 * than the other periodic checks: each protected process with Vulkan
 * and/or GL loaded costs an ELF section-header/symbol-table parse of
 * each library it has, not just a cheap ioctl. */
static int ac_render_hook_check_interval(void)
{
    return ac_env_interval("AC_RENDER_HOOK_CHECK_INTERVAL", 30);
}

/* Full implementations are defined later, alongside the periodic
 * environment-based checks; forward declared here (plus the struct/data
 * the CLI wrappers below need at compile time) so cmd_scan doesn't need
 * that whole section moved above this one. */
#define AC_ENVIRON_VAL_LEN 512

struct ac_environ_query {
    const char *name;                    /* variable name, no '=' */
    char value[AC_ENVIRON_VAL_LEN];       /* out */
    int found;                            /* out */
};

static int ac_read_environ_vars(int pid, struct ac_environ_query *vars,
                                 unsigned int nvars);
static int ac_read_ld_preload(int pid, char *out, size_t outsz);

static const char *const AC_VK_LAYER_ENV_VARS[] = {
    "VK_INSTANCE_LAYERS",
    "VK_LOADER_LAYERS_ENABLE",
    "VK_LAYER_PATH",
    "VK_ADD_LAYER_PATH",
};
#define AC_VK_LAYER_ENV_VARS_COUNT \
    (sizeof(AC_VK_LAYER_ENV_VARS) / sizeof(AC_VK_LAYER_ENV_VARS[0]))

/* CLI-facing wrapper for `scan --check-preload`. */
static int check_ld_preload(int pid)
{
    char val[512];
    int rc = ac_read_ld_preload(pid, val, sizeof(val));

    if (rc < 0) {
        printf("  LD_PRELOAD check: could not read /proc/%d/environ (%s)\n",
               pid, strerror(errno));
        return -1;
    }
    if (rc == 0) {
        printf("  LD_PRELOAD check: not set\n");
        return 0;
    }
    printf("  LD_PRELOAD check: %s\n"
           "    (informational only -- also used by legitimate overlay/compat\n"
           "     tools like MangoHud, gamemode, gamescope; not a verdict)\n",
           val);
    return 1;
}

/* CLI-facing wrapper for `scan --check-vklayers`. Checks every candidate
 * variable in one /proc/<pid>/environ pass (see ac_read_environ_vars()). */
static int check_vk_layer_env(int pid)
{
    struct ac_environ_query vars[AC_VK_LAYER_ENV_VARS_COUNT];
    unsigned int i;
    int rc, found_any = 0;

    for (i = 0; i < AC_VK_LAYER_ENV_VARS_COUNT; i++) {
        memset(&vars[i], 0, sizeof(vars[i]));
        vars[i].name = AC_VK_LAYER_ENV_VARS[i];
    }
    rc = ac_read_environ_vars(pid, vars, AC_VK_LAYER_ENV_VARS_COUNT);
    if (rc < 0) {
        printf("  Vulkan-layer check: could not fully read /proc/%d/environ (%s)\n",
               pid, strerror(errno));
        return -1;
    }
    for (i = 0; i < AC_VK_LAYER_ENV_VARS_COUNT; i++) {
        if (!vars[i].found)
            continue;
        printf("  Vulkan-layer check: %s=%s\n", vars[i].name, vars[i].value);
        found_any = 1;
    }
    if (!found_any) {
        printf("  Vulkan-layer check: no layer-activation environment variables set\n");
        return 0;
    }
    printf("    (informational only -- also used by legitimate overlay tools\n"
           "     like MangoHud; not a verdict. An implicit layer manifest\n"
           "     dropped into the loader's default search directories needs\n"
           "     no environment variable and is not detected by this check --\n"
           "     see --check-implicit-layers for that)\n");
    return 1;
}

/* Defined later, alongside its own data structures; forward declared so
 * cmd_scan doesn't need that whole section moved above this one. */
static int check_implicit_layers(int pid);

static int cmd_scan(int argc, char **argv)
{
    struct ac_scan_begin b;
    int pid = -1, ref_pid = -1, host_pid, i;
    int do_hash = 0, do_save = 0, do_check = 0, do_hooks = 0, do_preload = 0;
    int do_vklayers = 0, do_implicit = 0;
    char exe[PATH_MAX] = "";
    char *exe_link;
    unsigned int v;
    int mem_fd = -1;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0) {
            if (i + 1 >= argc)
                die("usage: --pid requires a value");
            pid = ac_parse_pid(argv[++i], "--pid");
        } else if (strcmp(argv[i], "--ns-of") == 0) {
            if (i + 1 >= argc)
                die("usage: --ns-of requires a value");
            ref_pid = ac_parse_pid(argv[++i], "--ns-of");
        } else if (strcmp(argv[i], "--hash") == 0)
            do_hash = 1;
        else if (strcmp(argv[i], "--save") == 0)
            do_save = 1;
        else if (strcmp(argv[i], "--check") == 0)
            do_check = 1;
        else if (strcmp(argv[i], "--check-hooks") == 0)
            do_hooks = 1;
        else if (strcmp(argv[i], "--check-preload") == 0)
            do_preload = 1;
        else if (strcmp(argv[i], "--check-vklayers") == 0)
            do_vklayers = 1;
        else if (strcmp(argv[i], "--check-implicit-layers") == 0)
            do_implicit = 1;
    }
    if (pid < 0)
        die("usage: anticheat scan --pid N [--ns-of REFPID] [--hash [--save|--check]] "
            "[--check-hooks] [--check-preload] [--check-vklayers] "
            "[--check-implicit-layers]");

    ac_open();
    memset(&b, 0, sizeof(b));
    b.pid = pid;
    b.ref_pid = ref_pid;
    b.emit_events = 1;
    if (ioctl_ok(AC_IOCTL_SCAN_BEGIN, &b) < 0)
        return 1;

    /* b.resolved_pid, not `pid`, for every /proc/<pid>/... access below:
     * with --ns-of, `pid` is namespace-relative and doesn't name anything
     * in the daemon's (host) /proc at all. Equal to `pid` when --ns-of
     * wasn't given. */
    host_pid = b.resolved_pid;

    printf("scan of pid %d: %u VMA(s), %u executable, %u RWX, %u anon-exec\n",
           pid, b.n_vmas, b.exec_count, b.rwx_count, b.anon_exec_count);
    if (b.anon_exec_count)
        printf("  (anon-exec = executable with no backing file; vdso/vvar are\n"
               "   expected here -- treat a *growing* count across repeated\n"
               "   scans as the signal, not the raw number)\n");
    if (b.truncated)
        printf("  (VMA snapshot truncated at %u entries)\n", AC_MAX_VMAS);

    if (do_hash) {
        char mem_path[64];

        exe_link = proc_exe_path(host_pid);
        if (exe_link)
            snprintf(exe, sizeof(exe), "%s", exe_link);

        /* Opened once here rather than once per VMA inside the loop
         * below: a process can have many executable file-backed VMAs,
         * and they all read through the same /proc/<pid>/mem fd. */
        snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", host_pid);
        mem_fd = open(mem_path, O_RDONLY);
        if (mem_fd < 0)
            fprintf(stderr, "cannot open %s: %s\n", mem_path, strerror(errno));
    }

    /* Single pass over the VMA snapshot: the default print/RWX/anon-exec
     * report and the --hash walk both need "every executable, file-backed
     * VMA", so branch into hash/save/check handling from the same loop
     * instead of re-running AC_IOCTL_SCAN_BEGIN/GET/END a second time to
     * re-walk VMAs already fetched above. */
    for (v = 0; v < b.n_vmas; v++) {
        struct ac_scan_get g;
        struct ac_vma_info *vi;

        memset(&g, 0, sizeof(g));
        g.pid = pid;
        g.index = v;
        if (ioctl(dev_fd, AC_IOCTL_SCAN_GET, &g) < 0)
            break;
        vi = &g.vma;

        if ((vi->flags & AC_VM_EXEC) && (vi->flags & AC_VM_WRITE))
            printf("  [!] RWX [%#llx-%#llx] %s\n",
                   vi->start, vi->end, vi->path[0] ? vi->path : "(anonymous)");
        else if ((vi->flags & AC_VM_EXEC) && !vi->is_file)
            printf("  [?] anon-exec [%#llx-%#llx]\n", vi->start, vi->end);
        else if ((vi->flags & AC_VM_EXEC) && g_verbose)
            printf("  exec [%#llx-%#llx] %s\n",
                   vi->start, vi->end, vi->path[0] ? vi->path : "(anonymous)");

        if (do_hash && (vi->flags & AC_VM_EXEC) && vi->is_file) {
            char hex[65], blpath[PATH_MAX];
            uint64_t size;

            size = vi->end - vi->start;
            if (size > AC_HASH_CAP)
                size = AC_HASH_CAP;
            if (mem_fd < 0 || hash_proc_mem(mem_fd, vi->start, size, hex) < 0) {
                printf("  hash failed for %s\n", vi->path);
                continue;
            }
            baseline_path_for(vi->path, blpath);
            printf("  %s [%#llx..%#llx] (offset %#llx) %s\n",
                   vi->path, vi->start, vi->start + size, vi->offset, hex);

            if (do_save) {
                int rc;

                ac_mkdir_baselines();
                rc = baseline_save_record(blpath, vi->inode, vi->offset,
                                           size, hex);
                if (rc == AC_BASELINE_SAVE_FULL)
                    fprintf(stderr, "cannot save baseline for %s: %s already"
                            " holds the maximum %d segment records\n",
                            vi->path, blpath, AC_BASELINE_MAX_RECORDS);
                else if (rc < 0)
                    fprintf(stderr, "cannot write baseline %s: %s\n",
                            blpath, strerror(errno));
                else
                    printf("    baseline saved: %s\n", blpath);
            }
            if (do_check) {
                struct ac_baseline_rec recs[AC_BASELINE_MAX_RECORDS];
                char bhex[65];
                int legacy = 0, size_mismatch = 0;
                int n = baseline_load_records(blpath, recs, &legacy);

                if (!baseline_find_record(recs, n, vi->inode, vi->offset, size,
                                           bhex, &size_mismatch)) {
                    if (legacy)
                        printf("    legacy-format baseline for %s"
                               " -- re-run --save to regenerate\n", vi->path);
                    else if (size_mismatch)
                        printf("    baseline for %s at offset %#llx was saved"
                               " for a different mapping size (rebuilt or"
                               " remapped?) -- re-run --save\n",
                               vi->path, vi->offset);
                    else
                        printf("    no baseline for %s at offset %#llx"
                               " (run with --save first)\n", vi->path, vi->offset);
                    continue;
                }
                if (strcmp(bhex, hex) != 0)
                    printf("    [ALERT] memory content differs from baseline"
                           " (possible runtime patching)\n");
                else
                    printf("    ok: matches baseline\n");
            }
        }
    }
    (void)ioctl(dev_fd, AC_IOCTL_SCAN_END, NULL); /* END only frees snapshot; failure is non-fatal */
    if (mem_fd >= 0)
        close(mem_fd);

    if (do_hooks)
        check_render_hooks(host_pid);

    if (do_preload)
        check_ld_preload(host_pid);

    if (do_vklayers)
        check_vk_layer_env(host_pid);

    if (do_implicit)
        check_implicit_layers(host_pid);

    ac_close();
    return 0;
}

/* ------------------------------------------------------------------ */
/* command: syscalls                                                   */
/* ------------------------------------------------------------------ */
static int cmd_syscalls(void)
{
    struct ac_syscall_check c;

    ac_open();
    memset(&c, 0, sizeof(c));
    if (ioctl(dev_fd, AC_IOCTL_CHECK_SYSCALLS, &c) < 0) {
        if (errno == ENODEV)
            fprintf(stderr, "syscall table was not located at module load;"
                    " integrity check unavailable\n");
        else
            fprintf(stderr, "ioctl %#lx failed: %s\n", AC_IOCTL_CHECK_SYSCALLS,
                    strerror(errno));
        return 1;
    }
    printf("syscall table @ %#llx\n", c.table_addr);
    printf("  entries examined : %u\n", c.nr_syscalls);
    printf("  non-NULL entries : %u\n", c.total);
    printf("  hooked           : %u\n", c.hooked);
    if (c.baseline_ready) {
        printf("  boot baseline    : %s\n", c.baseline_sha256);
        printf("  current checksum : %s%s\n", c.current_sha256,
               c.checksum_mismatch ? " (MISMATCH)" : "");
        printf("  redirected       : %u (in-text handler swap since boot)\n",
               c.redirected);
    } else {
        printf("  boot baseline    : unavailable (syscall table not located at load)\n");
    }
    if (c.ok && c.redirected == 0 && !c.checksum_mismatch)
        printf("  result           : OK — no hooks detected\n");
    else {
        if (!c.ok)
            printf("  result           : COMPROMISED — syscall hooks present!\n");
        if (c.redirected)
            printf("  result           : COMPROMISED — in-text syscall redirect(s) present!\n");
        if (c.checksum_mismatch && c.ok && c.redirected == 0)
            printf("  result           : COMPROMISED — syscall checksum mismatch"
                   " (handler churn not caught by per-slot checks)!\n");
        return 2;
    }
    ac_close();
    return 0;
}

/* ------------------------------------------------------------------ */
/* command: modules                                                    */
/* ------------------------------------------------------------------ */
/* Shared /proc/modules cross-check for the `modules` command and the
 * periodic monitor.  The name table is static (256 KiB): the daemon is
 * single-threaded, and a stack array that large is fragile under small
 * ulimit -s / LimitSTACK=.  Returns the hidden-module count, or -1 if the
 * kernel-side module list could not be read. */
#define AC_MAX_PROC_MODS 4096
static char proc_names[AC_MAX_PROC_MODS][AC_MOD_NAME_LEN];

static unsigned int collect_proc_modules(unsigned int cap)
{
    FILE *f = fopen("/proc/modules", "r");
    char line[256];
    unsigned int n = 0;

    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f) && n < cap) {
        if (sscanf(line, "%63s", proc_names[n]) == 1)
            n++;
    }
    fclose(f);
    return n;
}

static long crosscheck_modules(int verbose)
{
    unsigned int count, i, hidden = 0, proc_count;

    if (ioctl(dev_fd, AC_IOCTL_MODS_BEGIN, &count) < 0)
        return -1;
    proc_count = collect_proc_modules(AC_MAX_PROC_MODS);
    if (verbose)
        printf("%u modules in kernel list:\n", count);
    for (i = 0; i < count; i++) {
        struct ac_mod_get g;
        unsigned int j;
        int visible = 0;

        memset(&g, 0, sizeof(g));
        g.index = i;
        if (ioctl(dev_fd, AC_IOCTL_MODS_GET, &g) < 0)
            break;
        for (j = 0; j < proc_count; j++) {
            if (strcmp(proc_names[j], g.mod.name) == 0) {
                visible = 1;
                break;
            }
        }
        if (verbose)
            printf("  %-20s size=%-10llu state=%u %s\n",
                   g.mod.name, g.mod.size, g.mod.state,
                   visible ? "" : "[HIDDEN FROM /proc/modules!]");
        if (!visible)
            hidden++;
    }
    (void)ioctl(dev_fd, AC_IOCTL_MODS_END, NULL); /* END only frees snapshot; failure is non-fatal */
    if (verbose)
        printf("hidden modules: %u\n", hidden);
    return hidden;
}

static int cmd_modules(void)
{
    long hidden;

    ac_open();
    hidden = crosscheck_modules(1);
    ac_close();
    if (hidden < 0)
        return 1;
    return hidden ? 2 : 0;
}

/* ------------------------------------------------------------------ */
/* command: vmcheck                                                    */
/* ------------------------------------------------------------------ */
/* Two independent, purely-userspace signals that the OS itself (not any
 * specific process) is running inside a virtual machine. Neither needs
 * the kernel module or any elevated privilege: CPUID and
 * /sys/class/dmi/id/ files both already return the real, authoritative
 * hardware/firmware answer to any process on the machine, so routing
 * this through anticheat_module.c would add ioctl surface for no
 * security benefit -- same reasoning as the LD_PRELOAD/Vulkan-layer
 * checks above, which are also pure userspace reads.
 *
 * Heuristic like those checks too: running in a VM is completely normal
 * for plenty of legitimate reasons (cloud gaming, CI, testing,
 * GPU-passthrough streaming rigs), so this is never wired into the ban
 * pipeline -- see cmd_start()'s call site, which logs at
 * LOG_WARNING/LOG_INFO, never LOG_ALERT/LOG_CRIT.
 *
 * Known, unavoidable limitation: a hypervisor can be explicitly
 * configured to hide the CPUID leaf below (VMware's
 * "hypervisor.cpuid.v0 = FALSE", VirtualBox's equivalent, KVM/QEMU CPUID
 * masking) and to override the DMI strings below (QEMU's -smbios flag).
 * That defeats both checks here -- a property of the technique itself,
 * not a bug to fix (see THREAT_MODEL.md's "Explicitly out of scope").
 */

/* CPUID leaf 1, ECX bit 31: the standard "running under a hypervisor"
 * signal essentially every hypervisor sets by default. __cpuid() (not
 * the leaf-range-checked __get_cpuid()) is used deliberately -- leaf
 * 0x40000000 below is a hypervisor-reserved leaf, not a standard one,
 * and __get_cpuid() would refuse to read past whatever leaf 0 reports
 * as the max standard leaf. Returns 1 if the bit is set (and fills
 * vendor_out with the 12-char vendor ID string from leaf 0x40000000,
 * only architecturally defined once the presence bit is set), 0
 * otherwise. x86-64 only, matching this project's stated scope. */
static int detect_hypervisor_cpuid(char *vendor_out, size_t outsz)
{
    unsigned int eax, ebx, ecx, edx;

    if (vendor_out && outsz)
        vendor_out[0] = '\0';

    __cpuid(1, eax, ebx, ecx, edx);
    if (!(ecx & (1u << 31)))
        return 0;

    /* "KVMKVMKVM\0\0\0", "VMwareVMware", "VBoxVBoxVBox", "Microsoft Hv",
     * "XenVMMXenVMM", "TCGTCGTCGTCG" (QEMU's own software CPU
     * emulation, distinct from KVM-accelerated QEMU), "prl hyperv  "
     * (Parallels), "bhyve bhyve " are the known real-world values. */
    if (vendor_out && outsz >= 13) {
        __cpuid(0x40000000, eax, ebx, ecx, edx);
        memcpy(vendor_out + 0, &ebx, 4);
        memcpy(vendor_out + 4, &ecx, 4);
        memcpy(vendor_out + 8, &edx, 4);
        vendor_out[12] = '\0';
    }
    return 1;
}

static int read_dmi_field(const char *name, char *out, size_t outsz)
{
    char path[64];
    FILE *f;
    size_t n;

    out[0] = '\0';
    snprintf(path, sizeof(path), "/sys/class/dmi/id/%s", name);
    f = fopen(path, "r");
    if (!f)
        return -1;
    if (!fgets(out, (int)outsz, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';
    return 0;
}

/* Corroborating signal, not authoritative on its own: catches a
 * hypervisor that masks the CPUID leaf above but leaves default
 * BIOS/DMI strings in place. sys_vendor/product_name/board_vendor are
 * typically world-readable (unlike product_uuid/serial_number, which
 * are root-only and deliberately not read here -- nothing here needs
 * them); a permission or read failure just leaves that field empty
 * rather than failing the whole check. "Microsoft Corporation" is
 * matched only in combination with product_name containing "Virtual
 * Machine" (Hyper-V's actual value), not on sys_vendor alone -- real
 * Microsoft Surface hardware also reports sys_vendor=Microsoft
 * Corporation and would otherwise be a false positive. Returns 1 (and
 * fills `out` with which vendor/field matched) if any known VM
 * signature is found, 0 otherwise. */
static int detect_hypervisor_dmi(char *out, size_t outsz)
{
    char sys_vendor[128];
    char product_name[128];
    char board_vendor[128];

    read_dmi_field("sys_vendor", sys_vendor, sizeof(sys_vendor));
    read_dmi_field("product_name", product_name, sizeof(product_name));
    read_dmi_field("board_vendor", board_vendor, sizeof(board_vendor));

    if (out && outsz)
        out[0] = '\0';

    if (strstr(sys_vendor, "QEMU") || strstr(product_name, "QEMU")) {
        snprintf(out, outsz, "QEMU (sys_vendor=\"%s\")", sys_vendor);
        return 1;
    }
    if (strstr(sys_vendor, "VMware")) {
        snprintf(out, outsz, "VMware (sys_vendor=\"%s\")", sys_vendor);
        return 1;
    }
    if (strstr(sys_vendor, "innotek GmbH") || strstr(product_name, "VirtualBox")) {
        snprintf(out, outsz, "VirtualBox (sys_vendor=\"%s\")", sys_vendor);
        return 1;
    }
    if (strcmp(sys_vendor, "Microsoft Corporation") == 0 &&
        strstr(product_name, "Virtual Machine")) {
        snprintf(out, outsz, "Hyper-V (product_name=\"%s\")", product_name);
        return 1;
    }
    if (strstr(sys_vendor, "Xen")) {
        snprintf(out, outsz, "Xen (sys_vendor=\"%s\")", sys_vendor);
        return 1;
    }
    if (strstr(sys_vendor, "Parallels")) {
        snprintf(out, outsz, "Parallels (sys_vendor=\"%s\")", sys_vendor);
        return 1;
    }
    if (strstr(sys_vendor, "Google")) {
        snprintf(out, outsz, "Google Compute Engine (sys_vendor=\"%s\")", sys_vendor);
        return 1;
    }
    if (strstr(sys_vendor, "Amazon EC2") || strstr(board_vendor, "Amazon EC2")) {
        snprintf(out, outsz, "Amazon EC2 (sys_vendor=\"%s\")", sys_vendor);
        return 1;
    }
    if (strstr(product_name, "Bochs")) {
        snprintf(out, outsz, "Bochs (product_name=\"%s\")", product_name);
        return 1;
    }
    return 0;
}

static int cmd_vmcheck(void)
{
    char cpuid_vendor[16];
    char dmi_desc[192];
    int cpuid_hit, dmi_hit;

    cpuid_hit = detect_hypervisor_cpuid(cpuid_vendor, sizeof(cpuid_vendor));
    dmi_hit = detect_hypervisor_dmi(dmi_desc, sizeof(dmi_desc));

    printf("VM/hypervisor check:\n");
    if (cpuid_hit)
        printf("  CPUID hypervisor bit : present (vendor id: %s)\n", cpuid_vendor);
    else
        printf("  CPUID hypervisor bit : not present\n");
    if (dmi_hit)
        printf("  DMI/SMBIOS strings   : %s\n", dmi_desc);
    else
        printf("  DMI/SMBIOS strings   : no known VM vendor string found\n");

    if (cpuid_hit || dmi_hit) {
        printf("  result               : running inside a virtual machine\n"
               "    (informational only -- common for entirely legitimate\n"
               "     reasons: cloud gaming, CI, testing, GPU-passthrough\n"
               "     streaming rigs. Not a verdict -- and not something a\n"
               "     hypervisor configured to hide these signatures would\n"
               "     even show here. See THREAT_MODEL.md.)\n");
    } else {
        printf("  result               : no hypervisor detected\n");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* command: events                                                     */
/* ------------------------------------------------------------------ */
static int cmd_events(int argc, char **argv)
{
    int watch = 0, i;

    for (i = 0; i < argc; i++)
        if (strcmp(argv[i], "--watch") == 0)
            watch = 1;

    ac_open();
    for (;;) {
        struct ac_event_list el;

        memset(&el, 0, sizeof(el));
        if (ioctl_ok(AC_IOCTL_GET_EVENTS, &el) < 0)
            return 1;
        for (i = 0; i < (int)el.count; i++)
            print_event(&el.events[i]);
        if (el.dropped)
            printf("(ring dropped %u events)\n", el.dropped);
        if (!watch)
            break;
        usleep(200000);
    }
    ac_close();
    return 0;
}

/* ------------------------------------------------------------------ */
/* command: lock / unlock                                              */
/* ------------------------------------------------------------------ */
static int cmd_lock(int lock)
{
    ac_open();
    if (ioctl_ok(lock ? AC_IOCTL_LOCK : AC_IOCTL_UNLOCK, NULL) < 0)
        return 1;
    printf("module %s (rmmod will %s while pinned)\n",
           lock ? "pinned" : "unpinned",
           lock ? "fail" : "succeed");
    ac_close();
    return 0;
}

/* ------------------------------------------------------------------ */
/* command: start (monitoring daemon)                                  */
/* ------------------------------------------------------------------ */
static void sig_handler(int sig)
{
    (void)sig;
    g_stop = 1;
}

static int check_syscalls_periodic(void)
{
    /* Rising-edge state for a checksum-only compromise -- see below. */
    static int checksum_only_reported;
    struct ac_syscall_check c;

    memset(&c, 0, sizeof(c));
    if (ioctl(dev_fd, AC_IOCTL_CHECK_SYSCALLS, &c) < 0)
        return -1;
    /* Don't log hooked/redirected here: the kernel only emits
     * AC_EV_SYSCALL_HOOK / AC_EV_SYSCALL_REDIRECT into the event ring on
     * a rising edge (a new hook or in-text handler swap, not one already
     * reported), and the main loop's ring drain already logs both at
     * LOG_CRIT. Logging them here too would re-report the same
     * persistent hook/redirect at CRIT on every poll (see #52).
     *
     * checksum_mismatch has no matching kernel event, though: it exists
     * specifically to catch handler churn the per-slot walk (and so
     * those two events) didn't individually flag -- see anticheat.h's
     * comment on the field. Without a report here, that case is
     * detected by the kernel every 5s but never logged or acted on by
     * the daemon at all. Track our own rising edge so it's reported
     * once per transition, same rationale as #52.
     */
    if (c.checksum_mismatch && !c.hooked && !c.redirected) {
        if (!checksum_only_reported)
            logmsg(LOG_CRIT, "syscall table checksum mismatch: boot=%s "
                   "current=%s (handler churn not individually flagged)",
                   c.baseline_sha256, c.current_sha256);
        checksum_only_reported = 1;
    } else {
        checksum_only_reported = 0;
    }
    return c.hooked;
}

static int check_modules_periodic(void)
{
    long hidden = crosscheck_modules(0);

    if (hidden > 0)
        logmsg(LOG_CRIT, "%ld module(s) hidden from /proc/modules", hidden);
    return (int)hidden;
}

/* Per-pid baseline for AC_EV_ANON_EXEC-style detection: vdso/vvar are
 * anonymous+executable from process start and never change, so recording
 * whatever count we see on a pid's *first* scan as its baseline and only
 * alerting when the count later grows cleanly separates "always there"
 * kernel mappings from code that gets mapped in after we started watching
 * -- without needing to identify vdso/vvar by name in the kernel (which
 * would need arch-specific, harder-to-verify code; see the discussion in
 * anticheat.h). This does mean a pid that gets reused for an unrelated
 * process between two scans could show a spurious baseline reset; that's
 * a known, accepted limitation for this pass, not a security hole -- the
 * new process's own baseline just gets (re-)established on its first
 * scan, same as any newly-protected pid. */
struct ac_anon_baseline {
    int          pid;
    unsigned int count;
    int          in_use;
};
static struct ac_anon_baseline g_anon_baseline[AC_MAX_PROTS];

static void anon_baseline_forget_stale(const struct ac_prot_list *pl)
{
    unsigned int i, j;

    for (i = 0; i < AC_MAX_PROTS; i++) {
        if (!g_anon_baseline[i].in_use)
            continue;
        for (j = 0; j < pl->count; j++)
            if (pl->items[j].pid == g_anon_baseline[i].pid)
                break;
        if (j == pl->count)
            g_anon_baseline[i].in_use = 0;   /* no longer protected */
    }
}

static void anon_baseline_check(int pid, const char *comm, unsigned int count,
                                 int jit_allowed)
{
    unsigned int i, free_slot = AC_MAX_PROTS;

    for (i = 0; i < AC_MAX_PROTS; i++) {
        if (g_anon_baseline[i].in_use && g_anon_baseline[i].pid == pid) {
            if (count > g_anon_baseline[i].count) {
                if (jit_allowed)
                    logmsg(LOG_WARNING, "pid %d (%s): %u new anonymous "
                           "executable mapping(s) since first observed "
                           "(was %u, now %u) -- expected for a JIT-marked "
                           "process, not auto-reported",
                           pid, comm, count - g_anon_baseline[i].count,
                           g_anon_baseline[i].count, count);
                else
                    logmsg(LOG_CRIT, "pid %d (%s): %u new anonymous executable "
                           "mapping(s) since first observed (was %u, now %u) -- "
                           "possible code injection after process start",
                           pid, comm, count - g_anon_baseline[i].count,
                           g_anon_baseline[i].count, count);
            }
            g_anon_baseline[i].count = count;
            return;
        }
        if (free_slot == AC_MAX_PROTS && !g_anon_baseline[i].in_use)
            free_slot = i;
    }
    if (free_slot != AC_MAX_PROTS) {
        g_anon_baseline[free_slot].pid = pid;
        g_anon_baseline[free_slot].count = count;
        g_anon_baseline[free_slot].in_use = 1;
    }
}

/* ------------------------------------------------------------------ */
/* environment-based hook-evasion detection (LD_PRELOAD, Vulkan layers)*/
/*                                                                      */
/* Both checks below share one primitive: catching hooking that never   */
/* touches vkQueuePresentKHR's actual bytes, so the render-hook check   */
/* above can't see it. Both are deliberately heuristics, not verdicts   */
/* -- MangoHud, gamemode, gamescope, and other legitimate tools         */
/* routinely use both LD_PRELOAD and Vulkan layers, this is literally   */
/* how MangoHud's overlay works. Both ship at LOG_WARNING, not          */
/* LOG_ALERT/LOG_CRIT, so neither flows through the ban-pipeline        */
/* auto-report hook in logmsg() (scoped to pri <= LOG_CRIT) -- an       */
/* operator sees them in the log, but they don't accumulate as a        */
/* report against a client_id on their own.                             */
/* ------------------------------------------------------------------ */
#define AC_ENVIRON_BUF (256 * 1024)
/* struct ac_environ_query, AC_ENVIRON_VAL_LEN, and the VK layer env var
 * list are declared earlier (forward declarations before check_ld_preload)
 * since the CLI wrappers there need them at compile time too. */

/* /proc/<pid>/environ is populated once at exec() and never updated by
 * the process's own later setenv() calls -- exactly what's wanted here:
 * this shows what the process launched with, not whatever it might
 * claim about itself at runtime. NUL-separated KEY=VALUE entries.
 *
 * Reads environ exactly once and checks every entry against all of
 * `vars` in the same pass (rather than making callers re-open/re-read
 * the file once per variable name), filling vars[i].found/value for
 * whichever are present. Returns 0 on success (some or none may be
 * found; check vars[i].found individually), -1 if environ couldn't be
 * read at all or was too large to read in full before hitting
 * AC_ENVIRON_BUF -- in the latter case vars[i].found is only reliable
 * for names that were actually matched (a variable that would have
 * appeared past the truncation point is indistinguishable from one
 * that was never set, so treat -1 as inconclusive, never a confident
 * "not set"). errno is set on failure. */
static int ac_read_environ_vars(int pid, struct ac_environ_query *vars,
                                 unsigned int nvars)
{
    char path[64];
    char *buf;
    size_t total = 0;
    ssize_t n;
    int fd;
    size_t pos;
    unsigned int i;
    int truncated;

    for (i = 0; i < nvars; i++)
        vars[i].found = 0;

    snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    buf = malloc(AC_ENVIRON_BUF);
    if (!buf) {
        close(fd);
        return -1;
    }

    /* Loop to true EOF rather than trusting a single read() to capture
     * the whole file -- a real Steam/Proton/Flatpak launch environment
     * can comfortably exceed one read's worth. */
    while (total < AC_ENVIRON_BUF - 1) {
        n = read(fd, buf + total, AC_ENVIRON_BUF - 1 - total);
        if (n < 0) {
            close(fd);
            free(buf);
            return -1;
        }
        if (n == 0)
            break;
        total += (size_t)n;
    }
    close(fd);
    if (total == 0) {
        free(buf);
        return 0;
    }
    truncated = (total >= AC_ENVIRON_BUF - 1);
    buf[total] = '\0';

    for (pos = 0; pos < total; ) {
        const char *entry = buf + pos;
        size_t entry_len = strlen(entry);

        if (entry_len == 0)
            break;   /* malformed/truncated read -- stop rather than misread */
        for (i = 0; i < nvars; i++) {
            size_t nlen = strlen(vars[i].name);

            if (!vars[i].found && entry_len > nlen &&
                strncmp(entry, vars[i].name, nlen) == 0 && entry[nlen] == '=') {
                snprintf(vars[i].value, sizeof(vars[i].value), "%s", entry + nlen + 1);
                vars[i].found = 1;
            }
        }
        pos += entry_len + 1;
    }
    free(buf);
    if (truncated) {
        errno = EMSGSIZE;
        return -1;
    }
    return 0;
}

static int ac_read_ld_preload(int pid, char *out, size_t outsz)
{
    struct ac_environ_query q;
    int rc;

    memset(&q, 0, sizeof(q));
    q.name = "LD_PRELOAD";
    rc = ac_read_environ_vars(pid, &q, 1);
    if (rc < 0)
        return -1;
    if (!q.found)
        return 0;
    snprintf(out, outsz, "%s", q.value);
    return 1;
}

/* Vulkan-layer injection: the render-hook check above only catches
 * in-place byte patching of vkQueuePresentKHR; a cheat can instead
 * inject its hook via a Vulkan layer, which never touches those bytes
 * at all. This covers only the environment-variable activation path:
 * VK_INSTANCE_LAYERS (older loaders) / VK_LOADER_LAYERS_ENABLE (current
 * loaders) force-enable a layer by name; VK_LAYER_PATH / VK_ADD_LAYER_PATH
 * point the loader at additional manifest directories, which is how an
 * attacker's own layer becomes discoverable at all.
 *
 * Known, honest gap: an *implicit* layer manifest dropped directly into
 * one of the Vulkan loader's default search directories (e.g.
 * ~/.local/share/vulkan/implicit_layer.d/) is auto-enabled by the
 * loader with no environment variable involved at all, and is not
 * caught by this check -- see README. Detecting that would mean parsing
 * and cross-referencing layer manifest files against some notion of
 * "expected", a meaningfully bigger feature than an environ heuristic.
 * (AC_VK_LAYER_ENV_VARS itself is declared earlier, alongside
 * struct ac_environ_query, for the same forward-declaration reason.) */

/* Warn at most once per pid -- environ is static for the process's
 * lifetime, so re-checking every cycle would either always re-find
 * nothing or always re-find the same value; neither is worth repeating
 * in the log every cycle forever. Same in_use/pid slot-tracking pattern
 * as g_anon_baseline above. */
struct ac_preload_warned {
    int pid;
    int in_use;
};
static struct ac_preload_warned g_preload_warned[AC_MAX_PROTS];

static void preload_warned_forget_stale(const struct ac_prot_list *pl)
{
    unsigned int i, j;

    for (i = 0; i < AC_MAX_PROTS; i++) {
        if (!g_preload_warned[i].in_use)
            continue;
        for (j = 0; j < pl->count; j++)
            if (pl->items[j].pid == g_preload_warned[i].pid)
                break;
        if (j == pl->count)
            g_preload_warned[i].in_use = 0;
    }
}

static int preload_already_warned(int pid)
{
    unsigned int i;

    for (i = 0; i < AC_MAX_PROTS; i++)
        if (g_preload_warned[i].in_use && g_preload_warned[i].pid == pid)
            return 1;
    return 0;
}

static void preload_mark_warned(int pid)
{
    unsigned int i, free_slot = AC_MAX_PROTS;

    for (i = 0; i < AC_MAX_PROTS; i++) {
        if (g_preload_warned[i].in_use && g_preload_warned[i].pid == pid)
            return;
        if (free_slot == AC_MAX_PROTS && !g_preload_warned[i].in_use)
            free_slot = i;
    }
    if (free_slot != AC_MAX_PROTS) {
        g_preload_warned[free_slot].pid = pid;
        g_preload_warned[free_slot].in_use = 1;
    }
}

static void check_ld_preload_periodic(void)
{
    struct ac_prot_list pl;
    unsigned int i;

    memset(&pl, 0, sizeof(pl));
    if (ioctl(dev_fd, AC_IOCTL_LIST_PROTECTED, &pl) < 0)
        return;
    preload_warned_forget_stale(&pl);
    for (i = 0; i < pl.count; i++) {
        char val[512];

        if (preload_already_warned(pl.items[i].pid))
            continue;
        if (ac_read_ld_preload(pl.items[i].pid, val, sizeof(val)) != 1)
            continue;
        logmsg(LOG_WARNING, "pid %d (%s): LD_PRELOAD=%s set at exec -- "
               "common for legitimate overlay/compat tools (MangoHud, "
               "gamemode, gamescope) as well as library-injection hooking; "
               "informational only, not a verdict on its own",
               pl.items[i].pid, pl.items[i].comm, val);
        preload_mark_warned(pl.items[i].pid);
    }
}

static int ac_ld_preload_check_interval(void)
{
    return ac_env_interval("AC_LD_PRELOAD_CHECK_INTERVAL", 10);
}

/* Same warn-at-most-once-per-pid reasoning and slot-tracking pattern as
 * g_preload_warned above, kept as a separate array since a pid warned
 * for one doesn't imply anything about the other. */
struct ac_vklayer_warned {
    int pid;
    int in_use;
};
static struct ac_vklayer_warned g_vklayer_warned[AC_MAX_PROTS];

static void vklayer_warned_forget_stale(const struct ac_prot_list *pl)
{
    unsigned int i, j;

    for (i = 0; i < AC_MAX_PROTS; i++) {
        if (!g_vklayer_warned[i].in_use)
            continue;
        for (j = 0; j < pl->count; j++)
            if (pl->items[j].pid == g_vklayer_warned[i].pid)
                break;
        if (j == pl->count)
            g_vklayer_warned[i].in_use = 0;
    }
}

static int vklayer_already_warned(int pid)
{
    unsigned int i;

    for (i = 0; i < AC_MAX_PROTS; i++)
        if (g_vklayer_warned[i].in_use && g_vklayer_warned[i].pid == pid)
            return 1;
    return 0;
}

static void vklayer_mark_warned(int pid)
{
    unsigned int i, free_slot = AC_MAX_PROTS;

    for (i = 0; i < AC_MAX_PROTS; i++) {
        if (g_vklayer_warned[i].in_use && g_vklayer_warned[i].pid == pid)
            return;
        if (free_slot == AC_MAX_PROTS && !g_vklayer_warned[i].in_use)
            free_slot = i;
    }
    if (free_slot != AC_MAX_PROTS) {
        g_vklayer_warned[free_slot].pid = pid;
        g_vklayer_warned[free_slot].in_use = 1;
    }
}

static void check_vk_layers_periodic(void)
{
    struct ac_prot_list pl;
    unsigned int i, j;

    memset(&pl, 0, sizeof(pl));
    if (ioctl(dev_fd, AC_IOCTL_LIST_PROTECTED, &pl) < 0)
        return;
    vklayer_warned_forget_stale(&pl);
    for (i = 0; i < pl.count; i++) {
        struct ac_environ_query vars[AC_VK_LAYER_ENV_VARS_COUNT];

        if (vklayer_already_warned(pl.items[i].pid))
            continue;
        for (j = 0; j < AC_VK_LAYER_ENV_VARS_COUNT; j++) {
            memset(&vars[j], 0, sizeof(vars[j]));
            vars[j].name = AC_VK_LAYER_ENV_VARS[j];
        }
        if (ac_read_environ_vars(pl.items[i].pid, vars,
                                  AC_VK_LAYER_ENV_VARS_COUNT) < 0)
            continue;
        for (j = 0; j < AC_VK_LAYER_ENV_VARS_COUNT; j++) {
            if (!vars[j].found)
                continue;
            logmsg(LOG_WARNING, "pid %d (%s): %s=%s set at exec -- "
                   "common for legitimate overlay tools (MangoHud) as well "
                   "as Vulkan-layer-based hooking; informational only, not "
                   "a verdict on its own",
                   pl.items[i].pid, pl.items[i].comm,
                   vars[j].name, vars[j].value);
        }
        vklayer_mark_warned(pl.items[i].pid);
    }
}

static int ac_vk_layer_check_interval(void)
{
    return ac_env_interval("AC_VK_LAYER_CHECK_INTERVAL", 10);
}

/* ------------------------------------------------------------------ */
/* implicit Vulkan-layer manifest detection                            */
/*                                                                      */
/* --check-vklayers only sees layers activated via environment          */
/* variables. An *implicit* layer manifest dropped into one of the      */
/* Vulkan loader's default search directories is auto-enabled by the    */
/* loader for every Vulkan process -- unless the manifest itself        */
/* defines a "disable_environment" variable and the target has it set   */
/* -- with no environment variable involved at all: exactly the gap     */
/* documented when --check-vklayers shipped. This closes it by directly */
/* replicating what the loader itself does: enumerate the same          */
/* directories it searches (both the target user's own per-user paths,  */
/* the more realistic vector since writing there needs no elevated      */
/* privilege at all, and the system-wide ones), parse each manifest's    */
/* "library_path"/"disable_environment", and cross-reference against    */
/* the target's own environ (reusing ac_read_environ_vars()) to         */
/* determine whether each discovered layer is actually active for that  */
/* specific process right now.                                          */
/*                                                                      */
/* Deliberately never trusts the manifest content beyond parsing it as  */
/* data -- these files can be attacker-controlled (that's the whole     */
/* point of this check), so parsing is bounded and defensive throughout, */
/* same posture as elf_find_symbol_offset() above; nothing from a       */
/* layer's library_path is ever opened or loaded, only reported.        */
/*                                                                      */
/* A small, explicitly non-exhaustive allowlist of common legitimate    */
/* overlay layer names keeps the periodic check from warning on every   */
/* machine that happens to have MangoHud installed (extremely common).  */
/* This is a name-based heuristic, not a security boundary: a cheat     */
/* could name its own layer "VK_LAYER_MANGOHUD_overlay" to blend in --  */
/* the one-shot CLI check reports every active layer regardless of the  */
/* allowlist, precisely so a human reviewing it isn't relying on the    */
/* name check alone.                                                    */
/* ------------------------------------------------------------------ */
#define AC_MANIFEST_MAX_BYTES (64 * 1024)
#define AC_MANIFEST_STR_LEN 256
#define AC_MAX_IMPLICIT_LAYERS 64

struct ac_implicit_layer {
    char name[AC_MANIFEST_STR_LEN];
    char library_path[AC_MANIFEST_STR_LEN];
    char disable_env[AC_MANIFEST_STR_LEN];   /* empty if manifest has none */
};

/* Known-legitimate implicit overlay/compat/vendor layer name prefixes.
 * Not exhaustive, not a security boundary -- see block comment above. */
static const char *const AC_KNOWN_LAYER_PREFIXES[] = {
    "VK_LAYER_MANGOHUD",
    "VK_LAYER_OBS_HOOK",
    "VK_LAYER_OBS_hotkeys",
    "VK_LAYER_VKBASALT",
    "VK_LAYER_RENDERDOC",
    "VK_LAYER_LATENCYFLEX",
    "VK_LAYER_VALVE_steam_overlay",
    "VK_LAYER_VALVE_steam_fossilize",
    "VK_LAYER_GOOGLE_",
    "VK_LAYER_KHRONOS_",
    "VK_LAYER_MESA_",
    "VK_LAYER_INTEL_",
    "VK_LAYER_NV_",
    "VK_LAYER_AMD_",
};
#define AC_KNOWN_LAYER_PREFIXES_COUNT \
    (sizeof(AC_KNOWN_LAYER_PREFIXES) / sizeof(AC_KNOWN_LAYER_PREFIXES[0]))

static int ac_layer_name_known(const char *name)
{
    unsigned int i;

    for (i = 0; i < AC_KNOWN_LAYER_PREFIXES_COUNT; i++)
        if (strncmp(name, AC_KNOWN_LAYER_PREFIXES[i],
                    strlen(AC_KNOWN_LAYER_PREFIXES[i])) == 0)
            return 1;
    return 0;
}

/* Finds "key" as a JSON object key (a targeted extractor for the small,
 * well-defined Vulkan layer manifest schema, not a general JSON parser)
 * followed by ':' and a quoted string, and copies the string's content
 * into out. Returns 1 if found, 0 if not. Bounded and defensive
 * throughout: the manifest is attacker-influenceable content, never
 * trusted structure. Minimal escape handling -- a backslash-escaped
 * character is copied verbatim, which is close enough for the plain
 * ASCII paths/names these manifests contain in practice; a value using
 * more exotic JSON escapes just won't match cleanly, a safe failure
 * mode (skip, not misread). */
static int json_extract_string(const char *json, size_t json_len,
                                const char *key, char *out, size_t outsz)
{
    char needle[64];
    int needle_len;
    const char *p = json, *end = json + json_len;

    needle_len = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (needle_len <= 0 || (size_t)needle_len >= sizeof(needle))
        return 0;

    while (p < end) {
        const char *hit = memmem(p, (size_t)(end - p), needle, (size_t)needle_len);
        const char *q;
        size_t oi;

        if (!hit)
            return 0;
        q = hit + needle_len;
        while (q < end && isspace((unsigned char)*q))
            q++;
        if (q >= end || *q != ':') {
            p = hit + 1;
            continue;
        }
        q++;
        while (q < end && isspace((unsigned char)*q))
            q++;
        if (q >= end || *q != '"') {
            p = hit + 1;
            continue;
        }
        q++;
        oi = 0;
        while (q < end && *q != '"') {
            if (*q == '\\' && q + 1 < end)
                q++;
            if (oi + 1 < outsz)
                out[oi++] = *q;
            q++;
        }
        out[oi < outsz ? oi : outsz - 1] = '\0';
        return 1;
    }
    return 0;
}

/* Same idea as json_extract_string(), but "disable_environment"'s JSON
 * value is an object whose single key is the variable name -- e.g.
 * "disable_environment": { "DISABLE_MANGOHUD": "1" } -- so this needs
 * the first key inside that object, not a plain string value. */
static int json_extract_disable_env(const char *json, size_t json_len,
                                     char *out, size_t outsz)
{
    static const char needle[] = "\"disable_environment\"";
    const char *hit, *end = json + json_len;
    const char *q;
    size_t oi;

    hit = memmem(json, json_len, needle, sizeof(needle) - 1);
    if (!hit)
        return 0;
    q = hit + sizeof(needle) - 1;
    while (q < end && isspace((unsigned char)*q))
        q++;
    if (q >= end || *q != ':')
        return 0;
    q++;
    while (q < end && isspace((unsigned char)*q))
        q++;
    if (q >= end || *q != '{')
        return 0;
    q++;
    while (q < end && isspace((unsigned char)*q))
        q++;
    if (q >= end || *q != '"')
        return 0;
    q++;
    oi = 0;
    while (q < end && *q != '"') {
        if (*q == '\\' && q + 1 < end)
            q++;
        if (oi + 1 < outsz)
            out[oi++] = *q;
        q++;
    }
    out[oi < outsz ? oi : outsz - 1] = '\0';
    return 1;
}

/* Resolves the target process's real uid (from /proc/<pid>/status,
 * "Uid:" line, first field) and that user's home directory, so the
 * per-user implicit-layer manifest paths can be checked correctly --
 * the daemon runs as root, so its own $HOME is irrelevant to what a
 * game running as a different, unprivileged user would actually have
 * loaded. Returns 0 on success (fills home), -1 if the pid is gone or
 * the uid can't be resolved to a passwd entry (not fatal to the overall
 * check -- the system-wide directories are still checked either way). */
static int ac_resolve_pid_home(int pid, char *home, size_t homesz)
{
    char path[64];
    FILE *f;
    char line[256];
    uid_t uid = (uid_t)-1;
    struct passwd pwbuf, *pw = NULL;
    char pwdata[4096];

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    f = fopen(path, "r");
    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        unsigned long v;

        if (sscanf(line, "Uid: %lu", &v) == 1) {
            uid = (uid_t)v;
            break;
        }
    }
    fclose(f);
    if (uid == (uid_t)-1)
        return -1;

    if (getpwuid_r(uid, &pwbuf, pwdata, sizeof(pwdata), &pw) != 0 ||
        !pw || !pw->pw_dir)
        return -1;
    snprintf(home, homesz, "%s", pw->pw_dir);
    return 0;
}

/* Scans one implicit_layer.d directory for *.json manifests, appending
 * successfully-parsed layers into layers[*count] (capped at
 * AC_MAX_IMPLICIT_LAYERS total across all directories -- more than that
 * many implicit layers on one machine would be extraordinary). A
 * manifest missing "name" or "library_path" is skipped, not guessed at.
 * A missing directory is the overwhelmingly common case (most machines
 * have none of these paths at all) and is silently skipped, not an
 * error. */
static void ac_scan_implicit_layer_dir(const char *dir,
                                        struct ac_implicit_layer *layers,
                                        unsigned int *count)
{
    DIR *d;
    struct dirent *de;

    d = opendir(dir);
    if (!d)
        return;
    while (*count < AC_MAX_IMPLICIT_LAYERS && (de = readdir(d)) != NULL) {
        char path[PATH_MAX];
        size_t namelen = strlen(de->d_name);
        int fd;
        struct stat st;
        char *buf;
        ssize_t n;
        struct ac_implicit_layer *layer;

        if (namelen < 5 || strcmp(de->d_name + namelen - 5, ".json") != 0)
            continue;
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        /* Fix #97: two of the scanned directories live under the target
         * process's own home directory (attacker-writable). A `.json`-named
         * FIFO with no writer would hang a plain O_RDONLY open() forever,
         * stalling the periodic scan -- so open O_NONBLOCK (open returns
         * immediately on FIFOs) then fstat()/S_ISREG() to reject anything
         * that isn't a regular file (FIFO, socket, device) before reading.
         * Deliberately no O_NOFOLLOW: the Vulkan loader itself follows
         * symlinks, so skipping symlinked manifests would make a
         * `evil.json -> payload.json` symlink invisible to this scan while
         * still loaded by the real loader -- a scan-evasion blind spot
         * worse than the low-severity symlink-read it would prevent
         * (a symlinked root-readable non-JSON file fails closed in the
         * json_extract below with no read-back channel to the attacker).
         * Following symlinks keeps detection parity with the loader; the
         * FIFO/special-file risk holds through a symlink too and is still
         * closed by the S_ISREG gate below. */
        fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0)
            continue;
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
            close(fd);
            continue;
        }
        /* O_NONBLOCK was only needed to make the FIFO-with-no-writer
         * open() return instead of blocking; a regular file reads the
         * same either way, but clear it so the subsequent read() has
         * plain blocking semantics. */
        {
            int fl = fcntl(fd, F_GETFL);
            if (fl >= 0)
                (void)fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
        }
        buf = malloc(AC_MANIFEST_MAX_BYTES);
        if (!buf) {
            close(fd);
            continue;
        }
        n = read(fd, buf, AC_MANIFEST_MAX_BYTES - 1);
        close(fd);
        if (n <= 0) {
            free(buf);
            continue;
        }
        buf[n] = '\0';

        layer = &layers[*count];
        memset(layer, 0, sizeof(*layer));
        if (json_extract_string(buf, (size_t)n, "name", layer->name, sizeof(layer->name)) &&
            json_extract_string(buf, (size_t)n, "library_path", layer->library_path,
                                 sizeof(layer->library_path))) {
            json_extract_disable_env(buf, (size_t)n, layer->disable_env,
                                      sizeof(layer->disable_env));
            (*count)++;
        }
        free(buf);
    }
    closedir(d);
}

/* Enumerates every standard implicit_layer.d directory and returns the
 * layers that are actually active for this specific target: present,
 * and not disabled via its own "disable_environment" variable (if the
 * manifest defines one) in the target's own environ. Returns the count
 * found (0 is normal and common). */
static int ac_scan_active_implicit_layers(int pid,
                                           struct ac_implicit_layer *out,
                                           unsigned int outcap)
{
    struct ac_implicit_layer found[AC_MAX_IMPLICIT_LAYERS];
    unsigned int nfound = 0, nactive = 0, i;
    char home[PATH_MAX];

    if (ac_resolve_pid_home(pid, home, sizeof(home)) == 0) {
        char dir[PATH_MAX + 64];   /* home[] + the longest suffix below, with headroom */

        snprintf(dir, sizeof(dir), "%s/.config/vulkan/implicit_layer.d", home);
        ac_scan_implicit_layer_dir(dir, found, &nfound);
        snprintf(dir, sizeof(dir), "%s/.local/share/vulkan/implicit_layer.d", home);
        ac_scan_implicit_layer_dir(dir, found, &nfound);
    }
    ac_scan_implicit_layer_dir("/etc/vulkan/implicit_layer.d", found, &nfound);
    ac_scan_implicit_layer_dir("/usr/local/etc/vulkan/implicit_layer.d", found, &nfound);
    ac_scan_implicit_layer_dir("/usr/share/vulkan/implicit_layer.d", found, &nfound);
    ac_scan_implicit_layer_dir("/usr/local/share/vulkan/implicit_layer.d", found, &nfound);

    for (i = 0; i < nfound && nactive < outcap; i++) {
        if (found[i].disable_env[0]) {
            struct ac_environ_query q;

            memset(&q, 0, sizeof(q));
            q.name = found[i].disable_env;
            if (ac_read_environ_vars(pid, &q, 1) == 0 && q.found)
                continue;   /* explicitly disabled for this process */
        }
        out[nactive++] = found[i];
    }
    return (int)nactive;
}

/* CLI-facing wrapper for `scan --check-implicit-layers`. Reports every
 * active layer regardless of the allowlist -- unlike the periodic check
 * below, a human explicitly asked to see this. */
static int check_implicit_layers(int pid)
{
    struct ac_implicit_layer layers[AC_MAX_IMPLICIT_LAYERS];
    int n = ac_scan_active_implicit_layers(pid, layers, AC_MAX_IMPLICIT_LAYERS);
    int i, unknown = 0;

    if (n <= 0) {
        printf("  Implicit Vulkan-layer check: none active for this process\n");
        return 0;
    }
    for (i = 0; i < n; i++) {
        int known = ac_layer_name_known(layers[i].name);

        printf("  Implicit Vulkan-layer: %s -> %s%s\n",
               layers[i].name[0] ? layers[i].name : "(unnamed)",
               layers[i].library_path[0] ? layers[i].library_path : "(no library_path)",
               known ? "" : "  [not in the known-overlay allowlist]");
        if (!known)
            unknown++;
    }
    printf("    (informational only -- also used by legitimate overlay tools\n"
           "     like MangoHud; not a verdict. Name-based allowlist matching\n"
           "     can be spoofed by a layer that names itself similarly)\n");
    return unknown > 0 ? 1 : 0;
}

/* Periodic counterpart. Unlike the environ-based checks (LD_PRELOAD,
 * VK layer env vars), which read something fixed at exec() time,
 * manifest files live on disk and can change while a session is
 * running -- so this re-scans every cycle rather than checking once per
 * pid, but only ever warns on *growth* of the unrecognized-layer count
 * for a given pid, the same baseline-delta design as
 * anon_baseline_check(): a pid's already-active layers at first
 * observation are its baseline, not something to alert on, and only a
 * later increase (a new unrecognized layer appearing mid-session) is
 * the signal. */
struct ac_implicit_layer_baseline {
    int pid;
    unsigned int count;
    int in_use;
};
static struct ac_implicit_layer_baseline g_implicit_layer_baseline[AC_MAX_PROTS];

static void implicit_layer_baseline_forget_stale(const struct ac_prot_list *pl)
{
    unsigned int i, j;

    for (i = 0; i < AC_MAX_PROTS; i++) {
        if (!g_implicit_layer_baseline[i].in_use)
            continue;
        for (j = 0; j < pl->count; j++)
            if (pl->items[j].pid == g_implicit_layer_baseline[i].pid)
                break;
        if (j == pl->count)
            g_implicit_layer_baseline[i].in_use = 0;
    }
}

static void check_implicit_layers_periodic(void)
{
    struct ac_prot_list pl;
    unsigned int i;

    memset(&pl, 0, sizeof(pl));
    if (ioctl(dev_fd, AC_IOCTL_LIST_PROTECTED, &pl) < 0)
        return;
    implicit_layer_baseline_forget_stale(&pl);
    for (i = 0; i < pl.count; i++) {
        struct ac_implicit_layer layers[AC_MAX_IMPLICIT_LAYERS];
        int n = ac_scan_active_implicit_layers(pl.items[i].pid, layers,
                                                AC_MAX_IMPLICIT_LAYERS);
        char names[512];
        size_t noff = 0;
        unsigned int unknown = 0, j, slot = AC_MAX_PROTS, free_slot = AC_MAX_PROTS;

        if (n < 0)
            continue;
        for (j = 0; j < (unsigned int)n; j++) {
            const char *nm;

            if (ac_layer_name_known(layers[j].name))
                continue;
            nm = layers[j].name[0] ? layers[j].name : "(unnamed)";
            noff += (size_t)snprintf(names + noff,
                                      noff < sizeof(names) ? sizeof(names) - noff : 0,
                                      "%s%s", unknown ? ", " : "", nm);
            /* snprintf() returns the length it would have written, not the
             * length actually written -- clamp so noff never grows past
             * sizeof(names), which would otherwise make `names + noff`
             * (formed unconditionally next iteration) point more than one
             * element past the array's end: UB per C11 6.5.6p8 even without
             * a dereference. */
            if (noff > sizeof(names))
                noff = sizeof(names);
            unknown++;
        }

        for (j = 0; j < AC_MAX_PROTS; j++) {
            if (g_implicit_layer_baseline[j].in_use &&
                g_implicit_layer_baseline[j].pid == pl.items[i].pid) {
                slot = j;
                break;
            }
            if (free_slot == AC_MAX_PROTS && !g_implicit_layer_baseline[j].in_use)
                free_slot = j;
        }
        if (slot == AC_MAX_PROTS) {
            if (free_slot != AC_MAX_PROTS) {
                g_implicit_layer_baseline[free_slot].pid = pl.items[i].pid;
                g_implicit_layer_baseline[free_slot].count = unknown;
                g_implicit_layer_baseline[free_slot].in_use = 1;
            }
            continue;
        }
        if (unknown > g_implicit_layer_baseline[slot].count)
            logmsg(LOG_WARNING, "pid %d (%s): %u unrecognized implicit Vulkan "
                   "layer(s) active (%s) -- not in the known-overlay "
                   "allowlist; informational only, not a verdict on its own",
                   pl.items[i].pid, pl.items[i].comm, unknown, names);
        g_implicit_layer_baseline[slot].count = unknown;
    }
}

static int ac_implicit_layer_check_interval(void)
{
    return ac_env_interval("AC_IMPLICIT_LAYER_CHECK_INTERVAL", 30);
}

static int scan_protected_periodic(void)
{
    struct ac_prot_list pl;
    unsigned int i;

    memset(&pl, 0, sizeof(pl));
    if (ioctl(dev_fd, AC_IOCTL_LIST_PROTECTED, &pl) < 0)
        return -1;
    anon_baseline_forget_stale(&pl);
    for (i = 0; i < pl.count; i++) {
        struct ac_scan_begin b;

        memset(&b, 0, sizeof(b));
        b.pid = pl.items[i].pid;
        if (ioctl(dev_fd, AC_IOCTL_SCAN_BEGIN, &b) == 0) {
            if (b.rwx_count > 0)
                logmsg(LOG_WARNING, "pid %d (%s): %u RWX mapping(s) present",
                       pl.items[i].pid, pl.items[i].comm, b.rwx_count);
            anon_baseline_check(pl.items[i].pid, pl.items[i].comm,
                                 b.anon_exec_count,
                                 pl.items[i].jit_allowed != 0);
            (void)ioctl(dev_fd, AC_IOCTL_SCAN_END, NULL); /* END only frees snapshot; failure is non-fatal */
        }
    }
    return 0;
}

/* Re-verify every protected process's executable, file-backed mappings
 * against whatever baseline was saved for them via `scan --hash --save`.
 * Deliberately does NOT create a baseline here if one doesn't exist yet --
 * silently adopting whatever's currently loaded as "known good" the first
 * time the daemon happens to see a process would permanently hide a
 * compromise that predates monitoring starting. Baselines only ever come
 * from an explicit, operator-run `--save` on a binary already verified
 * clean -- this only re-checks what someone already vouched for. */
static int check_baselines_periodic(void)
{
    struct ac_prot_list pl;
    unsigned int i;

    memset(&pl, 0, sizeof(pl));
    if (ioctl(dev_fd, AC_IOCTL_LIST_PROTECTED, &pl) < 0)
        return -1;
    for (i = 0; i < pl.count; i++) {
        struct ac_scan_begin b;
        unsigned int v;
        int mem_fd = -1;
        int mem_open_failed = 0;

        memset(&b, 0, sizeof(b));
        b.pid = pl.items[i].pid;
        if (ioctl(dev_fd, AC_IOCTL_SCAN_BEGIN, &b) != 0)
            continue;
        for (v = 0; v < b.n_vmas; v++) {
            struct ac_scan_get g;
            struct ac_vma_info *vi;
            char blpath[PATH_MAX], hex[65], bhex[65];
            struct ac_baseline_rec recs[AC_BASELINE_MAX_RECORDS];
            uint64_t size;
            int n, legacy = 0, size_mismatch = 0;

            memset(&g, 0, sizeof(g));
            g.pid = pl.items[i].pid;
            g.index = v;
            if (ioctl(dev_fd, AC_IOCTL_SCAN_GET, &g) < 0)
                break;
            vi = &g.vma;
            if (!(vi->flags & AC_VM_EXEC) || !vi->is_file)
                continue;

            size = vi->end - vi->start;
            if (size > AC_HASH_CAP)
                size = AC_HASH_CAP;

            baseline_path_for(vi->path, blpath);
            n = baseline_load_records(blpath, recs, &legacy);
            if (!baseline_find_record(recs, n, vi->inode, vi->offset, size,
                                       bhex, &size_mismatch)) {
                if (legacy)
                    logmsg(LOG_WARNING, "pid %d (%s): legacy-format baseline"
                           " for %s -- run `scan --hash --save` to regenerate",
                           pl.items[i].pid, pl.items[i].comm, vi->path);
                else if (size_mismatch)
                    logmsg(LOG_WARNING, "pid %d (%s): baseline for %s was"
                           " saved for a different mapping size (rebuilt or"
                           " remapped?) -- run `scan --hash --save` to regenerate",
                           pl.items[i].pid, pl.items[i].comm, vi->path);
                continue; /* nothing (compatible) saved for this segment */
            }

            /* Opened lazily on the first VMA that actually has a saved
             * baseline, and reused for the rest of this pid's VMAs --
             * most protected processes have at most a handful of
             * baselined mappings out of possibly many VMAs, so this
             * avoids an open() for every single one. mem_open_failed
             * distinguishes "not tried yet" from "tried and failed" so a
             * permission/ENOENT failure (the pid is gone, or raced past
             * yama ptrace_scope) isn't retried on every remaining VMA of
             * this same pid. */
            if (mem_fd < 0) {
                char mem_path[64];

                if (mem_open_failed)
                    continue;
                snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem",
                         pl.items[i].pid);
                mem_fd = open(mem_path, O_RDONLY);
                if (mem_fd < 0) {
                    mem_open_failed = 1;
                    continue;
                }
            }

            if (hash_proc_mem(mem_fd, vi->start, size, hex) < 0)
                continue;
            if (strcmp(bhex, hex) != 0)
                logmsg(LOG_CRIT, "pid %d (%s): memory content of %s differs "
                       "from saved baseline (possible runtime patching)",
                       pl.items[i].pid, pl.items[i].comm, vi->path);
        }
        if (mem_fd >= 0)
            close(mem_fd);
        (void)ioctl(dev_fd, AC_IOCTL_SCAN_END, NULL); /* END only frees snapshot; failure is non-fatal */
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* server-side reporting (ban pipeline)                                */
/*                                                                      */
/* Opt-in only (AC_REPORT_URL + AC_REPORT_KEY unset by default -- no    */
/* network activity unless explicitly configured, same pattern as       */
/* AC_BASELINE_DIR). Every LOG_ALERT/LOG_CRIT logmsg() call -- i.e.     */
/* every genuine detection this daemon already makes, see logmsg()      */
/* above -- gets POSTed to a minimal report-ingestion server (see       */
/* server/ac_server.py) as {client_id, event_type, detail, ts}. A human */
/* reviews accumulated reports and decides whether to ban a client_id;  */
/* this deliberately does not auto-ban on an unverified client-side     */
/* report, since a false positive here bans a real player, and nothing  */
/* client-side can attest it wasn't tampered with by the very attacker  */
/* it's trying to catch. Enforcement (a game server checking            */
/* GET /banned/<id> before allowing a connection) is out of scope --    */
/* this project has no game server to integrate with, only the API a    */
/* real one would call.                                                 */
/*                                                                      */
/* No TLS: this is plain HTTP, meant for a local/LAN deployment behind  */
/* a reverse proxy that terminates TLS for anything reachable over an   */
/* untrusted network. AC_REPORT_URL is either "host:port" (plain TCP,   */
/* no scheme) or "unix:///path/to/socket" (AF_UNIX SOCK_STREAM instead  */
/* of a network socket -- the same HTTP/1.1 request framing goes out    */
/* either way, ac_server.py just needs to be listening on that path via */
/* its own --unix-socket, see server/ac_server.py). The Unix-socket     */
/* option trades the plaintext-network-credential exposure noted above  */
/* for filesystem permissions on the socket as the trust boundary --    */
/* the natural fit when the daemon and server are co-located, which is  */
/* the deployment this project actually expects (see THREAT_MODEL.md).  */
/* ------------------------------------------------------------------ */
#define AC_REPORT_TIMEOUT_SEC 3

/* connect() with an actual bound on how long it can block. On Linux,
 * SO_SNDTIMEO/SO_RCVTIMEO -- despite being set on this socket -- do NOT
 * apply to connect() itself, only to subsequent send/recv-family calls;
 * against a host that blackholes SYN packets rather than actively
 * refusing, a plain blocking connect() can hang for the kernel's TCP
 * SYN-retry timeout (~127s), not the few seconds this is supposed to be
 * bounded by. Doing the connect non-blocking and waiting on poll()
 * enforces the real bound. Returns 0 on success (fd left in its
 * original blocking mode), -1 on failure/timeout (errno set). */
static int ac_connect_timeout(int fd, const struct sockaddr *addr,
                               socklen_t addrlen, int timeout_sec)
{
    int flags, err;
    socklen_t errlen = sizeof(err);
    struct pollfd pfd;
    int rc;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    rc = connect(fd, addr, addrlen);
    if (rc == 0) {
        fcntl(fd, F_SETFL, flags);   /* restore blocking mode for send/recv */
        return 0;
    }
    if (errno != EINPROGRESS) {
        fcntl(fd, F_SETFL, flags);
        return -1;
    }

    pfd.fd = fd;
    pfd.events = POLLOUT;
    rc = poll(&pfd, 1, timeout_sec * 1000);
    if (rc <= 0) {
        fcntl(fd, F_SETFL, flags);
        errno = (rc == 0) ? ETIMEDOUT : errno;
        return -1;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0) {
        fcntl(fd, F_SETFL, flags);
        errno = (err != 0) ? err : errno;
        return -1;
    }

    fcntl(fd, F_SETFL, flags);
    return 0;
}

#define AC_RESOLVE_MAX 8

struct ac_resolved_addr {
    int family;
    int socktype;
    int protocol;
    socklen_t addrlen;
    struct sockaddr_storage addr;
};

/* Fix #98: the forked DNS-resolve child below never exec()s, so every fd
 * the daemon holds at fork time (log file, /dev/anticheat handle,
 * ac_server sockets, ...) would otherwise be inherited into a process
 * that only needs its result pipe -- where glibc's NSS plugin chain
 * inside getaddrinfo() could reach them. Close everything above stdio
 * except keep_fd before resolving: close_range() first (kernel-side,
 * no ceiling, O(n) in the kernel), then /proc/self/fd enumeration
 * (complete regardless of fd numbers), then an uncapped
 * sysconf(_SC_OPEN_MAX) sweep as a last resort for no-/proc + pre-5.9
 * kernels. No artificial cap: a capped sweep could leave a high-numbered
 * inherited fd (e.g. 9000) open and reachable by NSS code. */
static void ac_close_extra_fds(int keep_fd)
{
#ifdef __linux__
    /* close_range(2): close [first, last] in one syscall. Split around
     * keep_fd so the result pipe survives. On success both halves are
     * done -- return without touching /proc at all. On ENOSYS (pre-5.9
     * kernel) or any other error, fall through to the portable paths. */
    if (keep_fd <= 2) {
        if (close_range(3, ~0U, 0) == 0)
            return;
    } else {
        int r1 = 0, r2 = 0;

        if (keep_fd > 3)
            r1 = close_range(3, (unsigned int)keep_fd - 1, 0);
        r2 = close_range((unsigned int)keep_fd + 1, ~0U, 0);
        if (r1 == 0 && r2 == 0)
            return;
    }
#endif
    {
        DIR *d = opendir("/proc/self/fd");

        if (d) {
            int dir_fd = dirfd(d);
            struct dirent *de;

            while ((de = readdir(d)) != NULL) {
                char *end;
                long fd;

                if (de->d_name[0] == '.')
                    continue;
                fd = strtol(de->d_name, &end, 10);
                if (*end != '\0')
                    continue;
                if (fd <= 2 || fd == keep_fd || fd == dir_fd)
                    continue;
                close((int)fd);
            }
            closedir(d);
            return;
        }
    }
    {
        /* Last resort: /proc unavailable and close_range missing/failed.
         * Sweep the real descriptor table size -- no cap, so a high fd
         * can't survive. Slow for huge RLIMIT_NOFILE, but this path only
         * runs on pre-5.9 kernels without /proc mounted. */
        long maxfd = sysconf(_SC_OPEN_MAX);
        long fd;

        if (maxfd < 0)
            maxfd = 1024;
        for (fd = 3; fd < maxfd; fd++) {
            if (fd == keep_fd)
                continue;
            close((int)fd);
        }
    }
}

/* getaddrinfo() has no built-in timeout: against a slow or blackholed DNS
 * path it can block for the resolver's own timeout, which runs well past
 * AC_REPORT_TIMEOUT_SEC. ac_report() runs synchronously in the daemon's
 * only thread, so an unbounded resolve here would stall AC_IOCTL_GET_EVENTS
 * polling and let the kernel-side event ring fill and start dropping real
 * detections. Resolve in a short-lived child and bound how long we wait
 * for it with poll(), the same technique ac_connect_timeout() above uses
 * to bound connect(). Returns the number of addresses resolved (>=0), or
 * -1 on failure/timeout; the child is always reaped before returning. */
static int ac_resolve_timeout(const char *host, const char *port,
                               struct ac_resolved_addr *out, int max,
                               int timeout_sec)
{
    int pfd[2];
    pid_t pid;
    int n = 0;

    if (pipe(pfd) < 0)
        return -1;

    pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (pid == 0) {
        struct addrinfo hints, *res, *rp;

        close(pfd[0]);
        /* fork() without exec() carries every inherited fd into the
         * child, O_CLOEXEC or not -- including dev_fd, the daemon's
         * held-open /dev/anticheat handle (see ac_open()'s comment on
         * what keeping it open does: pins the module for as long as an
         * fd is held). This child only needs the write end of its own
         * pipe; drop the rest before doing anything else so a resolve
         * triggered mid-scan doesn't leave a second, redundant reference
         * to the device alive in a second process -- and so NSS plugins
         * loaded by getaddrinfo() below can't reach the log fd, report
         * sockets, or any other daemon fd (fix #98). */
        ac_close_extra_fds(pfd[1]);
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host, port, &hints, &res) == 0) {
            for (rp = res; rp; rp = rp->ai_next) {
                struct ac_resolved_addr a;

                if (rp->ai_addrlen > sizeof(a.addr))
                    continue;
                memset(&a, 0, sizeof(a));
                a.family = rp->ai_family;
                a.socktype = rp->ai_socktype;
                a.protocol = rp->ai_protocol;
                a.addrlen = rp->ai_addrlen;
                memcpy(&a.addr, rp->ai_addr, rp->ai_addrlen);
                if (write(pfd[1], &a, sizeof(a)) != (ssize_t)sizeof(a))
                    break;
            }
            freeaddrinfo(res);
        }
        close(pfd[1]);
        _exit(0);
    }

    close(pfd[1]);
    /* An absolute deadline, not a per-call timeout_sec passed to every
     * poll(): restarting the full timeout on each iteration would let a
     * resolver trickling out one address per interval (or a slow child)
     * keep the parent here for up to (max + 1) * timeout_sec -- exactly
     * the unbounded stall this whole function exists to prevent. */
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += timeout_sec;
    /* read()/poll() on this fd can return early on a signal, and a pipe
     * gives no guarantee that a writer's single write() shows up as a
     * single reader-side read() -- so accumulate into a byte buffer
     * until a full record is available instead of assuming one read()
     * call yields one struct. The loop also stops as soon as `max`
     * addresses are collected rather than draining every record the
     * child sends, so a host with more than `max` records doesn't cost
     * extra poll()/read() round trips just to discard the rest. */
    unsigned char buf[sizeof(struct ac_resolved_addr)];
    size_t have = 0;
    while (n < max) {
        struct pollfd p = { .fd = pfd[0], .events = POLLIN };
        struct timespec now;
        long remaining_ms;
        ssize_t r;

        clock_gettime(CLOCK_MONOTONIC, &now);
        remaining_ms = (deadline.tv_sec - now.tv_sec) * 1000L +
                       (deadline.tv_nsec - now.tv_nsec) / 1000000L;
        if (remaining_ms <= 0)
            break;   /* overall resolve deadline exceeded */
        if (poll(&p, 1, (int)remaining_ms) <= 0)
            break;   /* timed out waiting on the resolver, or poll error */
        r = read(pfd[0], buf + have, sizeof(buf) - have);
        if (r <= 0)
            break;   /* child is done (successfully or not) */
        have += (size_t)r;
        if (have == sizeof(buf)) {
            memcpy(&out[n++], buf, sizeof(buf));
            have = 0;
        }
    }
    close(pfd[0]);
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    return n;
}

/* Escapes a string for embedding in a JSON string literal. event_type and
 * detail both ultimately derive from formatted log messages that can
 * contain attacker-influenced bytes (a process's comm name, a file path
 * from /proc), so this has to be correct, not just "usually fine" --
 * unescaped control characters or quotes here would let a crafted comm
 * name break the JSON body's structure. */
static void ac_json_escape(const char *in, char *out, size_t outsz)
{
    size_t o = 0;

    if (outsz == 0)
        return;
    for (; *in && o + 7 < outsz; in++) {
        unsigned char c = (unsigned char)*in;

        switch (c) {
        case '"':  out[o++] = '\\'; out[o++] = '"';  break;
        case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
        case '\n': out[o++] = '\\'; out[o++] = 'n';  break;
        case '\r': out[o++] = '\\'; out[o++] = 'r';  break;
        case '\t': out[o++] = '\\'; out[o++] = 't';  break;
        default:
            if (c < 0x20)
                o += (size_t)snprintf(out + o, outsz - o, "\\u%04x", c);
            else
                out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

/* /etc/machine-id is the standard systemd-provided stable-per-install
 * identifier; falling back to the hostname keeps reporting useful (if
 * less precise) on a system where it's absent rather than disabling
 * reporting outright. The hostname fallback is sanitized to the server's
 * CLIENT_ID_RE ([A-Za-z0-9._-]{1,128}) so an unusual hostname (spaces,
 * non-ASCII, quotes) can't get the report rejected with a 400 or corrupt
 * the JSON body -- fix #96. */
static void ac_report_client_id(char *out, size_t outsz)
{
    FILE *f = fopen("/etc/machine-id", "r");

    if (f) {
        if (fgets(out, (int)outsz, f)) {
            size_t n = strlen(out);

            while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
                out[--n] = '\0';
            if (out[0]) {
                fclose(f);
                return;
            }
        }
        fclose(f);
    }
    if (outsz == 0)
        return;
    if (gethostname(out, outsz) == 0) {
        char *p;

        out[outsz - 1] = '\0';
        for (p = out; *p; p++) {
            unsigned char c = (unsigned char)*p;

            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                  c == '-'))
                *p = '_';
        }
        if (out[0])
            return;
    }
    snprintf(out, outsz, "unknown");
}

/* Strict HTTP status-line parser: "HTTP/1.<minor> <code> <reason>", where
 * <minor> and <code> must each be exactly the digit count RFC 7230's
 * HTTP-version/status-code grammar specifies (one, three) -- not "one or
 * more" the way a naive digit-scanning loop would accept. sscanf()'s
 * "%d" would also accept a leading sign or extra digits -- e.g. a
 * malformed "HTTP/1.1 +200 OK" is not a valid status line, but "%d"
 * happily parses it as a real 200 and reports success anyway. The major
 * version is required to be exactly "1": ac_report() always speaks
 * plain HTTP/1.x over a raw socket (see the no-TLS note above), so
 * anything else -- "HTTP/2.0 200 OK" included -- cannot be a genuine
 * response from the configured report server and must fail closed
 * rather than being parsed as a 2xx. Returns the parsed code, or -1 if
 * resp isn't a well-formed status line (fails closed: -1 is never
 * inside the accepted 2xx range). */
static int ac_http_status_code(const char *resp)
{
    const char *p = resp;

    if (strncmp(p, "HTTP/1.", 7) != 0)
        return -1;
    p += 7;
    if (!isdigit((unsigned char)*p))
        return -1;
    p++;
    if (*p != ' ')
        return -1;
    p++;
    if (!isdigit((unsigned char)p[0]) || !isdigit((unsigned char)p[1]) ||
        !isdigit((unsigned char)p[2]))
        return -1;
    /* The three digits must end at a proper status-line delimiter: a
     * space before the reason-phrase, a line ending if the reason
     * phrase is empty, or end-of-buffer if the response was cut off
     * exactly there. Anything else -- a fourth digit, or a stray
     * non-space byte glued onto the code like "200X" -- means these
     * three digits aren't actually the whole status code. */
    if (p[3] != ' ' && p[3] != '\r' && p[3] != '\n' && p[3] != '\0')
        return -1;
    return (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');
}

#define AC_REPORT_UNIX_PREFIX "unix://"

/* A parsed AC_REPORT_URL: either a TCP host:port, or an AF_UNIX socket
 * path. `host` is dual-purpose -- for TCP it's the bare hostname passed
 * to ac_resolve_timeout() and reused verbatim as the HTTP Host: header;
 * for a unix:// destination there's no real hostname, so it's filled
 * with a fixed "localhost" placeholder for the Host: header only (the
 * same convention curl's --unix-socket uses), and sock_path carries the
 * actual filesystem path instead. */
struct ac_report_dest {
    int is_unix;
    char host[256];
    char port[32];
    char sock_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
};

/* Parses AC_REPORT_URL into *out. Returns 0 on success; returns -1 on a
 * malformed URL, having already logged what's wrong to stderr. Kept
 * separate from ac_report() itself so the parsing logic is unit-testable
 * without needing a real socket -- see test/ac_report_url_test.c. */
static int ac_report_parse_url(const char *url, struct ac_report_dest *out)
{
    const char *host_start, *host_end, *port_str;
    size_t host_len;
    const char *orig_url = url;

    memset(out, 0, sizeof(*out));

    if (strncmp(url, AC_REPORT_UNIX_PREFIX,
                strlen(AC_REPORT_UNIX_PREFIX)) == 0) {
        const char *path = url + strlen(AC_REPORT_UNIX_PREFIX);
        if (!*path) {
            fprintf(stderr,
                    "ac_report: unix:// AC_REPORT_URL missing a socket "
                    "path\n");
            return -1;
        }
        /* sun_path has no room for a trailing NUL past this length --
         * reject up front instead of silently truncating the path and
         * connecting to the wrong (or a nonexistent) socket. */
        if (strlen(path) >= sizeof(out->sock_path)) {
            fprintf(stderr, "ac_report: unix socket path too long: %s\n",
                    path);
            return -1;
        }
        out->is_unix = 1;
        snprintf(out->sock_path, sizeof(out->sock_path), "%s", path);
        snprintf(out->host, sizeof(out->host), "localhost");
        return 0;
    }

    /* Optional http:// or https:// scheme prefix — accept but ignore for
     * now. Daemon still speaks plain HTTP over TCP; in a TLS deployment
     * the reverse proxy terminates TLS and this still connects via plain
     * TCP to localhost (see THREAT_MODEL.md). Stripping the prefix lets
     * an operator copy a full URL from documentation without getting a
     * spurious "must be host:port" error, and keeps error messages
     * referencing the original URL via orig_url. Path after port
     * (e.g. /report) is also ignored — the request line is always
     * POST /report. */
    if (strncmp(url, "http://", 7) == 0)
        url += 7;
    else if (strncmp(url, "https://", 8) == 0)
        url += 8;

    /* TCP host:port — support both "host:port" and "[ipv6]:port".
     * Bracketed form is unambiguous for IPv6 literals; bare form keeps
     * backwards compat via last-colon split (e.g. "::1:8787" -> host "::1"). */
    if (url[0] == '[') {
        const char *close = strchr(url, ']');

        if (!close) {
            fprintf(stderr,
                    "ac_report: AC_REPORT_URL missing closing ']' in "
                    "IPv6 literal: %s\n", orig_url);
            return -1;
        }
        if (close[1] != ':') {
            fprintf(stderr,
                    "ac_report: AC_REPORT_URL IPv6 literal must be "
                    "followed by ':port': %s\n", url);
            return -1;
        }
        host_start = url + 1;
        host_end = close;
        port_str = close + 2;
        if (host_end == host_start) {
            fprintf(stderr,
                    "ac_report: AC_REPORT_URL has empty host: %s\n", url);
            return -1;
        }
        host_len = (size_t)(host_end - host_start);
    } else {
        const char *colon = strrchr(url, ':');

        if (!colon) {
            fprintf(stderr,
                    "ac_report: AC_REPORT_URL must be host:port or "
                    "unix:///path/to/socket\n");
            return -1;
        }
        host_start = url;
        host_end = colon;
        port_str = colon + 1;
        host_len = (size_t)(host_end - host_start);
        if (host_len == 0) {
            fprintf(stderr,
                    "ac_report: AC_REPORT_URL has empty host: %s\n", url);
            return -1;
        }
    }

    {
        const char *port_end = strchr(port_str, '/');
        size_t port_len = port_end ? (size_t)(port_end - port_str) : strlen(port_str);

        if (port_len == 0) {
            fprintf(stderr,
                    "ac_report: AC_REPORT_URL missing port: %s\n", orig_url);
            return -1;
        }
        if (port_len >= sizeof(out->port)) {
            fprintf(stderr,
                    "ac_report: AC_REPORT_URL port too long: %s\n", orig_url);
            return -1;
        }
        if (host_len >= sizeof(out->host)) {
            fprintf(stderr,
                    "ac_report: AC_REPORT_URL host too long: %s\n", orig_url);
            return -1;
        }
        {
            char port_buf[32];
            char *end;
            unsigned long port_val;

            memcpy(port_buf, port_str, port_len);
            port_buf[port_len] = '\0';
            port_val = strtoul(port_buf, &end, 10);
            if (end == port_buf || *end != '\0') {
                fprintf(stderr,
                        "ac_report: AC_REPORT_URL port is not numeric: %s\n",
                        orig_url);
                return -1;
            }
            if (port_val == 0 || port_val > 65535) {
                fprintf(stderr,
                        "ac_report: AC_REPORT_URL port out of range (1-65535): "
                        "%s\n", orig_url);
                return -1;
            }
            memcpy(out->port, port_buf, port_len + 1);
        }
    }
    memcpy(out->host, host_start, host_len);
    out->host[host_len] = '\0';
    return 0;
}



static void ac_report(const char *event_type, const char *detail)
{
    const char *url = getenv("AC_REPORT_URL");
    const char *key = getenv("AC_REPORT_KEY");
    char client_id[128], client_id_esc[256], et_esc[64], detail_esc[600];
    char body[1024], req[2048], resp[64];
    struct ac_report_dest dest;
    struct ac_resolved_addr addrs[AC_RESOLVE_MAX];
    int fd = -1, naddrs, ai;
    struct timeval tv;
    ssize_t n;

    if (!url || !*url || !key || !*key)
        return;   /* not configured -- silently a no-op, by design */

    if (ac_report_parse_url(url, &dest) != 0)
        return;   /* ac_report_parse_url() already logged what's wrong */

    ac_report_client_id(client_id, sizeof(client_id));
    /* Defense in depth for #96: even though ac_report_client_id()
     * sanitizes the hostname fallback to CLIENT_ID_RE, escape client_id
     * like the other two fields so no future caller can reintroduce a
     * JSON-injection path. 256 holds the 127-char max at 2x expansion
     * (quote/backslash doubling); a control-char-heavy /etc/machine-id
     * would truncate here, safely, the same way detail already can. */
    ac_json_escape(client_id, client_id_esc, sizeof(client_id_esc));
    ac_json_escape(event_type, et_esc, sizeof(et_esc));
    ac_json_escape(detail, detail_esc, sizeof(detail_esc));
    {
        int bodyn = snprintf(body, sizeof(body),
                 "{\"client_id\":\"%s\",\"event_type\":\"%s\",\"detail\":\"%s\","
                 "\"ts\":%lld}",
                 client_id_esc, et_esc, detail_esc, (long long)time(NULL));
        if (bodyn < 0 || (size_t)bodyn >= sizeof(body)) {
            fprintf(stderr, "ac_report: report body too large to send\n");
            return;
        }
    }
    if (dest.is_unix) {
        struct sockaddr_un sun;

        memset(&sun, 0, sizeof(sun));
        sun.sun_family = AF_UNIX;
        /* dest.sock_path is already bounded to sizeof(sun.sun_path) by
         * ac_report_parse_url(), so this can't overflow. */
        memcpy(sun.sun_path, dest.sock_path, sizeof(sun.sun_path));

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            fprintf(stderr, "ac_report: socket() failed: %s\n",
                    strerror(errno));
            return;
        }
        tv.tv_sec = AC_REPORT_TIMEOUT_SEC;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (ac_connect_timeout(fd, (struct sockaddr *)&sun, sizeof(sun),
                                AC_REPORT_TIMEOUT_SEC) != 0) {
            fprintf(stderr,
                    "ac_report: could not connect to unix socket %s: %s\n",
                    dest.sock_path, strerror(errno));
            close(fd);
            return;
        }
    } else {
        naddrs = ac_resolve_timeout(dest.host, dest.port, addrs,
                                     AC_RESOLVE_MAX, AC_REPORT_TIMEOUT_SEC);
        if (naddrs <= 0) {
            fprintf(stderr, "ac_report: could not resolve %s:%s\n",
                    dest.host, dest.port);
            return;
        }
        /* A hung/unreachable report server must never stall the security
         * monitoring loop -- ac_connect_timeout() bounds connect() itself
         * (which SO_SNDTIMEO/SO_RCVTIMEO do not, on Linux), and those two
         * still bound the subsequent send/recv on whichever address works. */
        for (ai = 0; ai < naddrs; ai++) {
            fd = socket(addrs[ai].family, addrs[ai].socktype,
                        addrs[ai].protocol);
            if (fd < 0)
                continue;
            tv.tv_sec = AC_REPORT_TIMEOUT_SEC;
            tv.tv_usec = 0;
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            if (ac_connect_timeout(fd, (struct sockaddr *)&addrs[ai].addr,
                                    addrs[ai].addrlen,
                                    AC_REPORT_TIMEOUT_SEC) == 0)
                break;
            close(fd);
            fd = -1;
        }
        if (fd < 0) {
            fprintf(stderr, "ac_report: could not connect to %s:%s\n",
                    dest.host, dest.port);
            return;
        }
    }

    {
        int reqn = snprintf(req, sizeof(req),
                 "POST /report HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "Authorization: Bearer %s\r\n"
                 "Content-Type: application/json\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n"
                 "\r\n"
                 "%s",
                 dest.host, key, strlen(body), body);

        /* snprintf() returns the length the fully-formatted request would
         * have needed, even when it truncated req[] to fit -- an
         * unusually long AC_REPORT_KEY (an operator-controlled env var,
         * but nothing bounds its length before this point) could
         * otherwise silently truncate the request while Content-Length
         * still names the full, untruncated body's size: a malformed
         * request whose own framing header lies about what follows it.
         * Bail out instead of sending that. */
        if (reqn < 0 || (size_t)reqn >= sizeof(req)) {
            fprintf(stderr, "ac_report: request too large to send "
                    "(AC_REPORT_KEY/AC_REPORT_URL too long?)\n");
            close(fd);
            return;
        }
    }

    {
        size_t reqlen = strlen(req);
        size_t sent = 0;

        /* A short write is normal TCP socket behavior (send-buffer
         * pressure, or interrupted by the SO_SNDTIMEO deadline this
         * socket has set) -- checking only for a negative return and
         * assuming anything else means the whole request went out would
         * let a partial, malformed HTTP request reach the server
         * silently. */
        while (sent < reqlen) {
            ssize_t w = write(fd, req + sent, reqlen - sent);

            if (w < 0) {
                fprintf(stderr, "ac_report: send failed: %s\n", strerror(errno));
                close(fd);
                return;
            }
            if (w == 0)
                break;
            sent += (size_t)w;
        }
        if (sent != reqlen) {
            fprintf(stderr, "ac_report: short write (%zu of %zu bytes)\n",
                    sent, reqlen);
            close(fd);
            return;
        }
    }
    n = read(fd, resp, sizeof(resp) - 1);
    {
        int code = -1;
        char body[64];

        /* n <= 0 (connection closed before any bytes arrived, or the
         * read itself failed/timed out) is exactly as much a failed
         * delivery as a non-2xx status -- resp is uninitialized in that
         * case, so log a fixed placeholder instead of reading it, but
         * still fail closed (code stays -1) and still log, instead of
         * silently falling through with no operator-visible indication
         * that the report never landed. */
        if (n > 0) {
            resp[n] = '\0';
            /* Parse the numeric status code from the status line only
             * -- scanning the whole raw response for " 200"/" 201" as
             * substrings would also match those digits inside a header
             * value (e.g. "Content-Length: 200") on an actual error
             * response and misreport a failed delivery as successful. */
            code = ac_http_status_code(resp);
            snprintf(body, sizeof(body), "%.60s", resp);
        } else if (n == 0) {
            snprintf(body, sizeof(body), "(connection closed, no response)");
        } else {
            snprintf(body, sizeof(body), "(read failed: %s)",
                     strerror(errno));
        }
        if (code < 200 || code >= 300)
            fprintf(stderr, "ac_report: server response status %d: %s\n",
                    code, body);
    }
    close(fd);
}

/* How long the monitor loop below asks AC_IOCTL_GET_EVENTS to block for
 * (via struct ac_event_list's block_ms field, see #61) when the ring is
 * empty -- matches the fixed 1s cadence the loop used to get for free
 * from sleep(1), so the periodic checks that share this loop iteration
 * (check_syscalls_periodic() and friends, each independently gated by
 * its own next_* deadline) keep running at the same granularity as
 * before. Real detections no longer wait out this window: the kernel
 * wakes a blocked GET_EVENTS the moment an event is pushed, regardless
 * of how much of block_ms is left. */
#define AC_MONITOR_BLOCK_MS 1000

static int cmd_start(int argc, char **argv)
{
    int foreground = 0, i;
    pid_t pid;

    for (i = 0; i < argc; i++)
        if (strcmp(argv[i], "--foreground") == 0)
            foreground = 1;

    if (geteuid() != 0)
        die("anticheat start must run as root");

    ac_open();   /* holds /dev/anticheat open -> module pinned while we live */

    /* ABI version handshake: fail fast, before forking into the
     * background, rather than let a stale module/daemon pairing surface
     * later as confusing runtime behavior (struct layout mismatches,
     * garbage fields, ...). See issue #64. */
    {
        struct ac_status st;

        if (ioctl_ok(AC_IOCTL_STATUS, &st) < 0)
            die("cannot query module status via %s -- refusing to start",
                AC_DEV_PATH);
        if (st.version != AC_IOCTL_VERSION)
            die("ioctl ABI version mismatch: daemon built for "
                "AC_IOCTL_VERSION=%d, but the loaded kernel module reports "
                "version=%llu -- refusing to start. Rebuild/reload a "
                "matching daemon and module pair.",
                AC_IOCTL_VERSION, st.version);
    }

    if (!foreground) {
        /* Classic double-fork daemonization: the first child exits right
         * after the second fork, so its pid is already dead by the time
         * anything could report it. Only the surviving grandchild's pid
         * is the one an operator can actually kill/track -- pass it back
         * to the original, terminal-attached parent over a pipe before
         * the intermediate first child exits, instead of printing the
         * first child's own (about-to-die) pid. Printing from the
         * grandchild itself isn't an option: by the time it exists,
         * stdout has already been freopen()'d to the log file below. */
        int pfd[2];

        if (pipe(pfd) < 0)
            die("pipe: %s", strerror(errno));

        pid = fork();
        if (pid < 0)
            die("fork: %s", strerror(errno));
        if (pid > 0) {
            pid_t final_pid = -1;
            ssize_t r;

            close(pfd[1]);
            r = read(pfd[0], &final_pid, sizeof(final_pid));
            close(pfd[0]);
            if (r == (ssize_t)sizeof(final_pid) && final_pid > 0) {
                printf("anticheat daemon started (pid %d)\n", final_pid);
                /* _exit() skips stdio flushing (unlike exit()) -- when
                 * stdout isn't a tty (e.g. redirected to a file/pipe by
                 * the caller) it's fully buffered rather than
                 * line-buffered, so without this the message above can
                 * be silently lost. */
                fflush(stdout);
                _exit(0);
            }
            fprintf(stderr, "anticheat: daemon failed to start\n");
            _exit(1);
        }
        close(pfd[0]);
        setsid();
        pid = fork();
        if (pid < 0)
            die("fork: %s", strerror(errno));
        if (pid > 0) {
            pid_t final_pid = pid;

            /* A single write() of a pid_t-sized buffer is well under
             * PIPE_BUF, so it's atomic -- the parent's read() above gets
             * it whole in one call. Best-effort: if this write somehow
             * fails, the parent's short/absent read falls back to the
             * failure message above. */
            ssize_t w = write(pfd[1], &final_pid, sizeof(final_pid));

            (void)w;
            close(pfd[1]);
            _exit(0);
        }
        close(pfd[1]);
        /* best-effort daemonization; failures are not fatal */
        if (chdir("/") < 0)
            fprintf(stderr, "daemon: chdir failed: %s\n", strerror(errno));
        if (!freopen("/dev/null", "r", stdin))
            fprintf(stderr, "daemon: stdin redirect failed\n");
        if (!freopen("/var/log/anticheat.log", "a", stdout))
            fprintf(stderr, "daemon: stdout redirect failed\n");
        if (!freopen("/var/log/anticheat.log", "a", stderr))
            fprintf(stderr, "daemon: stderr redirect failed\n");
        /* Prevent non-root ptrace of the daemon via /proc/self/mem or
         * PTRACE_ATTACH when running backgrounded: the daemon is already
         * self-protected via AC_IOCTL_ADD_PROC (ptrace kprobe), but making
         * it non-dumpable adds a second layer that stops even a
         * same-uid attacker from reading its memory through /proc/<pid>/mem
         * without CAP_SYS_PTRACE. Only when backgrounded: --foreground is
         * the debug path where a developer may want to strace/gdb it. */
        if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
            fprintf(stderr, "daemon: prctl PR_SET_DUMPABLE failed: %s\n",
                    strerror(errno));
    }

    openlog("anticheat", LOG_PID | LOG_NDELAY, LOG_AUTH);
    {
        /* sigaction(), not signal(): glibc's signal() installs handlers
         * with SA_RESTART, which would make the kernel silently restart
         * a blocked AC_IOCTL_GET_EVENTS (see #61) after this handler
         * returns instead of letting the -EINTR/-ERESTARTSYS the module
         * returns actually surface -- the monitor loop below would then
         * not notice g_stop until the next full block_ms wait finishes
         * (still bounded, but no longer near-instant the way sleep(1)'s
         * interrupt-on-signal behavior used to be). Explicitly leaving
         * SA_RESTART unset keeps shutdown latency on SIGTERM/SIGINT the
         * same as before this change. */
        struct sigaction sa;

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sig_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;   /* no SA_RESTART */
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
    }
    signal(SIGHUP, SIG_IGN);
    /* Without this, a report endpoint that accepts a connection and closes
     * it mid-write (hostile or just misbehaving) sends SIGPIPE, whose
     * default action terminates the process -- trivial remote DoS of the
     * whole monitoring daemon via ac_report()'s socket write(). write()
     * still reports EPIPE on the next call either way, which is already
     * handled below as an ordinary send failure. */
    signal(SIGPIPE, SIG_IGN);

    logmsg(LOG_INFO, "anticheat daemon started (foreground=%d)", foreground);
    {
        struct ac_proc_id self;

        /* Protect our own pid: a cheat that can ptrace-attach or debug the
         * daemon away is a cheat that can bypass everything else here too.
         * This only stops ptrace-based attacks (see the kernel module's
         * ptrace-deny hook) -- it does not stop SIGKILL from a
         * root-privileged attacker, which is outside what this module can
         * defend against by design (see README's threat-model notes). */
        memset(&self, 0, sizeof(self));
        self.pid = getpid();
        if (ioctl(dev_fd, AC_IOCTL_ADD_PROC, &self) < 0)
            logmsg(LOG_WARNING, "failed to self-protect (pid %d): %s",
                   self.pid, strerror(errno));
        else
            logmsg(LOG_INFO, "self-protected (pid %d)", self.pid);
    }
    {
        /* Checked once here, not polled: whether the OS itself is
         * virtualized can't change mid-boot the way RWX growth or
         * hidden modules can. LOG_WARNING/LOG_INFO only, deliberately
         * never LOG_ALERT/LOG_CRIT -- see cmd_vmcheck()'s own comment
         * block for why this must never auto-feed the ban pipeline. */
        char cpuid_vendor[16];
        char dmi_desc[192];
        int cpuid_hit = detect_hypervisor_cpuid(cpuid_vendor, sizeof(cpuid_vendor));
        int dmi_hit = detect_hypervisor_dmi(dmi_desc, sizeof(dmi_desc));

        if (cpuid_hit)
            logmsg(LOG_WARNING, "running inside a virtual machine "
                   "(CPUID vendor id: %s%s%s) -- informational, not a verdict",
                   cpuid_vendor, dmi_hit ? "; " : "", dmi_hit ? dmi_desc : "");
        else if (dmi_hit)
            logmsg(LOG_WARNING, "running inside a virtual machine "
                   "(%s) -- informational, not a verdict", dmi_desc);
        else
            logmsg(LOG_INFO, "no hypervisor detected (CPUID/DMI checks)");
    }
    {
        time_t next_sys = 0, next_mod = 0, next_scan = 0, next_baseline = 0;
        time_t next_render = 0, next_preload = 0, next_vklayer = 0;
        time_t next_implicit = 0;

        while (!g_stop) {
            struct ac_event_list el;
            struct timespec t0, t1;
            long waited_ms;
            time_t now;
            int got;

            memset(&el, 0, sizeof(el));
            el.block_ms = AC_MONITOR_BLOCK_MS;
            clock_gettime(CLOCK_MONOTONIC, &t0);
            got = ioctl(dev_fd, AC_IOCTL_GET_EVENTS, &el);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            waited_ms = (t1.tv_sec - t0.tv_sec) * 1000L +
                        (t1.tv_nsec - t0.tv_nsec) / 1000000L;
            /* got < 0 here from a SIGTERM/SIGINT during the blocking
             * ioctl (-EINTR/-ERESTARTSYS, see the sigaction comment
             * above) must skip straight to the while(!g_stop) check --
             * otherwise the periodic checks and the fallback sleep
             * below would still run first, burning most of block_ms
             * and defeating the whole point of leaving SA_RESTART
             * unset. Any other ioctl failure (e.g. ENOTTY from a
             * legacy module) falls through to the fallback sleep as
             * before. */
            if (got < 0 && g_stop)
                break;
            if (got == 0) {
                for (i = 0; i < (int)el.count; i++) {
                    struct ac_event *e = &el.events[i];

                    if (e->type == AC_EV_PTRACE || e->type == AC_EV_PROCESS_VM)
                        logmsg(LOG_ALERT, "%s pid=%d comm=%s %s",
                               ev_type_str(e->type), e->pid, e->comm, e->data);
                    else if (e->type == AC_EV_SYSCALL_HOOK ||
                             e->type == AC_EV_SYSCALL_REDIRECT)
                        logmsg(LOG_CRIT, "%s %s", ev_type_str(e->type), e->data);
                    else
                        logmsg(LOG_INFO, "%s pid=%d comm=%s %s",
                               ev_type_str(e->type), e->pid, e->comm, e->data);
                }
            }
            now = time(NULL);
            if (now >= next_sys) {
                check_syscalls_periodic();
                next_sys = now + 5;
            }
            if (now >= next_mod) {
                check_modules_periodic();
                next_mod = now + 10;
            }
            if (now >= next_scan) {
                scan_protected_periodic();
                next_scan = now + ac_scan_check_interval();
            }
            if (now >= next_baseline) {
                check_baselines_periodic();
                next_baseline = now + ac_baseline_check_interval();
            }
            if (now >= next_render) {
                check_render_hooks_periodic();
                next_render = now + ac_render_hook_check_interval();
            }
            if (now >= next_preload) {
                check_ld_preload_periodic();
                next_preload = now + ac_ld_preload_check_interval();
            }
            if (now >= next_vklayer) {
                check_vk_layers_periodic();
                next_vklayer = now + ac_vk_layer_check_interval();
            }
            if (now >= next_implicit) {
                check_implicit_layers_periodic();
                next_implicit = now + ac_implicit_layer_check_interval();
            }
            /* Fallback for anything that doesn't actually honor block_ms
             * -- a module built before this field existed (ioctl number
             * mismatch -> ENOTTY), or the userspace mock, which answers
             * GET_EVENTS immediately regardless of block_ms (see
             * test/mock_anticheat.c). In either case the ioctl call
             * above returned almost instantly with no events, and
             * without this the loop would busy-spin at 100% CPU instead
             * of blocking. When the kernel *did* block for us (real
             * events made it return early, or it genuinely waited out
             * block_ms with nothing arriving) this is a no-op -- the
             * loop's cadence is unchanged from the old fixed sleep(1). */
            if ((got != 0 || el.count == 0) && waited_ms < AC_MONITOR_BLOCK_MS)
                usleep((useconds_t)(AC_MONITOR_BLOCK_MS - waited_ms) * 1000);
        }
    }
    logmsg(LOG_INFO, "anticheat daemon stopped");
    ac_close();
    closelog();
    return 0;
}

/* ------------------------------------------------------------------ */
static void usage(const char *prog)
{
    printf("usage: %s <command> [options]\n"
           "\n"
           "  status                     kernel module status\n"
           "  protect --pid N [--ns-of REFPID] [--jit] | --comm NAME [--jit]\n"
           "  unprotect --pid N [--ns-of REFPID]\n"
           "  list                       list protected processes\n"
           "  scan --pid N [--ns-of REFPID] [--hash [--save|--check]] [--check-hooks] "
           "[--check-preload]\n"
           "           [--check-vklayers] [--check-implicit-layers]\n"
           "  syscalls                   verify syscall table integrity\n"
           "  modules                    kernel module list + hidden module check\n"
           "  vmcheck                    VM/hypervisor detection (heuristic)\n"
           "  events [--watch]           dump security events\n"
           "  lock | unlock              pin / unpin the kernel module\n"
           "  start [--foreground]       run the monitoring daemon\n"
           "\n"
           "All commands except 'start' may also require root.\n",
           prog);
}

int main(int argc, char **argv)
{
    const char *cmd = argc > 1 ? argv[1] : "help";

    if (geteuid() != 0 && strcmp(cmd, "help") != 0) {
        /* the kernel device enforces CAP_SYS_ADMIN anyway; pre-check helps */
        fprintf(stderr, "warning: this tool is designed to run as root\n");
    }

    if (strcmp(cmd, "status") == 0)
        return cmd_status();
    if (strcmp(cmd, "protect") == 0)
        return cmd_protect(argc - 2, argv + 2);
    if (strcmp(cmd, "unprotect") == 0)
        return cmd_unprotect(argc - 2, argv + 2);
    if (strcmp(cmd, "list") == 0)
        return cmd_list();
    if (strcmp(cmd, "scan") == 0)
        return cmd_scan(argc - 2, argv + 2);
    if (strcmp(cmd, "syscalls") == 0)
        return cmd_syscalls();
    if (strcmp(cmd, "modules") == 0)
        return cmd_modules();
    if (strcmp(cmd, "vmcheck") == 0)
        return cmd_vmcheck();
    if (strcmp(cmd, "events") == 0)
        return cmd_events(argc - 2, argv + 2);
    if (strcmp(cmd, "lock") == 0)
        return cmd_lock(1);
    if (strcmp(cmd, "unlock") == 0)
        return cmd_lock(0);
    if (strcmp(cmd, "start") == 0)
        return cmd_start(argc - 2, argv + 2);
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 ||
        strcmp(cmd, "-h") == 0) {
        usage(argv[0]);
        return 0;
    }
    fprintf(stderr, "unknown command '%s'\n\n", cmd);
    usage(argv[0]);
    return 1;
}
