/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * test/mock_anticheat.c — a userspace stand-in for the anticheat kernel
 * module.  Loaded with LD_PRELOAD it makes the daemon CLI run end-to-end
 * without root or a real kernel module:
 *
 *   make test-mock        (or: LD_PRELOAD=test/libmock_anticheat.so ./anticheat status)
 *
 * Intercepted symbols (through the PLT):
 *   open/open64/openat/openat64  — AC_DEV_PATH returns a fake fd
 *   ioctl                        — implements the AC_IOCTL_* ABI
 *   close                        — swallows the fake fd
 *   geteuid/getuid               — returns 0 while AC_MOCK_ROOT=1
 *   process_vm_readv/writev      — denies protected pids (AC_EV_PROCESS_VM)
 *   pread/pread64                — fakes /proc/<pid>/mem for hook mock
 *   opendir/readdir/closedir     — fakes implicit_layer.d for manifest mock
 *
 * State (protected list, lock, event queue) persists across CLI
 * invocations in $AC_MOCK_STATE (default /tmp/ac_mock_state), mirroring
 * what the kernel module keeps alive between ioctls.
 *
 * Behaviour knobs (environment):
 *   AC_MOCK_ROOT=1      fake root (geteuid == 0)
 *   AC_MOCK_ATTACK=1    simulate a ptrace attack (PTRACE-DENIED events)
 *   AC_MOCK_HOOKED=1    simulate a compromised syscall table (out-of-text)
 *   AC_MOCK_REDIRECT=1  simulate an in-text syscall handler swap since the
 *                       boot baseline (SYSCALL-REDIRECT events; see #63)
 *   AC_MOCK_CHECKSUM_ONLY=1
 *                       simulate a whole-table checksum mismatch with no
 *                       per-slot hook/redirect flagged (see #63)
 *   AC_MOCK_VERSION=N   report ioctl ABI version N instead of the real
 *                       AC_IOCTL_VERSION (simulates a stale module)
 *   AC_MOCK_STATE=path  state file location
 *   AC_MOCK_HOOK_LIB=lib:symbol:status
 *                       inject a synthetic VMA for render-hook checks;
 *                       status is hooked|clean|inconclusive (e.g.
 *                       libvulkan.so.1:vkQueuePresentKHR:hooked)
 *   AC_MOCK_ENVIRON=entries
 *                       fake /proc/<pid>/environ content; entries are
 *                       KEY=VALUE separated by ';' (e.g.
 *                       LD_PRELOAD=/tmp/evil.so;VK_INSTANCE_LAYERS=...)
 *   AC_MOCK_MANIFEST=spec
 *                       fake implicit Vulkan layer manifest; spec is
 *                       name:library_path[:disable_env] or raw JSON
 *                       containing "name"
 *   AC_MOCK_ANON_EXEC_COUNT=N or pid:N,...
 *                       override anon_exec_count for SCAN_BEGIN; when set
 *                       the mock increments per-pid on each scan to
 *                       simulate growth for --jit downgrade tests
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include "../src/anticheat.h"

#define MOCK_FD 4242

/* ------------------------------------------------------------------ */
/* persistent state (survives across CLI processes, like the module)   */
/* ------------------------------------------------------------------ */
struct mock_state {
    unsigned int locked;
    unsigned int events_dropped_total;
    struct ac_prot_item prots[AC_MAX_PROTS];
    unsigned int nprots;
    struct ac_event evq[AC_MAX_EVENTS];
    unsigned int n_evq;
};

static struct mock_state S;
static char state_path[PATH_MAX] = "/tmp/ac_mock_state";
static int drain_count;

static void load_state(void)
{
    const char *e = getenv("AC_MOCK_STATE");
    FILE *f;

    if (e && *e)
        snprintf(state_path, sizeof(state_path), "%s", e);
    memset(&S, 0, sizeof(S));
    f = fopen(state_path, "rb");
    if (f) {
        if (fread(&S, sizeof(S), 1, f) != 1)
            memset(&S, 0, sizeof(S));   /* empty/corrupt state: start fresh */
        fclose(f);
    }
}

static void save_state(void)
{
    FILE *f = fopen(state_path, "wb");

    if (f) {
        if (fwrite(&S, sizeof(S), 1, f) != 1) {
            /* short write: drop the partial state; load_state resets
             * corrupt files, so a failed unlink is harmless */
            int rc = unlink(state_path);
            (void)rc;
        }
        fclose(f);
    }
}

/* ------------------------------------------------------------------ */
/* event queue                                                         */
/* ------------------------------------------------------------------ */
static void push_event(int type, int pid, const char *comm,
                       const char *fmt, ...)
{
    struct ac_event *e;
    va_list ap;

    if (S.n_evq >= AC_MAX_EVENTS) {
        S.events_dropped_total++;
        return;
    }
    e = &S.evq[S.n_evq++];
    memset(e, 0, sizeof(*e));
    e->ts = (unsigned long long)time(NULL) * 1000000000ULL;
    e->pid = pid;
    snprintf(e->comm, sizeof(e->comm), "%s", comm ? comm : "?");
    e->type = type;
    va_start(ap, fmt);
    vsnprintf(e->data, sizeof(e->data), fmt, ap);
    va_end(ap);
    save_state();
}

static void read_comm(int pid, char *out, size_t n)
{
    char path[64], *nl;
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    f = fopen(path, "r");
    if (!f) {
        snprintf(out, n, "?");
        return;
    }
    if (!fgets(out, (int)n, f))
        snprintf(out, n, "?");
    else if ((nl = strchr(out, '\n')))
        *nl = '\0';
    fclose(f);
}

/* Userspace analog of the real module's "t->flags & PF_KTHREAD" check --
 * see the AC_IOCTL_ADD_PROC comment below. /proc/<pid>/stat field 9 is the
 * task's raw kernel flags word (see `man 5 proc`), the same value the
 * module reads off t->flags, so this mirrors PF_KTHREAD exactly instead of
 * inferring it from an empty /proc/<pid>/cmdline -- a zombie userspace
 * process also reads back 0 bytes of cmdline and would have been
 * misclassified as a kernel thread by that heuristic. */
#define AC_MOCK_PF_KTHREAD 0x00200000UL
static int is_kthread_like(int pid)
{
    char path[64], line[512], *rparen;
    FILE *f;
    unsigned long flags;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    f = fopen(path, "r");
    if (!f)
        return 0;   /* pid gone / unreadable: not our call to make here */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);

    /* comm is the parenthesized 2nd field and may itself contain ')', so
     * skip to the *last* ')' before splitting the remaining fields --
     * same technique `man 5 proc` recommends. */
    rparen = strrchr(line, ')');
    if (!rparen)
        return 0;
    /* Fields after comm: state, ppid, pgrp, session, tty_nr, tpgid, flags.
     * flags is the 7th, i.e. the last of these six is skipped first. */
    if (sscanf(rparen + 1, " %*c %*d %*d %*d %*d %*d %lu", &flags) != 1)
        return 0;
    return (flags & AC_MOCK_PF_KTHREAD) != 0;
}

/* ------------------------------------------------------------------ */
/* VMA scan snapshot (parses /proc/<pid>/maps like the module walks    */
/* the mmap maple tree)                                                */
/* ------------------------------------------------------------------ */
static struct ac_vma_info *snap;
static unsigned int snap_n;

/* Mirrors ac_last_hook_count in the real module: only CHECK_SYSCALLS sets
 * it, and STATUS just reports whatever it was last set to (0 if
 * CHECK_SYSCALLS has never run). Deriving this straight from
 * AC_MOCK_HOOKED in the STATUS handler instead would make the mock report
 * a hook count before any check ever ran -- a real caller that reads
 * STATUS before triggering a check would never observe that with the
 * real module. */
static unsigned int last_hook_count;
/* Same rising-edge convention as last_hook_count above, but for the
 * boot-baseline in-text-redirect check (AC_EV_SYSCALL_REDIRECT, #63). */
static unsigned int last_redirect_count;

/* Fill a 65-byte digest buffer with 64 repeats of `c` + NUL. Not a real
 * SHA-256 digest -- the mock only needs the daemon/CLI to see
 * baseline_ready plus a current_sha256 that differs from baseline_sha256
 * exactly when a redirect/hook is simulated, mirroring what
 * AC_IOCTL_CHECK_SYSCALLS reports against the real module. */
static void mock_fill_digest(char out_hex[65], char c)
{
    memset(out_hex, c, 64);
    out_hex[64] = '\0';
}

/* ------------------------------------------------------------------ */
/* helpers for env-driven mocks (hook, anon, environ, manifest)        */
/* ------------------------------------------------------------------ */
struct hook_cfg {
    char lib[64];
    char sym[64];
    char status[16]; /* hooked|clean|inconclusive */
    int valid;
};
static struct hook_cfg g_hook;
static unsigned long long g_hook_base = 0x7f0000000000ULL;
static char g_hook_tmp_path[PATH_MAX] = "";

static int parse_hook_env(struct hook_cfg *out)
{
    const char *e = getenv("AC_MOCK_HOOK_LIB");
    char buf[256];
    char *p1, *p2;
    if (!e || !*e) {
        out->valid = 0;
        return 0;
    }
    snprintf(buf, sizeof(buf), "%s", e);
    p1 = strchr(buf, ':');
    if (!p1) return 0;
    *p1++ = '\0';
    p2 = strchr(p1, ':');
    if (!p2) return 0;
    *p2++ = '\0';
    strncpy(out->lib, buf, sizeof(out->lib)-1); out->lib[sizeof(out->lib)-1]='\0';
    strncpy(out->sym, p1, sizeof(out->sym)-1); out->sym[sizeof(out->sym)-1]='\0';
    strncpy(out->status, p2, sizeof(out->status)-1); out->status[sizeof(out->status)-1]='\0';
    out->valid = 1;
    return 1;
}

static int is_environ_path(const char *path)
{
    /* matches /proc/<pid>/environ exactly */
    if (!path) return 0;
    if (strncmp(path, "/proc/", 6) != 0) return 0;
    const char *slash = strchr(path+6, '/');
    if (!slash) return 0;
    return strcmp(slash, "/environ") == 0;
}
static int is_mem_path(const char *path)
{
    if (!path) return 0;
    if (strncmp(path, "/proc/", 6) != 0) return 0;
    const char *slash = strchr(path+6, '/');
    if (!slash) return 0;
    return strcmp(slash, "/mem") == 0;
}
static int __attribute__((unused)) is_manifest_json_path(const char *path)
{
    if (!path) return 0;
    if (!strstr(path, "implicit_layer.d")) return 0;
    size_t l = strlen(path);
    if (l < 5) return 0;
    return strcmp(path + l - 5, ".json") == 0;
}
static int __attribute__((unused)) is_implicit_dir(const char *path)
{
    if (!path) return 0;
    return strstr(path, "implicit_layer.d") != NULL;
}

/* locate host lib for hook: try /usr/lib/<lib>, /usr/lib64/<lib> etc. */
static int locate_host_lib(const char *lib, char *out, size_t outsz)
{
    const char *cands[] = {
        "/usr/lib/%s",
        "/usr/lib64/%s",
        "/usr/lib/x86_64-linux-gnu/%s",
        "/lib/%s",
        "/lib64/%s",
        NULL
    };
    int i;
    char tmp[PATH_MAX];
    if (strchr(lib, '/')) {
        if (access(lib, R_OK) == 0) {
            snprintf(out, outsz, "%s", lib);
            return 0;
        }
        return -1;
    }
    for (i = 0; cands[i]; i++) {
        snprintf(tmp, sizeof(tmp), cands[i], lib);
        if (access(tmp, R_OK) == 0) {
            snprintf(out, outsz, "%s", tmp);
            return 0;
        }
    }
    /* try with .so suffix variations: lib may be libvulkan.so.1 but we have libvulkan.so */
    return -1;
}

static int copy_file(const char *src, const char *dst)
{
    int sfd = -1, dfd = -1;
    char buf[8192];
    ssize_t n;
    /* use real open via dlsym to avoid our own interposition */
    int (*real_open)(const char *, int, ...) = dlsym(RTLD_NEXT, "open");
    if (!real_open) return -1;
    sfd = real_open(src, O_RDONLY);
    if (sfd < 0) return -1;
    dfd = real_open(dst, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (dfd < 0) { close(sfd); return -1; }
    while ((n = read(sfd, buf, sizeof(buf))) > 0) {
        if (write(dfd, buf, (size_t)n) != n) break;
    }
    close(sfd);
    close(dfd);
    return 0;
}

static int ensure_hook_tmp_file(const char *lib)
{
    char host[PATH_MAX] = "";
    char tmp[PATH_MAX];
    if (!lib || !*lib) return -1;
    snprintf(tmp, sizeof(tmp), "/tmp/%s", lib);
    /* basename may contain slash? we used lib as basename, ensure no dir */
    (void)tmp;
    /* already /tmp/<lib> */
    if (access(tmp, R_OK) == 0) {
        snprintf(g_hook_tmp_path, sizeof(g_hook_tmp_path), "%s", tmp);
        return 0;
    }
    if (locate_host_lib(lib, host, sizeof(host)) == 0) {
        if (copy_file(host, tmp) == 0) {
            snprintf(g_hook_tmp_path, sizeof(g_hook_tmp_path), "%s", tmp);
            return 0;
        }
    }
    /* fallback: try libvulkan as generic */
    if (locate_host_lib("libvulkan.so.1", host, sizeof(host)) == 0) {
        if (copy_file(host, tmp) == 0) {
            snprintf(g_hook_tmp_path, sizeof(g_hook_tmp_path), "%s", tmp);
            return 0;
        }
    }
    return -1;
}

/* anon exec count per-pid map for AC_MOCK_ANON_EXEC_COUNT */
struct anon_mock_entry { int pid; unsigned int count; int in_use; };
static struct anon_mock_entry anon_mocks[AC_MAX_PROTS];

static unsigned int get_mock_anon_count(int pid, unsigned int real_count)
{
    const char *e = getenv("AC_MOCK_ANON_EXEC_COUNT");
    char buf[256];
    unsigned int base = 0;
    int i, free_slot = -1;
    if (!e || !*e) return real_count;
    /* parse per-pid form pid:N or single N */
    if (strchr(e, ':') && !strchr(e, ';') && !strchr(e, ',')) {
        /* could be single pid:N or single N with colon? For hook env colon is different.
         * For anon, treat "123:5" as pid:count if pid part is numeric */
        const char *colon = strchr(e, ':');
        if (colon) {
            char left[64], right[64];
            size_t llen = (size_t)(colon - e);
            if (llen < sizeof(left)) {
                memcpy(left, e, llen);
                left[llen] = '\0';
                snprintf(right, sizeof(right), "%s", colon+1);
                int is_pid = 1;
                for (char *c = left; *c; c++) if (*c < '0' || *c > '9') is_pid = 0;
                if (is_pid) {
                    int p = atoi(left);
                    unsigned int c = (unsigned int)atoi(right);
                    if (p == pid) return c; /* exact per-pid without growth */
                    /* else fall through to generic */
                }
            }
        }
    }
    /* generic integer or comma list */
    if (strchr(e, ',')) {
        /* pid:count, pid:count */
        snprintf(buf, sizeof(buf), "%s", e);
        char *tok = strtok(buf, ",");
        while (tok) {
            char *c = strchr(tok, ':');
            if (c) {
                *c++ = '\0';
                int p = atoi(tok);
                unsigned int cnt = (unsigned int)atoi(c);
                if (p == pid) {
                    /* found per-pid entry: handle growth via anon_mocks */
                    for (i = 0; i < AC_MAX_PROTS; i++) {
                        if (anon_mocks[i].in_use && anon_mocks[i].pid == pid) {
                            anon_mocks[i].count++;
                            return anon_mocks[i].count;
                        }
                        if (free_slot == -1 && !anon_mocks[i].in_use) free_slot = i;
                    }
                    if (free_slot != -1) {
                        anon_mocks[free_slot].pid = pid;
                        anon_mocks[free_slot].count = cnt;
                        anon_mocks[free_slot].in_use = 1;
                        return cnt;
                    }
                    return cnt;
                }
            }
            tok = strtok(NULL, ",");
        }
        /* not found for this pid, use real */
        return real_count;
    }
    /* single integer for all pids with growth */
    base = (unsigned int)atoi(e);
    for (i = 0; i < AC_MAX_PROTS; i++) {
        if (anon_mocks[i].in_use && anon_mocks[i].pid == pid) {
            anon_mocks[i].count++;
            return anon_mocks[i].count;
        }
        if (free_slot == -1 && !anon_mocks[i].in_use) free_slot = i;
    }
    if (free_slot != -1) {
        anon_mocks[free_slot].pid = pid;
        anon_mocks[free_slot].count = base ? base : real_count;
        anon_mocks[free_slot].in_use = 1;
        return anon_mocks[free_slot].count;
    }
    return base ? base : real_count;
}

/* create temp file with given content and return fd (already unlinked) */
static int make_temp_fd_with_content(const void *data, size_t len)
{
    char tmpl[] = "/tmp/ac_mock_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    unlink(tmpl);
    if (len && write(fd, data, len) != (ssize_t)len) { close(fd); return -1; }
    lseek(fd, 0, SEEK_SET);
    return fd;
}
static int make_fake_environ_fd(void)
{
    const char *e = getenv("AC_MOCK_ENVIRON");
    char buf[8192];
    size_t off = 0;
    char tmp[4096];
    char *p, *save;
    if (!e || !*e) return -1;
    snprintf(tmp, sizeof(tmp), "%s", e);
    /* entries separated by ';' or '\n' */
    p = strtok_r(tmp, ";\n", &save);
    while (p) {
        /* trim leading spaces */
        while (*p == ' ' || *p == '\t') p++;
        if (*p) {
            size_t l = strlen(p);
            if (off + l + 1 < sizeof(buf)) {
                memcpy(buf + off, p, l);
                off += l;
                buf[off++] = '\0';
            }
        }
        p = strtok_r(NULL, ";\n", &save);
    }
    if (off == 0) return -1;
    return make_temp_fd_with_content(buf, off);
}
static int make_fake_manifest_fd(void)
{
    const char *e = getenv("AC_MOCK_MANIFEST");
    char json[2048];
    if (!e || !*e) return -1;
    if (strchr(e, '{')) {
        snprintf(json, sizeof(json), "%s", e);
    } else {
        /* parse name:library_path[:disable_env] */
        char buf[1024];
        char *p1, *p2;
        char name[256]="", libpath[256]="", dis[256]="";
        snprintf(buf, sizeof(buf), "%s", e);
        p1 = strchr(buf, ':');
        if (p1) {
            *p1++ = '\0';
            strncpy(name, buf, sizeof(name)-1); name[sizeof(name)-1]='\0';
            p2 = strchr(p1, ':');
            if (p2) {
                *p2++ = '\0';
                snprintf(libpath, sizeof(libpath), "%s", p1);
                snprintf(dis, sizeof(dis), "%s", p2);
            } else {
                snprintf(libpath, sizeof(libpath), "%s", p1);
            }
        } else {
            strncpy(name, buf, sizeof(name)-1); name[sizeof(name)-1]='\0';
            strncpy(libpath, "/tmp/fake.so", sizeof(libpath)-1); libpath[sizeof(libpath)-1]='\0';
        }
        if (!name[0]) snprintf(name, sizeof(name), "VK_LAYER_mock");
        if (!libpath[0]) snprintf(libpath, sizeof(libpath), "/tmp/fake.so");
        if (dis[0]) {
            snprintf(json, sizeof(json),
                "{\"file_format_version\":\"1.0.0\",\"layer\":{"
                "\"name\":\"%s\",\"library_path\":\"%s\","
                "\"api_version\":\"1.0.0\",\"implementation_version\":\"1\","
                "\"description\":\"mock\",\"disable_environment\":\"%s\"}}",
                name, libpath, dis);
        } else {
            snprintf(json, sizeof(json),
                "{\"file_format_version\":\"1.0.0\",\"layer\":{"
                "\"name\":\"%s\",\"library_path\":\"%s\","
                "\"api_version\":\"1.0.0\",\"implementation_version\":\"1\","
                "\"description\":\"mock\"}}",
                name, libpath);
        }
    }
    return make_temp_fd_with_content(json, strlen(json));
}

/* mem fd tracking for hook */
#define MAX_MEM_FDS 32
static int mem_fds[MAX_MEM_FDS];
static int mem_fds_cnt = 0;
static void track_mem_fd(int fd) {
    if (mem_fds_cnt < MAX_MEM_FDS) mem_fds[mem_fds_cnt++] = fd;
}
static int is_tracked_mem_fd(int fd) {
    int i;
    for (i=0;i<mem_fds_cnt;i++) if (mem_fds[i]==fd) return 1;
    return 0;
}
static void untrack_mem_fd(int fd) {
    int i, j;
    for (i=0;i<mem_fds_cnt;i++) if (mem_fds[i]==fd) {
        for (j=i;j+1<mem_fds_cnt;j++) mem_fds[j]=mem_fds[j+1];
        mem_fds_cnt--;
        break;
    }
}

/* fake DIR handling */
struct fake_dir {
    int in_use;
    int returned;
    char path[PATH_MAX];
};
static struct fake_dir fake_dirs[16];
static struct dirent fake_dirent;
static struct dirent *fake_dirent_ptr = NULL;

static DIR *alloc_fake_dir(const char *path)
{
    int i;
    for (i=0;i<16;i++) if (!fake_dirs[i].in_use) {
        fake_dirs[i].in_use = 1;
        fake_dirs[i].returned = 0;
        snprintf(fake_dirs[i].path, sizeof(fake_dirs[i].path), "%s", path);
        return (DIR*)&fake_dirs[i];
    }
    return NULL;
}
static struct fake_dir *find_fake_dir(DIR *d)
{
    int i;
    for (i=0;i<16;i++) if (fake_dirs[i].in_use && (DIR*)&fake_dirs[i]==d) return &fake_dirs[i];
    return NULL;
}

static void do_scan(int pid)
{
    char path[64], line[512];
    FILE *f;

    free(snap);
    snap = NULL;
    snap_n = 0;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    f = fopen(path, "r");
    if (!f)
        return;

    while (fgets(line, sizeof(line), f)) {
        struct ac_vma_info vi;
        unsigned long long start, end, off, inode;
        char perms[8] = "", dev[16] = "", p[AC_VMA_PATH] = "";
        unsigned long flags = 0;
        int n;

        memset(&vi, 0, sizeof(vi));
        n = sscanf(line, "%llx-%llx %7s %llx %15s %llu %127s",
                   &start, &end, perms, &off, dev, &inode, p);
        if (n < 6)
            continue;
        if (strchr(perms, 'r'))
            flags |= 0x1;   /* VM_READ */
        if (strchr(perms, 'w'))
            flags |= AC_VM_WRITE;   /* VM_WRITE */
        if (strchr(perms, 'x'))
            flags |= AC_VM_EXEC;     /* VM_EXEC */
        vi.start = start;
        vi.end = end;
        vi.offset = off;
        vi.inode = inode;
        vi.flags = flags;
        vi.is_file = inode != 0;
        if (n >= 7)
            snprintf(vi.path, sizeof(vi.path), "%s", p);
        if (snap_n < AC_MAX_VMAS) {
            snap = realloc(snap, (snap_n + 1) * sizeof(*snap));
            if (!snap) {
                snap_n = 0;
                break;
            }
            snap[snap_n++] = vi;
        }
    }
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* module list (real /proc/modules + one injected hidden module)       */
/* ------------------------------------------------------------------ */
static struct ac_mod_info *mods;
static unsigned int mods_n;

static void build_mods(void)
{
    char line[512];
    FILE *f;
    unsigned int cap = 512;

    free(mods);
    mods = NULL;
    mods_n = 0;
    mods = calloc(cap, sizeof(*mods));
    if (!mods)
        return;

    f = fopen("/proc/modules", "r");
    if (f) {
        while (fgets(line, sizeof(line), f) && mods_n < cap - 1) {
            if (sscanf(line, "%63s", mods[mods_n].name) == 1) {
                mods[mods_n].state = 0;   /* MODULE_STATE_LIVE */
                mods_n++;
            }
        }
        fclose(f);
    }
    /* the mock always injects one module hidden from /proc/modules,
     * exactly what a rootkit would do */
    snprintf(mods[mods_n].name, sizeof(mods[mods_n].name), "hidden_rootkit");
    mods[mods_n].size = 0xdead;
    mods[mods_n].state = 0;
    mods_n++;
}

/* ------------------------------------------------------------------ */
/* ioctl ABI                                                           */
/* ------------------------------------------------------------------ */
static int do_ioctl(unsigned long req, void *arg)
{
    /* Cross-process visibility: attacker pushes events from a different
     * process (fork) via the state file; reload so this process sees them.
     * All handlers save after mutating, so reloading here is safe. */
    load_state();
    switch (req) {
    case AC_IOCTL_STATUS: {
        struct ac_status *st = arg;
        const char *vover = getenv("AC_MOCK_VERSION");

        /* AC_MOCK_VERSION lets tests simulate a stale module/daemon
         * pairing by reporting a version other than the one this mock
         * (and the real module) actually speaks. */
        st->version = (vover && *vover) ?
            (unsigned long long)strtoull(vover, NULL, 0) : AC_IOCTL_VERSION;
        st->syscall_table_addr = 0xffffffff82d02300ULL; /* mirrors this kernel */
        st->active_procs = S.nprots;
        st->events_dropped = S.events_dropped_total;
        st->locked = S.locked;
        st->syscall_hook_count = last_hook_count;
        return 0;
    }
    case AC_IOCTL_ADD_PROC: {
        struct ac_proc_id *id = arg;
        unsigned int i;

        /* Mirror the real kernel module's PF_KTHREAD rejection (issue
         * #69 / ac_add_prot_task() in anticheat_module.c): this mock has
         * no task_struct to check PF_KTHREAD on, but a kernel thread's
         * /proc/<pid>/cmdline is always empty -- it has no argv, unlike
         * any real userspace process -- which is a reliable
         * userspace-visible analog for "not a valid protect target".
         * Rejecting it here lets mock_test.sh exercise the same
         * ADD_PROC-fails-for-a-kernel-thread behaviour end-to-end
         * without root or a loaded module. Checked first, matching
         * ac_add_prot_task()'s precedence: the real module rejects a
         * kernel thread before it ever looks at registry capacity. */
        if (is_kthread_like(id->pid)) {
            errno = EINVAL;
            return -1;
        }
        for (i = 0; i < S.nprots; i++)
            if (S.prots[i].pid == id->pid) {
                S.prots[i].jit_allowed = id->jit_allowed;  /* updatable via re-protect */
                save_state();
                return 0;   /* already protected */
            }
        if (S.nprots >= AC_MAX_PROTS) {
            errno = ENOSPC;
            return -1;
        }
        read_comm(id->pid, id->comm, sizeof(id->comm));
        S.prots[S.nprots].pid = id->pid;
        S.prots[S.nprots].jit_allowed = id->jit_allowed;
        snprintf(S.prots[S.nprots].comm, sizeof(S.prots[S.nprots].comm),
                 "%s", id->comm);
        S.nprots++;
        push_event(AC_EV_INFO, id->pid, id->comm, "mock: process protected");
        return 0;
    }
    case AC_IOCTL_DEL_PROC: {
        struct ac_proc_id *id = arg;
        unsigned int i;

        for (i = 0; i < S.nprots; i++)
            if (S.prots[i].pid == id->pid) {
                S.prots[i] = S.prots[S.nprots - 1];
                S.nprots--;
                push_event(AC_EV_INFO, id->pid, "", "mock: protection removed");
                return 0;
            }
        errno = ESRCH;
        return -1;
    }
    case AC_IOCTL_LIST_PROTECTED: {
        struct ac_prot_list *pl = arg;

        pl->count = S.nprots;
        memcpy(pl->items, S.prots, S.nprots * sizeof(*S.prots));
        return 0;
    }
    case AC_IOCTL_SCAN_BEGIN: {
        struct ac_scan_begin *b = arg;
        unsigned int i;

        do_scan(b->pid);
        /* inject synthetic VMA for hook mock if requested */
        {
            struct hook_cfg hc;
            if (parse_hook_env(&hc) && hc.valid) {
                char tmp[PATH_MAX];
                int found = 0;
                for (i = 0; i < snap_n; i++) {
                    const char *base = strrchr(snap[i].path, '/');
                    base = base ? base + 1 : snap[i].path;
                    if (strncmp(base, hc.lib, strlen(hc.lib)) == 0 ||
                        strstr(snap[i].path, hc.lib)) { found = 1; break; }
                }
                if (!found && snap_n < AC_MAX_VMAS) {
                    snprintf(tmp, sizeof(tmp), "/tmp/%s", hc.lib);
                    /* ensure tmp file exists (copy host lib) */
                    ensure_hook_tmp_file(hc.lib);
                    struct ac_vma_info vi;
                    memset(&vi, 0, sizeof(vi));
                    vi.start = g_hook_base;
                    vi.end = g_hook_base + 0x100000;
                    vi.offset = 0;
                    vi.inode = 0x12345;
                    vi.flags = 0x1 | AC_VM_EXEC; /* R+X */
                    vi.is_file = 1;
                    { size_t _l = strlen(tmp); if (_l >= sizeof(vi.path)) _l = sizeof(vi.path)-1; memcpy(vi.path, tmp, _l); vi.path[_l]='\0'; }
                    snap = realloc(snap, (snap_n + 1) * sizeof(*snap));
                    if (snap) {
                        snap[snap_n++] = vi;
                        g_hook = hc;
                        snprintf(g_hook_tmp_path, sizeof(g_hook_tmp_path), "%s", tmp);
                    }
                } else if (found) {
                    g_hook = hc;
                    /* try to ensure tmp path for existing lib */
                    ensure_hook_tmp_file(hc.lib);
                }
            }
        }
        /* pagination overflow simulation */
        if (getenv("AC_MOCK_PAGINATION") && strcmp(getenv("AC_MOCK_PAGINATION"), "1") == 0) {
            free(snap);
            snap = NULL;
            snap_n = 5000;
            snap = calloc(snap_n, sizeof(*snap));
            if (snap) {
                for (i = 0; i < snap_n; i++) {
                    snap[i].start = 0x100000ULL + (unsigned long long)i * 0x1000ULL;
                    snap[i].end = snap[i].start + 0x1000ULL;
                    snap[i].offset = 0;
                    snap[i].inode = 1000 + i;
                    snap[i].flags = 0x1 | AC_VM_EXEC;
                    if ((i % 7) == 0)
                        snap[i].flags |= AC_VM_WRITE;
                    snap[i].is_file = 1;
                    snprintf(snap[i].path, sizeof(snap[i].path), "/tmp/fake_vma_%u.so", i % 10);
                }
            } else {
                snap_n = 0;
            }
        }
        /* Mock has no real pid-namespace resolution -- mirror the input
         * pid, same as the real module's ref_pid<=0 (default) case. */
        b->resolved_pid = b->pid;
        b->n_vmas = snap_n;
        b->rwx_count = 0;
        b->exec_count = 0;
        b->anon_exec_count = 0;
        for (i = 0; i < snap_n; i++) {
            if (snap[i].flags & AC_VM_EXEC)
                b->exec_count++;
            if ((snap[i].flags & (AC_VM_WRITE | AC_VM_EXEC)) == (AC_VM_WRITE | AC_VM_EXEC))
                b->rwx_count++;
            if (!snap[i].is_file && (snap[i].flags & AC_VM_EXEC))
                b->anon_exec_count++;
        }
        /* override anon_exec_count if mock env set (with per-pid growth) */
        b->anon_exec_count = get_mock_anon_count(b->pid, b->anon_exec_count);
        /* pagination must show truncation */
        if (getenv("AC_MOCK_PAGINATION") && strcmp(getenv("AC_MOCK_PAGINATION"), "1") == 0) {
            b->truncated = 1;
        } else {
            b->truncated = 0;
        }
        if (b->emit_events && b->rwx_count)
            push_event(AC_EV_RWX, b->pid, "", "mock: %u RWX mapping(s)",
                       b->rwx_count);
        if (b->emit_events && b->anon_exec_count)
            push_event(AC_EV_ANON_EXEC, b->pid, "",
                       "mock: %u anon-exec mapping(s)", b->anon_exec_count);
        return 0;
    }
    case AC_IOCTL_SCAN_GET: {
        struct ac_scan_get *g = arg;

        if (g->index >= snap_n) {
            errno = EINVAL;
            return -1;
        }
        g->vma = snap[g->index];
        return 0;
    }
    case AC_IOCTL_SCAN_END:
        free(snap);
        snap = NULL;
        snap_n = 0;
        return 0;
    case AC_IOCTL_CHECK_SYSCALLS: {
        struct ac_syscall_check *c = arg;
        int mock_redirect = getenv("AC_MOCK_REDIRECT") != NULL;
        int mock_checksum_only = getenv("AC_MOCK_CHECKSUM_ONLY") != NULL;

        c->table_addr = 0xffffffff82d02300ULL;
        c->nr_syscalls = 472;
        c->total = 472;
        if (getenv("AC_MOCK_HOOKED")) {
            c->non_text = 1;
            c->hooked = 1;
        } else {
            c->non_text = 0;
            c->hooked = 0;
        }
        c->redirected = mock_redirect ? 1 : 0;

        /* Boot-time handler-address baseline (#63): the mock always
         * reports a captured baseline (mirrors the real module always
         * capturing one when the table was located, which it always is
         * here), with the live checksum diverging whenever either kind of
         * tampering -- out-of-text hook or in-text redirect -- is
         * simulated. AC_MOCK_CHECKSUM_ONLY simulates handler churn the
         * per-slot walk doesn't individually flag (out->redirected stays
         * 0): a slot going non-zero -> 0 flips the whole-table checksum
         * without tripping either per-slot counter. */
        c->baseline_ready = 1;
        mock_fill_digest(c->baseline_sha256, '1');
        mock_fill_digest(c->current_sha256,
                          (c->hooked || c->redirected || mock_checksum_only) ? '2' : '1');
        c->checksum_mismatch = (c->hooked || c->redirected || mock_checksum_only) ? 1 : 0;

        /* Mirrors ac_check_syscalls(): ok is clear whenever any of the
         * three signals fires, not just hooked. */
        c->ok = (c->hooked == 0 && c->redirected == 0 &&
                 !c->checksum_mismatch);

        /* Mirrors the real module's rising-edge gating (see #52): only
         * push a ring event on the clean->hooked/redirected transition,
         * not on every poll that still finds the same condition. */
        if (c->hooked && !last_hook_count)
            push_event(AC_EV_SYSCALL_HOOK, 0, "?",
                       "mock: syscall[57] -> 0xdeadbeef outside core kernel text");
        if (c->redirected && !last_redirect_count)
            push_event(AC_EV_SYSCALL_REDIRECT, 0, "?",
                       "mock: syscall[0] handler changed 0x1111 -> 0x2222 (still core text)");
        last_hook_count = c->hooked;
        last_redirect_count = c->redirected;
        return 0;
    }
    case AC_IOCTL_GET_EVENTS: {
        struct ac_event_list *el = arg;
        int is_pag = getenv("AC_MOCK_PAGINATION") && strcmp(getenv("AC_MOCK_PAGINATION"), "1") == 0;

        /* pagination overflow: seed 70 events on first drain after flush */
        if (is_pag && S.n_evq == 0 && S.events_dropped_total == 0) {
            /* push 70: first 64 fill, next 6 drop */
            int i;
            for (i = 0; i < 70; i++) {
                push_event(AC_EV_INFO, 1000 + i, "pag", "pagination event %d", i);
            }
            /* load_state was done at entry; push_event already saved */
        }
        /* pagination block_ms clamp test: when ring empty and block_ms>1000,
         * kernel clamps to AC_GET_EVENTS_MAX_BLOCK_MS (1000). Mock mirrors it
         * so block_ms=5000 sleeps only ~1000ms, proving the clamp. */
        if (is_pag && S.n_evq == 0 && el->block_ms > 0) {
            unsigned int sleep_ms = el->block_ms;
            if (sleep_ms > AC_GET_EVENTS_MAX_BLOCK_MS)
                sleep_ms = AC_GET_EVENTS_MAX_BLOCK_MS;
            /* usleep the clamped duration to simulate kernel blocking */
            usleep(sleep_ms * 1000);
        }

        /* Real module (#61): blocks interruptibly for up to
         * el->block_ms if the ring is empty, woken early the instant an
         * event is pushed. The mock deliberately does NOT simulate that
         * here -- it always answers immediately, block_ms or not. A
         * fake sleep in a plain userspace LD_PRELOAD shim would just
         * make every mock-backed test slower and, worse, timing-
         * dependent/flaky for no real coverage gain: there is no
         * concurrent kernel-side event source here that a genuine wait
         * could usefully block against, only whatever this same test
         * process already pushed via push_event() above. The daemon's
         * own monitor loop (anticheat_daemon.c's cmd_start()) treats an
         * instant, event-less return as this exact case (a caller that
         * doesn't honor block_ms) and falls back to a client-side sleep
         * to keep its polling cadence sane -- that fallback path, not a
         * fake blocking wait here, is what mock_test.sh's
         * "start --foreground" tests actually exercise. For pagination
         * testing (AC_MOCK_PAGINATION=1) we DO sleep above, clamped. */
        el->count = S.n_evq;
        el->dropped = S.events_dropped_total;
        memcpy(el->events, S.evq, S.n_evq * sizeof(*S.evq));
        S.n_evq = 0;
        save_state();
        if (getenv("AC_MOCK_ATTACK") && (drain_count++ % 3) == 0)
            push_event(AC_EV_PTRACE, getpid(), "mock",
                       "mock: simulated ptrace attach DENIED");
        return 0;
    }
    case AC_IOCTL_FLUSH_EVENTS:
        S.n_evq = 0;
        save_state();
        return 0;
    case AC_IOCTL_LOCK:
        S.locked = 1;
        save_state();
        return 0;
    case AC_IOCTL_UNLOCK:
        S.locked = 0;
        save_state();
        return 0;
    case AC_IOCTL_MODS_BEGIN: {
        /* pagination overflow: synthesize 1100 mods */
        if (getenv("AC_MOCK_PAGINATION") && strcmp(getenv("AC_MOCK_PAGINATION"), "1") == 0) {
            unsigned int i;
            free(mods);
            mods = calloc(1100, sizeof(*mods));
            if (!mods) {
                mods_n = 0;
                *(unsigned int *)arg = 0;
                return 0;
            }
            mods_n = 1100;
            for (i = 0; i < mods_n; i++) {
                snprintf(mods[i].name, sizeof(mods[i].name), "pag_mod_%u", i);
                mods[i].size = 0x1000 + i;
                mods[i].state = 0;
            }
            /* keep hidden_rootkit semantics? ensure at least one hidden */
            snprintf(mods[mods_n-1].name, sizeof(mods[mods_n-1].name), "hidden_rootkit");
            *(unsigned int *)arg = mods_n;
            return 0;
        }
        build_mods();
        *(unsigned int *)arg = mods_n;
        return 0;
    }
    case AC_IOCTL_MODS_GET: {
        struct ac_mod_get *g = arg;

        if (g->index >= mods_n) {
            errno = EINVAL;
            return -1;
        }
        g->mod = mods[g->index];
        return 0;
    }
    case AC_IOCTL_MODS_END:
        free(mods);
        mods = NULL;
        mods_n = 0;
        return 0;
    default:
        errno = ENOTTY;
        return -1;
    }
}

/* ------------------------------------------------------------------ */
/* symbol interposition                                                */
/* ------------------------------------------------------------------ */
static int is_mock_path(const char *path)
{
    return strcmp(path, AC_DEV_PATH) == 0;
}

static int mock_open_common(void)
{
    load_state();
    push_event(AC_EV_INFO, getpid(), "mock", "mock: device opened");
    if (getenv("AC_MOCK_ATTACK"))
        push_event(AC_EV_PTRACE, getpid(), "mock",
                   "mock: simulated ptrace attach DENIED");
    return MOCK_FD;
}

int open(const char *path, int flags, ...)
{
    static int (*real)(const char *, int, ...);
    mode_t mode = 0;

    if (!real)
        real = dlsym(RTLD_NEXT, "open");
    if (is_mock_path(path))
        return mock_open_common();
    /* environ mock */
    if (getenv("AC_MOCK_ENVIRON") && is_environ_path(path)) {
        int fd = make_fake_environ_fd();
        if (fd >= 0) return fd;
    }
    if (getenv("AC_MOCK_MANIFEST") && strstr(path, "mock_layer.json")) {
        int fd = make_fake_manifest_fd();
        if (fd >= 0) return fd;
    }
    if (flags & O_CREAT) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    {
        int fd = real(path, flags, mode);
        if (fd >= 0 && getenv("AC_MOCK_HOOK_LIB") && is_mem_path(path)) {
            track_mem_fd(fd);
        }
        return fd;
    }
}

int open64(const char *path, int flags, ...)
{
    static int (*real)(const char *, int, ...);
    mode_t mode = 0;

    if (!real)
        real = dlsym(RTLD_NEXT, "open64");
    if (is_mock_path(path))
        return mock_open_common();
    if (getenv("AC_MOCK_ENVIRON") && is_environ_path(path)) {
        int fd = make_fake_environ_fd();
        if (fd >= 0) return fd;
    }
    if (getenv("AC_MOCK_MANIFEST") && strstr(path, "mock_layer.json")) {
        int fd = make_fake_manifest_fd();
        if (fd >= 0) return fd;
    }
    if (flags & O_CREAT) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    {
        int fd = real(path, flags, mode);
        if (fd >= 0 && getenv("AC_MOCK_HOOK_LIB") && is_mem_path(path)) {
            track_mem_fd(fd);
        }
        return fd;
    }
}

int openat(int dirfd, const char *path, int flags, ...)
{
    static int (*real)(int, const char *, int, ...);
    mode_t mode = 0;

    if (!real)
        real = dlsym(RTLD_NEXT, "openat");
    if (is_mock_path(path))
        return mock_open_common();
    if (getenv("AC_MOCK_ENVIRON") && is_environ_path(path)) {
        int fd = make_fake_environ_fd();
        if (fd >= 0) return fd;
    }
    if (getenv("AC_MOCK_MANIFEST") && strstr(path, "mock_layer.json")) {
        int fd = make_fake_manifest_fd();
        if (fd >= 0) return fd;
    }
    if (flags & O_CREAT) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    {
        int fd = real(dirfd, path, flags, mode);
        if (fd >= 0 && getenv("AC_MOCK_HOOK_LIB") && is_mem_path(path)) {
            track_mem_fd(fd);
        }
        return fd;
    }
}

int openat64(int dirfd, const char *path, int flags, ...)
{
    static int (*real)(int, const char *, int, ...);
    mode_t mode = 0;

    if (!real)
        real = dlsym(RTLD_NEXT, "openat64");
    if (is_mock_path(path))
        return mock_open_common();
    if (getenv("AC_MOCK_ENVIRON") && is_environ_path(path)) {
        int fd = make_fake_environ_fd();
        if (fd >= 0) return fd;
    }
    if (getenv("AC_MOCK_MANIFEST") && strstr(path, "mock_layer.json")) {
        int fd = make_fake_manifest_fd();
        if (fd >= 0) return fd;
    }
    if (flags & O_CREAT) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    {
        int fd = real(dirfd, path, flags, mode);
        if (fd >= 0 && getenv("AC_MOCK_HOOK_LIB") && is_mem_path(path)) {
            track_mem_fd(fd);
        }
        return fd;
    }
}

int ioctl(int fd, unsigned long request, ...)
{
    static int (*real)(int, unsigned long, ...);
    void *arg;
    va_list ap;

    if (!real)
        real = dlsym(RTLD_NEXT, "ioctl");
    va_start(ap, request);
    arg = va_arg(ap, void *);
    va_end(ap);
    if (fd != MOCK_FD)
        return real(fd, request, arg);
    return do_ioctl(request, arg);
}

int close(int fd)
{
    static int (*real)(int);
    if (!real)
        real = dlsym(RTLD_NEXT, "close");
    if (fd == MOCK_FD)
        return 0;
    if (is_tracked_mem_fd(fd)) untrack_mem_fd(fd);
    return real(fd);
}

/* pread handling for hook mock */
ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    static ssize_t (*real)(int, void *, size_t, off_t);
    if (!real) real = dlsym(RTLD_NEXT, "pread");
    if (is_tracked_mem_fd(fd)) {
        struct hook_cfg hc;
        if (parse_hook_env(&hc) && hc.valid) {
            unsigned long long off = (unsigned long long)offset;
            if (off >= g_hook_base && off < g_hook_base + 0x100000) {
                if (strcmp(hc.status, "hooked") == 0) {
                    /* return differing bytes */
                    memset(buf, 0xCC, count);
                    return (ssize_t)count;
                } else if (strcmp(hc.status, "clean") == 0) {
                    /* return same as file: read from tmp file at file offset */
                    if (g_hook_tmp_path[0]) {
                        int (*real_open)(const char*, int, ...) = dlsym(RTLD_NEXT, "open");
                        int tfd = real_open(g_hook_tmp_path, O_RDONLY);
                        if (tfd >= 0) {
                            ssize_t r = real(tfd, buf, count, (off_t)(off - g_hook_base));
                            close(tfd);
                            if (r >= 0) return r;
                        }
                    }
                    memset(buf, 0xAA, count);
                    return (ssize_t)count;
                } else if (strcmp(hc.status, "inconclusive") == 0) {
                    errno = EIO;
                    return -1;
                }
            }
        }
    }
    return real(fd, buf, count, offset);
}
ssize_t pread64(int fd, void *buf, size_t count, off_t offset)
{
    return pread(fd, buf, count, offset);
}

/* opendir / readdir / closedir for manifest mock */
DIR *opendir(const char *name)
{
    static DIR *(*real)(const char *);
    if (!real) real = dlsym(RTLD_NEXT, "opendir");
    if (getenv("AC_MOCK_MANIFEST") && strcmp(name, "/etc/vulkan/implicit_layer.d") == 0) {
        DIR *d = alloc_fake_dir(name);
        if (d) return d;
    }
    return real(name);
}
struct dirent *readdir(DIR *dirp)
{
    static struct dirent *(*real)(DIR *);
    if (!real) real = dlsym(RTLD_NEXT, "readdir");
    struct fake_dir *fd = find_fake_dir(dirp);
    if (fd) {
        if (fd->returned) return NULL;
        fd->returned = 1;
        memset(&fake_dirent, 0, sizeof(fake_dirent));
        snprintf(fake_dirent.d_name, sizeof(fake_dirent.d_name), "mock_layer.json");
        fake_dirent_ptr = &fake_dirent;
        return &fake_dirent;
    }
    return real(dirp);
}
int closedir(DIR *dirp)
{
    static int (*real)(DIR *);
    if (!real) real = dlsym(RTLD_NEXT, "closedir");
    struct fake_dir *fd = find_fake_dir(dirp);
    if (fd) {
        fd->in_use = 0;
        fd->returned = 0;
        return 0;
    }
    return real(dirp);
}

/* ------------------------------------------------------------------ */
/* process_vm_readv/writev denial (mirrors ac_process_vm_pre())       */
/* ------------------------------------------------------------------ */
static int is_protected_pid(pid_t pid)
{
    unsigned int i;
    /* refresh from file -- attacker is a different process from the
     * protector, so its in-memory S may be stale */
    load_state();
    for (i = 0; i < S.nprots; i++)
        if (S.prots[i].pid == pid)
            return 1;
    return 0;
}

static ssize_t mock_process_vm_deny(pid_t pid, const char *op)
{
    char comm[AC_MAX_COMM] = "?";
    char self_comm[AC_MAX_COMM] = "?";
    read_comm(pid, comm, sizeof(comm));
    read_comm(getpid(), self_comm, sizeof(self_comm));
    /* load before push to have current S */
    load_state();
    push_event(AC_EV_PROCESS_VM, pid, comm,
               "process_vm_%s by pid %d (%s) DENIED", op, getpid(), self_comm);
    /* async SIGKILL like the kernel workqueue: succeed the syscall first,
     * then kill after a short delay so the caller sees ESRCH before dying */
    if (getenv("AC_MOCK_ATTACK")) {
        pid_t me = getpid();
        pid_t k = fork();
        if (k == 0) {
            usleep(10 * 1000);
            kill(me, SIGKILL);
            _exit(0);
        }
        /* parent (attacker) continues to return ESRCH; killer is reaped via SIGCHLD ignore or later wait */
    }
    errno = ESRCH;
    return -1;
}

ssize_t process_vm_readv(pid_t pid,
                         const struct iovec *local_iov, unsigned long liovcnt,
                         const struct iovec *remote_iov, unsigned long riovcnt,
                         unsigned long flags)
{
    if (pid > 0 && pid != getpid() && is_protected_pid(pid))
        return mock_process_vm_deny(pid, "readv");
    /* live path: direct syscall to avoid recursion through libc wrapper */
    return (ssize_t)syscall(SYS_process_vm_readv,
                            pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}

ssize_t process_vm_writev(pid_t pid,
                          const struct iovec *local_iov, unsigned long liovcnt,
                          const struct iovec *remote_iov, unsigned long riovcnt,
                          unsigned long flags)
{
    if (pid > 0 && pid != getpid() && is_protected_pid(pid))
        return mock_process_vm_deny(pid, "writev");
    return (ssize_t)syscall(SYS_process_vm_writev,
                            pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}

uid_t geteuid(void)
{
    static uid_t (*real)(void);

    if (!real)
        real = dlsym(RTLD_NEXT, "geteuid");
    return getenv("AC_MOCK_ROOT") ? 0 : real();
}

uid_t getuid(void)
{
    static uid_t (*real)(void);

    if (!real)
        real = dlsym(RTLD_NEXT, "getuid");
    return getenv("AC_MOCK_ROOT") ? 0 : real();
}
