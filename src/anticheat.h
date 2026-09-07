/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * anticheat.h — shared ABI between the kernel module and the userspace
 * daemon/CLI.  Plain C types only so the header can be included both by
 * kernel code (Kernel: -I$(KDIR)/include) and userspace code.
 *
 * This is a defensive security tool: it detects tampering with the running
 * kernel (syscall hooks, hidden modules) and with protected processes
 * (RWX code caves, debugger attaches).  It is NOT designed to bypass any
 * protection and must not be used for that purpose.
 */
#ifndef _AC_SHARED_H_
#define _AC_SHARED_H_

#define AC_DEV_NAME     "anticheat"
#define AC_DEV_PATH     "/dev/anticheat"
#define AC_IOCTL_MAGIC  0xAC
#define AC_IOCTL_VERSION 2

/* Upper bound (milliseconds) the kernel clamps struct ac_event_list's
 * block_ms field to for AC_IOCTL_GET_EVENTS -- see that struct's own
 * comment. Keeps a caller (malicious or just buggy) from tying up a
 * kernel thread indefinitely, and bounds worst-case ioctl-fuzz overhead
 * per iteration that happens to land on this command with an empty ring. */
#define AC_GET_EVENTS_MAX_BLOCK_MS 1000

#define AC_MAX_COMM     16
#define AC_MAX_PROCS    64
#define AC_MAX_VMAS     4096     /* snapshot cap for VMA scan */
#define AC_VMA_PATH     128
#define AC_MOD_NAME_LEN 64
#define AC_MAX_EVENTS   64
#define AC_MAX_PROTS    64
#define AC_MAX_MODS     1024    /* cap for module snapshot */
#define AC_EVENT_DATA   128

/* ------------------------------------------------------------------ */
/* ioctl numbers                                                       */
/* Note: the kernel ioctl size field is 14 bits (max 16383 bytes), so  */
/* bulk data is transferred with begin/get/end pairs instead of one    */
/* giant struct.                                                       */
/* ------------------------------------------------------------------ */
#define AC_IOCTL_STATUS           _IOR(AC_IOCTL_MAGIC,  1, struct ac_status)
#define AC_IOCTL_ADD_PROC         _IOW(AC_IOCTL_MAGIC,  2, struct ac_proc_id)
#define AC_IOCTL_DEL_PROC         _IOW(AC_IOCTL_MAGIC,  3, struct ac_proc_id)
#define AC_IOCTL_SCAN_BEGIN       _IOWR(AC_IOCTL_MAGIC, 4, struct ac_scan_begin)
#define AC_IOCTL_CHECK_SYSCALLS   _IOR(AC_IOCTL_MAGIC,  5, struct ac_syscall_check)
#define AC_IOCTL_GET_EVENTS       _IOWR(AC_IOCTL_MAGIC, 7, struct ac_event_list)
#define AC_IOCTL_FLUSH_EVENTS     _IO(AC_IOCTL_MAGIC,   8)
#define AC_IOCTL_LIST_PROTECTED   _IOR(AC_IOCTL_MAGIC,  9, struct ac_prot_list)
#define AC_IOCTL_LOCK             _IO(AC_IOCTL_MAGIC,  10)
#define AC_IOCTL_UNLOCK           _IO(AC_IOCTL_MAGIC,  11)
#define AC_IOCTL_SCAN_GET         _IOWR(AC_IOCTL_MAGIC, 12, struct ac_scan_get)
#define AC_IOCTL_SCAN_END         _IO(AC_IOCTL_MAGIC,  13)
#define AC_IOCTL_MODS_BEGIN       _IOR(AC_IOCTL_MAGIC, 14, unsigned int)
#define AC_IOCTL_MODS_GET         _IOWR(AC_IOCTL_MAGIC, 15, struct ac_mod_get)
#define AC_IOCTL_MODS_END         _IO(AC_IOCTL_MAGIC,  16)

/* ------------------------------------------------------------------ */
/* event types                                                         */
/* ------------------------------------------------------------------ */
enum {
    AC_EV_FORK = 1,       /* protected process forked a child (child inherits) */
    AC_EV_EXEC,           /* protected process invoked execve */
    AC_EV_EXIT,           /* protected process exited */
    AC_EV_PTRACE,         /* ptrace attempt against a protected process (denied) */
    AC_EV_SYSCALL_HOOK,   /* syscall table entry outside core kernel text */
    AC_EV_RWX,            /* executable+writable mapping detected in protected proc */
    AC_EV_ANON_EXEC,      /* executable mapping with no backing file (possible
                            * injected code -- also catches write-then-mprotect(R-X),
                            * which evades RWX-only detection since W and X are
                            * never both set at once). vdso/vvar legitimately show
                            * up here too; the daemon only alerts on an *increase*
                            * in this count after a process is first observed, not
                            * on the raw count, since vdso/vvar are present from
                            * process start and never change. */
    AC_EV_INFO,           /* informational (module load/unload, ...) */
    AC_EV_PROCESS_VM,     /* process_vm_readv/writev against a protected process
                            * (denied) -- the same memory access ptrace denial
                            * covers, via the syscall that doesn't go through
                            * ptrace(2) at all. Appended after the pre-existing
                            * values (not inserted alongside AC_EV_PTRACE above)
                            * so a module/daemon version mismatch can't silently
                            * misclassify any event that already shipped. */
    AC_EV_SYSCALL_REDIRECT, /* a syscall table entry's handler address changed
                            * since the boot-time snapshot (see
                            * ac_syscall_check.baseline_sha256) but still
                            * points inside core kernel text -- distinct from
                            * AC_EV_SYSCALL_HOOK, which is entries pointing
                            * outside core text/into a module. An in-text
                            * redirect (e.g. sys_read -> sys_write) is exactly
                            * the gap THREAT_MODEL.md's "Within-core-kernel-
                            * text redirects" note describes as out of scope
                            * for the original range-only check; this event
                            * raises the detection bar for it without
                            * claiming to close it against a kernel-privileged
                            * attacker (see #63). Appended after the
                            * pre-existing values for the same version-skew
                            * reason as AC_EV_PROCESS_VM above. */
    AC_EV_FORK_DROPPED,     /* a kretprobe (kernel_clone, or one of the
                            * execve/execveat variants) hit its maxactive
                            * limit and the kernel silently dropped one or
                            * more invocations -- under heavy fork/exec load
                            * (e.g. a fork bomb) a child's registration or a
                            * re-exec's rekey can be missed entirely, with no
                            * indication of this from the normal AC_EV_FORK/
                            * AC_EV_EXEC events, which only cover invocations
                            * the probe actually saw. pid is not meaningful
                            * here (the whole point is that the affected
                            * pid was never observed); data names which
                            * probe missed and by how much. Appended after
                            * the pre-existing values for the same
                            * version-skew reason as AC_EV_PROCESS_VM
                            * above. */
};

/* ------------------------------------------------------------------ */
/* VM flag values as seen by the daemon.  These are the Linux ABI bit
 * numbers for VM_EXEC / VM_WRITE (stable for decades); the daemon uses
 * these constants instead of pulling in kernel headers, and the module
 * reports raw vma->vm_flags so the values must match the running kernel. */
#define AC_VM_EXEC  0x4
#define AC_VM_WRITE 0x2

/* ------------------------------------------------------------------ */
/* structs                                                             */
/* ------------------------------------------------------------------ */
struct ac_status {
    unsigned long long version;      /* AC_IOCTL_VERSION */
    unsigned long long syscall_table_addr;
    unsigned int        active_procs;     /* protected process count */
    unsigned int        events_dropped;   /* ring buffer drops since load */
    unsigned int        locked;           /* module pinned by lock ioctl */
    unsigned int        syscall_hook_count; /* from last CHECK_SYSCALLS */
    unsigned int        kill_dropped;     /* kill work drops since load */
};

struct ac_proc_id {
    int  pid;
    int  ref_pid;             /* <=0: resolve `pid` in the caller's own
                                * (host) pid namespace -- default,
                                * current behavior. >0: resolve `pid`
                                * within the pid namespace that host-pid
                                * ref_pid lives in (see --ns-of). */
    int  jit_allowed;          /* 0/1: mark this pid as a known
                                 * JIT-using binary at protect time (see
                                 * --jit). Anon-exec growth still logs,
                                 * at reduced severity, not auto-reported
                                 * to the ban pipeline. */
    char comm[AC_MAX_COMM];   /* informational, may be empty on input */
};

struct ac_vma_info {
    unsigned long long start;
    unsigned long long end;
    unsigned long long offset;
    unsigned long long inode;
    unsigned long      flags;        /* VM_* flags (kernel semantics) */
    unsigned int       is_file;      /* 1 if backed by a file */
    char               path[AC_VMA_PATH];
};

struct ac_scan_begin {
    int          pid;
    int          ref_pid;       /* <=0: resolve `pid` in the caller's own
                                  * (host) pid namespace -- default,
                                  * current behavior. >0: resolve `pid`
                                  * within the pid namespace that host-pid
                                  * ref_pid lives in (see --ns-of), same
                                  * semantics as ac_proc_id.ref_pid. */
    int          emit_events;   /* 1 = also push AC_EV_RWX events */
    int          resolved_pid;  /* out: `pid` as seen in the *caller's*
                                  * (host) pid namespace -- identical to
                                  * `pid` when ref_pid was <=0, otherwise
                                  * the host pid the ns-of lookup landed
                                  * on. Use this, not the input `pid`, for
                                  * any /proc/<pid>/... access on the host
                                  * side after a namespace-relative scan. */
    unsigned int n_vmas;        /* out */
    unsigned int rwx_count;     /* out */
    unsigned int exec_count;    /* out */
    unsigned int anon_exec_count; /* out: executable, no backing file (see AC_EV_ANON_EXEC) */
    unsigned int truncated;     /* out: snapshot cap hit */
};

struct ac_scan_get {
    int              pid;
    unsigned int     index;
    struct ac_vma_info vma;     /* out */
};

struct ac_syscall_check {
    unsigned long long table_addr;
    unsigned int       nr_syscalls;   /* table size examined */
    unsigned int       total;         /* non-NULL entries */
    unsigned int       non_text;      /* entries outside core kernel text */
    unsigned int       hooked;        /* = non_text (kept for compat) */
    unsigned int       ok;            /* 1 if no hooked, redirected, or
                                          checksum_mismatch entries found */
    /* Boot-time handler-address baseline (#63): closes the gap
     * THREAT_MODEL.md calls out under "Within-core-kernel-text redirects"
     * -- table_addr/non_text/hooked above only ever look at *where* an
     * entry points relative to core text, so a hook that swaps one
     * in-text handler for another (e.g. sys_read -> sys_write) is
     * invisible to them by design. These fields compare the live table
     * against a checksum of the handler addresses captured once at
     * module load, independent of whether any given entry still looks
     * like a plausible core-text address. */
    unsigned int       baseline_ready;     /* 1 if a boot-time handler-address
                                             * snapshot was captured (0 if the
                                             * syscall table couldn't be
                                             * located at load time) */
    unsigned int       redirected;         /* entries whose handler address
                                             * differs from the boot baseline
                                             * while still pointing inside core
                                             * kernel text (in-text redirect) */
    unsigned int       checksum_mismatch;  /* 1 if the whole-table SHA-256
                                             * over live handler addresses
                                             * differs from the boot baseline
                                             * -- redundant with `redirected`
                                             * for the in-text case above, but
                                             * also catches any handler churn
                                             * the per-slot walk didn't
                                             * individually flag */
    char               baseline_sha256[65]; /* hex digest captured at load;
                                              * empty if baseline_ready == 0 */
    char               current_sha256[65];  /* hex digest of the live table
                                              * as of this check */
};

struct ac_mod_info {
    char           name[AC_MOD_NAME_LEN];
    unsigned long long size;
    unsigned int       state;   /* MODULE_STATE_* */
};

struct ac_mod_get {
    unsigned int  index;
    struct ac_mod_info mod;     /* out */
};

struct ac_event {
    unsigned long long ts;          /* ktime_get_real_fast_ns() */
    int                pid;
    char               comm[AC_MAX_COMM];
    unsigned int       type;
    char               data[AC_EVENT_DATA];
};

struct ac_event_list {
    unsigned int  count;
    unsigned int  dropped;      /* total drops (cumulative) */
    /* in: 0 (default -- a zero-filled struct, same as every pre-v2
     * caller sends) means AC_IOCTL_GET_EVENTS returns immediately,
     * exactly like before this field existed. >0 asks the kernel to
     * block interruptibly for up to this many milliseconds waiting for
     * the ring to become non-empty, woken early the moment an event is
     * pushed; the kernel clamps this down to
     * AC_GET_EVENTS_MAX_BLOCK_MS. A signal (including one used only to
     * ask a thread to stop, e.g. SIGTERM) interrupts the wait and the
     * ioctl returns -EINTR/-ERESTARTSYS rather than blocking through it
     * -- callers must not treat that as this field being ignored.
     * Not echoed back on output (the kernel does not promise to
     * preserve it across the call). */
    unsigned int  block_ms;
    struct ac_event events[AC_MAX_EVENTS];
};

struct ac_prot_item {
    int  pid;
    int  jit_allowed;    /* echoes the registry's current flag for this pid */
    char comm[AC_MAX_COMM];
};

struct ac_prot_list {
    unsigned int count;
    struct ac_prot_item items[AC_MAX_PROTS];
};

#endif /* _AC_SHARED_H_ */
