// SPDX-License-Identifier: GPL-2.0
/*
 * anticheat_module.c — kernel-mode anticheat engine.
 *
 * Defensive security instrumentation only.  Provides:
 *
 *  1. Syscall-table discovery + integrity checking (detects syscall hooks
 *     pointing outside the core kernel text, i.e. classic rootkits), plus a
 *     boot-time checksum of every handler address that also catches an
 *     in-text redirect (e.g. sys_read -> sys_write), which the range check
 *     alone can't see (see #63).
 *  2. Kernel module enumeration (userspace cross-checks /proc/modules to
 *     detect modules hidden from procfs).
 *  3. Protected process registry; protection is inherited by forked children.
 *  4. ptrace interception: attach/debug requests against protected processes
 *     are neutralised (request argument rewritten to an invalid value, so
 *     the syscall fails with -EIO and has no side effects) and, per policy,
 *     the offending tracer is SIGKILLed from a workqueue. process_vm_readv/
 *     writev against a protected process -- the standard ptrace-free way to
 *     read/write another process's memory -- gets the same treatment (pid
 *     argument rewritten to -1, so the syscall fails with -ESRCH before
 *     touching the target's memory).
 *  5. execve / exit monitoring of protected processes (kprobes).
 *  6. VMA-level memory scanning (RWX "code cave" detection, plus anonymous
 *     executable mappings -- catches the write-then-mprotect(R-X) injection
 *     pattern that RWX-only detection misses).
 *  7. Event ring buffer consumed by the userspace daemon via ioctls.
 *
 * All symbol resolution is done through kprobes (kallsyms_lookup_name is not
 * exported on modern kernels); nothing relies on /proc/kallsyms content.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/mmu_notifier.h>
#include <linux/vmalloc.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/dcache.h>
#include <linux/version.h>
#include <linux/timekeeping.h>
#include <linux/workqueue.h>
#include <linux/mempool.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/user_namespace.h>
#include <linux/ptrace.h>
#include <linux/err.h>
#include <linux/bitops.h>
#include <linux/rcupdate.h>
#include <asm/unistd.h>

#include "anticheat.h"
#include "sha256.h"

#ifndef __NR_syscalls
# define __NR_syscalls 512
#endif

/* forward declarations */
static void ac_emit(unsigned int type, int pid, const char *comm,
                    const char *fmt, ...);
/* Defined in the kill-from-workqueue section below; the mm-registration
 * deferral in the protected-process registry (see AC_PROT_RESERVED and
 * ac_schedule_prot_add()/ac_schedule_prot_rekey() further down) needs it
 * declared this early since it queues work from kprobe/kretprobe context
 * too, for the same reason ac_schedule_kill() does. */
static struct workqueue_struct *ac_wq;

/* Backing pools for the two deferred-work request structs allocated from
 * kprobe/kretprobe (atomic) context: struct ac_prot_add_req (fork-inherit/
 * exec-rekey registration, further down) and struct ac_prot_release_req
 * (mmu_notifier cleanup for an organically-exited mm, in the registry
 * section below). A plain kmalloc(GFP_ATOMIC) there can fail under memory
 * pressure -- silently dropping either request isn't just a missed event:
 * dropping an add/rekey leaves a should-be-protected mm unregistered
 * (ptrace/process_vm defenses would let an attacker through), and dropping
 * a release leaks the slot's mmu_notifier registration and its mm_count
 * reference permanently. mempool_alloc() falls back to a small pre-reserved
 * pool instead of returning NULL there, the standard kernel pattern for
 * atomic-context allocations that must not fail. Sized to AC_PROT_MAX: that
 * many concurrent in-flight requests already implies as many address
 * spaces are mid-transition, which is the same order of magnitude the
 * registry itself is bounded to. */
static mempool_t *ac_prot_add_pool;
static mempool_t *ac_prot_release_pool;
static mempool_t *ac_kill_pool;
static atomic_t ac_kill_dropped = ATOMIC_INIT(0);

/* ------------------------------------------------------------------ */
/* safe kernel reads/writes                                            */
/* ------------------------------------------------------------------ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
# define ac_kread(dst, src, n) copy_from_kernel_nofault((dst), (src), (n))
#else
# include <asm/uaccess.h>
# define ac_kread(dst, src, n) probe_kernel_read((dst), (src), (n))
#endif

/* copy_to_kernel_nofault() -- the write-side twin of copy_from_kernel_
 * nofault() that ac_kread() above wraps -- is not EXPORT_SYMBOL'd on
 * every kernel this module targets (confirmed missing from this build's
 * own symbol table), so it can't be called from a module. The only write
 * this file ever needs through a nofault path is a single register-sized
 * slot in a kprobe'd pt_regs frame (see ac_ptrace_pre()/ac_process_vm_
 * pre()'s neutralisation writes), so rebuild just that with the same
 * __put_kernel_nofault()/arch_put_kernel_nofault() building block
 * copy_to_kernel_nofault() itself is implemented with -- header-inline,
 * so no export is required. */
static inline int ac_kwrite_long(void *dst, unsigned long val)
{
    __put_kernel_nofault(dst, &val, unsigned long, ac_kwrite_long_fault);
    return 0;
ac_kwrite_long_fault:
    return -EFAULT;
}
/* Synchronous fail-closed override for the syscall-deny kprobes below.
 *
 * ac_schedule_kill() only queues a work item: the probed syscall resumes
 * with its original arguments long before the worker sends SIGKILL, and a
 * mempool-exhausted queue_work() may never send it at all. So whenever a
 * neutralisation write fails -- meaning the syscall would otherwise run
 * un-denied -- the pre-handler must also stop the probed function itself
 * from executing, synchronously, before returning.
 *
 * At function entry (the probed first instruction hasn't run, so no frame
 * of ours exists yet and the stack top still holds the caller's return
 * address) that is: pop the return address, stash the error in %rax, and
 * resume there with a non-zero pre-handler return so kprobes skips
 * single-stepping. From the caller's (do_syscall_64's) point of view this
 * is indistinguishable from the probed wrapper returning the error
 * itself. Uses only a nofault read and register writes, so it is safe in
 * atomic kprobe context; unlike override_function_with_return() it does
 * not depend on CONFIG_FUNCTION_ERROR_INJECTION (a no-op stub when that
 * is off). Returns 1 when the syscall was skipped, 0 when the stack slot
 * itself was unreadable (caller falls back to the queued kill alone).
 *
 * NOTE: kprobes ignores a regs->ip change + non-zero return while the
 * probe is jump/ftrace-optimized, so every probe whose pre-handler can
 * take this path carries the empty ac_probe_post() below: a probe with a
 * post_handler is never optimized, keeping this override honored. */
static int ac_skip_syscall(struct pt_regs *regs, long err)
{
    unsigned long ret_addr;

    if (ac_kread(&ret_addr, (const void *)regs->sp, sizeof(ret_addr)))
        return 0;
    regs_set_return_value(regs, (unsigned long)err);
    regs->ip = ret_addr;
    regs->sp += sizeof(ret_addr);
    return 1;
}

/* Empty on purpose -- see ac_skip_syscall's NOTE. A post_handler never
 * even fires on the override path (a non-zero pre-handler return
 * suppresses it); its only job is to keep the probe unoptimized. */
static void ac_probe_post(struct kprobe *p, struct pt_regs *regs,
                          unsigned long flags)
{
}

/* ------------------------------------------------------------------ */
/* policy / parameters                                                 */
/* ------------------------------------------------------------------ */
static unsigned int ac_policy = 0x1;   /* bit0: SIGKILL a process that attacks a
                                         * protected proc via ptrace or
                                         * process_vm_readv/writev */
module_param(ac_policy, uint, 0600);
MODULE_PARM_DESC(ac_policy, "policy bitmask: bit0 = kill ptrace/process_vm offenders");

static bool ac_verbose = true;
module_param(ac_verbose, bool, 0600);
MODULE_PARM_DESC(ac_verbose, "print extra diagnostics");

/* ------------------------------------------------------------------ */
/* symbol resolution via kprobes                                       */
/* ------------------------------------------------------------------ */
/* sleeps — do not call with spinlock held */
static unsigned long ac_lookup(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr = 0;

    might_sleep();

    if (register_kprobe(&kp) == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }
    return addr;
}

/* Normalize a kprobe-reported address to the start of the function.
 * On x86-64 with IBT + fentry the kprobe lands on the ftrace call site,
 * i.e. 4 bytes after the endbr64, whereas the syscall table stores the
 * symbol start (the endbr64 itself).  Detect endbr64 (0xf3 0x0f 0x1e 0xfa)
 * right before the address and step back; on kernels without that layout
 * the address is already the function start. */
static unsigned long ac_normalize_func(unsigned long addr)
{
    unsigned int insn;

    if (!addr)
        return 0;
    if (addr < 4)
        return addr;
    if (ac_kread(&insn, (void *)(addr - 4), sizeof(insn)) == 0 &&
        insn == 0xfa1e0ff3)   /* endbr64, little-endian */
        return addr - 4;
    return addr;
}

static unsigned long ac_stext;
static unsigned long ac_etext;
static unsigned long ac_text_end;   /* upper bound for "core kernel text" */

static bool ac_module_sane(const struct module *m);   /* fwd decl */

static void ac_resolve_text_bounds(void)
{
    ac_stext = ac_lookup("_stext");
    if (!ac_stext)
        ac_stext = ac_lookup("_text");
    ac_etext = ac_lookup("_etext");
    if (!ac_etext)
        ac_etext = ac_lookup("_sinittext");

    if (ac_etext)
        ac_text_end = ac_etext;
    else if (ac_stext)
        ac_text_end = ac_stext + 0x20000000UL;   /* generous image bound */
}

/* ------------------------------------------------------------------ */
/* module list walking (kernel-internal list; module_mutex is not      */
/* exported, so we walk under rcu_read_lock() instead — the same       */
/* protection the kernel's own is_module_address()/is_module_text_     */
/* address() use for this exact list).                                 */
/*                                                                      */
/* This is a real liveness guarantee, not best-effort: module unload   */
/* (kernel/module/main.c: free_module()) does list_del_rcu() followed  */
/* by synchronize_rcu() *before* freeing the module's core memory      */
/* (which is where `struct module` itself lives). Holding rcu_read_    */
/* lock() across the walk means that free can't complete until this    */
/* reader leaves the critical section, so a `struct module *` handed   */
/* out by list_for_each_entry_rcu() here is guaranteed live for as     */
/* long as we hold the lock -- no UAF, no generation-counter retry     */
/* loop needed. list_for_each_entry_rcu() (vs. plain list_for_each_    */
/* entry()) additionally pairs with the list's own list_add_rcu()/     */
/* list_del_rcu() writers via rcu_dereference(), so the ->next         */
/* pointers themselves are read safely too, not just the memory they   */
/* point at.                                                            */
/* ------------------------------------------------------------------ */
static bool ac_addr_in_module(unsigned long addr)
{
    struct module *m;
    bool found = false;

    rcu_read_lock();
    list_for_each_entry_rcu(m, &THIS_MODULE->list, list) {
        if (ac_module_sane(m) && within_module_core(addr, m)) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();
    return found;
}

static bool ac_in_core_text(unsigned long addr)
{
    if (!ac_stext || !ac_text_end)
        return false;
    if (addr < ac_stext || addr >= ac_text_end)
        return false;
    if (ac_addr_in_module(addr))
        return false;
    return true;
}

static unsigned long ac_anchor;   /* known-good syscall handler (read) */

/* Bounds-free handler sanity check: the address must live outside every
 * loaded module and within a sane window around a known-good handler.
 * (Exact _stext/_etext are preferred when kprobe-able, but are section
 * labels and may not be; this window is the fallback.) */
static bool ac_plausible_handler(unsigned long e, unsigned long anchor)
{
    if (!e)
        return false;
    if (ac_addr_in_module(e))
        return false;
    return e > anchor - 0x4000000UL && e < anchor + 0x4000000UL;
}

static bool ac_entry_bad(unsigned long e)
{
    if (ac_stext && ac_text_end)
        return !ac_in_core_text(e);
    return !ac_plausible_handler(e, ac_anchor);
}

/* ------------------------------------------------------------------ */
/* syscall table discovery                                             */
/* ------------------------------------------------------------------ */
static unsigned long ac_syscall_table;

/*
 * Locate sys_call_table without kallsyms_lookup_name:
 *  - resolve __x64_sys_read/__x64_sys_write handler addresses via kprobes,
 *  - scan the kernel image for an 8-byte slot equal to the read handler,
 *  - verify the write handler sits at table[__NR_write] and that most
 *    entries are real core-text handlers (distinguishes the main table
 *    from e.g. the x32 table, which reuses the same handlers sparsely).
 */
static bool ac_table_plausible(unsigned long base, unsigned long anchor)
{
    unsigned int i, valid = 0;

    for (i = 0; i < __NR_syscalls; i++) {
        unsigned long e = 0;

        if (ac_kread(&e, (void *)(base + i * sizeof(e)), sizeof(e)))
            continue;
        if (!e)
            continue;
        if (ac_plausible_handler(e, anchor) && ++valid >= 400)
            return true;
    }
    if (ac_verbose)
        pr_info("plausibility for base=0x%lx: valid=%u\n", base, valid);
    return valid >= 400;
}

/* Once the table is found, derive core-text bounds from its (plausible)
 * entries so the integrity check can classify entries even when the
 * _stext/_etext kprobe lookups failed. */
static void ac_derive_bounds(unsigned long base, unsigned long anchor)
{
    unsigned int i;
    unsigned long lo = 0, hi = 0;

    for (i = 0; i < __NR_syscalls; i++) {
        unsigned long e = 0;

        if (ac_kread(&e, (void *)(base + i * sizeof(e)), sizeof(e)))
            continue;
        if (!ac_plausible_handler(e, anchor))
            continue;
        if (!lo || e < lo)
            lo = e;
        if (e > hi)
            hi = e;
    }
    if (lo && hi) {
        if (!ac_stext)
            ac_stext = lo & ~0x1FFFFFUL;                 /* 2 MB round down */
        if (!ac_text_end)
            ac_text_end = (hi + 0x1FFFFFUL) & ~0x1FFFFFUL; /* 2 MB round up */
        pr_info("derived text bounds: stext=0x%lx end=0x%lx\n",
                ac_stext, ac_text_end);
    }
}

static unsigned long ac_find_syscall_table(void)
{
    unsigned long rh, wh, lo, hi, addr, base, v1, v2;

    rh = ac_normalize_func(ac_lookup("__x64_sys_read"));
    wh = ac_normalize_func(ac_lookup("__x64_sys_write"));
    if (ac_verbose)
        pr_info("lookup __x64_sys_read=0x%lx __x64_sys_write=0x%lx\n",
                rh, wh);
    if (!rh || !wh)
        return 0;

    if (!ac_stext && !ac_etext)
        pr_warn("text bounds unresolved (_stext/_etext not kprobe-able); "
                "using anchor-relative scan window around handler\n");

    /* Primary window: from the end of .text forward.  On x86-64 the table
     * lives in .rodata right after .text. */
    lo = ac_etext ? ac_etext : (ac_stext ? ac_stext : rh);
    hi = lo + 0x2000000UL;      /* 32 MB window */
    if (ac_verbose)
        pr_info("table scan window [0x%lx, 0x%lx)\n", lo, hi);
    for (addr = lo; addr < hi; addr += sizeof(unsigned long)) {
        if (ac_kread(&v1, (void *)addr, sizeof(v1)))
            continue;
        if (v1 != rh)
            continue;
        base = addr - __NR_read * sizeof(unsigned long);
        if (ac_kread(&v2, (void *)(base + __NR_write * sizeof(unsigned long)),
                     sizeof(v2)))
            continue;
        if (ac_verbose)
            pr_info("candidate addr=0x%lx base=0x%lx v2=0x%lx\n",
                    addr, base, v2);
        if (v2 == wh && ac_table_plausible(base, rh)) {
            ac_anchor = rh;
            ac_derive_bounds(base, rh);
            return base;
        }
    }

    /* Fallback: backward scan from the read handler.  Rarely taken (the
     * table is normally right after .text), so mirror the forward window
     * rather than skimping on it: some layouts place the table below the
     * first handler. */
    for (addr = rh; addr > rh - 0x2000000UL; addr -= sizeof(unsigned long)) {
        if (ac_kread(&v1, (void *)addr, sizeof(v1)))
            continue;
        if (v1 != rh)
            continue;
        base = addr - __NR_read * sizeof(unsigned long);
        if (ac_kread(&v2, (void *)(base + __NR_write * sizeof(unsigned long)),
                     sizeof(v2)))
            continue;
        if (ac_verbose)
            pr_info("fallback candidate addr=0x%lx base=0x%lx v2=0x%lx\n",
                    addr, base, v2);
        if (v2 == wh && ac_table_plausible(base, rh)) {
            ac_anchor = rh;
            ac_derive_bounds(base, rh);
            return base;
        }
    }
    return 0;
}

/* Per-slot "already reported" state so a persistent hook is emitted once
 * on the rising edge instead of on every AC_IOCTL_CHECK_SYSCALLS call
 * (the daemon polls this every 5s); see #52. */
static unsigned long ac_hooked_bitmap[BITS_TO_LONGS(__NR_syscalls)];

/* ------------------------------------------------------------------ */
/* boot-time syscall-handler-address baseline (#63)                    */
/*                                                                      */
/* The range check above (ac_entry_bad() / ac_hooked_bitmap) only ever */
/* asks "does this entry still point inside core kernel text" -- by    */
/* design it can't see a hook that redirects one in-text handler to    */
/* another (e.g. sys_read -> sys_write), which is explicitly out of    */
/* scope per THREAT_MODEL.md's "Within-core-kernel-text redirects"     */
/* note. This snapshot closes that specific gap: capture every         */
/* handler address once, at module load, checksum it, and on every     */
/* later check compare both the whole-table checksum and each          */
/* individual slot against that baseline. A slot whose address changed */
/* while still passing the core-text check is exactly the redirect     */
/* case the range check can't catch on its own.                        */
/* ------------------------------------------------------------------ */
static unsigned long ac_syscall_baseline[__NR_syscalls];
static char ac_syscall_baseline_hex[65];
static bool ac_syscall_baseline_ready;
/* Per-slot rising-edge state for AC_EV_SYSCALL_REDIRECT, same rationale
 * as ac_hooked_bitmap above (avoid re-emitting every 5s poll). */
static unsigned long ac_redirect_bitmap[BITS_TO_LONGS(__NR_syscalls)];
/* Set for slot i once ac_syscall_baseline[i] holds a value ac_kread()
 * actually returned for it (at boot, or backfilled below) -- including a
 * successful read of 0, which is why this is a separate bitmap rather
 * than just testing ac_syscall_baseline[i] for truthiness: a failed
 * read is also stored as 0, and the two must not be conflated (see
 * ac_check_syscalls()'s "read_ok" handling below). */
static unsigned long ac_baseline_captured[BITS_TO_LONGS(__NR_syscalls)];
/* Serializes ac_check_syscalls() below: AC_IOCTL_CHECK_SYSCALLS is called
 * with no per-fd state, so the periodic monitor-loop caller and an
 * on-demand `anticheat syscalls` caller (or several of the latter) can
 * run concurrently. Without this, two callers racing a slot whose boot
 * capture failed could each pass the "not yet captured" check and
 * backfill ac_syscall_baseline[i] from a different live read -- if an
 * attacker redirects that slot between the two reads, the redirected
 * address can win the race and become the trusted baseline. The lock
 * covers the whole read-backfill-hash-bitmap sequence per call, not just
 * the backfill, since ac_syscall_baseline_hex is rewritten in place and
 * an unlocked reader (out->baseline_sha256's strscpy()) could otherwise
 * observe it mid-update.
 */
static DEFINE_MUTEX(ac_syscall_check_lock);

/* Called once from ac_init(), after ac_syscall_table is located. A read
 * failure on any individual slot leaves that slot uncaptured (0, bit
 * clear in ac_baseline_captured) rather than aborting the whole
 * baseline -- ac_check_syscalls() below backfills such a slot from the
 * first later successful read, so a boot-time hiccup on one slot only
 * narrows (doesn't defeat) redirect detection for it. */
static void ac_capture_syscall_baseline(void)
{
    unsigned long base = ac_syscall_table;
    unsigned int i;

    if (!base)
        return;

    for (i = 0; i < __NR_syscalls; i++) {
        unsigned long e = 0;

        if (!ac_kread(&e, (void *)(base + i * sizeof(e)), sizeof(e)))
            __set_bit(i, ac_baseline_captured);   /* a successful read of
                                                     * 0 still counts */
        else
            e = 0;
        ac_syscall_baseline[i] = e;
    }
    ac_sha256_hex(ac_syscall_baseline, sizeof(ac_syscall_baseline),
                  ac_syscall_baseline_hex);
    ac_syscall_baseline_ready = true;
    if (ac_verbose)
        pr_info("syscall handler baseline captured: sha256=%s\n",
                ac_syscall_baseline_hex);
}

static int ac_check_syscalls(struct ac_syscall_check *out)
{
    unsigned long base = ac_syscall_table;
    unsigned int i;
    ac_sha256_ctx hash;
    uint8_t digest[32];

    memset(out, 0, sizeof(*out));
    out->table_addr = base;
    if (!base)
        return -ENODEV;   /* table not located at load time; not an I/O fault */

    out->nr_syscalls = __NR_syscalls;
    out->baseline_ready = ac_syscall_baseline_ready;

    mutex_lock(&ac_syscall_check_lock);
    ac_sha256_init(&hash);
    for (i = 0; i < __NR_syscalls; i++) {
        unsigned long e = 0;
        bool bad, read_ok, have_baseline;

        read_ok = !ac_kread(&e, (void *)(base + i * sizeof(e)), sizeof(e));
        have_baseline = ac_syscall_baseline_ready &&
                        test_bit(i, ac_baseline_captured);

        if (!read_ok) {
            /* Nothing was actually observed this round. 0 is itself a
             * value a slot could legitimately hold (see
             * ac_baseline_captured's comment), so hashing a fabricated 0
             * here would let a transient ac_kread() failure masquerade as
             * a real handler change and manufacture a false checksum-only
             * compromise report. Fall back to whatever's already trusted
             * for this slot instead, so an unobserved slot's contribution
             * to the whole-table hash reads as "unchanged". */
            e = have_baseline ? ac_syscall_baseline[i] : 0;
        }
        ac_sha256_update(&hash, &e, sizeof(e));

        if (!read_ok) {
            /* Leave ac_redirect_bitmap/ac_hooked_bitmap and the backfill
             * state exactly as they were -- clearing either here would
             * both hide a condition that's still there and, on the next
             * successful read of an unchanged-but-still-flagged slot,
             * re-trigger the event via the rising-edge checks below,
             * defeating the once-per-transition dedup. */
            continue;
        }

        if (ac_syscall_baseline_ready) {
            if (!have_baseline) {
                /* Boot-time capture never got a reading for this slot
                 * (ac_table_plausible() already validated hundreds of
                 * other entries, so this is a narrow per-slot hiccup, not
                 * a misidentified table). Adopt this first later reading
                 * -- including a legitimate 0 -- as the baseline now
                 * instead of leaving the slot permanently exempt from
                 * redirect detection; this only narrows, same as the
                 * already-accepted pre-snapshot-redirect gap in
                 * THREAT_MODEL.md, the window in which a redirect
                 * installed before the backfill would be captured as
                 * "normal". */
                ac_syscall_baseline[i] = e;
                __set_bit(i, ac_baseline_captured);
                ac_sha256_hex(ac_syscall_baseline, sizeof(ac_syscall_baseline),
                              ac_syscall_baseline_hex);
                clear_bit(i, ac_redirect_bitmap);
            } else if (e != ac_syscall_baseline[i]) {
                if (!ac_entry_bad(e)) {
                    /* still inside core text but a different handler than
                     * what was there at boot -- the in-text-redirect case. */
                    out->redirected++;
                    if (!test_and_set_bit(i, ac_redirect_bitmap))
                        ac_emit(AC_EV_SYSCALL_REDIRECT, 0, "?",
                                "syscall[%u] handler changed 0x%lx -> 0x%lx (still core text)",
                                i, ac_syscall_baseline[i], e);
                } else {
                    clear_bit(i, ac_redirect_bitmap);
                }
            } else {
                clear_bit(i, ac_redirect_bitmap);
            }
        }

        if (!e)
            continue;
        out->total++;
        bad = ac_entry_bad(e);
        if (bad) {
            out->non_text++;
            out->hooked++;
            if (!test_and_set_bit(i, ac_hooked_bitmap))
                ac_emit(AC_EV_SYSCALL_HOOK, 0, "?",
                        "syscall[%u] -> 0x%lx outside core kernel text", i, e);
        } else {
            clear_bit(i, ac_hooked_bitmap);
        }
    }
    if (ac_syscall_baseline_ready)
        strscpy(out->baseline_sha256, ac_syscall_baseline_hex,
                sizeof(out->baseline_sha256));   /* after the loop: reflects
                                                    * any backfill above */
    mutex_unlock(&ac_syscall_check_lock);
    ac_sha256_final(&hash, digest);
    ac_sha256_hex_digest(digest, out->current_sha256);
    out->checksum_mismatch = ac_syscall_baseline_ready &&
        strcmp(out->current_sha256, out->baseline_sha256) != 0;

    out->ok = (out->hooked == 0);
    return 0;
}

/* ------------------------------------------------------------------ */
/* event ring buffer                                                   */
/* ------------------------------------------------------------------ */
#define AC_RING_SIZE 256

static struct ac_event ac_ring[AC_RING_SIZE];
static unsigned int ac_ring_head, ac_ring_tail, ac_ring_count;
static DEFINE_SPINLOCK(ac_ring_lock);
static unsigned int ac_dropped;
static unsigned int ac_last_hook_count;
/* Monotonic count of events ever removed from the ring, by *any* means
 * (overflow eviction below, ac_drain_events(), or ac_commit_events()).
 * Lets ac_commit_events() tell "already removed by a racing eviction
 * since the matching ac_peek_events()" apart from "still present, safe
 * to remove" -- see the pairing's comment below for why a plain
 * remove-n-oldest is wrong. */
static u64 ac_ring_removed;
/* Serializes the whole peek -> copy_to_user() -> commit sequence for
 * AC_IOCTL_GET_EVENTS so two overlapping callers can't both peek the
 * same entries and then each independently decide it's safe to commit
 * them -- ac_ring_removed alone only protects against ac_emit()'s
 * eviction racing a single GET_EVENTS call, not two GET_EVENTS calls
 * racing each other. */
static DEFINE_MUTEX(ac_get_events_lock);
/* Woken any time ac_emit() pushes a new entry, so AC_IOCTL_GET_EVENTS can
 * block until the ring is actually non-empty instead of polling on a
 * fixed cadence (see the wait in its ioctl handler below). Only ever
 * used to wake blocked GET_EVENTS callers -- it carries no data of its
 * own, ac_ring_lock/ac_ring_count remain the source of truth. */
static DECLARE_WAIT_QUEUE_HEAD(ac_event_wq);

static void ac_emit(unsigned int type, int pid, const char *comm,
                    const char *fmt, ...)
{
    struct ac_event *ev;
    va_list args;
    unsigned long flags;

    spin_lock_irqsave(&ac_ring_lock, flags);
    if (ac_ring_count >= AC_RING_SIZE) {
        ac_ring_tail = (ac_ring_tail + 1) % AC_RING_SIZE;
        ac_ring_count--;
        ac_dropped++;
        ac_ring_removed++;
    }
    ev = &ac_ring[ac_ring_head];
    memset(ev, 0, sizeof(*ev));
    ev->ts = ktime_get_real_fast_ns();
    ev->pid = pid;
    strscpy(ev->comm, comm ? comm : "?", sizeof(ev->comm));
    ev->type = type;
    va_start(args, fmt);
    vsnprintf(ev->data, sizeof(ev->data), fmt, args);
    va_end(args);
    ac_ring_head = (ac_ring_head + 1) % AC_RING_SIZE;
    ac_ring_count++;
    spin_unlock_irqrestore(&ac_ring_lock, flags);
    /* Outside the spinlock: wake_up_interruptible() takes its own lock
     * (the waitqueue's) and there is no ordering requirement that
     * requires holding ac_ring_lock across it -- a waiter that checks
     * ac_ring_count right after this event was already counted in will
     * always see it non-empty, whether it observes that before or after
     * this wake-up call. */
    wake_up_interruptible(&ac_event_wq);
}

static int ac_drain_events(struct ac_event_list *out)
{
    unsigned long flags;

    spin_lock_irqsave(&ac_ring_lock, flags);
    if (out) {
        out->dropped = ac_dropped;
        out->count = 0;
    }
    while (ac_ring_count > 0 && (!out || out->count < AC_MAX_EVENTS)) {
        if (out)
            out->events[out->count++] = ac_ring[ac_ring_tail];
        ac_ring_tail = (ac_ring_tail + 1) % AC_RING_SIZE;
        ac_ring_count--;
        ac_ring_removed++;
    }
    spin_unlock_irqrestore(&ac_ring_lock, flags);
    return 0;
}

/* Copies up to AC_MAX_EVENTS oldest ring entries into *out without
 * removing them from the ring, and records the current ac_ring_removed
 * value in *removed_before. Paired with ac_commit_events() below so
 * AC_IOCTL_GET_EVENTS can copy_to_user() the snapshot first and only
 * remove entries from the ring once that copy actually lands -- a
 * copy_to_user() fault must not lose events that were never successfully
 * handed to userspace. Call only while holding ac_get_events_lock. */
static void ac_peek_events(struct ac_event_list *out, u64 *removed_before)
{
    unsigned long flags;
    unsigned int idx;

    spin_lock_irqsave(&ac_ring_lock, flags);
    out->dropped = ac_dropped;
    out->count = 0;
    *removed_before = ac_ring_removed;
    idx = ac_ring_tail;
    while (out->count < ac_ring_count && out->count < AC_MAX_EVENTS) {
        out->events[out->count] = ac_ring[idx];
        idx = (idx + 1) % AC_RING_SIZE;
        out->count++;
    }
    spin_unlock_irqrestore(&ac_ring_lock, flags);
}

/* Removes the `n` entries a prior ac_peek_events() returned, now that
 * the caller has safely copied them to userspace -- *not* simply "the
 * current n oldest entries", which would be wrong if ac_emit()'s
 * overflow eviction removed some of *our* peeked entries in the
 * meantime and then new, never-copied events were appended: naively
 * removing n-oldest-now would delete those new events instead. Using
 * removed_before (recorded at peek time) to compute how many of our own
 * n entries were already evicted lets this only ever remove entries
 * this call actually copied out. Call only while holding
 * ac_get_events_lock (serializes against another GET_EVENTS's
 * peek/commit; ac_ring_lock alone only orders against ac_emit()). */
static void ac_commit_events(unsigned int n, u64 removed_before)
{
    unsigned long flags;
    u64 removed_since;
    unsigned int to_remove;

    spin_lock_irqsave(&ac_ring_lock, flags);
    removed_since = ac_ring_removed - removed_before;
    to_remove = removed_since >= n ? 0 : n - (unsigned int)removed_since;
    if (to_remove > ac_ring_count)
        to_remove = ac_ring_count;
    ac_ring_tail = (ac_ring_tail + to_remove) % AC_RING_SIZE;
    ac_ring_count -= to_remove;
    ac_ring_removed += to_remove;
    spin_unlock_irqrestore(&ac_ring_lock, flags);
}

/* ------------------------------------------------------------------ */
/* protected process registry (mm_struct-keyed; see #62 / discussion   */
/* #85 for why -- one entry per address space, torn down via an        */
/* mmu_notifier .release callback instead of tracking per-thread        */
/* task_struct exit/exec transitions.                                  */
/*                                                                      */
/* mmu_notifier_register()/_unregister() both sleep (they take          */
/* mm->mmap_lock internally), but registry mutations can also originate */
/* from kprobe/kretprobe handlers (ac_clone_ret(), the exec kretprobes  */
/* below), which run in atomic context -- same constraint documented on */
/* ac_schedule_kill() further down. Those paths never call the notifier */
/* functions directly: they hand off to ac_schedule_prot_add()/         */
/* ac_schedule_prot_rekey(), which defer the actual (un)registration to */
/* ac_wq and run in ordinary process context. AC_IOCTL_ADD_PROC/         */
/* DEL_PROC and module unload are already process context (ioctl        */
/* handler, ac_exit()), so they call ac_add_prot_mm()/ac_del_prot_mm()   */
/* synchronously.                                                       */
/* ------------------------------------------------------------------ */
#define AC_PROT_MAX 64

/* Placeholder for a slot that's in the middle of being claimed: the
 * table-scan-and-claim step (spinlock, can't sleep) and the actual
 * mmu_notifier_register() call (sleeps) can't happen atomically, so the
 * slot is marked with this sentinel while the lock is dropped for the
 * register() call, to stop a concurrent caller from claiming it too.
 * Never a real mm_struct pointer (kmalloc'd objects are never at this
 * address); every free-slot scan below naturally skips it since it's
 * neither NULL nor equal to any real mm pointer. The *dedupe* scan can't
 * just skip it the same way, though -- see .claiming below -- so it isn't
 * quite true that no special-casing is needed anywhere else. */
#define AC_PROT_RESERVED ((struct mm_struct *)1)

struct ac_prot_entry {
    struct mm_struct *mm;        /* NULL = free slot; see AC_PROT_RESERVED */
    struct mmu_notifier notifier;
    pid_t pid;                   /* display only, snapshot at register time */
    bool jit_allowed;
    /* Set under ac_prot_lock for the duration of an in-flight
     * mmu_notifier_unregister() call on this slot (ac_del_prot_mm(),
     * ac_clear_protected()) -- see those functions for why a slot can't
     * be treated as free/reusable just because .mm reads NULL or matches,
     * until that call has actually returned. */
    bool removing;
    /* Meaningful only while .mm == AC_PROT_RESERVED: the real mm this
     * slot is mid-registering for. AC_PROT_RESERVED itself carries no mm
     * identity, so without this a second ac_add_prot_mm() call for the
     * exact same mm -- e.g. two AC_IOCTL_ADD_PROC calls naming two
     * threads of one process, or one racing ac_prot_add_worker() after an
     * exec rekey -- can't see that a registration for it is already in
     * flight, and claims a second slot: two independent notifier
     * registrations for one address space, inflating ac_prot_count,
     * double-listing the pid, and leaving one still registered after
     * ac_del_prot_mm() stops at its first (and only known) match. */
    struct mm_struct *claiming;
    char comm[AC_MAX_COMM];
};

static struct ac_prot_entry ac_prots[AC_PROT_MAX];
static DEFINE_SPINLOCK(ac_prot_lock);
static unsigned int ac_prot_count;

static struct task_struct *ac_find_task(pid_t pid)
{
    struct pid *pidp = find_get_pid(pid);
    struct task_struct *task;

    if (!pidp)
        return NULL;
    task = get_pid_task(pidp, PIDTYPE_PID);
    put_pid(pidp);
    return task;
}

/* Resolve `nr` as a pid number within the pid namespace that host-pid
 * ref_pid lives in, rather than the caller's own namespace. Lets a
 * privileged caller target a process by its in-namespace pid (e.g. a
 * sandboxed/containerized game) when it can supply some other
 * host-resolvable pid known to be in that same namespace (ref_pid).
 *
 * find_pid_ns() has no internal locking (unlike find_get_pid(), which
 * wraps rcu_read_lock() itself), and task_active_pid_ns(ref_task) is
 * only safe to read while ref_task's reference is held -- ref_task could
 * otherwise exit concurrently on another CPU. So the namespace lookup and
 * find_pid_ns() call must both happen strictly before put_task_struct().
 * The resulting struct pid is pinned with get_pid() before the RCU
 * read-side critical section ends, mirroring how find_get_pid() itself
 * pins under rcu_read_lock(). */
static struct task_struct *ac_find_task_in_ns_of(pid_t nr, pid_t ref_pid)
{
    struct task_struct *ref_task, *target;
    struct pid_namespace *ns;
    struct pid *pidp;

    ref_task = ac_find_task(ref_pid);
    if (!ref_task)
        return NULL;

    rcu_read_lock();
    ns = task_active_pid_ns(ref_task);
    pidp = ns ? find_pid_ns(nr, ns) : NULL;
    if (pidp)
        get_pid(pidp);
    rcu_read_unlock();

    put_task_struct(ref_task);
    if (!pidp)
        return NULL;

    target = get_pid_task(pidp, PIDTYPE_PID);
    put_pid(pidp);
    return target;
}

/* mmu_notifier_register() takes an mm_count reference (mmgrab()) that only
 * mmu_notifier_unregister() balances (mmdrop(), unconditionally, even if
 * ->release() already ran) -- calling it is mandatory for every successful
 * register(), not just a courtesy. ac_del_prot_mm()/ac_clear_protected()
 * provide that call for the explicit-removal case, but nothing else ever
 * will for a slot whose mm exited organically: once ac_mmu_release() below
 * clears e->mm to NULL, no future scan can ever match this slot by mm
 * pointer again to unregister it. Deferred here via ac_wq, same GFP_ATOMIC/
 * queue_work() shape as ac_schedule_kill() -- this callback must not call
 * mmu_notifier_unregister() reentrantly on itself (see ac_mmu_release()'s
 * own comment), and its calling context isn't guaranteed sleepable. The mm
 * can't be freed before the worker runs: the very mmgrab() reference this
 * is balancing is what's keeping mm_count elevated until then. */
struct ac_prot_release_req {
    struct work_struct work;
    struct ac_prot_entry *e;
    struct mm_struct *mm;
};

static void ac_prot_release_worker(struct work_struct *w)
{
    struct ac_prot_release_req *r =
        container_of(w, struct ac_prot_release_req, work);
    unsigned long flags;

    /* ->release() already ran synchronously before this worker was even
     * queued (that's how we got here), so this call's hlist_unhashed()
     * check will find it already unhashed and won't re-invoke release() --
     * it only performs the mdrop() this slot still owes. */
    mmu_notifier_unregister(&r->e->notifier, r->mm);

    spin_lock_irqsave(&ac_prot_lock, flags);
    r->e->removing = false;
    spin_unlock_irqrestore(&ac_prot_lock, flags);
    mempool_free(r, ac_prot_release_pool);
}

/* ->release() is invoked either by exit_mmap() when mm_users hits zero
 * (the normal "process actually exited" path) or synchronously from
 * within mmu_notifier_unregister() (explicit AC_IOCTL_DEL_PROC / module
 * unload / a successful exec-rekey's drop of the old entry) -- either way
 * this is the one and only place a table slot is cleared, so entry removal
 * can't race itself or be done twice. Must not call
 * mmu_notifier_unregister() synchronously from in here for the *organic*
 * case (that would reenter the generic release path we're already inside
 * of); see ac_prot_release_worker() for why and how that call still
 * happens, deferred.
 *
 * e->removing, already true here whenever ac_del_prot_mm()/
 * ac_clear_protected() is the one whose in-flight mmu_notifier_unregister()
 * call triggered this ->release() synchronously, is exactly the signal
 * needed to tell that apart from a real organic exit_mmap(): AC_EV_EXIT
 * must fire only for the latter -- the address space is still alive in
 * the former case (an operator's unprotect, module unload, or a
 * protected process re-exec'ing), so "protected process exited" would be
 * a false claim, and the caller's own in-flight unregister() call already
 * owes no further deferral (it does the mdrop() itself on return). */
static void ac_mmu_release(struct mmu_notifier *subscription,
                            struct mm_struct *mm)
{
    struct ac_prot_entry *e = container_of(subscription,
                                            struct ac_prot_entry, notifier);
    unsigned long flags;
    pid_t pid;
    char comm[AC_MAX_COMM];
    bool removed = false;
    bool caller_initiated = false;
    struct ac_prot_release_req *r;

    spin_lock_irqsave(&ac_prot_lock, flags);
    if (e->mm == mm) {
        pid = e->pid;
        strscpy(comm, e->comm, sizeof(comm));
        caller_initiated = e->removing;
        e->mm = NULL;
        if (!caller_initiated)
            e->removing = true;   /* pins the slot against ac_add_prot_mm()
                                    * reuse until the deferred worker's
                                    * unregister() call actually returns */
        ac_prot_count--;
        removed = true;
    }
    spin_unlock_irqrestore(&ac_prot_lock, flags);
    if (!removed)
        return;

    if (caller_initiated) {
        /* ac_del_prot_mm()/ac_clear_protected() is already inside its own
         * mmu_notifier_unregister() call for this exact slot; that call
         * does the mandatory mmdrop() itself on return, so no further
         * deferral is needed here. */
        return;
    }

    ac_emit(AC_EV_EXIT, pid, comm, "protected process exited");

    /* mempool-backed, same reasoning as ac_schedule_prot_add_req() -- a
     * plain kmalloc(GFP_ATOMIC) failure here would leak this slot's
     * mm_count reference *permanently* (nothing else will ever call
     * mmu_notifier_unregister() for it, see the comment above
     * ac_prot_release_worker()) and pin the slot against reuse forever,
     * so repeated failures could eventually exhaust AC_PROT_MAX. The NULL
     * check below is defense in depth, not the expected path. */
    r = mempool_alloc(ac_prot_release_pool, GFP_ATOMIC);
    if (!r) {
        pr_err("anticheat: OOM deferring mmu_notifier cleanup for exited pid %d (%s); mm and slot leaked\n",
               pid, comm);
        return;
    }
    r->e = e;
    r->mm = mm;
    INIT_WORK(&r->work, ac_prot_release_worker);
    queue_work(ac_wq, &r->work);
}

static const struct mmu_notifier_ops ac_mmu_notifier_ops = {
    .release = ac_mmu_release,
};

/* Register `mm` (already pinned by the caller for the duration of this
 * call -- this function neither takes nor drops a reference on it) as
 * protected. Must be called from process context: mmu_notifier_register()
 * sleeps (mm->mmap_lock). Dedupes by mm pointer, same shape as the old
 * ac_add_prot_task() but keyed by address space instead of task.
 *
 * Two racing calls for the same mm (two AC_IOCTL_ADD_PROC calls naming
 * different threads of one process, or one racing ac_prot_add_worker()
 * after an exec rekey) must not both end up claiming a slot: see the
 * .claiming field's comment for why the dedupe scan checks AC_PROT_RESERVED
 * slots too, not just fully-registered ones. A slot mid-teardown
 * (.removing) is deliberately *not* treated as a dedupe match -- reporting
 * "already protected" for a registration that's about to actually vanish
 * (ac_del_prot_mm()/ac_clear_protected() completing moments later) would
 * be a false claim, so this proceeds to register a fresh one instead;
 * briefly having two independent registrations for the same mm during
 * that narrow handoff is harmless (the kernel allows it) and self-resolves
 * once the old one's teardown finishes. */
static int ac_add_prot_mm(struct mm_struct *mm, pid_t pid, const char *comm,
                           bool jit_allowed)
{
    unsigned long flags;
    int i, slot = -1;
    int ret;

    /* Kernel threads (PF_KTHREAD) never own an mm_struct (see issue #69's
     * concern about them wasting a registry slot) -- get_task_mm() already
     * returns NULL for one, so every caller here (ac_add_prot_pid(),
     * ac_clone_ret() via ac_schedule_prot_add()) bails out before ever
     * reaching this task. No separate PF_KTHREAD check is needed at the
     * mm layer. */
    spin_lock_irqsave(&ac_prot_lock, flags);
    for (i = 0; i < AC_PROT_MAX; i++) {
        if (ac_prots[i].mm == mm && !ac_prots[i].removing) {
            ac_prots[i].jit_allowed = jit_allowed;  /* updatable via re-protect */
            spin_unlock_irqrestore(&ac_prot_lock, flags);
            return 0;                                /* already protected */
        }
        if (ac_prots[i].mm == AC_PROT_RESERVED && ac_prots[i].claiming == mm) {
            /* Another caller is already mid-register for this exact mm;
             * its registration will cover it once it lands, so don't also
             * claim a second slot for it. */
            spin_unlock_irqrestore(&ac_prot_lock, flags);
            return 0;
        }
        if (!ac_prots[i].mm && !ac_prots[i].removing && slot < 0)
            slot = i;
    }
    if (slot < 0) {
        spin_unlock_irqrestore(&ac_prot_lock, flags);
        return -ENOSPC;
    }
    ac_prots[slot].mm = AC_PROT_RESERVED;
    ac_prots[slot].claiming = mm;
    spin_unlock_irqrestore(&ac_prot_lock, flags);

    /* struct mmu_notifier has no ops parameter of its own -- the caller
     * sets ->ops directly before registering. */
    ac_prots[slot].notifier.ops = &ac_mmu_notifier_ops;
    ret = mmu_notifier_register(&ac_prots[slot].notifier, mm);

    spin_lock_irqsave(&ac_prot_lock, flags);
    if (ret) {
        ac_prots[slot].mm = NULL;
        spin_unlock_irqrestore(&ac_prot_lock, flags);
        return ret;
    }
    ac_prots[slot].mm = mm;
    ac_prots[slot].pid = pid;
    ac_prots[slot].jit_allowed = jit_allowed;
    strscpy(ac_prots[slot].comm, comm, sizeof(ac_prots[slot].comm));
    ac_prot_count++;
    spin_unlock_irqrestore(&ac_prot_lock, flags);
    return 0;
}

static int ac_add_prot_pid(pid_t pid, pid_t ref_pid, bool jit_allowed,
                            char *comm_out)
{
    struct task_struct *t = ref_pid > 0 ? ac_find_task_in_ns_of(pid, ref_pid)
                                         : ac_find_task(pid);
    struct mm_struct *mm;
    int ret;

    if (!t)
        return -ESRCH;
    if (comm_out)
        strscpy(comm_out, t->comm, AC_MAX_COMM);
    mm = get_task_mm(t);
    if (!mm) {
        put_task_struct(t);
        return -ESRCH;  /* kernel thread, or already tearing down */
    }
    ret = ac_add_prot_mm(mm, t->pid, t->comm, jit_allowed);
    put_task_struct(t);
    mmput(mm);           /* process context (ioctl): plain mmput() is fine */
    return ret;
}

/* Unregister `mm` (caller-pinned, same convention as ac_add_prot_mm()).
 * Process context only: mmu_notifier_unregister() sleeps, and it invokes
 * ac_mmu_release() synchronously before returning, which does the actual
 * table cleanup -- so there's no separate removal step here. No-op if
 * `mm` has no registry entry (including if ac_mmu_release() already ran
 * for it concurrently, e.g. the process exited right as this was
 * called).
 *
 * The match-and-mark below has to happen in the same ac_prot_lock critical
 * section: finding slot i under the lock, dropping the lock, and only then
 * marking it as being removed would leave a window where ac_add_prot_mm()
 * can see the slot as free (once ac_mmu_release() clears it from a
 * concurrent exit_mmap()) and reinitialise ac_prots[i].notifier for an
 * unrelated mm before the mmu_notifier_unregister() call below runs --
 * which would then unregister a notifier that no longer belongs to `mm`
 * at all, corrupting whatever mm it now belongs to. Marking .removing
 * under the same lock that finds the match closes that window: it stops
 * ac_add_prot_mm() from reusing the slot (see its free-slot scan) for as
 * long as this call is in flight, regardless of whether ac_mmu_release()
 * also fires concurrently and clears .mm out from under it. */
static void ac_del_prot_mm(struct mm_struct *mm)
{
    unsigned long flags;
    int i;
    bool found = false;

    spin_lock_irqsave(&ac_prot_lock, flags);
    for (i = 0; i < AC_PROT_MAX; i++) {
        if (ac_prots[i].mm == mm && !ac_prots[i].removing) {
            ac_prots[i].removing = true;
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&ac_prot_lock, flags);
    if (!found)
        return;

    mmu_notifier_unregister(&ac_prots[i].notifier, mm);

    spin_lock_irqsave(&ac_prot_lock, flags);
    ac_prots[i].removing = false;
    spin_unlock_irqrestore(&ac_prot_lock, flags);
}

/* Fork inheritance already extends *protection* itself to children (see
 * ac_clone_ret()); mirror that for jit_allowed too, so a legitimate
 * JIT-marked process's child processes don't generate false anon-exec
 * reports just because the flag reset to false on them.
 *
 * Dedup in ac_add_prot_mm() is by mm pointer, so there's exactly one entry
 * per address space in the steady state, and a concurrent ADD_PROC racing
 * an in-flight register for the same mm no longer creates a second one
 * either (see the .claiming field's comment). The one remaining source of
 * a transient duplicate is narrower: ac_add_prot_mm() deliberately doesn't
 * treat a slot mid-teardown (.removing) as a dedupe match, so a fresh
 * AC_IOCTL_ADD_PROC racing an in-flight ac_del_prot_mm()/
 * ac_clear_protected() for the same mm can briefly leave two entries for
 * it until the old one's teardown finishes (see ac_add_prot_mm()'s own
 * comment). AND-reduce across every matching entry, same as the old
 * task-keyed ac_task_jit_allowed(): the mm is jit_allowed only if *every*
 * entry for it agrees, failing toward the safer (more likely to report)
 * state rather than depending on scan order or which entry wins the
 * race. */
static bool ac_prot_jit_allowed_mm(struct mm_struct *mm)
{
    unsigned long flags;
    int i;
    bool jit_allowed = true;
    bool found = false;

    spin_lock_irqsave(&ac_prot_lock, flags);
    for (i = 0; i < AC_PROT_MAX; i++) {
        if (ac_prots[i].mm == mm) {
            found = true;
            jit_allowed = jit_allowed && ac_prots[i].jit_allowed;
        }
    }
    spin_unlock_irqrestore(&ac_prot_lock, flags);
    return found && jit_allowed;
}

static bool ac_is_protected_mm(struct mm_struct *mm)
{
    unsigned long flags;
    int i;
    bool prot = false;

    if (!mm)
        return false;
    spin_lock_irqsave(&ac_prot_lock, flags);
    for (i = 0; i < AC_PROT_MAX; i++) {
        if (ac_prots[i].mm == mm) {
            prot = true;
            break;
        }
    }
    spin_unlock_irqrestore(&ac_prot_lock, flags);
    return prot;
}

/* current's own mm -- reading current->mm directly (no get_task_mm()) is
 * safe since a task can't have its own ->mm concurrently freed out from
 * under itself. */
static bool ac_is_protected_current(void)
{
    return ac_is_protected_mm(current->mm);
}

/* Like ac_is_protected_mm(), but for an arbitrary target task_struct
 * rather than current -- process_vm_readv(2)/writev(2) and ptrace(2)
 * accept any thread ID in a process, not just its tgid, and every thread
 * shares the same mm_struct, so a target-permission check must resolve
 * the target's mm rather than compare task/thread-group identity. Safe
 * from kprobe context: get_task_mm() only takes task_lock() (a spinlock)
 * and bumps mm_users, it doesn't sleep -- but the matching drop uses
 * mmput_async() rather than plain mmput(), since *that* call can run the
 * real teardown (sleeps) if it happens to be the last reference, which a
 * kprobe pre-handler must never risk. */
static bool ac_is_protected_task_mm(struct task_struct *t)
{
    struct mm_struct *mm = get_task_mm(t);
    bool prot;

    if (!mm)
        return false;
    prot = ac_is_protected_mm(mm);
    mmput_async(mm);
    return prot;
}

static bool ac_is_protected_pid(pid_t pid, char *comm_out)
{
    struct task_struct *t = ac_find_task(pid);
    bool prot = false;

    if (!t)
        return false;
    prot = ac_is_protected_task_mm(t);
    if (prot && comm_out)
        strscpy(comm_out, t->comm, AC_MAX_COMM);
    put_task_struct(t);
    return prot;
}

/* ------------------------------------------------------------------ */
/* deferred mm (un)registration -- see the block comment at the top of  */
/* the registry section above for why kprobe/kretprobe-originated        */
/* add/rekey requests can't call mmu_notifier_register()/_unregister()   */
/* directly and must hand off to ac_wq instead.                         */
/*                                                                      */
/* Known gap (tracked in issue #87, not fixed here): a child's own      */
/* exec racing ahead of its own not-yet-run fork-inherit request. If a  */
/* protected process forks and the child execs before                  */
/* ac_prot_add_worker() has dequeued and run the fork-inherit request   */
/* ac_clone_ret() queued for it, ac_exec_entry() finds current->mm not  */
/* yet in ac_prots[] (registration is still pending, not done) and      */
/* treats the child as unprotected -- it does nothing, rather than      */
/* redirecting the in-flight request to the child's new post-exec mm.   */
/* The worker then goes on to register the child's now-orphaned         */
/* pre-exec mm, which is a mostly harmless no-op (that mm has no live    */
/* task using it and organically self-releases moments later, via the   */
/* very mmput() ac_prot_add_worker() itself does once ac_add_prot_mm()   */
/* returns -- no permanent slot leak), but leaves a real, narrow window  */
/* where the freshly-exec'd child is NOT actually covered by             */
/* ptrace/process_vm defenses despite the inherit policy intending it    */
/* to be. Properly closing this needs a "pending transition" visible to  */
/* ac_exec_entry() (and ac_is_protected_mm()'s other callers) so an      */
/* exec racing an in-flight fork/rekey request can redirect it to the    */
/* live mm instead of racing past it -- a materially bigger change than  */
/* anything else in this file's mm-keyed registry, deliberately left for */
/* a follow-up rather than folded into it under time pressure.           */
/* ------------------------------------------------------------------ */
struct ac_prot_add_req {
    struct work_struct work;
    struct mm_struct *mm;        /* new mm to register; ref owned by this
                                   * request until the worker mmput()s it */
    struct mm_struct *old_mm;    /* exec-rekey only: entry to drop once mm
                                   * is registered; NULL for a plain fork-
                                   * inherit add */
    pid_t new_pid;
    char new_comm[AC_MAX_COMM];
    pid_t src_pid;                /* parent (fork) or pre-exec self (exec) */
    char src_comm[AC_MAX_COMM];
    bool jit_allowed;
};

static void ac_prot_add_worker(struct work_struct *w)
{
    struct ac_prot_add_req *r = container_of(w, struct ac_prot_add_req, work);
    int ret = ac_add_prot_mm(r->mm, r->new_pid, r->new_comm, r->jit_allowed);

    if (r->old_mm) {
        if (ret == 0) {
            ac_del_prot_mm(r->old_mm);
            ac_emit(AC_EV_EXEC, r->new_pid, r->new_comm,
                    "protected pid %d re-exec'd; protection carried to new image",
                    r->src_pid);
        } else {
            ac_emit(AC_EV_INFO, r->src_pid, r->src_comm,
                    "protected pid %d re-exec'd but NOT re-registered: %d",
                    r->src_pid, ret);
        }
        mmput(r->old_mm);
    } else {
        if (ret == 0)
            ac_emit(AC_EV_FORK, r->new_pid, r->new_comm,
                    "child of protected pid %d (%s); protection inherited",
                    r->src_pid, r->src_comm);
        else
            ac_emit(AC_EV_INFO, r->new_pid, r->new_comm,
                    "child of protected pid %d (%s) NOT protected: %d",
                    r->src_pid, r->src_comm, ret);
    }
    mmput(r->mm);
    mempool_free(r, ac_prot_add_pool);
}

static void ac_schedule_prot_add_req(struct mm_struct *mm,
                                      struct mm_struct *old_mm,
                                      pid_t new_pid, const char *new_comm,
                                      pid_t src_pid, const char *src_comm,
                                      bool jit_allowed)
{
    /* mempool_alloc() with GFP_ATOMIC falls back to ac_prot_add_pool's
     * pre-reserved elements instead of returning NULL whenever a plain
     * kmalloc(GFP_ATOMIC) would have -- see the pool's own comment for why
     * silently dropping this request (leaving a should-be-protected mm
     * unregistered) isn't acceptable here. The NULL check below is
     * defense in depth, not the expected path: it can in principle still
     * fail if more than AC_PROT_MAX requests are simultaneously
     * outstanding *and* the underlying allocator is also failing. */
    struct ac_prot_add_req *r = mempool_alloc(ac_prot_add_pool, GFP_ATOMIC);

    if (!r) {
        mmput_async(mm);
        if (old_mm)
            mmput_async(old_mm);
        return;
    }
    INIT_WORK(&r->work, ac_prot_add_worker);
    r->mm = mm;
    r->old_mm = old_mm;
    r->new_pid = new_pid;
    strscpy(r->new_comm, new_comm, sizeof(r->new_comm));
    r->src_pid = src_pid;
    strscpy(r->src_comm, src_comm, sizeof(r->src_comm));
    r->jit_allowed = jit_allowed;
    queue_work(ac_wq, &r->work);
}

/* Queue `mm` (caller's get_task_mm() reference -- handed off, always
 * consumed via mmput()/mmput_async() by the worker or on failure here) for
 * protection inherited from a fork. Callable from kretprobe context
 * (ac_clone_ret()). */
static void ac_schedule_prot_add(struct mm_struct *mm, pid_t new_pid,
                                  const char *new_comm, pid_t parent_pid,
                                  const char *parent_comm, bool jit_allowed)
{
    ac_schedule_prot_add_req(mm, NULL, new_pid, new_comm,
                              parent_pid, parent_comm, jit_allowed);
}

/* Queue a rekey from `old_mm` to `new_mm` after a protected task's
 * execve() replaced its address space. Both are caller-pinned references,
 * handed off the same way. Callable from kretprobe context (the exec
 * kretprobes below). */
static void ac_schedule_prot_rekey(struct mm_struct *old_mm,
                                    struct mm_struct *new_mm, pid_t pid,
                                    const char *comm, bool jit_allowed)
{
    ac_schedule_prot_add_req(new_mm, old_mm, pid, comm, pid, comm,
                              jit_allowed);
}

/* lock state: pinned by AC_IOCTL_LOCK (try_module_get) */
static atomic_t ac_lock_count = ATOMIC_INIT(0);

static unsigned int ac_protected_count(void)
{
    unsigned long flags;
    unsigned int n;

    spin_lock_irqsave(&ac_prot_lock, flags);
    n = ac_prot_count;
    spin_unlock_irqrestore(&ac_prot_lock, flags);
    return n;
}

static int ac_list_protected(struct ac_prot_list *out)
{
    unsigned long flags;
    unsigned int n = 0;
    int i;

    spin_lock_irqsave(&ac_prot_lock, flags);
    for (i = 0; i < AC_PROT_MAX && n < AC_MAX_PROTS; i++) {
        if (!ac_prots[i].mm || ac_prots[i].mm == AC_PROT_RESERVED)
            continue;
        out->items[n].pid = ac_prots[i].pid;
        out->items[n].jit_allowed = ac_prots[i].jit_allowed;
        strscpy(out->items[n].comm, ac_prots[i].comm,
                sizeof(out->items[n].comm));
        n++;
    }
    out->count = n;
    spin_unlock_irqrestore(&ac_prot_lock, flags);
    return 0;
}

/* ------------------------------------------------------------------ */
/* kill-from-workqueue (safe delivery from atomic kprobe context)      */
/* ------------------------------------------------------------------ */
struct ac_kill_req {
    struct work_struct work;
    struct pid *pid;
};

static void ac_kill_worker(struct work_struct *w)
{
    struct ac_kill_req *r = container_of(w, struct ac_kill_req, work);
    struct task_struct *t = get_pid_task(r->pid, PIDTYPE_PID);

    if (t) {
        pr_info("policy: SIGKILL pid %d (attacked a protected process)\n",
                t->pid);
        send_sig(SIGKILL, t, 0);
        put_task_struct(t);
    }
    put_pid(r->pid);
    mempool_free(r, ac_kill_pool);
}

static void ac_schedule_kill(struct task_struct *victim)
{
    struct ac_kill_req *r;

    if (!victim)
        return;
    r = mempool_alloc(ac_kill_pool, GFP_ATOMIC);
    if (!r) {
        atomic_inc(&ac_kill_dropped);
        pr_warn("anticheat: kill work dropped (pool exhausted)\n");
        return;
    }
    INIT_WORK(&r->work, ac_kill_worker);
    r->pid = get_task_pid(victim, PIDTYPE_PID);
    queue_work(ac_wq, &r->work);
}
/* ------------------------------------------------------------------ */
/* kprobes                                                             */
/* ------------------------------------------------------------------ */
static struct kprobe ac_kp_ptrace32;


static int ac_ptrace_pre(struct kprobe *p, struct pt_regs *regs)
{
    /*
     * Modern x86-64 syscall wrappers (__x64_sys_*, __ia32_sys_*) are
     * `long f(const struct pt_regs *regs)`: %rdi at entry points to the
     * syscall's pt_regs frame, and the wrapper unpacks the arguments
     * from it.  regs->di is the frame pointer, not the request.
     *
     * The native (__x64_sys_ptrace) wrapper unpacks its first two
     * arguments from args->di/args->si (the x86-64 argument registers).
     * The compat (__ia32_compat_sys_ptrace) wrapper instead unpacks them
     * from args->bx/args->cx, since ia32 syscall entry passes arguments in
     * ebx, ecx, edx, esi, edi, ebp rather than the native ABI's rdi,
     * rsi, rdx, r10, r8, r9. Reading di/si for the compat probe would
     * pick up the wrong register (ia32 arg5/arg4), silently mismatching
     * every compat ptrace() call.
     */
    struct pt_regs *args = (struct pt_regs *)regs->di;
    bool is_compat = (p == &ac_kp_ptrace32);
    long request, target;
    char tcomm[AC_MAX_COMM] = "?";
    bool deny = false, kill = false, killed = false;
    int rc;

    /* `args` is trusted only as far as regs->di actually points at a real
     * pt_regs frame -- if this probe ever lands on a different call site,
     * or a future kernel changes the wrapper ABI, it's an arbitrary
     * pointer. A raw args->field dereference here runs in atomic kprobe
     * context, where a bad address is an unrecoverable oops, not a
     * fault we can handle -- so every read/write through it goes through
     * the same *_nofault() machinery ac_kread() already uses for the
     * syscall-table scan. */
    if (is_compat) {
        if (ac_kread(&request, &args->bx, sizeof(request)) ||
            ac_kread(&target, &args->cx, sizeof(target)))
            return 0;
    } else {
        if (ac_kread(&request, &args->di, sizeof(request)) ||
            ac_kread(&target, &args->si, sizeof(target)))
            return 0;
    }

    if (request == PTRACE_TRACEME) {
        /* the protected process itself asks to be traced; PTRACE_TRACEME
         * ignores its arguments, so args->si holds whatever was in the
         * register — report current->pid, not stale garbage */
        if (ac_is_protected_current()) {
            strscpy(tcomm, current->comm, sizeof(tcomm));
            target = current->pid;
            deny = true;
        }
    } else if (target > 0) {
        if (ac_is_protected_pid((pid_t)target, tcomm)) {
            deny = true;
            kill = true;
        }
    }
    if (!deny)
        return 0;

    ac_emit(AC_EV_PTRACE, (int)target, tcomm,
            "ptrace req %ld by pid %d (%s) DENIED",
            request, current->pid, current->comm);

    killed = kill && (ac_policy & 0x1);
    if (killed)
        ac_schedule_kill(current);

    /* Neutralise the syscall: rewrite the request slot in the frame to an
     * invalid value.  ptrace() rejects unknown requests with -EIO and
     * performs no side effects, so the tracer sees a clean failure. The
     * reads above having succeeded means `args` does point at readable
     * memory, but a nofault write is still the right tool here: it's the
     * same "don't oops in atomic context on a bad address" guarantee,
     * and costs nothing on the expected path. */
    if (is_compat)
        rc = ac_kwrite_long(&args->bx, (unsigned long)-1);
    else
        rc = ac_kwrite_long(&args->di, (unsigned long)-1);

    if (rc) {
        /* Should be unreachable: args->{bx,di} is the very address
         * ac_kread() just read successfully above, on the same
         * always-mapped-RW kernel stack page, with nothing in between
         * that could change that. If it somehow fails anyway, we can no
         * longer neutralise this call -- ptrace() may still run with its
         * original, un-denied arguments. Escalate unconditionally: kill
         * the caller regardless of ac_policy (that bit governs the
         * normal deny path above, not this emergency fallback), since
         * the primary defense has already failed and letting the caller
         * keep running would defeat the deny entirely. A queued SIGKILL
         * alone is not containment -- the worker runs after this handler
         * returns, i.e. after the syscall has already run, and pool
         * exhaustion can drop the kill outright -- so also skip the
         * probed wrapper synchronously, returning the same -EIO the
         * neutralisation would have produced. Either barrier stops the
         * attack on its own. */
        pr_crit("anticheat: ptrace neutralisation write failed for req %ld target %d (%s) by pid %d (%s) -- killing caller\n",
                request, (int)target, tcomm, current->pid, current->comm);
        if (!killed)
            ac_schedule_kill(current);
        if (ac_skip_syscall(regs, -EIO))
            return 1;
    }
    return 0;
}

/* process_vm_readv(2)/process_vm_writev(2): the standard way to read or
 * write another process's memory without ever calling ptrace(2), so the
 * ptrace kprobe above doesn't see it at all. Both syscalls take the target
 * pid as their first argument (SYSCALL_DEFINE6(process_vm_read{v,writev},
 * pid_t, pid, ...)); neither has a distinct COMPAT_SYSCALL_DEFINE (unlike
 * ptrace, whose compat_long_t args need special handling), so the i386
 * syscall table maps straight to the same sys_process_vm_{read,write}v --
 * the standard wrapper-generation machinery still emits both a native
 * (__x64_sys_*) and a compat (__ia32_sys_*) entry point from that one
 * definition, unpacking the pid from the same register slot the ptrace
 * probe above already established: di for native, bx for compat. */
static struct kprobe ac_kp_process_vm_readv;
static struct kprobe ac_kp_process_vm_readv32;
static struct kprobe ac_kp_process_vm_writev32;

static int ac_process_vm_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *args = (struct pt_regs *)regs->di;
    bool is_compat = (p == &ac_kp_process_vm_readv32 ||
                       p == &ac_kp_process_vm_writev32);
    unsigned long raw_target;
    pid_t target;
    struct task_struct *t;
    char tcomm[AC_MAX_COMM] = "?";
    bool protected_target, killed;
    int rc;

    /* Same nofault requirement as ac_ptrace_pre() above: `args` is only
     * as trustworthy as regs->di, and a raw dereference here runs in
     * atomic kprobe context where a bad address oopses the kernel. */
    if (is_compat) {
        if (ac_kread(&raw_target, &args->bx, sizeof(raw_target)))
            return 0;
    } else {
        if (ac_kread(&raw_target, &args->di, sizeof(raw_target)))
            return 0;
    }
    target = (pid_t)raw_target;

    if (target <= 0)
        return 0;

    /* Resolve the target once and compare thread groups directly, rather
     * than comparing raw pid numbers against current->pid: current->pid is
     * this *thread's* kernel-internal id, not what a non-leader thread's
     * own getpid() returns (that's the thread-group id, current->tgid) --
     * and either can additionally differ from the raw kernel id inside a
     * nested pid namespace. A numeric self-check against current->pid
     * would therefore mis-fire for a protected process's own worker
     * thread reading its own memory: target (its getpid()) != current->pid
     * (this thread's own tid), so it would fall through to the protection
     * check below, match (same thread group), and get itself denied and,
     * per the default kill policy, SIGKILLed by its own daemon. Comparing
     * resolved task_structs sidesteps pid-namespace translation and thread
     * vs. thread-group id entirely. */
    t = ac_find_task(target);
    if (!t)
        return 0;
    if (same_thread_group(t, current)) {
        put_task_struct(t);
        return 0;
    }
    protected_target = ac_is_protected_task_mm(t);
    if (protected_target)
        strscpy(tcomm, t->comm, sizeof(tcomm));
    put_task_struct(t);
    if (!protected_target)
        return 0;

    ac_emit(AC_EV_PROCESS_VM, target, tcomm,
            "process_vm_%s by pid %d (%s) DENIED",
            (p == &ac_kp_process_vm_readv32 ||
             p == &ac_kp_process_vm_readv) ? "readv" : "writev",
            current->pid, current->comm);

    killed = ac_policy & 0x1;
    if (killed)
        ac_schedule_kill(current);

    /* Neutralise the syscall: rewrite the pid slot in the frame to an
     * invalid value. find_get_task_by_vpid() only runs after the iovecs
     * are parsed but before any target memory is touched, so this fails
     * cleanly with -ESRCH and never copies a single byte to/from the
     * protected process. Written via ac_kwrite_long(), not a raw store --
     * see ac_ptrace_pre()'s neutralisation comment. */
    if (is_compat)
        rc = ac_kwrite_long(&args->bx, (unsigned long)-1);
    else
        rc = ac_kwrite_long(&args->di, (unsigned long)-1);

    if (rc) {
        /* See ac_ptrace_pre()'s identical fallback: should be unreachable
         * (same address ac_kread() just read successfully, on an
         * always-mapped-RW kernel stack page), but if the write ever
         * does fail, the pid slot is unchanged and process_vm_{read,
         * write}v may still run against the protected target. Escalate
         * unconditionally, regardless of ac_policy, since the primary
         * defense has already failed -- and skip the probed wrapper
         * synchronously (the same -ESRCH it would have failed with),
         * since the queued SIGKILL only lands after the syscall has run
         * and pool exhaustion can drop it outright. */
        pr_crit("anticheat: process_vm neutralisation write failed for target pid %d (%s) by pid %d (%s) -- killing caller\n",
                target, tcomm, current->pid, current->comm);
        if (!killed)
            ac_schedule_kill(current);
        if (ac_skip_syscall(regs, -ESRCH))
            return 1;
    }
    return 0;
}

/* Fork tracking: kretprobe on kernel_clone().  The ret handler receives the
 * new task's pid via regs_return_value().  (A plain kprobe post_handler runs
 * after the first instruction of the function, not after it returns, so it
 * cannot see the return value.) */
static int ac_clone_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    long child_pid = (long)regs_return_value(regs);
    struct task_struct *child;
    struct mm_struct *child_mm;
    pid_t cpid;
    char ccomm[AC_MAX_COMM];

    if (child_pid <= 0)
        return 0;
    if (!ac_is_protected_current())
        return 0;

    child = ac_find_task((pid_t)child_pid);
    if (!child)
        return 0;

    /* CLONE_VM (e.g. pthread_create(), and vfork() until the child execs
     * or exits) makes the child share current's mm_struct pointer exactly
     * -- the registry entry for that mm already covers it, so there's
     * nothing to register. This is automatic by construction now that the
     * registry is keyed by address space: unlike the old task-keyed
     * registry, there's no separate CLONE_THREAD dedup check to
     * maintain here. Only a genuinely new mm (real fork()) needs its own
     * entry. */
    child_mm = get_task_mm(child);
    cpid = child->pid;
    strscpy(ccomm, child->comm, sizeof(ccomm));
    put_task_struct(child);
    if (!child_mm)
        return 0;                  /* kernel thread, or already gone */
    if (child_mm == current->mm) {
        mmput_async(child_mm);     /* kretprobe context: atomic, no plain mmput() */
        return 0;
    }

    /* Hands the child_mm reference off to the workqueue; released there
     * (or in ac_schedule_prot_add_req() on kmalloc failure) via
     * mmput_async(), never a plain mmput() -- this handler runs in
     * kretprobe (atomic) context, same reasoning as ac_schedule_kill().
     * The real AC_EV_FORK/AC_EV_INFO event is emitted from the worker
     * once the actual registration outcome (including -ENOSPC) is known,
     * not here -- see ac_prot_add_worker(): an event claiming inherited
     * protection before the deferred registration has even run would be
     * exactly the kind of false claim the old synchronous code's comment
     * warned about. */
    ac_schedule_prot_add(child_mm, cpid, ccomm, current->pid, current->comm,
                          ac_prot_jit_allowed_mm(current->mm));
    return 0;
}

static struct kretprobe ac_kp_clone = {
    .kp = { .symbol_name = "kernel_clone" },
    .handler = ac_clone_ret,
    .maxactive = 128,
};

/* execve()/execveat() tracking: a kretprobe, not a plain pre-handler.
 * Unlike the old task-keyed registry -- where task_struct identity
 * survives exec, so a protected process needed zero registry work on its
 * own execve() -- the mm-keyed registry has to actively re-key on exec,
 * since execve() replaces current->mm via exec_mmap() while current->pid
 * stays the same. Without this, re-exec of an already-protected process
 * would silently drop protection.
 *
 * entry_handler runs before exec_mmap(), in the role the old pre_handler
 * played, and pins the *old* mm if it was protected. handler (the ret
 * probe) runs after the real syscall body returns -- on a successful
 * exec that's after exec_mmap() already installed the new mm, so
 * get_task_mm(current) there returns the *new* one and the rekey can be
 * queued. On a failed exec (nonzero return), current is unchanged and
 * still owns old_mm -- nothing to rekey, just drop the pin.
 *
 * CLONE_VM without CLONE_THREAD -- vfork(), and therefore posix_spawn()/
 * system()/popen() on a libc that uses it -- makes current->mm literally
 * the still-live PARENT's mm_struct pointer until this exec (or an exit)
 * releases it back via mm_release(). If that shared mm happens to be
 * protected, that protection belongs to the parent, not to current: an
 * entry_handler here that pinned it as old_mm would have the ret probe
 * rekey/remove the PARENT's own live registry entry once this exec
 * succeeds, permanently dropping the parent's protection and logging a
 * false "protected process exited" for a process that's still running.
 * current->vfork_done is non-NULL for exactly the duration of that
 * borrowed-mm window (set at clone time, cleared by mm_release()), so
 * detecting it here and never touching old_mm/d->old_mm is what keeps the
 * parent's entry untouched -- ac_clone_ret() already decided at clone time
 * that this shared period needs no registry work of its own, and that
 * decision must hold until current gets its own independent mm.
 *
 * That still leaves the vfork child itself needing to inherit protection
 * across its own exec, the same as a plain fork()+exec() child already
 * does -- current->real_parent is exactly who that inheritance decision
 * should be attributed to, and it's safe to read without extra locking
 * here specifically because current->vfork_done being set guarantees the
 * parent is synchronously blocked waiting on this exec/exit, so it can't
 * be concurrently reaped or reparented out from under us. The entry
 * itself is queued the same way ac_clone_ret() queues a fork-inherit
 * add -- a fresh registration for the new mm, not a rekey -- since there
 * was never an old_mm entry belonging to current to remove. */
struct ac_exec_entry_data {
    struct mm_struct *old_mm;
    bool vfork_inherit;
    bool jit_allowed;              /* only meaningful if vfork_inherit */
    pid_t parent_pid;
    char parent_comm[AC_MAX_COMM];
};

static int ac_exec_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ac_exec_entry_data *d = (struct ac_exec_entry_data *)ri->data;

    d->old_mm = NULL;
    d->vfork_inherit = false;
    if (current->vfork_done) {
        if (current->mm && ac_is_protected_mm(current->mm)) {
            struct task_struct *parent;

            d->vfork_inherit = true;
            d->jit_allowed = ac_prot_jit_allowed_mm(current->mm);

            rcu_read_lock();
            parent = rcu_dereference(current->real_parent);
            d->parent_pid = parent->pid;
            strscpy(d->parent_comm, parent->comm, sizeof(d->parent_comm));
            rcu_read_unlock();
        }
        return 0;
    }
    if (current->mm && ac_is_protected_mm(current->mm)) {
        d->old_mm = current->mm;
        mmget(d->old_mm);
        /* AC_EV_INFO, not AC_EV_EXEC -- this fires on every attempt,
         * before the outcome (success/failure/rekey result) is known.
         * ac_exec_ret()/ac_prot_add_worker() emit the one authoritative
         * AC_EV_EXEC for this exec once that outcome actually lands, so
         * emitting it here too would double-count every successful
         * re-exec of a protected process. */
        ac_emit(AC_EV_INFO, current->pid, current->comm,
                "execve() invoked (path is a user pointer, not resolved)");
    }
    return 0;
}

static int ac_exec_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ac_exec_entry_data *d = (struct ac_exec_entry_data *)ri->data;
    long rc = (long)regs_return_value(regs);
    struct mm_struct *new_mm;

    if (d->vfork_inherit) {
        if (rc != 0)
            return 0;   /* exec failed: still sharing the parent's mm,
                          * which the parent's own entry keeps covering */
        new_mm = get_task_mm(current);
        if (!new_mm)
            return 0;   /* shouldn't happen on a successful exec */
        ac_schedule_prot_add(new_mm, current->pid, current->comm,
                              d->parent_pid, d->parent_comm, d->jit_allowed);
        return 0;
    }

    if (!d->old_mm)
        return 0;
    if (rc != 0) {
        mmput_async(d->old_mm);   /* exec failed: current still owns old_mm */
        return 0;
    }

    new_mm = get_task_mm(current);
    if (!new_mm || new_mm == d->old_mm) {
        /* Shouldn't happen on a successful exec, but don't leak the pin or
         * attempt a same-mm "rekey" if it somehow does. */
        mmput_async(d->old_mm);
        if (new_mm)
            mmput_async(new_mm);
        return 0;
    }

    ac_schedule_prot_rekey(d->old_mm, new_mm, current->pid, current->comm,
                            ac_prot_jit_allowed_mm(d->old_mm));
    return 0;
}

static struct kretprobe ac_kp_execve = {
    .kp = { .symbol_name = "__x64_sys_execve" },
    .entry_handler = ac_exec_entry,
    .handler = ac_exec_ret,
    .data_size = sizeof(struct ac_exec_entry_data),
    .maxactive = 64,
};
static struct kretprobe ac_kp_execveat = {
    .kp = { .symbol_name = "__x64_sys_execveat" },
    .entry_handler = ac_exec_entry,
    .handler = ac_exec_ret,
    .data_size = sizeof(struct ac_exec_entry_data),
    .maxactive = 64,
};
static struct kretprobe ac_kp_execve32 = {
    /* Same reasoning as ac_kp_ptrace32 below: execve/execveat have distinct
     * COMPAT_SYSCALL_DEFINEs, so the ia32 syscall table entries resolve to
     * __ia32_compat_sys_execve[at], not the unused generic __ia32_sys_*
     * stub. */
    .kp = { .symbol_name = "__ia32_compat_sys_execve" },
    .entry_handler = ac_exec_entry,
    .handler = ac_exec_ret,
    .data_size = sizeof(struct ac_exec_entry_data),
    .maxactive = 64,
};
static struct kretprobe ac_kp_execveat32 = {
    .kp = { .symbol_name = "__ia32_compat_sys_execveat" },
    .entry_handler = ac_exec_entry,
    .handler = ac_exec_ret,
    .data_size = sizeof(struct ac_exec_entry_data),
    .maxactive = 64,
};

static struct kretprobe *ac_kretprobes[] = {
    &ac_kp_clone, &ac_kp_execve, &ac_kp_execveat,
    &ac_kp_execve32, &ac_kp_execveat32,
};
static bool ac_kretp_ok[ARRAY_SIZE(ac_kretprobes)];
static unsigned int ac_kretprobes_registered;

static struct kprobe ac_kp_ptrace = {
    .symbol_name = "__x64_sys_ptrace",
    .pre_handler = ac_ptrace_pre,
    .post_handler = ac_probe_post,
};
static struct kprobe ac_kp_ptrace32 = {
    /* ptrace has a distinct COMPAT_SYSCALL_DEFINE (unlike process_vm_readv/
     * writev below), so arch/x86/entry/syscalls/syscall_32.tbl wires the
     * ia32 ptrace slot to the compat entry point, not the generic
     * __ia32_sys_ptrace stub the plain SYSCALL_DEFINE also emits but that
     * no syscall table ever references -- a kprobe there would silently
     * never fire for a real 32-bit ptrace() call. */
    .symbol_name = "__ia32_compat_sys_ptrace",
    .pre_handler = ac_ptrace_pre,
    .post_handler = ac_probe_post,
};
static struct kprobe ac_kp_process_vm_readv = {
    .symbol_name = "__x64_sys_process_vm_readv",
    .pre_handler = ac_process_vm_pre,
    .post_handler = ac_probe_post,
};
static struct kprobe ac_kp_process_vm_readv32 = {
    .symbol_name = "__ia32_sys_process_vm_readv",
    .pre_handler = ac_process_vm_pre,
    .post_handler = ac_probe_post,
};
static struct kprobe ac_kp_process_vm_writev = {
    .symbol_name = "__x64_sys_process_vm_writev",
    .pre_handler = ac_process_vm_pre,
    .post_handler = ac_probe_post,
};
static struct kprobe ac_kp_process_vm_writev32 = {
    .symbol_name = "__ia32_sys_process_vm_writev",
    .pre_handler = ac_process_vm_pre,
    .post_handler = ac_probe_post,
};

static struct kprobe *ac_kprobes[] = {
    &ac_kp_ptrace, &ac_kp_ptrace32,
    &ac_kp_process_vm_readv, &ac_kp_process_vm_readv32,
    &ac_kp_process_vm_writev, &ac_kp_process_vm_writev32,
};
static bool ac_kp_ok[ARRAY_SIZE(ac_kprobes)];  /* per-slot registration state */
static unsigned int ac_kprobes_registered;     /* count, for the log line */

static void ac_register_kprobes(void)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(ac_kprobes); i++) {
        int ret = register_kprobe(ac_kprobes[i]);

        ac_kp_ok[i] = (ret == 0);
        if (ret == 0) {
            ac_kprobes_registered++;
        } else if (ac_verbose) {
            pr_info("kprobe %s unavailable: %d\n",
                    ac_kprobes[i]->symbol_name, ret);
        }
    }
    for (i = 0; i < ARRAY_SIZE(ac_kretprobes); i++) {
        int ret = register_kretprobe(ac_kretprobes[i]);

        ac_kretp_ok[i] = (ret == 0);
        if (ret == 0) {
            ac_kretprobes_registered++;
        } else if (ac_verbose) {
            pr_info("kretprobe %s unavailable: %d\n",
                    ac_kretprobes[i]->kp.symbol_name, ret);
        }
    }
}

static void ac_unregister_kprobes(void)
{
    unsigned int i;

    /* unregister only the probes that actually registered: a failed probe
     * (e.g. no IA32 support) must not be passed to unregister_kprobe() */
    for (i = 0; i < ARRAY_SIZE(ac_kprobes); i++)
        if (ac_kp_ok[i])
            unregister_kprobe(ac_kprobes[i]);
    ac_kprobes_registered = 0;
    memset(ac_kp_ok, 0, sizeof(ac_kp_ok));
    for (i = 0; i < ARRAY_SIZE(ac_kretprobes); i++)
        if (ac_kretp_ok[i])
            unregister_kretprobe(ac_kretprobes[i]);
    ac_kretprobes_registered = 0;
    memset(ac_kretp_ok, 0, sizeof(ac_kretp_ok));
}

/* ------------------------------------------------------------------ */
/* VMA scan (snapshot per file-description)                            */
/* ------------------------------------------------------------------ */
struct ac_fd_state {
    struct mutex lock;          /* serializes SCAN/MODS snapshot access:
                                 * a shared/dup'd fd must not race a GET
                                 * against a concurrent BEGIN/END */
    struct ac_vma_info *vmas;   /* SCAN snapshot */
    int resolved_pid;           /* host-namespace pid of the last SCAN_BEGIN
                                  * target, for ac_scan_begin.resolved_pid */
    unsigned int n_vmas;
    unsigned int rwx_count;
    unsigned int exec_count;
    unsigned int anon_exec_count;
    unsigned int truncated;
    struct ac_mod_info *mods;   /* MODS snapshot */
    unsigned int n_mods;
};

static void ac_free_fd_state(struct ac_fd_state *st)
{
    if (!st)
        return;
    kvfree(st->vmas);
    kvfree(st->mods);
    kfree(st);
}

/* Guards the check-then-set of file->private_data below. Without this,
 * two threads sharing one open file description (SCM_RIGHTS, or fork()
 * without O_CLOEXEC) calling SCAN_BEGIN/MODS_BEGIN concurrently for the
 * first time on that fd can both observe private_data == NULL, both
 * allocate, and race to publish -- the loser's ac_fd_state (and its
 * kvmalloc_array'd snapshot) is silently overwritten with nothing left
 * pointing at it, a permanent kernel memory leak, and its own BEGIN's
 * result becomes unreachable via the fd's later GET calls. Global, not
 * per-file: this only serializes the rare first-BEGIN-on-an-fd moment,
 * never the SCAN/MODS hot path, which already has its own per-state
 * st->lock below. */
static DEFINE_MUTEX(ac_fd_state_alloc_lock);

static struct ac_fd_state *ac_get_fd_state(struct file *file)
{
    /* Fast path: once published below, an fd's state never changes again
     * for the life of the fd, so every BEGIN after the first on a given
     * fd -- the overwhelming majority of calls -- can skip the global
     * lock entirely instead of serializing against every other fd's
     * first BEGIN too. The acquire pairs with the release store below:
     * seeing a non-NULL pointer here also guarantees this thread observes
     * every write (kzalloc's zeroing, mutex_init()) that happened-before
     * that store, on any CPU. */
    struct ac_fd_state *st = smp_load_acquire(&file->private_data);

    if (st)
        return st;

    mutex_lock(&ac_fd_state_alloc_lock);
    st = file->private_data;
    if (!st) {
        st = kzalloc(sizeof(*st), GFP_KERNEL);
        if (st) {
            mutex_init(&st->lock);
            /* Release store: publishes the pointer only after the state
             * it points to is fully initialized, so the fast-path load
             * above can never observe a partially-initialized
             * ac_fd_state. */
            smp_store_release(&file->private_data, st);
        }
    }
    mutex_unlock(&ac_fd_state_alloc_lock);
    return st;
}

static unsigned long long ac_module_size(const struct module *mod)
{
    unsigned long long size = 0;

    for_class_mod_mem_type(type, core)
        size += mod->mem[type].size;
    return size;
}

/* A plausible module entry: LIVE with a non-zero, sane text mapping.
 * Guards the mutex-less module walk against torn entries (module_mutex
 * is not exported; see ac_addr_in_module()'s comment for why the walk
 * itself is RCU-protected against *freed* ones).  A garbage entry with
 * base=0 and a huge size would otherwise make within_module_core() claim
 * every kernel address, poisoning both the hidden-module check and the
 * syscall plausibility filter.
 *
 * The is_vmalloc_addr() check guards against a subtler problem than a
 * torn entry: both walk sites below do
 * list_for_each_entry_rcu(m, &THIS_MODULE->list, list), which only stops
 * once it circles back to THIS_MODULE's own list node -- not the
 * kernel's real (unexported) `modules` list_head sentinel. A full walk
 * necessarily passes through that sentinel too, and list_for_each_entry_rcu
 * unconditionally container_of()s it into a `struct module *` as if it
 * were a real entry, even though it isn't embedded in one. Dereferencing
 * that bogus pointer reads whatever kernel global happens to sit at
 * that computed offset -- a real, reproduced KASAN global-out-of-bounds
 * (confirmed: lands inside a kernel workqueue global on one tested
 * layout). A genuine struct module always lives inside that module's
 * own vmalloc'd core memory; the sentinel-derived pointer instead lands
 * in the kernel's statically-linked image, so is_vmalloc_addr() tells
 * the two apart without ever needing the sentinel's own (unexported)
 * address. */
static bool ac_module_sane(const struct module *m)
{
    if (!is_vmalloc_addr(m))
        return false;
    if (m->state != MODULE_STATE_LIVE)
        return false;
    if (!m->mem[MOD_TEXT].base || !m->mem[MOD_TEXT].size)
        return false;
    if (m->mem[MOD_TEXT].size > 0x40000000UL)   /* > 1 GiB text: bogus */
        return false;
    return true;
}

static int ac_build_vma_snapshot(struct ac_fd_state *st, int pid,
                                 int ref_pid, int emit_events)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned int n = 0;
    char *pathbuf;

    kvfree(st->vmas);
    st->vmas = NULL;
    st->n_vmas = st->rwx_count = st->exec_count = st->anon_exec_count = st->truncated = 0;
    st->resolved_pid = 0;

    task = ref_pid > 0 ? ac_find_task_in_ns_of(pid, ref_pid)
                        : ac_find_task(pid);
    if (!task)
        return -ESRCH;
    /* task_pid_nr(), not the caller-supplied `pid`: with ref_pid > 0,
     * `pid` is namespace-relative and meaningless for host-side
     * /proc/<pid>/... access -- the daemon needs this host pid for its
     * own --hash/--check-hooks/--check-preload/etc. work after
     * SCAN_BEGIN returns. Must be read before put_task_struct() below,
     * same reference-liveness reasoning as ac_find_task_in_ns_of()'s own
     * comment. */
    st->resolved_pid = task_pid_nr(task);
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return -ESRCH;

    st->vmas = kvmalloc_array(AC_MAX_VMAS, sizeof(struct ac_vma_info),
                              GFP_KERNEL);
    if (!st->vmas) {
        pr_warn("scan: kvmalloc_array(%u, %zu) failed for pid %d\n",
                AC_MAX_VMAS, sizeof(struct ac_vma_info), pid);
        mmput(mm);
        return -ENOMEM;
    }

    /* Allocated once, before mmap_read_lock(), and reused for every
     * file-backed VMA's d_path() below. A per-VMA GFP_KERNEL kmalloc while
     * holding the *target* process's mmap_read_lock is a sleeping
     * allocation under another task's lock -- a lockdep/reclaim footgun,
     * and it needlessly extends how long that lock is held on a process
     * with many VMAs. Missing this buffer just means that VMA's path is
     * left empty; it never fails the whole scan. */
    pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);

    mmap_read_lock(mm);
    VMA_ITERATOR(vmi, mm, 0);
    for_each_vma(vmi, vma) {
        struct ac_vma_info *vi;
        char *p;

        if (n >= AC_MAX_VMAS) {
            st->truncated = 1;
            break;
        }
        vi = &st->vmas[n];
        memset(vi, 0, sizeof(*vi));
        vi->start = vma->vm_start;
        vi->end = vma->vm_end;
        vi->offset = (unsigned long long)vma->vm_pgoff << PAGE_SHIFT;
        vi->flags = vma->vm_flags;
        if (vma->vm_file) {
            struct file *f = vma->vm_file;

            vi->is_file = 1;
            if (f->f_inode)
                vi->inode = f->f_inode->i_ino;
            if (pathbuf) {
                p = d_path(&f->f_path, pathbuf, PATH_MAX);
                if (!IS_ERR(p))
                    strscpy(vi->path, p, sizeof(vi->path));
            }
        }
        if ((vma->vm_flags & (VM_EXEC | VM_WRITE)) == (VM_EXEC | VM_WRITE)) {
            st->rwx_count++;
            if (emit_events)
                ac_emit(AC_EV_RWX, pid, "?",
                        "RWX mapping [0x%llx-0x%llx] %s",
                        vi->start, vi->end,
                        vi->path[0] ? vi->path : "(anonymous)");
        }
        if (!vi->is_file && (vma->vm_flags & VM_EXEC)) {
            /* No backing file at all -- legitimate executable code is always
             * backed by a file (the binary or a shared library) via mmap.
             * Also catches shellcode written to a RW mapping and then
             * mprotect()'d to R-X, which never trips the RWX check above
             * since W and X are never both set at the same instant.
             * vdso/vvar are expected, harmless members of this set (see the
             * AC_EV_ANON_EXEC comment in anticheat.h) -- the daemon alerts
             * on new entries appearing after a process is first observed,
             * not on the raw count. */
            st->anon_exec_count++;
            if (emit_events)
                ac_emit(AC_EV_ANON_EXEC, pid, "?",
                        "anonymous executable mapping [0x%llx-0x%llx]",
                        vi->start, vi->end);
        }
        if (vma->vm_flags & VM_EXEC)
            st->exec_count++;
        n++;
    }
    vma_iter_invalidate(&vmi);
    mmap_read_unlock(mm);
    mmput(mm);
    kfree(pathbuf);
    st->n_vmas = n;
    return 0;
}

static int ac_build_mod_snapshot(struct ac_fd_state *st)
{
    struct module *mod;
    unsigned int n = 0;

    kvfree(st->mods);
    st->mods = NULL;
    st->n_mods = 0;

    /* Single pass with a hard cap.  module_mutex is not exported, so this
     * walk uses rcu_read_lock() instead (see ac_addr_in_module()'s comment
     * above for why that's a real liveness guarantee against concurrent
     * load/unload, not just best-effort).  A single pass still avoids the
     * count/fill mismatch and the heap overflow a two-pass walk could
     * cause when the list's *membership* changes between passes -- RCU
     * protects the memory of entries we do visit, not the list shape. */
    st->mods = kvmalloc_array(AC_MAX_MODS, sizeof(struct ac_mod_info),
                              GFP_KERNEL);
    if (!st->mods)
        return -ENOMEM;

    rcu_read_lock();
    list_for_each_entry_rcu(mod, &THIS_MODULE->list, list) {
        struct ac_mod_info *mi;

        if (!ac_module_sane(mod))
            continue;
        if (n >= AC_MAX_MODS)
            break;
        mi = &st->mods[n];
        /* memset first: name[]+size+state leaves 4 bytes of compiler
         * padding for 8-byte struct alignment that strscpy/direct field
         * assignment never touch. MODS_GET copies this struct to
         * userspace verbatim, so unzeroed padding is a real (if small)
         * kernel info leak -- same bug class as the GET_EVENTS fix above,
         * found by the same audit. */
        memset(mi, 0, sizeof(*mi));
        strscpy(mi->name, mod->name, sizeof(mi->name));
        mi->size = ac_module_size(mod);
        mi->state = mod->state;
        n++;
    }
    rcu_read_unlock();
    st->n_mods = n;
    return 0;
}

/* ------------------------------------------------------------------ */
/* ioctl / misc device                                                 */
/* ------------------------------------------------------------------ */
static long ac_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    void __user *uarg = (void __user *)arg;
    int ret = 0;

    /* ac_open() already gated this fd to a CAP_SYS_ADMIN caller, but that
     * check ran once, for whoever called open() -- it says nothing about
     * who's calling ioctl() now. A process can legitimately open a
     * privileged fd and then drop privileges for the rest of its life (a
     * completely normal pattern), or the fd can cross a privilege boundary
     * entirely via SCM_RIGHTS or an inherited exec(). Without rechecking
     * here, whoever ends up holding the fd keeps full access -- including
     * LOCK (pin the module permanently) and ADD_PROC/DEL_PROC (rewrite
     * protection state) -- regardless of their current privilege.
     *
     * ns_capable(&init_user_ns, ...), not plain capable(): capable()
     * checks the capability against current_cred()'s own user_ns, so a
     * process holding CAP_SYS_ADMIN only inside an unprivileged user
     * namespace (e.g. "root" in a container) would pass. This device
     * protects the host, so the check has to be against the host
     * (init) namespace specifically -- that's exactly what
     * ns_capable(&init_user_ns, ...) does, and is the kernel's own
     * documented idiom for "real root only" checks. */
    if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
        return -EPERM;

    switch (cmd) {
    case AC_IOCTL_STATUS: {
        struct ac_status st;

        memset(&st, 0, sizeof(st));
        st.version = AC_IOCTL_VERSION;
        st.syscall_table_addr = ac_syscall_table;
        st.active_procs = ac_protected_count();
        st.events_dropped = READ_ONCE(ac_dropped);
        st.locked = atomic_read(&ac_lock_count) > 0 ? 1 : 0;
        st.syscall_hook_count = READ_ONCE(ac_last_hook_count);
        st.kill_dropped = (unsigned int)atomic_read(&ac_kill_dropped);
        if (copy_to_user(uarg, &st, sizeof(st)))
            return -EFAULT;
        return 0;
    }
    case AC_IOCTL_ADD_PROC: {
        struct ac_proc_id a;

        if (copy_from_user(&a, uarg, sizeof(a)))
            return -EFAULT;
        ret = ac_add_prot_pid(a.pid, a.ref_pid, a.jit_allowed != 0, a.comm);
        if (ret == 0 && ac_verbose)
            pr_info("protected pid %d (%s)\n", a.pid, a.comm);
        return ret;
    }
    case AC_IOCTL_DEL_PROC: {
        struct ac_proc_id d;
        struct task_struct *t;
        struct mm_struct *mm;

        if (copy_from_user(&d, uarg, sizeof(d)))
            return -EFAULT;
        t = d.ref_pid > 0 ? ac_find_task_in_ns_of(d.pid, d.ref_pid)
                           : ac_find_task(d.pid);
        if (!t)
            return -ESRCH;
        mm = get_task_mm(t);
        put_task_struct(t);
        if (!mm)
            return -ESRCH;
        /* Process context (ioctl): ac_del_prot_mm() sleeps
         * (mmu_notifier_unregister()). No-op if d.pid's mm isn't
         * currently registered. */
        ac_del_prot_mm(mm);
        mmput(mm);
        return 0;
    }
    case AC_IOCTL_SCAN_BEGIN: {
        struct ac_scan_begin b;
        struct ac_fd_state *st;

        if (copy_from_user(&b, uarg, sizeof(b)))
            return -EFAULT;
        st = ac_get_fd_state(file);
        if (!st) {
            pr_warn("scan: fd state alloc failed\n");
            return -ENOMEM;
        }
        mutex_lock(&st->lock);
        ret = ac_build_vma_snapshot(st, b.pid, b.ref_pid, b.emit_events);
        if (!ret) {
            b.resolved_pid = st->resolved_pid;
            b.n_vmas = st->n_vmas;
            b.rwx_count = st->rwx_count;
            b.exec_count = st->exec_count;
            b.anon_exec_count = st->anon_exec_count;
            b.truncated = st->truncated;
        }
        mutex_unlock(&st->lock);
        if (ret) {
            pr_warn("scan: build_vma_snapshot(pid=%d) = %d\n", b.pid, ret);
            return ret;
        }
        if (copy_to_user(uarg, &b, sizeof(b)))
            return -EFAULT;
        return 0;
    }
    case AC_IOCTL_SCAN_GET: {
        struct ac_scan_get g;
        struct ac_fd_state *st = smp_load_acquire(&file->private_data);
        int rc = 0;

        if (copy_from_user(&g, uarg, sizeof(g)))
            return -EFAULT;
        if (!st) {
            rc = -EINVAL;
        } else {
            mutex_lock(&st->lock);
            if (g.index >= st->n_vmas)
                rc = -EINVAL;
            else
                g.vma = st->vmas[g.index];
            mutex_unlock(&st->lock);
        }
        if (rc)
            return rc;
        if (copy_to_user(uarg, &g, sizeof(g)))
            return -EFAULT;
        return 0;
    }
    case AC_IOCTL_SCAN_END: {
        struct ac_fd_state *st = smp_load_acquire(&file->private_data);

        if (st) {
            mutex_lock(&st->lock);
            kvfree(st->vmas);
            st->vmas = NULL;
            st->n_vmas = 0;
            mutex_unlock(&st->lock);
        }
        return 0;
    }
    case AC_IOCTL_CHECK_SYSCALLS: {
        struct ac_syscall_check c;

        ret = ac_check_syscalls(&c);
        if (ret)
            return ret;
        WRITE_ONCE(ac_last_hook_count, c.hooked);
        if (copy_to_user(uarg, &c, sizeof(c)))
            return -EFAULT;
        return 0;
    }
    case AC_IOCTL_MODS_BEGIN: {
        struct ac_fd_state *st;
        unsigned int count;

        st = ac_get_fd_state(file);
        if (!st)
            return -ENOMEM;
        mutex_lock(&st->lock);
        ret = ac_build_mod_snapshot(st);
        if (!ret)
            count = st->n_mods;
        mutex_unlock(&st->lock);
        if (ret)
            return ret;
        if (copy_to_user(uarg, &count, sizeof(count)))
            return -EFAULT;
        return 0;
    }
    case AC_IOCTL_MODS_GET: {
        struct ac_mod_get g;
        struct ac_fd_state *st = smp_load_acquire(&file->private_data);
        int rc = 0;

        if (copy_from_user(&g, uarg, sizeof(g)))
            return -EFAULT;
        if (!st) {
            rc = -EINVAL;
        } else {
            mutex_lock(&st->lock);
            if (g.index >= st->n_mods)
                rc = -EINVAL;
            else
                g.mod = st->mods[g.index];
            mutex_unlock(&st->lock);
        }
        if (rc)
            return rc;
        if (copy_to_user(uarg, &g, sizeof(g)))
            return -EFAULT;
        return 0;
    }
    case AC_IOCTL_MODS_END: {
        struct ac_fd_state *st = smp_load_acquire(&file->private_data);

        if (st) {
            mutex_lock(&st->lock);
            kvfree(st->mods);
            st->mods = NULL;
            st->n_mods = 0;
            mutex_unlock(&st->lock);
        }
        return 0;
    }
    case AC_IOCTL_GET_EVENTS: {
        /* kzalloc, not kmalloc: ac_drain_events() only fills events[0..count),
         * leaving events[count..AC_MAX_EVENTS) untouched. The ioctl below
         * copies the whole struct to userspace regardless of count, so an
         * un-zeroed allocation would leak whatever uninitialized kernel heap
         * data happened to be in that slab slot -- a real info-disclosure
         * bug (CWE-457/CWE-200), not just a style nit. Found during an
         * input-hardening audit of every ioctl handler, not by symptom. */
        struct ac_event_list *el = kzalloc(sizeof(*el), GFP_KERNEL);
        u64 removed_before;
        unsigned int block_ms;
        long wret;

        if (!el)
            return -ENOMEM;
        /* Only block_ms is actually read from the caller -- copy the
         * whole struct in anyway (matches every other ioctl handler's
         * copy_from_user pattern) rather than a targeted sub-field copy;
         * ac_peek_events() below fully overwrites count/dropped/events
         * regardless of whatever was in the input buffer. */
        if (copy_from_user(el, uarg, sizeof(*el))) {
            kfree(el);
            return -EFAULT;
        }
        block_ms = el->block_ms;
        if (block_ms > AC_GET_EVENTS_MAX_BLOCK_MS)
            block_ms = AC_GET_EVENTS_MAX_BLOCK_MS;

        /* Block *outside* ac_get_events_lock -- it only needs to be held
         * across the peek/copy/commit sequence below, and holding it
         * across a multi-hundred-millisecond sleep would need every
         * other concurrent GET_EVENTS caller to also block on the mutex
         * for no reason. wait_event_interruptible_timeout() re-checks
         * the condition itself on every wake-up, so this is a plain
         * racy hint, not something that needs ac_ring_lock held: the
         * actual, authoritative peek happens under the lock afterwards
         * regardless of why we stopped waiting. Deliberately the
         * *_interruptible_ variant, not a plain uninterruptible wait --
         * a caller (the daemon monitor loop) must stay killable/
         * signal-responsive while blocked here. */
        if (block_ms) {
            wret = wait_event_interruptible_timeout(ac_event_wq,
                        READ_ONCE(ac_ring_count) > 0,
                        msecs_to_jiffies(block_ms));
            if (wret < 0) {
                /* Interrupted by a signal -- propagate -ERESTARTSYS
                 * rather than silently falling through to an empty
                 * result, so the caller (and its signal handler, e.g.
                 * the daemon's SIGTERM/SIGINT stop request) actually
                 * gets to run instead of this ioctl swallowing it. */
                kfree(el);
                return (int)wret;
            }
        }

        /* Held across the full peek/copy/commit sequence: see
         * ac_get_events_lock's own comment for why ac_ring_lock alone
         * isn't enough to keep two overlapping GET_EVENTS calls from
         * both peeking and then both committing the same entries. */
        mutex_lock(&ac_get_events_lock);
        ac_peek_events(el, &removed_before);
        if (copy_to_user(uarg, el, sizeof(*el))) {
            mutex_unlock(&ac_get_events_lock);
            kfree(el);
            return -EFAULT;
        }
        ac_commit_events(el->count, removed_before);
        mutex_unlock(&ac_get_events_lock);
        kfree(el);
        return 0;
    }
    case AC_IOCTL_FLUSH_EVENTS:
        ac_drain_events(NULL);
        return 0;
    case AC_IOCTL_LIST_PROTECTED: {
        struct ac_prot_list pl;

        memset(&pl, 0, sizeof(pl));
        ret = ac_list_protected(&pl);
        if (ret)
            return ret;
        if (copy_to_user(uarg, &pl, sizeof(pl)))
            return -EFAULT;
        return 0;
    }
    case AC_IOCTL_LOCK:
        /* Pin the module until a matching UNLOCK.  The reference is taken
         * globally (not per-fd), so the pin intentionally outlives the
         * locking process (crash, kill, or a CLI that opens/closes the
         * device).  Recovery is always possible: any CAP_SYS_ADMIN caller
         * can issue UNLOCK, which balances the count and releases the
         * reference. */
        if (try_module_get(THIS_MODULE)) {
            atomic_inc(&ac_lock_count);
            return 0;
        }
        return -EBUSY;
    case AC_IOCTL_UNLOCK:
        /* atomic_dec_if_positive() makes the check-and-decrement a single
         * atomic step, so two concurrent UNLOCKs racing a single LOCK can't
         * both observe a positive count and both call module_put(). */
        if (atomic_dec_if_positive(&ac_lock_count) >= 0)
            module_put(THIS_MODULE);
        return 0;
    default:
        return -ENOTTY;
    }
}

static int ac_open(struct inode *inode, struct file *file)
{
    /* See ac_ioctl()'s identical check: ns_capable(&init_user_ns, ...)
     * so a container "root" with CAP_SYS_ADMIN only in its own user
     * namespace can't open this device at all. */
    if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
        return -EPERM;
    file->private_data = NULL;
    return 0;
}

static int ac_release(struct inode *inode, struct file *file)
{
    /* Deliberately no module_put() here: the lock pin taken by
     * AC_IOCTL_LOCK is global and outlives this fd.  It is released by a
     * later AC_IOCTL_UNLOCK, which any privileged caller can issue. */
    ac_free_fd_state(file->private_data);
    file->private_data = NULL;
    return 0;
}

static const struct file_operations ac_fops = {
    .owner = THIS_MODULE,
    .open = ac_open,
    .release = ac_release,
    .unlocked_ioctl = ac_ioctl,
};

static struct miscdevice ac_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = AC_DEV_NAME,
    .fops = &ac_fops,
};

/* ------------------------------------------------------------------ */
/* module lifecycle                                                    */
/* ------------------------------------------------------------------ */
/* Called from ac_exit() after ac_unregister_kprobes() and flush_workqueue()
 * (see there for why the flush must come first): no new clone/exec/ioctl
 * path can add or rekey an entry once the kprobes are gone and the
 * workqueue is drained (misc_deregister() already ran too, and .owner on
 * ac_fops means rmmod itself can't happen while any fd is open, so no
 * ioctl can be in flight either), so this only has to unwind what's
 * already there. mmu_notifier_unregister() sleeps -- module unload is
 * process context, so that's fine -- and invokes ac_mmu_release()
 * synchronously, which is what actually clears each slot and decrements
 * ac_prot_count; there's nothing left for this function to touch
 * directly.
 *
 * Marks each slot .removing under the same lock that reads it, same
 * reasoning as ac_del_prot_mm(): although nothing here can reuse a slot
 * out from under this loop (no producer of new entries is still reachable
 * at this point), a real process backing one of these mms can still exit
 * for real at the same moment, racing this function's mmu_notifier_
 * unregister() call against that mm's own exit_mmap(); marking .removing
 * costs nothing and keeps the invariant -- a slot only ever has one
 * in-flight unregister -- true everywhere, not just here by virtue of
 * unload ordering. */
static void ac_clear_protected(void)
{
    int i;

    for (i = 0; i < AC_PROT_MAX; i++) {
        unsigned long flags;
        struct mm_struct *mm = NULL;

        spin_lock_irqsave(&ac_prot_lock, flags);
        if (ac_prots[i].mm && ac_prots[i].mm != AC_PROT_RESERVED &&
            !ac_prots[i].removing) {
            mm = ac_prots[i].mm;
            ac_prots[i].removing = true;
        }
        spin_unlock_irqrestore(&ac_prot_lock, flags);

        if (!mm)
            continue;

        mmu_notifier_unregister(&ac_prots[i].notifier, mm);

        spin_lock_irqsave(&ac_prot_lock, flags);
        ac_prots[i].removing = false;
        spin_unlock_irqrestore(&ac_prot_lock, flags);
    }
}

static int __init ac_init(void)
{
    int ret;

    /*
     * ac_schedule_kill() (see below) queues a tiny, non-blocking work item
     * (get_pid_task/send_sig/put_task_struct/put_pid/kfree — no sleeping,
     * no heavy CPU use) from kprobe context, i.e. atomic context, via
     * kmalloc(GFP_ATOMIC) + queue_work(). WQ_MEM_RECLAIM preserves
     * create_workqueue()'s guarantee of a rescuer thread so kill delivery
     * still makes forward progress under memory pressure. WQ_HIGHPRI gets
     * the kill dispatched ahead of ordinary work, which matters here since
     * this is the delivery path for terminating a process that just
     * attacked a protected one. WQ_UNBOUND is deliberately omitted rather
     * than passed: each work item is queued from the CPU that took the
     * kprobe hit, and bound (per-CPU) execution keeps that cache locality
     * without the NUMA/affinity machinery unbound queues carry, which
     * this queue has no use for. max_active 0 selects the kernel's
     * default cap (WQ_DFL_ACTIVE, 256), raising the limit from
     * create_workqueue()'s max_active of 1 -- ac_schedule_kill() allocates
     * a fresh ac_kill_req and queues it on every call, so concurrent
     * attacks can leave several kill work items in flight at once; that's
     * fine here since each one only touches its own independently-owned
     * pid, with no state shared between work items.
     */
    ac_wq = alloc_workqueue("anticheat", WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
    if (!ac_wq)
        return -ENOMEM;

    ac_prot_add_pool = mempool_create_kmalloc_pool(AC_PROT_MAX,
                                                    sizeof(struct ac_prot_add_req));
    if (!ac_prot_add_pool) {
        destroy_workqueue(ac_wq);
        return -ENOMEM;
    }
    ac_prot_release_pool = mempool_create_kmalloc_pool(AC_PROT_MAX,
                                                        sizeof(struct ac_prot_release_req));
    if (!ac_prot_release_pool) {
        mempool_destroy(ac_prot_add_pool);
        destroy_workqueue(ac_wq);
        return -ENOMEM;
    }
    ac_kill_pool = mempool_create_kmalloc_pool(16, sizeof(struct ac_kill_req));
    if (!ac_kill_pool) {
        mempool_destroy(ac_prot_release_pool);
        mempool_destroy(ac_prot_add_pool);
        destroy_workqueue(ac_wq);
        return -ENOMEM;
    }

    ac_resolve_text_bounds();
    if (ac_verbose)
        pr_info("text bounds: stext=0x%lx etext=0x%lx\n", ac_stext, ac_etext);

    ac_syscall_table = ac_find_syscall_table();
    if (ac_syscall_table) {
        pr_info("syscall table located at 0x%lx\n", ac_syscall_table);
        ac_capture_syscall_baseline();
    } else {
        pr_warn("syscall table not located; syscall integrity checks disabled\n");
    }

    ac_register_kprobes();

    ret = misc_register(&ac_misc);
    if (ret) {
        pr_err("misc_register failed: %d\n", ret);
        ac_unregister_kprobes();
        /* A clone/exec could in principle have fired between
         * ac_register_kprobes() and here and queued deferred registry
         * work; drain it before tearing the workqueue down (see the same
         * reasoning in ac_exit() below). */
        flush_workqueue(ac_wq);
        mempool_destroy(ac_kill_pool);
        mempool_destroy(ac_prot_release_pool);
        mempool_destroy(ac_prot_add_pool);
        destroy_workqueue(ac_wq);
        return ret;
    }

    pr_info("loaded (policy=0x%x, %u kprobes, %u kretprobes, %u protected slots)\n",
            ac_policy, ac_kprobes_registered, ac_kretprobes_registered,
            AC_PROT_MAX);
    return 0;
}

static void __exit ac_exit(void)
{
    misc_deregister(&ac_misc);
    ac_unregister_kprobes();
    /* ac_unregister_kprobes() stops new deferred add/rekey work from being
     * queued, but doesn't wait for work already in flight (queued by a
     * clone/exec that fired moments before unload) to finish running --
     * that work calls ac_add_prot_mm()/ac_del_prot_mm(), mutating
     * ac_prots[] concurrently with ac_clear_protected() below unless it's
     * drained first. */
    flush_workqueue(ac_wq);
    ac_clear_protected();
    /* ac_clear_protected() can itself race a genuinely-live protected
     * process exiting for real at the same moment: ac_mmu_release() would
     * see the organic (non-caller-initiated) case for that slot and queue
     * an ac_prot_release_worker() onto ac_wq to finish the mmdrop() it
     * owes. destroy_workqueue() expects an already-drained queue, so flush
     * once more here to catch exactly that. */
    flush_workqueue(ac_wq);
    destroy_workqueue(ac_wq);
    /* Safe only now: mempool_destroy() requires every element already
     * returned, and the two flush_workqueue() calls above guarantee every
     * ac_prot_add_worker()/ac_prot_release_worker() that could still be
     * holding one has already run to completion and freed it back. */
    mempool_destroy(ac_kill_pool);
    mempool_destroy(ac_prot_add_pool);
    mempool_destroy(ac_prot_release_pool);
    pr_info("unloaded\n");
}

module_init(ac_init);
module_exit(ac_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kernel-anticheat project");
MODULE_DESCRIPTION("Kernel-mode anticheat: syscall/module integrity, "
                   "process protection, ptrace denial, RWX scan");
MODULE_VERSION("1.0.0");
