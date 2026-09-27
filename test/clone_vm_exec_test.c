/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * test/clone_vm_exec_test.c -- live test helper for #83 (exec from a
 * non-vfork CLONE_VM child must not unregister the still-running
 * protected parent).
 *
 * The old ac_exec_entry() used current->vfork_done as its "this task
 * borrows its parent's mm" test. A child cloned with CLONE_VM|SIGCHLD
 * but *without* CLONE_VFORK shares the parent's live mm with
 * vfork_done == NULL, so its exec took the old_mm path and the worker
 * deleted the parent's own live registry entry -- the protected parent
 * silently lost protection.
 *
 * Protocol (same coproc style as thread_spawn_after_protect_test):
 *   - parent prints "PARENT_PID <pid>", blocks on a stdin line so the
 *     driver (test.sh) can protect PARENT_PID *before* any clone
 *     happens. Once unblocked it clones a CLONE_VM (no CLONE_VFORK, no
 *     CLONE_THREAD) child that immediately execs /proc/self/exe with
 *     the "exec-child" argument, then prints "CHILD_PID <pid>" (the
 *     clone() return value) and parks.
 *   - the exec'd image prints "EXEC_CHILD <pid>" -- same pid, proving
 *     the exec itself completed -- and parks.
 *
 * The driver then asserts both CHILD_PID (inherited protection for the
 * new image) and PARENT_PID (untouched by the child's exec) are still
 * listed, with the parent check repeated after a settle delay since the
 * buggy unregister landed asynchronously from a workqueue.
 *
 * The child runs on a dedicated static stack and calls execve() without
 * touching stdio first: until the exec it shares every byte of the
 * parent's address space, so flushing/locking the parent's FILE buffers
 * from the child would corrupt the parent's own output.
 *
 * Needs root and the module loaded -- see test.sh.
 */
#define _GNU_SOURCE

#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static char child_stack[1 << 20];

static int child_fn(void *arg)
{
    char *const *argv_exec = (char *const *)arg;

    /* No stdio here -- shared buffers with the parent until exec. */
    execve("/proc/self/exe", argv_exec, NULL);
    return 2; /* execve failed: clone() wrapper exit()s with this */
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "exec-child") == 0) {
        printf("EXEC_CHILD %d\n", (int)getpid());
        fflush(stdout);
        for (;;)
            pause();
        return 0; /* unreachable */
    }

    {
        char line[16];
        char *argv_exec[] = { argv[0], "exec-child", NULL };
        pid_t child;

        printf("PARENT_PID %d\n", (int)getpid());
        fflush(stdout);

        /* Block until the driver has protected PARENT_PID -- the clone
         * below must happen strictly after protection lands, or this
         * proves nothing about the exec path. */
        if (!fgets(line, sizeof(line), stdin))
            return 2;

        fflush(stdout); /* shared buffer must be clean before CLONE_VM */
        child = clone(child_fn,
                      child_stack + sizeof(child_stack),
                      CLONE_VM | SIGCHLD,
                      argv_exec);
        if (child < 0) {
            perror("clone_vm_exec_test: clone");
            return 2;
        }
        printf("CHILD_PID %d\n", (int)child);
        fflush(stdout);

        for (;;)
            pause();
    }
    return 0; /* unreachable */
}
