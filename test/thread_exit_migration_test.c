/*
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * test/thread_exit_migration_test.c -- live test helper for the
 * mm_struct-keyed protected-process registry's leader-only-exit case
 * (#62). The registry is keyed by address space, not task_struct, so
 * this scenario needs no migration logic at all: the shared mm is
 * untouched by one thread exiting, and the entry (still displayed under
 * MAIN_TID, the pid it was registered under) simply stays valid for as
 * long as the mm does.
 *
 * Starts single-threaded, prints its own tid as MAIN_TID, spawns a worker
 * thread that prints its own tid as WORKER_TID and then just waits, and
 * blocks the main/leader thread on a line from stdin. The driver
 * (test.sh) reads both tids, protects this process by MAIN_TID (the
 * leader), then writes a line to unblock the leader thread, which calls
 * pthread_exit() (not exit()/exit_group()) so only the leader thread
 * exits while the worker thread -- and the process's mm -- keeps
 * running. That is exactly the scenario that used to require
 * ac_exit_pre()'s sibling-scan migration (ac_replace_prot_task()) under
 * the old task-keyed registry, and now requires nothing.
 *
 * Needs root and the module loaded -- see test.sh.
 */
#define _GNU_SOURCE

#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

static pid_t self_tid(void)
{
    return (pid_t)syscall(SYS_gettid);
}

static void *worker_main(void *arg)
{
    (void)arg;

    printf("WORKER_TID %d\n", self_tid());
    fflush(stdout);

    /* Stays alive until the driver kills the whole process (any live
     * thread of the group) during cleanup. */
    for (;;)
        pause();
    return NULL;
}

int main(void)
{
    pthread_t worker;
    char line[16];

    printf("MAIN_TID %d\n", self_tid());
    fflush(stdout);

    if (pthread_create(&worker, NULL, worker_main, NULL) != 0) {
        fprintf(stderr,
                "thread_exit_migration_test: pthread_create failed\n");
        return 2;
    }

    /* Block until the driver has protected MAIN_TID and is ready for it
     * to exit -- protection must land before the leader thread exits, or
     * this proves nothing about the migration path. */
    if (!fgets(line, sizeof(line), stdin))
        return 2;

    /* Exit only this (leader) thread. exit()/exit_group() here would tear
     * down the whole process, including the worker -- pthread_exit() is
     * the one way to reproduce "the exact registered task exits, other
     * threads in its group don't". */
    pthread_exit(NULL);
    return 0; /* unreachable */
}
