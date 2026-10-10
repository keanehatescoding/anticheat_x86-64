/*
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * test/thread_spawn_after_protect_test.c -- live test helper for
 * ac_clone_ret()'s CLONE_THREAD dedup (guards against the duplicate
 * registry entry bug: a pthread_create() by an already-protected thread
 * must NOT get its own registry slot, since ac_is_protected_thread_group()
 * already covers it via the group's existing entry).
 *
 * Starts single-threaded, prints its own tid as MAIN_TID, then blocks on a
 * line from stdin so the driver (test.sh) can protect MAIN_TID *before*
 * any clone happens. Once unblocked, spawns a worker thread -- this is
 * the clone the bug is about, since it happens strictly after protection
 * is already in place -- prints its tid as WORKER_TID, and both threads
 * then park until the driver kills the whole process during cleanup.
 *
 * The worker's own WORKER_TID print races the parent's ac_clone_ret()
 * kretprobe: the child can start running on another CPU before
 * kernel_clone() actually returns in the parent (and thus before the
 * kretprobe, attached to that return, has run). So the driver also waits
 * for SPAWN_DONE, printed by the parent strictly after pthread_create()
 * returns -- pthread_create() cannot return until its underlying clone()
 * syscall has, which is strictly after ac_clone_ret() already ran. Seeing
 * SPAWN_DONE is therefore a real happens-after guarantee that the
 * registry decision has already landed, unlike a fixed sleep.
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

    /* Block until the driver has protected MAIN_TID -- the clone below
     * must happen strictly after protection lands, or this proves nothing
     * about ac_clone_ret()'s dedup. */
    if (!fgets(line, sizeof(line), stdin))
        return 2;

    if (pthread_create(&worker, NULL, worker_main, NULL) != 0) {
        fprintf(stderr,
                "thread_spawn_after_protect_test: pthread_create failed\n");
        return 2;
    }
    printf("SPAWN_DONE\n");
    fflush(stdout);

    for (;;)
        pause();
    return 0; /* unreachable */
}
