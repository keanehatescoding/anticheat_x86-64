/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * waitpid_eintr_fault.c -- LD_PRELOAD fault injector for
 * daemon_robustness_test.c. While AC_WAITPID_FAULT_ARMED=1, every
 * waitpid(..., WNOHANG) call fails with EINTR instead of running;
 * blocking waitpids and everything else delegate to the real call.
 *
 * Why this exists: waitpid_timeout() polls with WNOHANG, so each
 * waitpid is microseconds wide and a timer signal almost always lands
 * in the loop's usleep() instead -- signals alone cannot reliably prove
 * the EINTR-retry branch executes. Arming the injector around one
 * waitpid_timeout() call faults 100% of its waitpids deterministically.
 * waitpid_fault_count() reports how many faults were injected so the
 * test can assert the EINTR path actually ran, not just that the call
 * timed out.
 *
 * Build: make daemon-robustness-test (builds this alongside the test)
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

static int injected;

pid_t waitpid(pid_t pid, int *status, int options)
{
    static pid_t (*real_waitpid)(pid_t, int *, int) = NULL;
    const char *armed;

    if (!real_waitpid) {
        real_waitpid = dlsym(RTLD_NEXT, "waitpid");
        if (!real_waitpid) {
            errno = ENOSYS;
            return -1;
        }
    }
    armed = getenv("AC_WAITPID_FAULT_ARMED");
    if ((options & WNOHANG) && armed && armed[0] == '1') {
        injected++;
        errno = EINTR;
        return -1;
    }
    return real_waitpid(pid, status, options);
}

int waitpid_fault_count(void)
{
    return injected;
}
