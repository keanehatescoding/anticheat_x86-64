/*
 * render_hook_test.c -- self-hooks an exported symbol (default:
 * vkQueuePresentKHR in libvulkan.so.1; pass a different library/symbol
 * pair as argv[1]/argv[2] to exercise the GLX/OpenGL or EGL path
 * instead) in its own address space, to prove `anticheat scan
 * --check-hooks` actually fires on a real tampering, not just on the
 * "library not loaded" skip path or the trivial case of matching an
 * already-clean process (test.sh separately verifies that true-negative
 * case against a real running process).
 *
 * Loads the library, makes the target symbol's page writable, and
 * overwrites 8 bytes starting at an offset within it (argv[4], default
 * 0 -- the classic inline-hook-at-entry pattern; a nonzero offset proves
 * detection isn't limited to the function's first few bytes, since the
 * check now compares the symbol's whole declared ELF size, not a fixed
 * window). The function is never actually invoked (the patched bytes
 * are inert NOPs), so this is safe to run; it exists purely to be
 * scanned from another process while it sleeps.
 *
 * argv[4] (mode, default "hook") varies what else the process does:
 *   clean    -- load the library but patch nothing (true-negative
 *               fixture, e.g. for an lld-linked library whose text
 *               segment has p_vaddr != p_offset, #85)
 *   decoy-ro -- hook, then map a clean read-only copy of the same
 *               library file *below* the real one (#84: the check used
 *               to take the lowest-addressed mapping as the library)
 *   decoy-x  -- same, but the decoy is mapped PROT_EXEC too, so it is
 *               an executable mapping of the same file competing with
 *               the real, hooked one
 *   remap-anon  -- replace the page holding the symbol with an anonymous
 *               RWX copy of itself, then hook that: the file-backed text
 *               mapping is split around a hole and no longer contains
 *               the symbol at all
 *
 * Usage: ./render_hook_test [library symbol [offset [mode]]] &
 *   -- prints "READY pid=<pid>", then sleeps.
 */
#define _GNU_SOURCE  /* MAP_ANONYMOUS under a strict -std= build; this
                      * project's own Makefile doesn't set one (the GNU
                      * dialect is already the default), but don't rely
                      * on that staying true forever. */
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
    void *h, *sym, *page, *target;
    long pagesize;
    unsigned char patch[8] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    const char *lib = argc > 1 ? argv[1] : "libvulkan.so.1";
    const char *symbol = argc > 2 ? argv[2] : "vkQueuePresentKHR";
    long offset = argc > 3 ? atol(argv[3]) : 0;
    const char *mode = argc > 4 ? argv[4] : "hook";

    h = dlopen(lib, RTLD_NOW);
    if (!h) {
        fprintf(stderr, "render_hook_test: dlopen %s: %s\n", lib, dlerror());
        return 2;
    }
    sym = dlsym(h, symbol);
    if (!sym) {
        fprintf(stderr, "render_hook_test: dlsym %s: %s\n", symbol, dlerror());
        return 2;
    }
    target = (void *)((uintptr_t)sym + (uintptr_t)offset);

    pagesize = sysconf(_SC_PAGESIZE);
    page = (void *)((uintptr_t)target & ~(uintptr_t)(pagesize - 1));
    if (mprotect(page, (size_t)pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("render_hook_test: mprotect");
        return 2;
    }
    if (strcmp(mode, "remap-anon") == 0) {
        void *copy = malloc((size_t)pagesize);

        if (!copy) {
            perror("render_hook_test: malloc");
            return 2;
        }
        memcpy(copy, page, (size_t)pagesize);
        if (mmap(page, (size_t)pagesize, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) {
            perror("render_hook_test: mmap remap-anon");
            return 2;
        }
        memcpy(page, copy, (size_t)pagesize);
        free(copy);
    }
    if (strcmp(mode, "clean") != 0)
        memcpy(target, patch, sizeof(patch));

    if (strncmp(mode, "decoy-", 6) == 0) {
        struct link_map *lm = NULL;
        struct stat st;
        void *decoy;
        int fd, prot = PROT_READ;

        if (strcmp(mode, "decoy-x") == 0)
            prot |= PROT_EXEC;
        if (dlinfo(h, RTLD_DI_LINKMAP, &lm) != 0 || !lm || !lm->l_name[0]) {
            fprintf(stderr, "render_hook_test: dlinfo: %s\n", dlerror());
            return 2;
        }
        fd = open(lm->l_name, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            perror("render_hook_test: open decoy");
            return 2;
        }
        if (fstat(fd, &st) != 0 || st.st_size <= 0) {
            perror("render_hook_test: fstat decoy");
            return 2;
        }
        /* Far below the 0x7f.. region the loader uses, so the decoy is
         * the lowest-addressed mapping of this file. Map the whole
         * file (the symbol's bytes live well past offset 0). */
        decoy = mmap((void *)0x100000000UL, (size_t)st.st_size, prot,
                     MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, 0);
        close(fd);
        if (decoy == MAP_FAILED) {
            perror("render_hook_test: mmap decoy");
            return 2;
        }
    }

    printf("READY pid=%d\n", getpid());
    fflush(stdout);
    for (;;)
        pause();
    return 0;
}
