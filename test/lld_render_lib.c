/*
 * lld_render_lib.c -- stand-in for libEGL.so.1, linked with lld so its
 * executable PT_LOAD has p_vaddr != p_offset (lld doesn't pad the file
 * to keep them equal the way GNU ld's default layout does). Exercises
 * the render-hook check's st_value -> file-offset translation (#85):
 * before it, an untouched library with this layout read as hooked,
 * because the reference bytes were pread() at st_value (a vaddr) rather
 * than at the symbol's real file offset. Never called -- only mapped by
 * render_hook_test and scanned. See test.sh.
 */
volatile int lld_render_lib_sink;

int eglSwapBuffers(void *dpy, void *surface)
{
    int i;

    for (i = 0; i < 8; i++)
        lld_render_lib_sink += (int)(long)dpy * i + (int)(long)surface;
    return lld_render_lib_sink != 0;
}
