#!/usr/bin/env bash
# Build the backslashxx/KernelSU late-load LKM against the SOG02 4.19 tree.
#
# Automates the parts that are easy to get wrong on this vendor kernel:
#   - KSU Kconfig/auto.conf wiring + KALLSYMS_ALL
#   - device-derived full Module.symvers (exact CRCs)
#   - compile.h / flask.h generation
#   - -mbranch-protection=none (clang 17 PAuth relocs)
#   - +lse / CONFIG_AS_LSE for the module's atomics
#   - the path_umount weak-extern GOT workaround (4.19 loader has no GOT relocs)
#   - verification that no GOT/PAuth relocations remain
#
# KernelSU fork: https://github.com/backslashxx/KernelSU
# modpost/KALLSYMS_ALL tweak: backslashxx/kernel_xiaomi_sm6225@dd352cb
#
# Usage:
#   tools/build_kernelsu_lkm.sh                       # builds origin/staging
#   KSU_REF=master tools/build_kernelsu_lkm.sh        # builds a branch
#   KSU_COMMIT=e2f2e397 tools/build_kernelsu_lkm.sh   # builds an exact commit
#   VMLINUX=/path/vmlinux.elf tools/build_kernelsu_lkm.sh  # regenerate symvers
#
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PROJECT=${PROJECT:-sog02-58.2.C.3.127}
KERNEL_DIR=${KERNEL_DIR:-$ROOT/stockkernel_sony_sm8250-main}
KSU_DIR=${KSU_DIR:-$ROOT/KernelSU}
KSU_URL=${KSU_URL:-https://github.com/backslashxx/KernelSU}
KSU_REF=${KSU_REF:-staging}
KSU_COMMIT=${KSU_COMMIT:-}
NDK_ROOT=${NDK_ROOT:-$ROOT/android-ndk-r26d}
API=${API:-30}
OUT=${OUT:-$ROOT/build/$PROJECT}
SYMVERS=${SYMVERS:-$KERNEL_DIR/Module.symvers}
VMLINUX=${VMLINUX:-}
KCFLAGS_EXTRA=${KCFLAGS_EXTRA:-}
JOBS=${JOBS:-$(nproc 2>/dev/null || echo 4)}
GEN_SYMVERS=${GEN_SYMVERS:-$ROOT/gen_symvers.py}

log() { printf '[lkm] %s\n' "$*"; }
die() { printf '[lkm] error: %s\n' "$*" >&2; exit 1; }

case "${1:-}" in
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac

[ -d "$KERNEL_DIR" ] || die "kernel tree not found: $KERNEL_DIR"
[ -f "$KERNEL_DIR/.config" ] || die "no .config in $KERNEL_DIR"
[ -d "$NDK_ROOT" ] || die "NDK not found: $NDK_ROOT (set NDK_ROOT)"

NDK_BIN=$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin
CLANG=$NDK_BIN/aarch64-linux-android${API}-clang
[ -x "$CLANG" ] || die "clang not found: $CLANG"
command -v git >/dev/null || die "git not found"
command -v python3 >/dev/null || die "python3 not found"
command -v gcc >/dev/null || die "host gcc not found"

# 1. KernelSU source
if [ ! -d "$KSU_DIR/.git" ]; then
    log "cloning $KSU_URL -> $KSU_DIR"
    git clone --filter=blob:none "$KSU_URL" "$KSU_DIR"
fi
git -C "$KSU_DIR" fetch origin --tags
if [ -n "$KSU_COMMIT" ]; then
    git -C "$KSU_DIR" checkout --quiet "$KSU_COMMIT"
else
    # Follow the fetched remote ref: staging is force-updated, and the local
    # branch can be stale (e.g. e2f2e397 vs origin/staging 4269960c).
    git -C "$KSU_DIR" checkout --quiet -B "$KSU_REF" "origin/$KSU_REF"
fi
KSU_REV=$(git -C "$KSU_DIR" rev-parse --short HEAD)
log "KernelSU $KSU_REV ($(git -C "$KSU_DIR" describe --tags --always 2>/dev/null || echo "$KSU_REV"))"

# 2. Wire the module into the stock tree
mkdir -p "$KERNEL_DIR/KernelSU"
rm -rf "$KERNEL_DIR/KernelSU/kernel"
cp -a "$KSU_DIR/kernel" "$KERNEL_DIR/KernelSU/kernel"

if ! grep -q 'source "KernelSU/kernel/Kconfig"' "$KERNEL_DIR/Kconfig"; then
    printf '\nsource "KernelSU/kernel/Kconfig"\n' >> "$KERNEL_DIR/Kconfig"
    log "added KernelSU Kconfig source"
fi

# 3. KSU config + sync
sed -i '/^CONFIG_KSU/d;/^# CONFIG_KSU/d' "$KERNEL_DIR/.config"
cat >> "$KERNEL_DIR/.config" <<'EOF'
CONFIG_KSU=m
CONFIG_KSU_HACK_ARM64_BRANCH_LINK=y
CONFIG_KSU_LSM_SECURITY_HOOKS=y
# CONFIG_KSU_FEATURE_ADBROOT is not set
# CONFIG_KSU_KPROBES_KSUD is not set
# CONFIG_KSU_TAMPER_SYSCALL_TABLE is not set
EOF
grep -q '^CONFIG_KALLSYMS_ALL=y$' "$KERNEL_DIR/.config" \
    || log "warning: CONFIG_KALLSYMS_ALL is not y (device config normally has it)"

# 4. Device full Module.symvers
if [ ! -s "$SYMVERS" ] || [ "$(wc -l < "$SYMVERS")" -lt 1000 ]; then
    [ -f "$GEN_SYMVERS" ] || die "Module.symvers is incomplete and $GEN_SYMVERS is missing"
    [ -n "$VMLINUX" ] || die "Module.symvers is incomplete; set VMLINUX=/path/to/vmlinux.elf"
    log "generating full Module.symvers from $VMLINUX"
    VMLINUX="$VMLINUX" SYMVERS="$SYMVERS" python3 "$GEN_SYMVERS"
fi
log "Module.symvers: $(wc -l < "$SYMVERS") symbols"

# 5. Config + generated headers
MAKE_ARGS=(
    "ARCH=arm64" "LLVM_IAS=1"
    "CROSS_COMPILE=aarch64-linux-android${API}-"
    "CC=$CLANG" "LD=ld.lld" "AR=llvm-ar" "NM=llvm-nm"
    "OBJCOPY=llvm-objcopy" "OBJDUMP=llvm-objdump" "STRIP=llvm-strip"
    "HOSTCC=gcc"
)
export PATH="$NDK_BIN:$PATH"
make -C "$KERNEL_DIR" "${MAKE_ARGS[@]}" olddefconfig >/dev/null
make -C "$KERNEL_DIR" "${MAKE_ARGS[@]}" syncconfig >/dev/null
grep -q '^CONFIG_KSU=m$' "$KERNEL_DIR/include/config/auto.conf" \
    || die "CONFIG_KSU=m missing from auto.conf (Kconfig source not applied?)"

# compile.h
( cd "$KERNEL_DIR" && sh scripts/mkcompile_h include/generated/compile.h \
    arm64 SMP PREEMPT "$CLANG" ld.lld >/dev/null 2>&1 ) || true

# flask.h / av_permissions.h (security/selinux)
if [ ! -f "$KERNEL_DIR/security/selinux/flask.h" ] || \
   [ ! -f "$KERNEL_DIR/security/selinux/av_permissions.h" ]; then
    if [ ! -x "$KERNEL_DIR/scripts/selinux/genheaders/genheaders" ]; then
        ( cd "$KERNEL_DIR" && gcc -O2 -I include/uapi -I include \
            -I security/selinux/include \
            -o scripts/selinux/genheaders/genheaders \
            scripts/selinux/genheaders/genheaders.c )
    fi
    ( cd "$KERNEL_DIR" && ./scripts/selinux/genheaders/genheaders \
        security/selinux/flask.h security/selinux/av_permissions.h )
    log "generated flask.h / av_permissions.h"
fi

# 6. path_umount
# The staging source wraps the weak path_umount in #ifndef MODULE, so the
# module always takes the ksyscall(umount) path and emits no GOT relocations.
# No source patch is needed; older sources would need the runtime lookup.

# 7. Build
rm -f "$KERNEL_DIR/KernelSU/kernel/ksu.o" \
      "$KERNEL_DIR/KernelSU/kernel/kernelsu.ko" \
      "$KERNEL_DIR/KernelSU/kernel/kernelsu.mod.c"
log "building kernelsu.ko"
make -C "$KERNEL_DIR" "${MAKE_ARGS[@]}" -j"$JOBS" \
    KBUILD_MODPOST_WARN=1 \
    KCFLAGS="-march=armv8-a+lse -DCONFIG_AS_LSE=1 -mbranch-protection=none ${KCFLAGS_EXTRA}" \
    M="$KERNEL_DIR/KernelSU/kernel" modules

KO="$KERNEL_DIR/KernelSU/kernel/kernelsu.ko"
[ -f "$KO" ] || die "build produced no kernelsu.ko"

# 8. Verify + stage
if "$NDK_BIN/llvm-readelf" -r "$KO" 2>/dev/null | grep -qiE 'GOT|AUTH'; then
    die "kernelsu.ko still has GOT/PAuth relocations (clang flags?)"
fi

mkdir -p "$OUT"
cp "$KO" "$OUT/kernelsu.ko"
log "built $OUT/kernelsu.ko"
log "KernelSU $KSU_REV, $(stat -c %s "$OUT/kernelsu.ko") bytes, md5 $(md5sum "$OUT/kernelsu.ko" | cut -d' ' -f1)"
