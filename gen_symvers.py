#!/usr/bin/env python3
"""Generate a full Module.symvers from the device vmlinux.

The Sony 4.19 tree is built with CONFIG_MODVERSIONS=y and the module must carry
the exact CRCs the device kernel was built with.  This walks __ksymtab /
__ksymtab_gpl and pairs each entry with __kcrctab{,_gpl}, resolving the
relative __ksymtab name offsets (name is relative to entry+4, not entry).

Environment:
  VMLINUX  path to an ELF-converted vmlinux (required)
  SYMVERS  output Module.symvers (default: kernel_sony_sm8250/Module.symvers)
"""
import os
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

ELF = os.environ.get("VMLINUX", "")
if not ELF:
    sys.exit("set VMLINUX=/path/to/vmlinux.elf")

OUT = os.environ.get(
    "SYMVERS", os.path.join(ROOT, "kernel_sony_sm8250", "Module.symvers")
)

# SOG02 4.19.157 .kernel / .kernel2 (VA base, file offset, size).
SECTIONS = [
    (0xFFFFFF8008080000, 0x240, 0x22A7098),
    (0xFFFFFF800A630758, 0x22A72D8, 0x46B8B8),
]

data = open(ELF, "rb").read()


def rd(va, n):
    for base, off, size in SECTIONS:
        if base <= va and va + n <= base + size:
            o = off + (va - base)
            return data[o:o + n]
    raise ValueError(f"VA {va:#x}+{n} not mapped")


def r32(va):
    return struct.unpack("<I", rd(va, 4))[0]


def r32s(va):
    return struct.unpack("<i", rd(va, 4))[0]


def cstr(va):
    out = bytearray()
    while len(out) < 256:
        b = rd(va + len(out), 1)
        if b == b"\0":
            break
        out += b
    return out.decode("latin1")


syms = {}
for line in subprocess.check_output(["nm", ELF], text=True).splitlines():
    p = line.split()
    if len(p) == 3:
        syms[p[2]] = int(p[0], 16)

tables = [
    ("__start___ksymtab", "__start___ksymtab_gpl",
     "__start___kcrctab", "EXPORT_SYMBOL"),
    ("__start___ksymtab_gpl", "__start___ksymtab_gpl_future",
     "__start___kcrctab_gpl", "EXPORT_SYMBOL_GPL"),
]

out = []
for start_name, end_name, crc_name, export in tables:
    start, end, cstart = syms[start_name], syms[end_name], syms[crc_name]
    count = (end - start) // 8
    for i in range(count):
        e = start + i * 8
        noff = r32s(e + 4)
        name = cstr(e + 4 + noff)
        crc = r32(cstart + i * 4)
        out.append(f"0x{crc:08x}\t{name}\tvmlinux\t{export}")

with open(OUT, "w") as f:
    f.write("\n".join(out) + "\n")

print(f"generated {len(out)} symbols -> {OUT}")
for n in ("module_layout", "printk"):
    hit = next((l for l in out if l.split("\t")[1] == n), None)
    print(f"  {n}: {hit}")
