#!/usr/bin/env python3
"""Fail if any ELF LOAD segment has p_align < 16384 (Android 15 16 KB pages)."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

MIN_ALIGN = 16384
PT_LOAD = 1


def load_aligns(path: Path) -> list[int]:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF":
        raise ValueError(f"{path}: not an ELF file")
    ei_class = data[4]
    ei_data = data[5]
    endian = "<" if ei_data == 1 else ">"
    if ei_class == 1:
        e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
        e_phentsize = struct.unpack_from(endian + "H", data, 42)[0]
        e_phnum = struct.unpack_from(endian + "H", data, 44)[0]
        align_off, align_fmt = 28, endian + "I"
    elif ei_class == 2:
        e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
        e_phentsize = struct.unpack_from(endian + "H", data, 54)[0]
        e_phnum = struct.unpack_from(endian + "H", data, 56)[0]
        align_off, align_fmt = 48, endian + "Q"
    else:
        raise ValueError(f"{path}: unknown ELF class {ei_class}")

    aligns: list[int] = []
    for index in range(e_phnum):
        base = e_phoff + index * e_phentsize
        p_type = struct.unpack_from(endian + "I", data, base)[0]
        if p_type != PT_LOAD:
            continue
        aligns.append(struct.unpack_from(align_fmt, data, base + align_off)[0])
    if not aligns:
        raise ValueError(f"{path}: no PT_LOAD segments")
    return aligns


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "roots",
        nargs="*",
        type=Path,
        default=[
            Path(
                "android-shield-native/build/intermediates/"
                "stripped_native_libs/release"
            ),
            Path(
                "android-shield-native/build/intermediates/"
                "library_and_local_jars_jni/release"
            ),
        ],
        help="Directories to search for libandroidshield.so (defaults to release packaging outputs)",
    )
    args = parser.parse_args()

    sos: list[Path] = []
    missing: list[Path] = []
    for root in args.roots:
        if root.is_file() and root.suffix == ".so":
            sos.append(root)
            continue
        if not root.is_dir():
            missing.append(root)
            continue
        sos.extend(sorted(root.rglob("libandroidshield.so")))
        sos.extend(sorted(root.rglob("libc++_shared.so")))
    if not sos and missing:
        print("error: missing build output:", file=sys.stderr)
        for path in missing:
            print(f"  {path}", file=sys.stderr)
        return 2

    unique = list(dict.fromkeys(sos))
    if not unique:
        print("error: no native .so files found to check", file=sys.stderr)
        return 2

    failed = False
    for so in unique:
        try:
            aligns = load_aligns(so)
        except ValueError as exc:
            print(f"FAIL  {exc}", file=sys.stderr)
            failed = True
            continue
        bad = [align for align in aligns if align < MIN_ALIGN]
        summary = ",".join(hex(align) for align in aligns)
        if bad:
            print(f"FAIL  {so} LOAD align={summary} (need >= {hex(MIN_ALIGN)})")
            failed = True
        else:
            print(f"OK    {so} LOAD align={summary}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
