"""Reconstruct a PE from its in-memory (mapped) image -- the 'dump' half of
dynamic unpacking.

Once a packer has unpacked the real code into memory, we read the mapped image
back out and rebuild a PE from it. In memory a section occupies its VIRTUAL range
(``[VirtualAddress, VirtualAddress + VirtualSize)``), so the dumped file uses a
raw = virtual layout: each section's ``PointerToRawData`` becomes its
``VirtualAddress`` and ``FileAlignment`` is set to ``SectionAlignment``. The
discovered original entry point (OEP) is written into the header. This is the
classic "dump at OEP" reconstruction.

`dump_pe` is a pure function over a ``read_mem(addr, size) -> bytes`` callable, so
it is testable with no live process (serve bytes from a simulated mapped image);
`dump_module` is the thin adapter that feeds it a Debugger's ``read_memory``.

NOTE: this produces a raw memory dump with a fixed entry point. It does NOT yet
rebuild the import directory (a dumped IAT holds resolved addresses); IAT
reconstruction is a follow-on. The raw dump is already useful for static analysis.
"""
from __future__ import annotations

import struct
from typing import Callable, Optional


def _align_up(x: int, a: int) -> int:
    return (x + a - 1) // a * a if a else x


def dump_pe(read_mem: Callable[[int, int], bytes], base: int,
            oep_rva: Optional[int] = None) -> bytes:
    """Rebuild a PE file from the module mapped at ``base``.

    ``read_mem(addr, size)`` returns ``size`` bytes at absolute address ``addr``.
    If ``oep_rva`` is given it overwrites AddressOfEntryPoint (the recovered OEP).
    """
    hdr = bytearray(read_mem(base, 0x1000))
    if hdr[:2] != b"MZ":
        raise ValueError("no MZ header at the mapped base")
    (e_lfanew,) = struct.unpack_from("<I", hdr, 0x3C)
    if hdr[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("no PE signature at the mapped base")
    coff = e_lfanew + 4
    _machine, nsec, _a, _b, _c, opt_size, _chars = struct.unpack_from(
        "<HHIIIHH", hdr, coff)
    opt = coff + 20
    if not (0 < nsec <= 96):
        raise ValueError(f"implausible section count {nsec}")
    sect_align, = struct.unpack_from("<I", hdr, opt + 32)
    file_align, = struct.unpack_from("<I", hdr, opt + 36)
    size_of_headers, = struct.unpack_from("<I", hdr, opt + 60)
    if sect_align == 0:
        raise ValueError("zero SectionAlignment")
    if size_of_headers > len(hdr):
        hdr = bytearray(read_mem(base, size_of_headers))

    sec_table = coff + 20 + opt_size   # COFF header is 20 bytes
    sections = []   # (hdr_off, vsize, vaddr)
    image_end = size_of_headers
    for i in range(nsec):
        off = sec_table + i * 40
        vsize, vaddr = struct.unpack_from("<II", hdr, off + 8)
        sections.append((off, vsize, vaddr))
        image_end = max(image_end, vaddr + vsize)

    total = _align_up(image_end, sect_align)
    out = bytearray(total)
    out[:size_of_headers] = hdr[:size_of_headers]

    # optional-header patches: raw layout mirrors virtual, and the OEP if known.
    struct.pack_into("<I", out, opt + 36, sect_align)          # FileAlignment
    if oep_rva is not None:
        struct.pack_into("<I", out, opt + 16, oep_rva)         # AddressOfEntryPoint

    for off, vsize, vaddr in sections:
        raw = _align_up(vsize, sect_align)
        struct.pack_into("<I", out, off + 16, raw)             # SizeOfRawData
        struct.pack_into("<I", out, off + 20, vaddr)           # PointerToRawData
        if vsize and vaddr + vsize <= total:
            body = read_mem(base + vaddr, vsize)
            out[vaddr:vaddr + len(body)] = body
    return bytes(out)


def dump_module(dbg: "Debugger", base: int,
                oep_rva: Optional[int] = None) -> bytes:
    """Dump the module mapped at ``base`` from a live debuggee via ``dbg``.

    ``dbg`` is any object exposing a Debugger-style ``read_memory(addr, size)``.
    Typed against :class:`aletheia.debugger.Debugger` via a string forward-ref so
    dump.py stays a leaf module (no import of debugger)."""
    return dump_pe(dbg.read_memory, base, oep_rva)
