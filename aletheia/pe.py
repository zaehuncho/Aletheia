"""Dependency-free PE reader for Aletheia's static triage.

Parses just enough of an x86/x64 PE to reason about *how it's protected*:
sections (with Shannon entropy + R/W/X), the entry point and which section holds
it, and the import table (which DLLs, how many functions). Pure `struct` — no
`lief`, no third-party deps — so it stays small and portable and never chokes on
a hostile file (it fails closed to `PEInfo(ok=False, ...)`).
"""
from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional

_SCN_EXEC = 0x20000000
_SCN_READ = 0x40000000
_SCN_WRITE = 0x80000000
_FILE_DLL = 0x2000
_MACHINE = {0x8664: "x64", 0x014C: "x86", 0xAA64: "ARM64", 0x0200: "IA64"}
_MAX_SECTIONS = 96
_MAX_IMPORT_DLLS = 4096
_MAX_THUNKS = 100000


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte, 0.0 (uniform) .. 8.0 (random)."""
    if not data:
        return 0.0
    n = len(data)
    ent = 0.0
    for c in Counter(data).values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


@dataclass
class Section:
    name: str
    vaddr: int          # RVA
    vsize: int
    raw_ptr: int
    raw_size: int
    entropy: float
    readable: bool
    writable: bool
    executable: bool

    @property
    def flags(self) -> str:
        return (("R" if self.readable else "-")
                + ("W" if self.writable else "-")
                + ("X" if self.executable else "-"))

    def contains_rva(self, rva: int) -> bool:
        span = max(self.vsize, self.raw_size)
        return self.vaddr <= rva < self.vaddr + span


@dataclass
class PEInfo:
    ok: bool
    error: str = ""
    is_dll: bool = False
    is_dotnet: bool = False
    machine: int = 0
    arch: str = "?"
    image_base: int = 0
    entry_rva: int = 0
    entry_section: str = ""
    sections: List[Section] = field(default_factory=list)
    import_dlls: List[str] = field(default_factory=list)
    import_func_count: int = 0
    overall_entropy: float = 0.0
    size: int = 0


def _rva_to_off(sections: List[Section], rva: int) -> Optional[int]:
    for s in sections:
        if s.raw_size and s.vaddr <= rva < s.vaddr + max(s.vsize, s.raw_size):
            off = rva - s.vaddr
            if off < s.raw_size:
                return s.raw_ptr + off
    return None


def _cstr(data: bytes, off: Optional[int], limit: int = 256) -> str:
    if off is None or off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = min(off + limit, len(data))
    return data[off:end].decode("latin-1", "replace")


def parse(path: str) -> PEInfo:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return PEInfo(ok=False, error=f"cannot read: {exc}")
    return parse_bytes(data)


def parse_bytes(data: bytes) -> PEInfo:
    info = PEInfo(ok=False, size=len(data))
    if len(data) < 64 or data[:2] != b"MZ":
        info.error = "not a PE (no MZ header)"
        return info
    try:
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            info.error = "not a PE (no PE signature)"
            return info
        coff = e_lfanew + 4
        machine, num_sections, _ts, _psym, _nsym, opt_size, characteristics = \
            struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        (opt_magic,) = struct.unpack_from("<H", data, opt)
        is_plus = opt_magic == 0x20B     # PE32+
        (entry_rva,) = struct.unpack_from("<I", data, opt + 16)
        if is_plus:
            (image_base,) = struct.unpack_from("<Q", data, opt + 24)
            dd_off = opt + 112
        else:
            (image_base,) = struct.unpack_from("<I", data, opt + 28)
            dd_off = opt + 96
        (num_dd,) = struct.unpack_from("<I", data, opt + (108 if is_plus else 92))
        import_rva = clr_rva = 0
        if num_dd > 1:
            import_rva, _ = struct.unpack_from("<II", data, dd_off + 8 * 1)
        if num_dd > 14:
            clr_rva, clr_sz = struct.unpack_from("<II", data, dd_off + 8 * 14)
            info.is_dotnet = bool(clr_rva or clr_sz)
    except struct.error as exc:
        info.error = f"truncated PE header ({exc})"
        return info

    info.machine = machine
    info.arch = _MACHINE.get(machine, f"0x{machine:04X}")
    info.image_base = image_base
    info.entry_rva = entry_rva
    info.is_dll = bool(characteristics & _FILE_DLL)

    if not (0 < num_sections <= _MAX_SECTIONS):
        info.error = f"implausible section count: {num_sections}"
        return info
    sec_table = coff + 20 + opt_size
    for i in range(num_sections):
        off = sec_table + i * 40
        if off + 40 > len(data):
            info.error = "section table runs past EOF"
            return info
        raw_name = data[off:off + 8].split(b"\x00", 1)[0]
        name = raw_name.decode("latin-1", "replace") or f"sect{i}"
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        (chars,) = struct.unpack_from("<I", data, off + 36)
        body = data[raw_ptr:raw_ptr + raw_size] if raw_size and raw_ptr else b""
        info.sections.append(Section(
            name=name, vaddr=vaddr, vsize=vsize, raw_ptr=raw_ptr,
            raw_size=raw_size, entropy=shannon_entropy(body),
            readable=bool(chars & _SCN_READ), writable=bool(chars & _SCN_WRITE),
            executable=bool(chars & _SCN_EXEC)))

    for s in info.sections:
        if s.contains_rva(entry_rva):
            info.entry_section = s.name
            break

    # overall entropy over the union of section bodies
    body = b"".join(data[s.raw_ptr:s.raw_ptr + s.raw_size]
                    for s in info.sections if s.raw_size)
    info.overall_entropy = shannon_entropy(body)

    if import_rva:
        _parse_imports(data, info, import_rva, is_plus)

    info.ok = True
    return info


def _parse_imports(data: bytes, info: PEInfo, import_rva: int, is_plus: bool) -> None:
    base = _rva_to_off(info.sections, import_rva)
    if base is None:
        return
    thunk_size = 8 if is_plus else 4
    for i in range(_MAX_IMPORT_DLLS):
        desc = base + i * 20
        if desc + 20 > len(data):
            break
        oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", data, desc)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        name = _cstr(data, _rva_to_off(info.sections, name_rva))
        if name:
            info.import_dlls.append(name)
        # count functions via the (Original)FirstThunk array
        thunk_rva = oft or ft
        toff = _rva_to_off(info.sections, thunk_rva)
        if toff is None:
            continue
        for j in range(_MAX_THUNKS):
            pos = toff + j * thunk_size
            if pos + thunk_size > len(data):
                break
            val = int.from_bytes(data[pos:pos + thunk_size], "little")
            if val == 0:
                break
            info.import_func_count += 1
