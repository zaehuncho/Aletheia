"""Tests for the memory->PE dumper (no live process needed: a simulated image)."""
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia import dump  # noqa: E402
from aletheia.pe import parse_bytes  # noqa: E402

BASE = 0x400000


def _mapped(sections, entry=0x1000, sect_align=0x1000) -> bytes:
    """Build a MAPPED (virtual-layout) PE image: headers in the first page, each
    section's bytes at its RVA. `sections` = list of (name, rva, body)."""
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)            # PE32+
    struct.pack_into("<I", opt, 16, entry)           # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 24, 0x140000000)     # ImageBase
    struct.pack_into("<I", opt, 32, sect_align)      # SectionAlignment
    struct.pack_into("<I", opt, 36, sect_align)      # FileAlignment
    struct.pack_into("<I", opt, 60, sect_align)      # SizeOfHeaders
    struct.pack_into("<I", opt, 108, 16)             # NumberOfRvaAndSizes
    coff = struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0, 240, 0x0022)
    sec_hdrs = b""
    for name, rva, body in sections:
        nm = name.encode().ljust(8, b"\x00")[:8]
        sec_hdrs += nm + struct.pack("<IIII", len(body), rva, 0, 0) \
            + b"\x00" * 12 + struct.pack("<I", 0x60000020)
    headers = dos + b"PE\x00\x00" + coff + bytes(opt) + sec_hdrs
    total = max(rva + len(body) for _, rva, body in sections)
    total = (total + sect_align - 1) // sect_align * sect_align
    img = bytearray(total)
    img[:len(headers)] = headers
    for _name, rva, body in sections:
        img[rva:rva + len(body)] = body
    return bytes(img)


def _reader(img):
    return lambda addr, size: img[addr - BASE:addr - BASE + size]


def test_dump_roundtrips_to_valid_pe():
    text = bytes(range(256)) * 2          # 512 bytes
    data = b"\xAA" * 300
    img = _mapped([(".text", 0x1000, text), (".data", 0x2000, data)])
    dumped = dump.dump_pe(_reader(img), BASE, oep_rva=0x1000)

    pe = parse_bytes(dumped)
    assert pe.ok and pe.arch == "x64"
    assert [s.name for s in pe.sections] == [".text", ".data"]
    assert pe.entry_rva == 0x1000
    # section bytes survived the dump (raw layout == virtual layout)
    tsec = next(s for s in pe.sections if s.name == ".text")
    assert dumped[tsec.raw_ptr:tsec.raw_ptr + len(text)] == text
    dsec = next(s for s in pe.sections if s.name == ".data")
    assert dumped[dsec.raw_ptr:dsec.raw_ptr + len(data)] == data


def test_dump_writes_recovered_oep():
    img = _mapped([(".text", 0x1000, b"\xCC" * 64)], entry=0x1000)
    dumped = dump.dump_pe(_reader(img), BASE, oep_rva=0x1044)
    assert parse_bytes(dumped).entry_rva == 0x1044


def test_dump_rejects_non_pe():
    with pytest.raises(ValueError):
        dump.dump_pe(lambda a, s: b"\x00" * s, BASE)
