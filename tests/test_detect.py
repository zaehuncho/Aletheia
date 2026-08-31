"""Tests for Aletheia's static triage: PE parsing + packer detection."""
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia.detect import analyze  # noqa: E402
from aletheia.pe import PEInfo, Section, parse_bytes, shannon_entropy  # noqa: E402


# --- entropy ---------------------------------------------------------------
def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 4096) == 0.0
    assert shannon_entropy(bytes(range(256)) * 8) == pytest.approx(8.0, abs=1e-9)
    assert shannon_entropy(b"\x00\x01" * 256) == pytest.approx(1.0, abs=1e-9)


# --- a hand-built minimal PE exercises the parser --------------------------
def _make_pe(text: bytes, data: bytes, machine=0x8664, dll=False,
             entry=0x1000) -> bytes:
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)          # e_lfanew = 64
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)                        # PE32+ magic
    struct.pack_into("<I", opt, 16, entry)                      # entry RVA
    struct.pack_into("<Q", opt, 24, 0x140000000)               # image base
    struct.pack_into("<I", opt, 108, 16)                       # num data dirs
    coff = struct.pack("<HHIIIHH", machine, 2, 0, 0, 0, 240,
                       0x2000 if dll else 0x0022)
    raw0 = 512
    hdr_text = (b".text\x00\x00\x00" + struct.pack("<IIII", len(text), 0x1000,
                len(text), raw0) + b"\x00" * 12 + struct.pack("<I", 0x60000020))
    hdr_data = (b".data\x00\x00\x00" + struct.pack("<IIII", len(data), 0x2000,
                len(data), raw0 + len(text)) + b"\x00" * 12
                + struct.pack("<I", 0xC0000040))
    head = dos + b"PE\x00\x00" + coff + bytes(opt) + hdr_text + hdr_data
    return head + b"\x00" * (raw0 - len(head)) + text + data


def test_parse_minimal_pe():
    pe = parse_bytes(_make_pe(b"\x90" * 128, b"\x00" * 64))
    assert pe.ok and pe.arch == "x64" and not pe.is_dll
    assert [s.name for s in pe.sections] == [".text", ".data"]
    assert pe.entry_section == ".text"
    assert pe.import_func_count == 0
    text = next(s for s in pe.sections if s.name == ".text")
    assert text.executable and not text.writable


def test_parse_rejects_non_pe():
    assert not parse_bytes(b"not a pe" * 20).ok


# --- detection heuristics on hand-built PEInfo -----------------------------
def _sec(name, entropy=4.0, r=True, w=False, x=False, vsize=0x1000,
         raw=0x1000, vaddr=0x1000):
    return Section(name=name, vaddr=vaddr, vsize=vsize, raw_ptr=0x400,
                   raw_size=raw, entropy=entropy, readable=r, writable=w,
                   executable=x)


def _pe(sections, entry_section=".text", imports=100, dotnet=False):
    return PEInfo(ok=True, arch="x64", entry_rva=0x1000,
                  entry_section=entry_section, import_func_count=imports,
                  import_dlls=["kernel32.dll"], is_dotnet=dotnet,
                  sections=sections)


def test_clean_binary_not_flagged():
    clean = _pe([
        _sec(".text", 6.1, x=True),
        _sec(".rdata", 4.8),
        _sec(".data", 3.5, w=True),
        _sec(".rsrc", 4.0),
    ])
    v = analyze(clean)
    assert not v.packed and v.confidence < 0.5 and v.likely_packer is None


def test_packed_binary_flagged():
    packed = _pe([
        _sec("packed0", 7.9, w=True, x=True, vsize=0x9000, raw=0x1000),
        _sec("packed1", 7.95, w=True),
    ], entry_section="packed0", imports=2)
    v = analyze(packed)
    assert v.packed and v.confidence >= 0.5
    assert any("writable+executable" in s for s in v.signals)
    assert any("high-entropy" in s for s in v.signals)


def test_vmprotect_by_section_name():
    v = analyze(_pe([_sec(".text", 6.0, x=True), _sec(".vmp0", 7.8),
                     _sec(".vmp1", 7.9, w=True, x=True)],
                    entry_section=".vmp1"))
    assert v.likely_packer == "VMProtect" and v.packed


def test_upx_by_section_name():
    v = analyze(_pe([_sec("UPX0", 0.0, x=True, raw=0), _sec("UPX1", 7.9, x=True)],
                    entry_section="UPX1", imports=3))
    assert v.likely_packer == "UPX" and v.packed


def test_lethe_magic_detected():
    v = analyze(_pe([_sec(".text", 6.0, x=True)]),
                raw=b"....stuff....LETHE01\x00....more....")
    assert v.likely_packer == "Lethe" and v.packed
    assert any("LETHE01" in s for s in v.signals)


def test_import_elision_signal():
    v = analyze(_pe([_sec(".text", 6.5, x=True)], imports=0))
    assert any("no import table" in s for s in v.signals)
