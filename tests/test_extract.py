"""Tests for the static artifact extractors (strings / resources / entropy).

The resource leaf-walk and its RVA->file-offset translation are proven on a
hand-built ON-DISK synthetic PE (deterministic, byte-exact asserts), not just on
a real system exe; the real-EXE tests are a smoke layer on top and skip cleanly
where the file doesn't exist (non-Windows)."""
import os
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia import extract  # noqa: E402
from aletheia.extract import FoundString  # noqa: E402
from aletheia.pe import parse_bytes  # noqa: E402

NOTEPAD = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                       "System32", "notepad.exe")


# ===========================================================================
# synthetic ON-DISK PE builder (disk layout: raw_ptr/raw_size, unlike the
# mapped-image builder in test_dump.py)
# ===========================================================================
def _disk_pe(sections, data_dirs=None, entry=0x1000):
    """Build an on-disk PE32+ file. `sections` = [(name, rva, raw_off, body)];
    `data_dirs` = {index: (rva, size)}."""
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)      # e_lfanew = 64
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)                   # PE32+
    struct.pack_into("<I", opt, 16, entry)                  # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 24, 0x140000000)            # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)                 # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)                  # FileAlignment
    struct.pack_into("<I", opt, 108, 16)                    # NumberOfRvaAndSizes
    for idx, (rva, size) in (data_dirs or {}).items():
        struct.pack_into("<II", opt, 112 + 8 * idx, rva, size)
    coff = struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0, 240, 0x0022)
    sec_hdrs = b""
    for name, rva, raw_off, body in sections:
        nm = name.encode().ljust(8, b"\x00")[:8]
        sec_hdrs += nm + struct.pack("<IIII", max(len(body), 1), rva,
                                     len(body), raw_off)
        sec_hdrs += b"\x00" * 12 + struct.pack("<I", 0x40000040)   # R, idata
    headers = dos + b"PE\x00\x00" + coff + bytes(opt) + sec_hdrs
    total = max(raw_off + len(body) for _, _, raw_off, body in sections)
    img = bytearray(total)
    img[:len(headers)] = headers
    for _, _, raw_off, body in sections:
        img[raw_off:raw_off + len(body)] = body
    return bytes(img)


RSRC_RVA = 0x1000
RSRC_OFF = 0x400


def _dir(buf, pos, num_named, num_id):
    struct.pack_into("<IIHHHH", buf, pos, 0, 0, 0, 0, num_named, num_id)


def _manifest_pe():
    """One RT_MANIFEST leaf through the full 3-level tree:
    root@0 -> type 24 -> subdir@24 -> id #1 -> subdir@48 -> lang 0x409 ->
    data entry@72 -> payload@88 (RVA 0x1088 -> file 0x488)."""
    payload = b"<assembly manifest='aletheia-test'/>"
    rsrc = bytearray(0x200)
    _dir(rsrc, 0, 0, 1)
    struct.pack_into("<II", rsrc, 16, 24, 0x80000000 | 24)   # RT_MANIFEST -> @24
    _dir(rsrc, 24, 0, 1)
    struct.pack_into("<II", rsrc, 40, 1, 0x80000000 | 48)    # id #1 -> @48
    _dir(rsrc, 48, 0, 1)
    struct.pack_into("<II", rsrc, 64, 0x409, 72)             # lang -> data entry
    struct.pack_into("<IIII", rsrc, 72, RSRC_RVA + 88, len(payload), 0, 0)
    rsrc[88:88 + len(payload)] = payload
    pe = _disk_pe([(".rsrc", RSRC_RVA, RSRC_OFF, bytes(rsrc))],
                  data_dirs={2: (RSRC_RVA, 0x200)})
    return pe, payload


# ===========================================================================
# 1. strings
# ===========================================================================
def test_extract_strings_ascii_wide_and_noise():
    data = (b"\x01\x02" + b"HelloWorld" + b"\x03"
            + "WideStr!".encode("utf-16le") + b"\x00\x00" + b"abc" + b"\x05")
    found = extract.extract_strings(data, min_len=4)
    assert found == [
        FoundString(offset=2, encoding="ascii", text="HelloWorld"),
        FoundString(offset=13, encoding="utf-16le", text="WideStr!"),
    ]
    # the wide string produced NO spurious ASCII entries, and "abc" (len 3) is out
    assert all(f.encoding != "ascii" or f.text == "HelloWorld" for f in found)


def test_extract_strings_min_len_boundary_and_empty():
    assert [f.text for f in extract.extract_strings(b"abcd\x00abc\x00")] == ["abcd"]
    assert extract.extract_strings(b"") == []
    assert extract.extract_strings(b"\x00\x01\x02") == []


def test_extract_strings_wide_dedup_at_min_len_1():
    # "XY" wide, then a lone ASCII 'Z': the wide run's interleaved single chars
    # must NOT also be reported as ASCII, even at min_len=1.
    data = "XY".encode("utf-16le") + b"\x00" + b"Z\x01"
    found = extract.extract_strings(data, min_len=1)
    assert found == [
        FoundString(offset=0, encoding="utf-16le", text="XY"),
        FoundString(offset=5, encoding="ascii", text="Z"),
    ]


def test_extract_strings_wide_at_odd_offset():
    data = b"\x07" + "Aligned!".encode("utf-16le") + b"\x00\x00"
    found = extract.extract_strings(data, min_len=4)
    assert found == [FoundString(offset=1, encoding="utf-16le", text="Aligned!")]


def test_interesting_strings_buckets():
    strs = [
        FoundString(0, "ascii", "connect https://evil.example/c2 now"),
        FoundString(0, "utf-16le", r"HKLM\Software\BadCo\Agent"),
        FoundString(0, "ascii", "LoadLibrary kernel32.dll and user32.DLL"),
        FoundString(0, "ascii", r"drop to C:\Windows\Temp\x.bin"),
        FoundString(0, "ascii", "beacon 10.0.0.1 not 999.1.1.1"),
        FoundString(0, "ascii", "kernel32.dll"),        # duplicate -> de-duped
    ]
    got = extract.interesting_strings(strs)
    assert got["urls"] == ["https://evil.example/c2"]
    assert got["registry"] == [r"HKLM\Software\BadCo\Agent"]
    assert got["dlls"] == ["kernel32.dll", "user32.DLL"]
    assert got["paths"] == [r"C:\Windows\Temp\x.bin"]
    assert got["ipv4"] == ["10.0.0.1"]                  # 999.x rejected


# ===========================================================================
# 2. resources -- deterministic synthetic tree first, real-EXE smoke second
# ===========================================================================
def test_resources_synthetic_manifest_leaf():
    pe_bytes, payload = _manifest_pe()
    assert parse_bytes(pe_bytes).ok            # the builder made a real PE
    res = extract.extract_resources(pe_bytes)
    assert len(res) == 1
    r = res[0]
    assert r.type == "RT_MANIFEST"
    assert r.name == "#1"
    assert r.lang == 0x409
    assert r.rva == RSRC_RVA + 88
    assert r.size == len(payload)
    # RVA -> file-offset translation, proven byte-exact
    assert r.offset == RSRC_OFF + 88
    assert pe_bytes[r.offset:r.offset + r.size] == payload


def test_resources_synthetic_named_type():
    # a NAMED type entry ("CFG" via IMAGE_RESOURCE_DIR_STRING_U) -> #7 -> lang 0
    payload = b"cfgdata!"
    rsrc = bytearray(0x200)
    _dir(rsrc, 0, 1, 0)
    struct.pack_into("<II", rsrc, 16, 0x80000000 | 88, 0x80000000 | 24)
    _dir(rsrc, 24, 0, 1)
    struct.pack_into("<II", rsrc, 40, 7, 0x80000000 | 48)
    _dir(rsrc, 48, 0, 1)
    struct.pack_into("<II", rsrc, 64, 0, 72)
    struct.pack_into("<IIII", rsrc, 72, RSRC_RVA + 96, len(payload), 0, 0)
    struct.pack_into("<H", rsrc, 88, 3)                       # name length 3
    rsrc[90:96] = "CFG".encode("utf-16le")
    rsrc[96:96 + len(payload)] = payload
    pe_bytes = _disk_pe([(".rsrc", RSRC_RVA, RSRC_OFF, bytes(rsrc))],
                        data_dirs={2: (RSRC_RVA, 0x200)})
    res = extract.extract_resources(pe_bytes)
    assert len(res) == 1
    assert (res[0].type, res[0].name, res[0].lang) == ("CFG", "#7", 0)
    assert pe_bytes[res[0].offset:res[0].offset + res[0].size] == payload


def test_resources_fail_closed_on_garbage():
    assert extract.extract_resources(b"") == []
    assert extract.extract_resources(b"\x00" * 100) == []
    assert extract.extract_resources(b"MZ" + b"\x90" * 200) == []
    # a valid PE with NO resource directory
    pe_bytes = _disk_pe([(".text", 0x1000, 0x400, b"\xCC" * 32)])
    assert extract.extract_resources(pe_bytes) == []
    # resource directory RVA pointing outside every section
    pe_bytes = _disk_pe([(".text", 0x1000, 0x400, b"\xCC" * 32)],
                        data_dirs={2: (0x900000, 0x100)})
    assert extract.extract_resources(pe_bytes) == []


def test_resources_cycle_guard_terminates():
    # root's only entry is a subdirectory pointing back at the root: must
    # terminate (no recursion blow-up) and yield nothing.
    rsrc = bytearray(0x100)
    _dir(rsrc, 0, 0, 1)
    struct.pack_into("<II", rsrc, 16, 24, 0x80000000 | 0)
    pe_bytes = _disk_pe([(".rsrc", RSRC_RVA, RSRC_OFF, bytes(rsrc))],
                        data_dirs={2: (RSRC_RVA, 0x100)})
    assert extract.extract_resources(pe_bytes) == []


@pytest.mark.skipif(not os.path.exists(NOTEPAD), reason="no system notepad.exe")
def test_resources_real_exe_smoke():
    with open(NOTEPAD, "rb") as fh:
        data = fh.read()
    res = extract.extract_resources(data)
    types = {r.type for r in res}
    assert types & {"RT_VERSION", "RT_MANIFEST", "RT_GROUP_ICON"}
    for r in res:            # every translated offset stays inside the file
        assert r.offset is None or 0 <= r.offset < len(data)


# ===========================================================================
# 3. entropy
# ===========================================================================
def test_entropy_map_and_high_spans_localize():
    low = b"\x00" * 4096
    high = bytes(range(256)) * 16          # every 256-window: entropy exactly 8.0
    emap = extract.entropy_map(low + high, window=256)
    assert len(emap) == 32
    assert emap[0] == (0, 0.0)
    assert emap[16] == (4096, 8.0)
    spans = extract.high_entropy_spans(emap, threshold=7.0)
    assert spans == [(4096, 8192)]          # the high half, and ONLY the high half


def test_high_entropy_spans_split_on_gap():
    emap = [(0, 7.5), (256, 7.5), (512, 1.0), (768, 8.0)]
    assert extract.high_entropy_spans(emap) == [(0, 512), (768, 1024)]
    assert extract.high_entropy_spans([]) == []


def test_section_entropy_from_pe():
    pe_bytes, _ = _manifest_pe()
    pe = parse_bytes(pe_bytes)
    ents = extract.section_entropy(pe)
    assert [n for n, _ in ents] == [".rsrc"]
    assert ents[0][1] == pytest.approx(pe.sections[0].entropy)


# ===========================================================================
# 4. roll-up
# ===========================================================================
def test_extract_all_synthetic(tmp_path):
    pe_bytes, payload = _manifest_pe()
    p = tmp_path / "sample.exe"
    p.write_bytes(pe_bytes)
    result = extract.extract_all(str(p))
    assert result.ok
    assert any(payload.decode() == f.text for f in result.strings)
    assert [r.type for r in result.resources] == ["RT_MANIFEST"]
    assert result.section_entropy and result.section_entropy[0][0] == ".rsrc"
    assert set(result.interesting) == {"urls", "ipv4", "paths", "registry", "dlls"}


def test_extract_all_fails_closed_on_non_pe(tmp_path):
    p = tmp_path / "not_a_pe.bin"
    p.write_bytes(b"just some bytes, no MZ")
    result = extract.extract_all(str(p))
    assert not result.ok and result.error
    assert result.strings == [] and result.resources == []
    missing = extract.extract_all(str(tmp_path / "nope.exe"))
    assert not missing.ok and "cannot read" in missing.error


@pytest.mark.skipif(not os.path.exists(NOTEPAD), reason="no system notepad.exe")
def test_extract_all_real_exe_smoke():
    result = extract.extract_all(NOTEPAD)
    assert result.ok
    assert len(result.strings) > 50
    assert result.resources
    assert result.section_entropy
    assert any(n == ".text" for n, _ in result.section_entropy)
