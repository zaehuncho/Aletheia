"""Tests for aletheia.signatures: the YARA-style content scanner and the
FLIRT-style function identifier (first cut).

The hex-wildcard -> regex compiler is proved exhaustively (full 256-byte
sweeps per wildcard form -- the nibble classes and the DOTALL trap are where
the subtle bugs live), conditions are pinned on a 0/1/2-hits matrix, the
default rules on synthetic buffers with hand-placed constants, and the
function identifier on a synthetic address->bytes map plus (capstone
permitting) a hand-assembled on-disk PE through disasm_pe. The only
environment-dependent test is a best-effort real-EXE smoke, skipped where no
candidate system binary exists.
"""
import re
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia.signatures import (  # noqa: E402
    DEFAULT_RULES, DEMO_SIGDB, FuncSignature, Match, Pattern, Rule,
    _hex_to_regex, identify_functions, scan, scan_pe,
)


# ===========================================================================
# hex-wildcard compiler (the load-bearing bit)
# ===========================================================================
def test_hex_compiler_sample_pattern_and_offset():
    # the spec's own example: fixed opcode bytes + a wildcard mod/rm + a call
    # with all four rel32 bytes masked
    rx, nbytes = _hex_to_regex("48 8B ?? E8 ?? ?? ?? ??")
    assert nbytes == 8
    good = bytes.fromhex("488BC0E811223344")
    bad = bytes.fromhex("488CC0E811223344")          # 8B -> 8C: one literal off
    m = re.compile(rx).search(b"\xee" * 5 + good + b"\xee")
    assert m is not None and m.start() == 5 and m.group() == good
    assert re.compile(rx).search(bad) is None


@pytest.mark.parametrize("spec,accept", [
    # full-byte wildcard: every value 0..255, including 0x0A (the '.'-without-
    # DOTALL trap) and 0x00
    ("??", lambda v: True),
    ("?", lambda v: True),                            # lone '?' == '??'
    # high nibble fixed: contiguous range class
    ("4?", lambda v: 0x40 <= v <= 0x4F),
    # low nibble fixed: 16 NON-contiguous values -- enumerated class
    ("?B", lambda v: (v & 0x0F) == 0x0B),
    # metacharacter-heavy nibble ranges: 0x20..0x2F spans space/*/+/-/.,
    # 0x50..0x5F spans [/\/]/^ -- escaping must keep them inert
    ("2?", lambda v: 0x20 <= v <= 0x2F),
    ("5?", lambda v: 0x50 <= v <= 0x5F),
    ("?D", lambda v: (v & 0x0F) == 0x0D),             # includes \r and ']'
])
def test_hex_wildcards_exhaustive_256_sweep(spec, accept):
    rx, nbytes = _hex_to_regex(spec)
    assert nbytes == 1
    pat = re.compile(rx)
    for v in range(256):
        assert bool(pat.fullmatch(bytes([v]))) == accept(v), hex(v)


def test_hex_nibble_wildcard_spec_examples():
    # the spec's explicit cases: 4? matches 48 and 4F but not 50
    rx, _ = _hex_to_regex("4?")
    pat = re.compile(rx)
    assert pat.fullmatch(b"\x48") and pat.fullmatch(b"\x4f")
    assert pat.fullmatch(b"\x50") is None


def test_hex_compiler_literal_bytes_are_escaped():
    # 0x2A '*', 0x5D ']', 0x24 '$' as LITERAL bytes must not act as regex ops
    rx, n = _hex_to_regex("2A 5D 24")
    assert n == 3
    pat = re.compile(rx)
    assert pat.fullmatch(b"*]$")
    assert pat.search(b"aa*]$bb").start() == 2
    assert pat.search(b"**]$") is not None            # '*' matched literally,
    assert pat.fullmatch(b"]$") is None               # never as a quantifier


def test_hex_compiler_contiguous_run_equals_spaced():
    assert _hex_to_regex("488BC0") == _hex_to_regex("48 8B C0")
    assert _hex_to_regex("48 8BC0") == _hex_to_regex("48 8B C0")
    rx, n = _hex_to_regex("4?8b")                     # case-insensitive digits
    assert n == 2 and re.compile(rx).fullmatch(b"\x4c\x8b")


@pytest.mark.parametrize("bad", ["", "   ", "4", "48 8", "4G", "GG", "4 8B",
                                 "48 ?Z", "48 ???"])
def test_hex_compiler_rejects_malformed(bad):
    with pytest.raises(ValueError):
        _hex_to_regex(bad)


# ===========================================================================
# Pattern / Rule construction
# ===========================================================================
def test_text_pattern_escapes_metacharacters():
    p = Pattern(id="$t", text="a.c(x)*")
    assert p._compiled.search(b"zz a.c(x)* zz").start() == 3
    assert p._compiled.search(b"abc(x)(x)") is None   # '.' and '*' are literal


def test_pattern_requires_exactly_one_kind():
    with pytest.raises(ValueError):
        Pattern(id="$none")
    with pytest.raises(ValueError):
        Pattern(id="$two", text="a", hex="41")
    with pytest.raises(ValueError):
        Pattern(id="$badrx", regex=rb"(unclosed")
    with pytest.raises(ValueError):
        Pattern(id="$empty", text="")


def test_rule_validates_condition_and_patterns():
    pats = [Pattern(id="$a", text="AAAA"), Pattern(id="$b", text="BBBB")]
    with pytest.raises(ValueError):
        Rule(name="r", patterns=[])
    with pytest.raises(ValueError):
        Rule(name="r", patterns=pats, condition=0)
    with pytest.raises(ValueError):
        Rule(name="r", patterns=pats, condition=3)    # can never fire
    with pytest.raises(ValueError):
        Rule(name="r", patterns=pats, condition=True)  # bool is not an N
    with pytest.raises(ValueError):
        Rule(name="r", patterns=[Pattern(id="$a", text="x"),
                                 Pattern(id="$a", text="y")])  # dup ids


# ===========================================================================
# conditions on a 0 / 1 / 2 hit matrix
# ===========================================================================
@pytest.mark.parametrize("cond,expect_0,expect_1,expect_2", [
    ("any", False, True, True),
    ("all", False, False, True),
    (1,     False, True, True),
    (2,     False, False, True),
])
def test_conditions(cond, expect_0, expect_1, expect_2):
    rule = Rule(name="r", condition=cond,
                patterns=[Pattern(id="$a", text="AAAA"),
                          Pattern(id="$b", text="BBBB")])
    hits = {0: b"xxxxxxxx", 1: b"xxAAAAxx", 2: b"xxAAAAxxBBBBxx"}
    for n, expect in ((0, expect_0), (1, expect_1), (2, expect_2)):
        fired = bool(scan(hits[n], [rule]))
        assert fired == expect, f"condition={cond!r} with {n} hits"


def test_match_reports_every_hit_location():
    rule = Rule(name="r", condition="any",
                patterns=[Pattern(id="$a", hex="41 42"),        # "AB"
                          Pattern(id="$b", text="CD")])
    data = b"..AB....AB..CD.."
    (m,) = scan(data, [rule])
    assert isinstance(m, Match) and m.rule_name == "r"
    # every location of every hitting pattern, offset-sorted
    assert m.strings == [("$a", 2, b"AB"), ("$a", 8, b"AB"), ("$b", 12, b"CD")]


# ===========================================================================
# DEFAULT_RULES on synthetic buffers
# ===========================================================================
_AES_SBOX16 = bytes.fromhex("637C777BF26B6FC53001672BFED7AB76")


def _fired(data):
    return {m.rule_name: m for m in scan(data, DEFAULT_RULES)}


def test_crypto_rule_aes_sbox():
    data = b"The quick brown fox " * 4 + _AES_SBOX16 + b" tail"
    fired = _fired(data)
    assert "crypto-constants" in fired
    assert ("$aes_sbox", 80, _AES_SBOX16) in fired["crypto-constants"].strings
    assert "crypto-constants" not in _fired(b"The quick brown fox " * 8)


def test_crypto_rule_md5_and_sha256_constants():
    md5 = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")   # RFC 1321 init
    k_le = bytes.fromhex("982F8A4291443771CFFBC0B5A5DBB5E9")  # FIPS 180-4 K, LE
    k_be = bytes.fromhex("428A2F9871374491B5C0FBCFE9B5DBA5")  # same, BE words
    for blob, pid in ((md5, "$md5_sha1_init"), (k_le, "$sha256_k_le"),
                      (k_be, "$sha256_k_be")):
        fired = _fired(b"\xee" * 10 + blob)
        assert "crypto-constants" in fired, pid
        assert any(s[0] == pid and s[1] == 10
                   for s in fired["crypto-constants"].strings), pid


def _minimal_dos_pe() -> bytes:
    """A 64-byte DOS header with e_lfanew=64 followed by PE\\0\\0 -- the
    smallest thing the embedded-pe rule should recognize as a PE header."""
    return b"MZ" + b"\x00" * 58 + struct.pack("<I", 64) + b"PE\x00\x00"


def test_embedded_pe_rule_fires_only_at_nonzero_offset():
    host = _minimal_dos_pe() + b"\x00" * 100
    assert "embedded-pe" not in _fired(host)          # MZ at 0 == the host itself
    embedded = b"\x00" * 64 + host
    fired = _fired(embedded)
    assert "embedded-pe" in fired
    assert fired["embedded-pe"].strings[0][1] == 64   # the embedded MZ's offset


def test_embedded_pe_rule_dropper_style_appended_payload():
    host = _minimal_dos_pe() + b"\xcc" * 300          # host image
    payload = _minimal_dos_pe() + b"\x00" * 32        # appended second PE
    fired = _fired(host + b"PADDING!" + payload)
    assert "embedded-pe" in fired
    assert fired["embedded-pe"].strings[0][1] == len(host) + 8


def test_suspicious_imports_rule():
    fired = _fired(b"\x00kernel32.dll\x00IsDebuggerPresent\x00")
    assert "suspicious-imports" in fired
    assert any(s[0] == "$isdebugger" for s in fired["suspicious-imports"].strings)
    assert "suspicious-imports" not in _fired(b"nothing to see here" * 3)


# ===========================================================================
# FLIRT first cut: identify_functions on a synthetic address map
# ===========================================================================
def _map_reader(segments):
    """read_code over {addr: bytes}; anything unmapped reads as b''."""
    def read_code(addr, size):
        for base, blob in segments.items():
            if base <= addr < base + len(blob):
                off = addr - base
                return blob[off:off + size]
        return b""
    return read_code


def test_identify_functions_wildcard_reloc_names_exactly_the_match():
    # func A: sub rsp,28h; call rel32 -- imm8 and all 4 displacement bytes
    # land on DEMO_SIGDB's wildcards (the relocation-masking mechanism)
    func_a = bytes.fromhex("4883EC28" "E8AABBCCDD" "C3")
    func_b = bytes.fromhex("31C0C3")                  # xor eax,eax; ret
    read = _map_reader({0x401000: func_a, 0x402000: func_b})
    out = identify_functions(read, [0x401000, 0x402000], DEMO_SIGDB)
    assert out == {0x401000: "demo_shadow_call"}


def test_identify_functions_first_match_wins():
    sigdb = [FuncSignature(name="broad", pattern="55"),
             FuncSignature(name="narrow", pattern="55 48 89 E5")]
    read = _map_reader({0x1000: bytes.fromhex("554889E5C3")})
    assert identify_functions(read, [0x1000], sigdb) == {0x1000: "broad"}
    # reversed priority: the narrow signature now claims it
    assert identify_functions(read, [0x1000], sigdb[::-1]) == {0x1000: "narrow"}


def test_identify_functions_fails_closed():
    sigdb = [FuncSignature(name="frame", pattern="55 48 89 E5")]
    read = _map_reader({0x1000: b"\x55\x48"})         # truncated: 2 of 4 bytes
    assert identify_functions(read, [0x1000, 0xdead0000], sigdb) == {}
    assert identify_functions(read, [0x1000], []) == {}


def test_func_signature_length_is_metadata_only():
    sig = FuncSignature(name="s", pattern="55 48 89 E5", length=120)
    assert sig.nbytes == 4 and sig.length == 120
    assert sig.matches_start(bytes.fromhex("554889E5"))  # 4 bytes suffice


# ===========================================================================
# identify_in_pe: hand-assembled PE through disasm_pe (needs capstone)
# ===========================================================================
def _make_pe(text: bytes) -> bytes:
    """Minimal single-.text x64 PE, entry at RVA 0x1000 (same builder shape as
    test_detect's -- replicated because test modules don't import each other)."""
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)          # e_lfanew = 64
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)                       # PE32+
    struct.pack_into("<I", opt, 16, 0x1000)                     # entry RVA
    struct.pack_into("<Q", opt, 24, 0x140000000)                # image base
    struct.pack_into("<I", opt, 108, 16)                        # num data dirs
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x0022)
    raw0 = 512
    hdr = (b".text\x00\x00\x00" + struct.pack("<IIII", len(text), 0x1000,
           len(text), raw0) + b"\x00" * 12 + struct.pack("<I", 0x60000020))
    head = dos + b"PE\x00\x00" + coff + bytes(opt) + hdr
    return head + b"\x00" * (raw0 - len(head)) + text


def test_identify_in_pe_names_entry_and_call_targets(tmp_path):
    pytest.importorskip("capstone")
    from aletheia.signatures import identify_in_pe  # noqa: E402

    base = 0x140000000
    # RVA 0x1000 (entry): push rbp; mov rbp,rsp; call +7 (-> 0x1010); pop; ret
    # RVA 0x1010: sub rsp,28h; call +7 (-> 0x1020); add rsp,28h; ret
    # RVA 0x1020: push rbp; mov rbp,rsp; pop rbp; ret
    text = bytes.fromhex(
        "55" "4889E5" "E807000000" "5D" "C3"    # 0x1000..0x100A
        "9090909090"                            # pad to 0x1010
        "4883EC28" "E807000000" "4883C428" "C3"  # 0x1010..0x101D
        "9090"                                  # pad to 0x1020
        "55" "4889E5" "5D" "C3")                # 0x1020..0x1025
    path = tmp_path / "synth.exe"
    path.write_bytes(_make_pe(text))

    out = identify_in_pe(str(path), DEMO_SIGDB)
    assert out == {
        base + 0x1000: "demo_frame_prologue",   # the entry point
        base + 0x1010: "demo_shadow_call",      # call target, reloc wildcarded
        base + 0x1020: "demo_frame_prologue",   # nested call target
    }


# ===========================================================================
# scan_pe: error path + best-effort real smoke
# ===========================================================================
def test_scan_pe_unreadable_path_raises():
    with pytest.raises(OSError):
        scan_pe(r"Z:\definitely\not\here.exe")


_REAL_EXES = [r"C:\Windows\System32\notepad.exe", r"C:\Windows\System32\cmd.exe",
              r"C:\Windows\explorer.exe"]


def test_scan_pe_real_smoke_suspicious_imports_fire():
    present = [p for p in _REAL_EXES if Path(p).is_file()]
    if not present:
        pytest.skip("no candidate system executable on this machine")
    fired_any = False
    for exe in present:
        matches = scan_pe(exe)                        # must never crash
        assert isinstance(matches, list)
        for m in matches:
            assert m.strings, f"{m.rule_name} fired with no hit locations"
        if any(m.rule_name == "suspicious-imports" for m in matches):
            fired_any = True
    # those API names sit verbatim in real import tables (verified locally on
    # notepad.exe and cmd.exe); if a future Windows build strips them all,
    # this assert failing is the honest signal, not something to paper over
    assert fired_any, ("suspicious-imports fired on none of: "
                       + ", ".join(present))


# ===========================================================================
# C. Structural function classification (FLIRT over IR shape)
#
# Each signature gets a hand-built IR fixture bearing exactly its marker (a
# magic constant for the crypto/hash family, a loop shape for the libc family).
# The IR is built directly -- no capstone needed -- so these run everywhere.
# ===========================================================================
from aletheia.ir import (  # noqa: E402
    IRBlock, IRFunction, IRInsn, Op, Value, VTag,
)
from aletheia.signatures import (  # noqa: E402
    StructuralSignature, classify_by_structure,
    classify_functions_by_structure, structural_signatures,
)


# -- tiny IR builders -------------------------------------------------------
def _r(name, size=64):
    return Value(VTag.REG, name=name, size=size)


def _i(v, size=32):
    return Value(VTag.IMM, imm=v, size=size)


def _m(base=None, index=None, scale=1, disp=0, size=8):
    return Value(VTag.MEM, size=size,
                 base=_r(base) if base else None,
                 index=_r(index) if index else None, scale=scale, disp=disp)


def _cc(tok="cc_ne"):
    return Value(VTag.TEMP, name=tok, size=8)


def _fn(blocks, start):
    """Assemble an IRFunction from IRBlocks, entry == start."""
    return IRFunction(start=start, blocks={b.start: b for b in blocks},
                      entry=start)


def _loop_fn(body_insns, base=0x1000):
    """A 3-block function: entry -> self-looping body (back-edge) -> exit(ret).
    ``body_insns`` are the loop-body ops before the terminating BR."""
    h, lp, e = base, base + 0x10, base + 0x20
    entry = IRBlock(start=h, insns=[], succs=[lp])
    br = IRInsn(lp, Op.BR, dst=None, args=(_cc(),), then_ea=lp, else_ea=e)
    loop = IRBlock(start=lp, insns=list(body_insns) + [br], succs=[lp, e])
    exit_ = IRBlock(start=e, insns=[IRInsn(e, Op.RET)], succs=[])
    return _fn([entry, loop, exit_], h)


def _straight_fn(insns, base=0x400):
    """A single-block, loop-free function ending in RET."""
    blk = IRBlock(start=base, insns=list(insns) + [IRInsn(base, Op.RET)], succs=[])
    return _fn([blk], base)


# -- libc-family fixtures ---------------------------------------------------
def _memcpy_fn(base=0x1000):
    lp = base + 0x10
    return _loop_fn([
        IRInsn(lp, Op.LOAD, dst=_r("t0", 8), args=(_m(base="rsi", index="rcx"),)),
        IRInsn(lp, Op.STORE, dst=_m(base="rdi", index="rcx"), args=(_r("t0", 8),)),
        IRInsn(lp, Op.ADD, dst=_r("rcx"), args=(_r("rcx"), _i(1, 64))),
        IRInsn(lp, Op.CMP, dst=None, args=(_r("rcx"), _r("rdx"))),   # counter vs size
    ], base)


def _memset_fn(base=0x1000):
    lp = base + 0x10
    return _loop_fn([
        IRInsn(lp, Op.STORE, dst=_m(base="rdi", index="rcx"), args=(_i(0, 8),)),
        IRInsn(lp, Op.ADD, dst=_r("rcx"), args=(_r("rcx"), _i(1, 64))),
        IRInsn(lp, Op.CMP, dst=None, args=(_r("rcx"), _r("rdx"))),
    ], base)


def _strlen_fn(base=0x1000):
    lp = base + 0x10
    return _loop_fn([
        IRInsn(lp, Op.LOAD, dst=_r("t0", 8), args=(_m(base="rdi", index="rcx"),)),
        IRInsn(lp, Op.CMP, dst=None, args=(_r("t0", 8), _i(0, 8))),  # *p == 0 ?
        IRInsn(lp, Op.ADD, dst=_r("rcx"), args=(_r("rcx"), _i(1, 64))),
    ], base)


def _strcpy_fn(base=0x1000):
    lp = base + 0x10
    return _loop_fn([
        IRInsn(lp, Op.LOAD, dst=_r("t0", 8), args=(_m(base="rsi", index="rcx"),)),
        IRInsn(lp, Op.STORE, dst=_m(base="rdi", index="rcx"), args=(_r("t0", 8),)),
        IRInsn(lp, Op.CMP, dst=None, args=(_r("t0", 8), _i(0, 8))),  # exit on NUL
        IRInsn(lp, Op.ADD, dst=_r("rcx"), args=(_r("rcx"), _i(1, 64))),
    ], base)


def _memcmp_fn(base=0x1000):
    lp = base + 0x10
    return _loop_fn([
        IRInsn(lp, Op.LOAD, dst=_r("t0", 8), args=(_m(base="rsi", index="rcx"),)),
        IRInsn(lp, Op.LOAD, dst=_r("t1", 8), args=(_m(base="rdi", index="rcx"),)),
        IRInsn(lp, Op.CMP, dst=None, args=(_r("t0", 8), _r("t1", 8))),  # a[i] vs b[i]
        IRInsn(lp, Op.ADD, dst=_r("rcx"), args=(_r("rcx"), _i(1, 64))),
    ], base)


def _memmove_fn(base=0x1000):
    lp = base + 0x10
    return _loop_fn([
        IRInsn(lp, Op.CMP, dst=None, args=(_r("rsi"), _r("rdi"))),   # overlap check
        IRInsn(lp, Op.LOAD, dst=_r("t0", 8), args=(_m(base="rsi", index="rcx"),)),
        IRInsn(lp, Op.STORE, dst=_m(base="rdi", index="rcx"), args=(_r("t0", 8),)),
        IRInsn(lp, Op.ADD, dst=_r("rcx"), args=(_r("rcx"), _i(1, 64))),
    ], base)


# -- crypto/hash fixtures ---------------------------------------------------
def _const_fn(const, base=0x400, extra=()):
    """A loop-free function that loads a distinctive constant into a register,
    plus optional extra ops."""
    return _straight_fn([
        IRInsn(base, Op.ASSIGN, dst=_r("eax", 32), args=(_i(const, 32),)),
        *extra,
    ], base)


def _aes_sbox_fn(base=0x400):
    # first four S-box bytes 63 7C 77 7B packed big-endian
    return _const_fn(0x637c777b, base)


def _aesni_fn(base=0x400):
    return _straight_fn([
        IRInsn(base, Op.UNDEF, text="aesenc xmm0, xmm1"),
    ], base)


def _chacha_fn(base=0x400):
    b = base

    def rot(reg, amt):
        return IRInsn(b, Op.ROL, dst=_r(reg), args=(_r(reg), _i(amt, 32)))

    def xor(d, s):
        return IRInsn(b, Op.XOR, dst=_r(d), args=(_r(d), _r(s)))

    def add(d, s):
        return IRInsn(b, Op.ADD, dst=_r(d), args=(_r(d), _r(s)))

    return _straight_fn([
        add("a", "b"), xor("d", "a"), rot("d", 16),
        add("c", "d"), xor("b", "c"), rot("b", 12),
        add("a", "b"), xor("d", "a"), rot("d", 8),
        add("c", "d"), xor("b", "c"), rot("b", 7),
    ], base)


def _sha256_fn(base=0x400):
    return _const_fn(0x428a2f98, base)             # K[0]


def _sha1_fn(base=0x400):
    return _const_fn(0x5a827999, base)             # round constant K0 (unique)


def _md5_fn(base=0x400):
    return _const_fn(0xd76aa478, base)             # T[1]


def _crc32_fn(base=0x400):
    return _straight_fn([
        IRInsn(base, Op.XOR, dst=_r("rax"), args=(_r("rax"), _r("rdx"))),
        IRInsn(base, Op.SHR, dst=_r("rax"), args=(_r("rax"), _i(1, 8))),
        IRInsn(base, Op.AND, dst=_r("rax"), args=(_r("rax"), _i(0xedb88320, 32))),
    ], base)


def _fnv_fn(base=0x400):
    return _straight_fn([
        IRInsn(base, Op.XOR, dst=_r("rax"), args=(_r("rax"), _r("rdx"))),
        IRInsn(base, Op.IMUL, dst=_r("rax"), args=(_r("rax"), _i(0x01000193, 32))),
    ], base)


def _nomatch_fn(base=0x400):
    # a plausible loop-free function with no marker and no primitive shape
    return _straight_fn([
        IRInsn(base, Op.ASSIGN, dst=_r("rax"), args=(_i(5, 64),)),
        IRInsn(base, Op.ADD, dst=_r("rax"), args=(_r("rax"), _r("rbx"))),
        IRInsn(base, Op.CALL, args=(_i(0x8000, 64),)),
    ], base)


# -- the required, per-signature tests --------------------------------------
def test_structural_memcpy_shape():
    assert classify_by_structure(_memcpy_fn()).name == "memcpy"


def test_structural_strlen_shape():
    assert classify_by_structure(_strlen_fn()).name == "strlen"


def test_structural_aes_via_sbox_constant():
    sig = classify_by_structure(_aes_sbox_fn())
    assert sig.name == "aes_round" and sig.kind == "crypt"


def test_structural_chacha_quarter_round_shape():
    assert classify_by_structure(_chacha_fn()).name == "chacha_quarter_round"


def test_structural_sha256_via_k_constant():
    sig = classify_by_structure(_sha256_fn())
    assert sig.name == "sha256_compression"


def test_structural_random_function_matches_nothing():
    assert classify_by_structure(_nomatch_fn()) is None


def test_structural_precedence_memcpy_beats_memset():
    # a load+store loop satisfies BOTH the memcpy and the (more generic) memset
    # predicate; the more specific memcpy is listed first and must win.
    f = _memcpy_fn()
    sigs = {s.name: s for s in structural_signatures()}
    assert sigs["memcpy"].predicate(f)             # both predicates fire...
    assert sigs["memset"].predicate(f)
    names = [s.name for s in structural_signatures()]
    assert names.index("memcpy") < names.index("memset")   # ...memcpy is first
    assert classify_by_structure(f).name == "memcpy"       # ...so memcpy wins


# -- the rest of the catalog ------------------------------------------------
def test_structural_memset_shape():
    assert classify_by_structure(_memset_fn()).name == "memset"


def test_structural_strcpy_beats_memcpy():
    # load+store+NUL-test: strcpy is more specific than memcpy and ordered first
    assert classify_by_structure(_strcpy_fn()).name == "strcpy"


def test_structural_memcmp_shape():
    assert classify_by_structure(_memcmp_fn()).name == "memcmp"


def test_structural_memmove_beats_memcpy():
    # load+store+pointer-overlap-check: memmove is more specific than memcpy
    assert classify_by_structure(_memmove_fn()).name == "memmove"


def test_structural_aes_via_aesni_intrinsic():
    # the lifter drops AESENC to UNDEF(text="aesenc ..."); we recognise it there
    assert classify_by_structure(_aesni_fn()).name == "aes_round"


def test_structural_sha1_via_round_constant():
    assert classify_by_structure(_sha1_fn()).name == "sha1_compression"


def test_structural_md5_via_t_constant():
    assert classify_by_structure(_md5_fn()).name == "md5_compression"


def test_structural_crc32_shape():
    assert classify_by_structure(_crc32_fn()).name == "crc32"


def test_structural_fnv_shape():
    assert classify_by_structure(_fnv_fn()).name == "fnv_hash"


def test_structural_shared_md5_sha1_init_word_does_not_false_match():
    # 0x67452301 is BOTH an MD5 and a SHA-1 init word -- keying on it would be
    # ambiguous, so neither signature uses it. A lone shared word matches nothing.
    f = _const_fn(0x67452301)
    assert classify_by_structure(f) is None


def test_structural_batch_maps_start_to_signature():
    funcs = [_memcpy_fn(0x1000), _sha256_fn(0x2000), _nomatch_fn(0x3000)]
    out = classify_functions_by_structure(funcs)
    assert {k: v.name for k, v in out.items()} == {
        0x1000: "memcpy", 0x2000: "sha256_compression"}    # nomatch is absent


def test_structural_survives_ssa_construction():
    # predicates compare names via ssa_base_name, so a fully renamed function
    # (rcx -> rcx#4, t0 -> t0#1, plus phis) still classifies identically.
    import copy
    from aletheia.dataflow import build_ssa
    f = copy.deepcopy(_memcpy_fn())
    build_ssa(f)
    assert classify_by_structure(f).name == "memcpy"

    g = copy.deepcopy(_strlen_fn())
    build_ssa(g)
    assert classify_by_structure(g).name == "strlen"


def test_structural_classify_never_raises_on_degenerate_input():
    # empty function / no CFG must fail closed (None), not explode
    empty = IRFunction(start=0, blocks={}, entry=0)
    assert classify_by_structure(empty) is None
    # a function whose entry isn't even in its block map
    orphan = IRFunction(start=0x99, blocks={0x1: IRBlock(start=0x1, insns=[])},
                        entry=0x99)
    assert classify_by_structure(orphan) is None


def test_structural_catalog_invariants():
    cat = structural_signatures()
    assert len(cat) >= 10                          # ship at least ten
    assert all(isinstance(s, StructuralSignature) for s in cat)
    names = [s.name for s in cat]
    assert len(set(names)) == len(names)           # unique names
    kinds = [s.kind for s in cat]
    assert kinds.count("libc") >= 5                # section minimums (task spec)
    assert kinds.count("crypt") >= 3
    assert kinds.count("hash") >= 2
    for s in cat:
        assert s.kind in ("libc", "crypt", "hash")
        assert 0.0 <= s.confidence <= 1.0
        assert s.citation.startswith("http")       # every marker is cited
        assert callable(s.predicate)


def test_structural_signatures_returns_independent_copy():
    a = structural_signatures()
    a.clear()
    assert len(structural_signatures()) >= 10      # catalog itself is untouched
