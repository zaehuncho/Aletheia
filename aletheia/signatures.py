"""Content signatures for Aletheia's triage layer: a YARA-style byte-pattern
scanner and a FLIRT-style library-function identifier (first cut).

Two complementary capabilities:

* **A. Content scanning** -- :class:`Pattern` / :class:`Rule` / :func:`scan` /
  :data:`DEFAULT_RULES` / :func:`scan_pe`. Rules are plain dataclasses (a full
  YARA text-grammar parser is deliberately out of scope); each pattern is a
  literal, a hex-with-wildcards byte pattern, or a raw ``re`` bytes regex, and a
  rule fires when its boolean condition over the pattern hits holds.
* **B. Function identification** -- :class:`FuncSignature` /
  :func:`identify_functions` / :func:`identify_in_pe`. **FIRST CUT, honestly
  scoped:** real IDA FLIRT is CRC16-over-function-bytes with relocation masking,
  a prefix tree, and collision-resolution tails, backed by giant per-compiler
  databases. What ships here is the *matching engine* -- wildcard-masked
  prologue patterns anchored at recovered function starts -- plus a tiny DEMO
  database proving the mechanism. It does NOT identify real libc/CRT functions;
  a production DB and a .sig/.pat importer are the follow-on.

**Positioning vs detect.py:** ``detect.py`` judges how the PE is *shaped*
(section names, entropy, R/W/X, import elision). This module judges what the
bytes *contain* (crypto constants, embedded executables, API-name strings,
known code sequences). Complementary; nothing here re-implements detect.py.

**The hex-wildcard compiler (the load-bearing bit).** A pattern like
``"48 8B ?? E8 ?? ?? ?? ??"`` compiles token-by-token to a bytes regex:

* ``AB`` (two hex digits)  -> that literal byte, ``re.escape``-d.
* ``??`` (or a lone ``?``) -> any byte: the class ``[\\x00-\\xff]`` -- an
  explicit class, never ``.``, so matching NEVER depends on ``re.DOTALL``
  (``.`` silently refuses 0x0A and that bug hides until a sample contains a
  newline byte).
* ``4?`` (high nibble fixed) -> the 16 byte values 0x40..0x4F are contiguous,
  so a range class ``[\\x40-\\x4f]`` (endpoints ``re.escape``-d).
* ``?B`` (low nibble fixed)  -> the 16 values 0x0B, 0x1B, .. 0xFB are NOT
  contiguous, so an enumerated class of all 16 escaped bytes.

Tokens are whitespace-separated; a run like ``"488B??"`` is also accepted and
split into byte pairs (odd-length runs are a :class:`ValueError` -- nibbles
must pair into bytes). ``re.escape`` on every literal/endpoint byte keeps regex
metacharacters (``]`` = 0x5D, ``-`` = 0x2D, ``*`` = 0x2A ...) inert.

House style: pure stdlib (``re``/``struct``), dataclasses, fails closed on
hostile *sample* input (malformed analyst-authored patterns raise early, at
construction), never runs the sample. ``identify_in_pe`` composes with
``disasm.py`` (capstone) via a lazy import so this module imports everywhere.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

ReadCode = Callable[[int, int], bytes]

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
# Fail-closed bound: a pathological pattern (e.g. "??") over a large file could
# emit millions of hit tuples; a rule's verdict never needs more than this many.
_MAX_HITS_PER_PATTERN = 4096


# ===========================================================================
# hex-with-wildcards -> bytes regex (the load-bearing compiler)
# ===========================================================================
def _hex_to_regex(spec: str) -> Tuple[bytes, int]:
    """Compile a hex-with-wildcards ``spec`` to ``(regex_bytes, byte_count)``.

    See the module docstring for the per-token translation. Raises
    :class:`ValueError` on an empty spec, an odd-length hex run, or any
    character outside ``[0-9a-fA-F? \\t]`` -- analyst patterns fail loudly at
    definition time, not silently at scan time."""
    tokens: List[str] = []
    for run in spec.split():
        if run == "?":                       # lone '?' == any byte, like '??'
            tokens.append("??")
            continue
        if len(run) % 2:
            raise ValueError(f"odd-length hex run {run!r} in {spec!r} "
                             "(nibbles must pair into bytes)")
        tokens.extend(run[i:i + 2] for i in range(0, len(run), 2))
    if not tokens:
        raise ValueError(f"empty hex pattern {spec!r}")

    out = bytearray()
    for tok in tokens:
        hi, lo = tok[0], tok[1]
        for ch in (hi, lo):
            if ch != "?" and ch not in _HEX_DIGITS:
                raise ValueError(f"bad hex token {tok!r} in {spec!r}")
        if hi == "?" and lo == "?":          # any byte -- explicit class,
            out += b"[\x00-\xff]"            # never '.', never DOTALL-dependent
        elif hi != "?" and lo != "?":        # fixed byte -- escaped literal
            out += re.escape(bytes([int(tok, 16)]))
        elif lo == "?":                      # '4?': 0x40..0x4F is contiguous
            base = int(hi, 16) << 4
            out += (b"[" + re.escape(bytes([base])) + b"-"
                    + re.escape(bytes([base | 0x0F])) + b"]")
        else:                                # '?B': 16 non-contiguous values
            low = int(lo, 16)
            out += (b"["
                    + b"".join(re.escape(bytes([(h << 4) | low]))
                               for h in range(16))
                    + b"]")
    return bytes(out), len(tokens)


# ===========================================================================
# A. YARA-style content rules
# ===========================================================================
@dataclass
class Pattern:
    """One named pattern inside a rule -- exactly one of ``text`` (literal,
    ``re.escape``-d so metacharacters are inert), ``hex`` (hex-with-wildcards,
    see module docstring), or ``regex`` (a raw ``re`` pattern over bytes,
    trusted as written) must be set. ``str`` inputs are encoded latin-1 (byte-
    transparent). Compiled once, at construction -- a malformed pattern raises
    :class:`ValueError` immediately."""
    id: str
    text: Optional[Union[str, bytes]] = None
    hex: Optional[str] = None
    regex: Optional[Union[str, bytes]] = None

    def __post_init__(self) -> None:
        set_fields = [f for f in ("text", "hex", "regex")
                      if getattr(self, f) is not None]
        if len(set_fields) != 1:
            raise ValueError(f"pattern {self.id!r}: exactly one of "
                             f"text/hex/regex required, got {set_fields}")
        if self.text is not None:
            lit = self.text.encode("latin-1") if isinstance(self.text, str) \
                else self.text
            if not lit:
                raise ValueError(f"pattern {self.id!r}: empty text")
            src = re.escape(lit)
        elif self.hex is not None:
            src, _ = _hex_to_regex(self.hex)
        else:
            src = self.regex.encode("latin-1") if isinstance(self.regex, str) \
                else self.regex
        try:
            self._compiled: "re.Pattern[bytes]" = re.compile(src)
        except re.error as exc:
            raise ValueError(f"pattern {self.id!r}: bad regex: {exc}") from exc

    def finditer(self, data: bytes) -> "Iterable[re.Match[bytes]]":
        return self._compiled.finditer(data)


@dataclass
class Rule:
    """A named set of patterns plus a boolean condition over which patterns
    hit: ``"any"`` (>= 1 pattern has a hit), ``"all"`` (every pattern does), or
    an int ``N`` (>= N distinct patterns do; validated 1 <= N <= len(patterns)
    so an unfireable rule is rejected at construction, not silently dead)."""
    name: str
    patterns: List[Pattern]
    condition: Union[str, int] = "any"
    tags: Tuple[str, ...] = ()
    meta: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.patterns:
            raise ValueError(f"rule {self.name!r}: no patterns")
        ids = [p.id for p in self.patterns]
        if len(set(ids)) != len(ids):
            raise ValueError(f"rule {self.name!r}: duplicate pattern ids")
        c = self.condition
        if isinstance(c, bool) or not (
                c in ("any", "all")
                or (isinstance(c, int) and 1 <= c <= len(self.patterns))):
            raise ValueError(f"rule {self.name!r}: bad condition {c!r} "
                             f"(want 'any', 'all', or 1..{len(self.patterns)})")

    def _satisfied(self, hit_count: int) -> bool:
        if self.condition == "any":
            return hit_count >= 1
        if self.condition == "all":
            return hit_count == len(self.patterns)
        return hit_count >= int(self.condition)


@dataclass
class Match:
    """One fired rule. ``strings`` holds every hit location of every pattern
    that matched: ``(pattern_id, offset, matched_bytes)``, offset-sorted.
    Matches within one pattern are non-overlapping (``finditer`` semantics)."""
    rule_name: str
    tags: Tuple[str, ...]
    strings: List[Tuple[str, int, bytes]]


def scan(data: bytes, rules: List[Rule]) -> List[Match]:
    """Run every rule over ``data``; return a :class:`Match` per fired rule, in
    rule order. Per-pattern hits are capped at ``_MAX_HITS_PER_PATTERN`` (the
    verdict is unaffected -- the condition only asks *whether* a pattern hit)."""
    out: List[Match] = []
    for rule in rules:
        strings: List[Tuple[str, int, bytes]] = []
        hit_patterns = 0
        for pat in rule.patterns:
            hits = 0
            for m in pat.finditer(data):
                strings.append((pat.id, m.start(), m.group()))
                hits += 1
                if hits >= _MAX_HITS_PER_PATTERN:
                    break
            if hits:
                hit_patterns += 1
        if rule._satisfied(hit_patterns):
            strings.sort(key=lambda s: (s[1], s[0]))
            out.append(Match(rule_name=rule.name, tags=rule.tags,
                             strings=strings))
    return out


# ---------------------------------------------------------------------------
# DEFAULT_RULES -- a small, curated, high-signal starter set. CONTENT rules
# only (section-name/shape heuristics live in detect.py). Illustrative, not
# exhaustive; every constant is real and cited.
# ---------------------------------------------------------------------------
DEFAULT_RULES: List[Rule] = [
    # Crypto constants -- tables/IVs the algorithms cannot run without, so
    # statically-linked crypto nearly always carries at least one verbatim.
    Rule(
        name="crypto-constants",
        tags=("crypto",),
        condition="any",
        meta={"note": "well-known algorithm constants embedded verbatim"},
        patterns=[
            # AES forward S-box, first 16 entries (FIPS-197 sec 5.1.1, the
            # SubBytes table): 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76.
            Pattern(id="$aes_sbox",
                    hex="63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76"),
            # MD5 init state A,B,C,D = 67452301 efcdab89 98badcfe 10325476
            # (RFC 1321 sec 3.3) as they sit in little-endian memory. SHA-1
            # shares H0..H3 (FIPS 180-4 sec 5.3.1), so this hits both.
            Pattern(id="$md5_sha1_init",
                    hex="01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10"),
            # SHA-256 round constants K[0..3] = 428a2f98 71374491 b5c0fbcf
            # e9b5dba5 (FIPS 180-4 sec 4.2.2), as a uint32 array in LE memory
            # (x86) and as raw BE words (byte-oriented implementations).
            Pattern(id="$sha256_k_le",
                    hex="98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9"),
            Pattern(id="$sha256_k_be",
                    hex="42 8A 2F 98 71 37 44 91 B5 C0 FB CF E9 B5 DB A5"),
        ],
    ),
    # Embedded PE -- an MZ header at a NONZERO offset with a PE\0\0 signature
    # a plausible e_lfanew away: the classic dropper/self-extractor payload
    # tell. Anatomy of the regex, left to right:
    #   (?<=[\x00-\xff])       one byte must precede -> the host's own header
    #                          at offset 0 can never fire this rule;
    #   MZ [\x00-\xff]{60}     a full 64-byte DOS header (2 magic + 60 body
    #   \x00\x00               + e_lfanew's HIGH WORD at +0x3E..0x3F, which a
    #                          real header always has zero -- e_lfanew < 64KB
    #                          in practice; this anchor is what stops stray
    #                          "MZ" bytes in code from matching);
    #   [\x00-\xff]{0,1984}?   the DOS stub / Rich header gap, lazily, capped
    #                          so the PE sig sits within 2KB of the MZ;
    #   PE\x00\x00             the embedded image's own PE signature.
    # HEURISTIC, stated plainly: a regex cannot DEREFERENCE e_lfanew, so a
    # zero-word + PE\0\0 coincidence within 2KB of a stray 4D 5A still false-
    # positives (measured: 0 on cmd.exe/notepad.exe, 4 on the 3.4MB
    # explorer.exe), and an encrypted/compressed payload is a miss. The honest
    # confirmation is pe.parse_bytes on the bytes at each reported offset.
    Rule(
        name="embedded-pe",
        tags=("dropper",),
        condition="any",
        meta={"note": "MZ..PE\\0\\0 at nonzero offset -- embedded executable"},
        patterns=[
            Pattern(id="$mz_pe",
                    regex=rb"(?<=[\x00-\xff])MZ[\x00-\xff]{60}\x00\x00"
                          rb"[\x00-\xff]{0,1984}?PE\x00\x00"),
        ],
    ),
    # Suspicious API names -- INFORMATIONAL. These appear in import tables of
    # plenty of legitimate binaries (the CRT itself references
    # IsDebuggerPresent); the signal is for a human reading the triage output,
    # and it degrades to silence when a packer elides/obfuscates imports.
    Rule(
        name="suspicious-imports",
        tags=("info", "apis"),
        condition="any",
        meta={"note": "API name strings common in injection/anti-debug code; "
                      "informational -- ubiquitous in legit binaries too"},
        patterns=[
            Pattern(id="$virtualalloc", text="VirtualAlloc"),
            Pattern(id="$writeprocmem", text="WriteProcessMemory"),
            Pattern(id="$isdebugger", text="IsDebuggerPresent"),
            Pattern(id="$loadlibrarya", text="LoadLibraryA"),
        ],
    ),
]


def scan_pe(path: str, extra_rules: Optional[List[Rule]] = None) -> List[Match]:
    """Read the file at ``path`` and :func:`scan` it with :data:`DEFAULT_RULES`
    plus any ``extra_rules``. Content scanning needs no valid PE structure, so
    a non-PE still scans (the name marks intent, not a precondition). An
    unreadable path raises :class:`OSError` -- that's a caller/environment
    error, not hostile sample input, and a silent ``[]`` would forge a "clean"
    verdict."""
    with open(path, "rb") as fh:
        data = fh.read()
    return scan(data, DEFAULT_RULES + list(extra_rules or []))


# ===========================================================================
# B. FLIRT-style function identification -- FIRST CUT
# ===========================================================================
@dataclass
class FuncSignature:
    """A wildcard-masked byte pattern for a function's opening bytes, with the
    wildcards covering relocation/immediate bytes (a rel32 call displacement,
    a cookie address...) that differ per binary.

    ``length`` is the function's declared full byte length -- METADATA reserved
    for the follow-on CRC-tail stage that real FLIRT uses to split collisions;
    the first-cut matcher matches on ``pattern`` alone. ``nbytes`` is how many
    opening bytes the pattern constrains."""
    name: str
    pattern: str
    length: Optional[int] = None

    def __post_init__(self) -> None:
        src, self.nbytes = _hex_to_regex(self.pattern)
        self._compiled: "re.Pattern[bytes]" = re.compile(src)

    def matches_start(self, code: bytes) -> bool:
        """Anchored match against the function's opening bytes; fewer bytes
        than the pattern constrains == unmapped/truncated == no match."""
        return len(code) >= self.nbytes and self._compiled.match(code) is not None


# A TINY demo database so the mechanism is exercised end-to-end. These are
# generic compiler idioms, deliberately named demo_* -- they prove the matcher
# works, they do NOT identify real library functions. A production DB (and a
# .sig/.pat importer) is the documented follow-on.
DEMO_SIGDB: List[FuncSignature] = [
    # push rbp; mov rbp, rsp -- the classic frame-pointer prologue.
    FuncSignature(name="demo_frame_prologue", pattern="55 48 89 E5"),
    # sub rsp, imm8; call rel32 -- shadow-space reserve then a call whose
    # 4 displacement bytes are relocation-dependent, hence wildcarded: the
    # exact masking real FLIRT does over relocated bytes.
    FuncSignature(name="demo_shadow_call", pattern="48 83 EC ?? E8 ?? ?? ?? ??"),
]


def identify_functions(read_code: ReadCode, func_starts: Iterable[int],
                       sigdb: List[FuncSignature]) -> Dict[int, str]:
    """Match each function start against ``sigdb``; first match wins (DB order
    is priority order). ``read_code(addr, size) -> bytes`` serves image bytes
    (short/empty == unmapped -- that start silently doesn't match: fail
    closed). Returns ``{addr: name}`` for identified starts only."""
    if not sigdb:
        return {}
    max_bytes = max(sig.nbytes for sig in sigdb)
    out: Dict[int, str] = {}
    for addr in sorted(set(func_starts)):
        try:
            code = read_code(addr, max_bytes)
        except Exception:            # noqa: BLE001 - failed read == unmapped
            continue
        for sig in sigdb:
            if sig.matches_start(code):
                out[addr] = sig.name
                break
    return out


def identify_in_pe(path: str, sigdb: List[FuncSignature]) -> Dict[int, str]:
    """Recover function starts from a PE via :func:`aletheia.disasm.disasm_pe`
    (the entry point plus every direct call target) and run
    :func:`identify_functions` over them. Requires capstone (imported lazily
    inside disasm, so this module itself imports everywhere).

    The virtual-address -> file-bytes reader mirrors ``disasm_pe``'s internal
    one (which it does not export); a small deliberate duplication, same as
    ``extract.py``'s data-directory reader, so ``disasm.py`` stays untouched."""
    from aletheia import pe as pe_mod
    from aletheia.disasm import disasm_pe

    result = disasm_pe(path)
    starts = {result.entry}
    starts.update(ins.target for ins in result.instructions.values()
                  if ins.is_call and ins.target is not None)

    with open(path, "rb") as fh:
        data = fh.read()
    info = pe_mod.parse_bytes(data)
    if not info.ok:
        raise ValueError(f"not a parseable PE: {info.error}")
    image_base, sections = info.image_base, info.sections

    def read_code(addr: int, size: int) -> bytes:
        rva = addr - image_base
        if rva < 0:
            return b""
        for s in sections:
            if not s.raw_size or not s.contains_rva(rva):
                continue
            off_in_sec = rva - s.vaddr
            if off_in_sec >= s.raw_size:      # virtual-only padding: no bytes
                return b""
            start = s.raw_ptr + off_in_sec
            return data[start:start + min(size, s.raw_size - off_in_sec)]
        return b""

    return identify_functions(read_code, starts, sigdb)


# ===========================================================================
# C. Structural function classification -- FLIRT-style ID over IR SHAPE
# ===========================================================================
# A third, independent tier. Where B (:class:`FuncSignature`) matches a
# function's *opening bytes*, this tier matches the *structure* of its lifted
# SSA IR: op counts, loop shape, and distinctive magic constants that a
# primitive cannot compute without. That makes it robust to the two things
# byte-signatures die on -- a stripped binary (no symbols) and a recompile that
# reshuffles the exact instruction bytes -- because the SSA shape and the
# algorithm constants survive both. It is the antithesis-side dual of what
# real FLIRT does (CRC16 over relocated bytes); here we fingerprint IR shape.
#
# HONESTY, up front (see per-signature notes + the module tests):
#   * Constant-based crypto/hash predicates are STRONG but not proofs: any
#     function that embeds one of these magic words for an unrelated reason
#     (a copied lookup table, a hard-coded test vector, a hash-of-a-hash) will
#     false-match. The predicate answers "this constant is present", which is
#     evidence, not a QED.
#   * Shape-based libc predicates are HEURISTICS: a hand-rolled struct copy is
#     structurally a ``memcpy``; a scan-for-terminator loop is a ``strlen``.
#     We report the shape, honestly labelled, at a lower confidence.
#   * These run on the lifter's bounded-op IR (:mod:`aletheia.ir`), pre- OR
#     post-SSA. Every predicate compares names through
#     :func:`aletheia.dataflow.ssa_base_name`, so ``rcx`` and ``rcx#4`` are the
#     same variable to it -- feed it either shape.
#
# aletheia.ir imports capstone lazily, so importing it here keeps signatures.py
# importable without capstone, exactly like the rest of this module.
from aletheia.ir import IRFunction, Op, Value, VTag   # noqa: E402
from aletheia.dataflow import ssa_base_name                    # noqa: E402


@dataclass
class StructuralSignature:
    """A structural pattern that identifies a well-known primitive by IR shape,
    not by byte pattern. ``name`` is what to label a matching function.

    ``predicate`` is a pure ``IRFunction -> bool`` test (it must not mutate the
    function). ``confidence`` is a self-assessed 0.0-1.0 -- constant-bearing
    crypto/hash signatures score high (a 32-bit magic word is distinctive),
    loop-shape libc signatures score lower (a shape is suggestive, not unique).
    ``citation`` documents the marker with a public URL."""
    name: str                     # e.g. "memcpy", "aes_round", "sha256_compression"
    kind: str                     # "libc" | "crypt" | "hash"
    predicate: Callable[["IRFunction"], bool]
    confidence: float             # 0.0-1.0; how sure we are on a match
    citation: str                 # URL / RFC / paper documenting the pattern

    def __post_init__(self) -> None:
        if self.kind not in ("libc", "crypt", "hash"):
            raise ValueError(f"signature {self.name!r}: bad kind {self.kind!r}")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"signature {self.name!r}: confidence out of range")
        if not callable(self.predicate):
            raise ValueError(f"signature {self.name!r}: predicate not callable")


# ---------------------------------------------------------------------------
# magic-constant catalogs (every value cited at its signature below)
# ---------------------------------------------------------------------------
_MASK64 = (1 << 64) - 1

# SHA-256 round constants K[0..] -- the first alone is a fingerprint (FIPS 180-4
# sec 4.2.2). https://en.wikipedia.org/wiki/SHA-2
_SHA256_K = frozenset({0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                       0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5})

# SHA-1 markers. NB: the init words H0..H3 (0x67452301, 0xefcdab89, 0x98badcfe,
# 0x10325476) are shared VERBATIM with MD5, so keying on them would confuse the
# two. We key ONLY on values unique to SHA-1: H4 = 0xc3d2e1f0 and the four round
# constants K0..K3. (FIPS 180-4 sec 5.3.1 / sec 6.1.2.)
# https://en.wikipedia.org/wiki/SHA-1
_SHA1_MARKERS = frozenset({0xc3d2e1f0,
                           0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6})

# MD5 T-table T[1..] = floor(2^32 * abs(sin(i))) -- unique to MD5 (RFC 1321
# sec 3.4). https://datatracker.ietf.org/doc/html/rfc1321
_MD5_T = frozenset({0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501})

# AES forward S-box, first four bytes 63 7C 77 7B packed as a 32-bit word, both
# byte orders (FIPS-197 sec 5.1.1). https://en.wikipedia.org/wiki/Rijndael_S-box
_AES_SBOX_WORD = frozenset({0x637c777b, 0x7b777c63})

# CRC-32 polynomials: the reversed IEEE poly 0xEDB88320 (used by zlib/PNG, the
# usual embedded form) and the normal-order 0x04C11DB7.
# https://en.wikipedia.org/wiki/Cyclic_redundancy_check
_CRC32_POLY = frozenset({0xedb88320, 0x04c11db7})

# FNV: the 32/64-bit primes and offset bases (FNV-1/1a).
# https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
_FNV_MARKERS = frozenset({0x01000193, 0x100000001b3,          # primes 32 / 64
                          0x811c9dc5, 0xcbf29ce484222325})     # offset basis 32 / 64

# ChaCha quarter-round rotation amounts, as a rotate-LEFT impl (16,12,8,7) and
# as the equivalent rotate-RIGHT impl (32 minus each). (RFC 8439 sec 2.1.)
# https://datatracker.ietf.org/doc/html/rfc8439#section-2.1
_CHACHA_ROTL = frozenset({16, 12, 8, 7})
_CHACHA_ROTR = frozenset({16, 20, 24, 25})


# ---------------------------------------------------------------------------
# IR-walking helpers (all tolerate pre- or post-SSA IR)
# ---------------------------------------------------------------------------
def _iter_insns(func: "IRFunction"):
    """Every IRInsn in the function, block order-independent."""
    for blk in func.blocks.values():
        for insn in blk.insns:
            yield insn


def _imm_leaves(v: Optional[Value]):
    """Yield the concrete integers a Value contributes: an IMM's ``imm``, plus a
    memory operand's absolute displacement (a hard-coded table/address). Recurses
    through MEM base/index."""
    if v is None:
        return
    if v.tag == VTag.IMM:
        yield v.imm
    elif v.tag == VTag.MEM:
        if v.disp:
            yield v.disp
        yield from _imm_leaves(v.base)
        yield from _imm_leaves(v.index)


def _iter_imms(func: "IRFunction"):
    for insn in _iter_insns(func):
        for v in (insn.dst,) + tuple(insn.args):
            yield from _imm_leaves(v)


def _norm_targets(values) -> Set[int]:
    """Expand each wanted value to its 64-bit and low-32-bit forms so a match is
    width-agnostic (a 32-bit magic sign-extended into a 64-bit immediate, or
    truncated, still hits)."""
    out: Set[int] = set()
    for v in values:
        out.add(v & _MASK64)
        out.add(v & 0xFFFFFFFF)
    return out


def _has_immediate(func: "IRFunction", values: Set[int]) -> bool:
    """True if any IMM Value (or MEM displacement) in ``func`` equals one of the
    given ints, compared at any width (see :func:`_norm_targets`). The single
    strongest marker for the crypto/hash primitives -- an algorithm constant the
    code cannot run without."""
    targets = _norm_targets(values)
    for imm in _iter_imms(func):
        if (imm & _MASK64) in targets or (imm & 0xFFFFFFFF) in targets:
            return True
    return False


def _has_op(func: "IRFunction", ops: Set["Op"]) -> bool:
    for insn in _iter_insns(func):
        if insn.op in ops:
            return True
    return False


def _count_op(func: "IRFunction", op: "Op") -> int:
    return sum(1 for insn in _iter_insns(func) if insn.op == op)


def _rotation_amounts(func: "IRFunction") -> Set[int]:
    """The set of immediate rotate counts (mod 64) used by ROL/ROR ops."""
    out: Set[int] = set()
    for insn in _iter_insns(func):
        if insn.op in (Op.ROL, Op.ROR):
            for a in insn.args:
                if a.tag == VTag.IMM:
                    out.add(a.imm & 63)
    return out


def _has_aesni(func: "IRFunction") -> bool:
    """True if the function carries an AES-NI intrinsic. The lifter does not model
    AESENC/AESDEC/AESKEYGENASSIST/AESIMC -- it drops them to ``UNDEF`` with the
    mnemonic in ``text`` -- so we look for an UNDEF whose mnemonic starts 'aes'."""
    for insn in _iter_insns(func):
        if insn.op == Op.UNDEF and insn.text:
            if insn.text.split()[0].lower().startswith("aes"):
                return True
    return False


# ---- loop-shape analysis (the libc-family backbone) ------------------------
def _back_edges(func: "IRFunction") -> List[Tuple[int, int]]:
    """CFG back-edges ``(tail, header)`` -- an edge whose target dominates its
    source (a self-loop ``b -> b`` counts). Uses the dominator tree from
    :mod:`aletheia.dataflow`; returns ``[]`` when the entry is unreachable / the
    function has no CFG to speak of."""
    try:
        from aletheia.dataflow import dominators
        idom = dominators(func)
    except Exception:                    # noqa: BLE001 - never crash a scan
        return []
    if not idom:
        return []

    def dominates(a: int, b: int) -> bool:
        x = b
        while True:
            if x == a:
                return True
            nxt = idom.get(x)
            if nxt is None or nxt == x:   # reached the entry's self-idom
                return False
            x = nxt

    edges: List[Tuple[int, int]] = []
    for b in idom:
        for s in func.blocks[b].succs:
            if s in idom and dominates(s, b):
                edges.append((b, s))
    return edges


def _natural_loop_blocks(func: "IRFunction", tail: int, header: int) -> Set[int]:
    """The natural loop of back-edge ``tail -> header``: the header plus every
    block that can reach the tail without passing through the header."""
    preds: Dict[int, List[int]] = {b: [] for b in func.blocks}
    for b in func.blocks:
        for s in func.blocks[b].succs:
            if s in preds:
                preds[s].append(b)
    loop = {header}
    stack: List[int] = []
    if tail != header:
        loop.add(tail)
        stack.append(tail)
    while stack:
        n = stack.pop()
        for p in preds[n]:
            if p not in loop:
                loop.add(p)
                stack.append(p)
    return loop


@dataclass
class _LoopFacts:
    """A compact structural summary of a function's single loop body."""
    n_load: int
    n_store: int
    zero_test_on_loaded: bool     # a loaded value compared against 0 (string end)
    compare_of_two_loaded: bool   # two loaded values compared (memcmp/strcmp)
    pointer_compare: bool         # two pointer registers compared (overlap check)


def _mem_base_names(v: Optional[Value], out: Set[str]) -> None:
    """Collect the base-register names of any MEM operand (the pointer through
    which the access happens). Index regs are excluded on purpose -- an overlap
    check compares the base pointers, not the running index."""
    if v is None or v.tag != VTag.MEM:
        return
    if v.base is not None and v.base.tag in (VTag.REG, VTag.TEMP) and v.base.name:
        out.add(ssa_base_name(v.base))


def _loop_facts(func: "IRFunction") -> Optional["_LoopFacts"]:
    """Summarise the function's loop, or None if it does not have exactly one
    (natural) loop. All the libc-family shape predicates gate on this: no single
    loop, no simple mem/str primitive (fail closed)."""
    edges = _back_edges(func)
    if len(edges) != 1:
        return None
    tail, header = edges[0]
    body = _natural_loop_blocks(func, tail, header)
    insns = [i for b in body for i in func.blocks[b].insns]

    loaded: Set[str] = set()
    mem_bases: Set[str] = set()
    n_load = n_store = 0
    for insn in insns:
        if insn.op == Op.LOAD:
            n_load += 1
            if insn.dst is not None:
                nm = ssa_base_name(insn.dst)
                if nm:
                    loaded.add(nm)
        elif insn.op == Op.STORE:
            n_store += 1
        for v in (insn.dst,) + tuple(insn.args):
            _mem_base_names(v, mem_bases)

    zero_loaded = two_loaded = ptr_cmp = False
    for insn in insns:
        if insn.op not in (Op.CMP, Op.TEST) or len(insn.args) < 2:
            continue
        a, b = insn.args[0], insn.args[1]
        na, nb = ssa_base_name(a), ssa_base_name(b)
        a_reg = a.tag in (VTag.REG, VTag.TEMP)
        b_reg = b.tag in (VTag.REG, VTag.TEMP)
        a_imm0 = a.tag == VTag.IMM and a.imm == 0
        b_imm0 = b.tag == VTag.IMM and b.imm == 0
        if insn.op == Op.CMP and ((na in loaded and b_imm0)
                                  or (nb in loaded and a_imm0)):
            zero_loaded = True
        if insn.op == Op.TEST and a_reg and na == nb and na in loaded:
            zero_loaded = True                       # test r,r ; jz  == (r == 0)
        if a_reg and b_reg and na != nb:
            if na in loaded and nb in loaded:
                two_loaded = True
            if na in mem_bases and nb in mem_bases:
                ptr_cmp = True
    return _LoopFacts(n_load, n_store, zero_loaded, two_loaded, ptr_cmp)


# ---------------------------------------------------------------------------
# the predicates (named, so their intent + a match are both inspectable)
# ---------------------------------------------------------------------------
# -- crypto / hash: distinctive embedded constants ----
def _pred_aes_round(func: "IRFunction") -> bool:
    # The S-box first-word is extremely distinctive; the AES-NI intrinsic is
    # unambiguous. We deliberately do NOT match on rcon (0x01,0x02,0x04,...)
    # alone: those are plain powers of two and would false-match everything.
    return _has_immediate(func, _AES_SBOX_WORD) or _has_aesni(func)


def _pred_chacha_qround(func: "IRFunction") -> bool:
    # 4+ XORs and the signature rotation-amount set (rotl 16/12/8/7, or the
    # rotr-encoded equivalent). Very hard to hit by accident.
    if _count_op(func, Op.XOR) < 4:
        return False
    rots = _rotation_amounts(func)
    return _CHACHA_ROTL <= rots or _CHACHA_ROTR <= rots


def _pred_sha256(func: "IRFunction") -> bool:
    return _has_immediate(func, _SHA256_K)


def _pred_sha1(func: "IRFunction") -> bool:
    return _has_immediate(func, _SHA1_MARKERS)


def _pred_md5(func: "IRFunction") -> bool:
    return _has_immediate(func, _MD5_T)


def _pred_crc32(func: "IRFunction") -> bool:
    # poly + the XOR-then-shift kernel; the poly alone would be a weaker signal.
    return (_has_immediate(func, _CRC32_POLY)
            and _has_op(func, {Op.XOR})
            and _has_op(func, {Op.SHR, Op.SHL}))


def _pred_fnv(func: "IRFunction") -> bool:
    # an FNV prime/basis together with the XOR that defines FNV-1a's mix.
    return _has_immediate(func, _FNV_MARKERS) and _has_op(func, {Op.XOR})


# -- libc: loop shape ----
def _pred_memmove(func: "IRFunction") -> bool:
    f = _loop_facts(func)
    return bool(f and f.n_load >= 1 and f.n_store >= 1 and f.pointer_compare)


def _pred_strcpy(func: "IRFunction") -> bool:
    f = _loop_facts(func)
    return bool(f and f.n_load >= 1 and f.n_store >= 1 and f.zero_test_on_loaded)


def _pred_memcmp(func: "IRFunction") -> bool:
    f = _loop_facts(func)
    return bool(f and f.n_load >= 2 and f.n_store == 0 and f.compare_of_two_loaded)


def _pred_strlen(func: "IRFunction") -> bool:
    f = _loop_facts(func)
    return bool(f and f.n_load >= 1 and f.n_store == 0 and f.zero_test_on_loaded)


def _pred_memcpy(func: "IRFunction") -> bool:
    f = _loop_facts(func)
    return bool(f and f.n_load >= 1 and f.n_store >= 1)


def _pred_memset(func: "IRFunction") -> bool:
    f = _loop_facts(func)
    return bool(f and f.n_store >= 1)


# ---------------------------------------------------------------------------
# the shipped catalog -- ORDER IS DETECTION PREFERENCE (specific -> generic)
# ---------------------------------------------------------------------------
# Constant-bearing crypto/hash signatures come FIRST: a distinctive magic word
# is a far more specific match than a loop shape, and (crucially) a real
# SHA-256 or AES round is itself a load/store loop -- if the fuzzy libc shapes
# ran first, such a function would be mislabelled "memcpy" before its S-box or
# K-constant was ever consulted. Constants win; shapes are the fallback.
_STRUCTURAL_SIGNATURES: List[StructuralSignature] = [
    # -- crypto (kind="crypt") --
    StructuralSignature(
        name="aes_round", kind="crypt", predicate=_pred_aes_round,
        confidence=0.90,
        citation="https://en.wikipedia.org/wiki/Rijndael_S-box"),
    StructuralSignature(
        name="chacha_quarter_round", kind="crypt", predicate=_pred_chacha_qround,
        confidence=0.95,
        citation="https://datatracker.ietf.org/doc/html/rfc8439#section-2.1"),
    StructuralSignature(
        name="sha256_compression", kind="crypt", predicate=_pred_sha256,
        confidence=0.95,
        citation="https://en.wikipedia.org/wiki/SHA-2"),
    StructuralSignature(
        name="sha1_compression", kind="crypt", predicate=_pred_sha1,
        confidence=0.90,
        citation="https://en.wikipedia.org/wiki/SHA-1"),
    # -- hashing / others (kind="hash") --
    StructuralSignature(
        name="md5_compression", kind="hash", predicate=_pred_md5,
        confidence=0.95,
        citation="https://datatracker.ietf.org/doc/html/rfc1321"),
    StructuralSignature(
        name="crc32", kind="hash", predicate=_pred_crc32,
        confidence=0.80,
        citation="https://en.wikipedia.org/wiki/Cyclic_redundancy_check"),
    StructuralSignature(
        name="fnv_hash", kind="hash", predicate=_pred_fnv,
        confidence=0.75,
        citation="https://en.wikipedia.org/wiki/"
                 "Fowler%E2%80%93Noll%E2%80%93Vo_hash_function"),
    # -- libc (kind="libc"); shape heuristics, more specific -> more generic --
    StructuralSignature(
        name="memmove", kind="libc", predicate=_pred_memmove,
        confidence=0.55,
        citation="https://en.cppreference.com/w/c/string/byte/memmove"),
    StructuralSignature(
        name="strcpy", kind="libc", predicate=_pred_strcpy,
        confidence=0.60,
        citation="https://en.cppreference.com/w/c/string/byte/strcpy"),
    StructuralSignature(
        name="memcmp", kind="libc", predicate=_pred_memcmp,
        confidence=0.60,
        citation="https://en.cppreference.com/w/c/string/byte/memcmp"),
    StructuralSignature(
        name="strlen", kind="libc", predicate=_pred_strlen,
        confidence=0.65,
        citation="https://en.cppreference.com/w/c/string/byte/strlen"),
    StructuralSignature(
        name="memcpy", kind="libc", predicate=_pred_memcpy,
        confidence=0.55,
        citation="https://en.cppreference.com/w/c/string/byte/memcpy"),
    StructuralSignature(
        name="memset", kind="libc", predicate=_pred_memset,
        confidence=0.50,
        citation="https://en.cppreference.com/w/c/string/byte/memset"),
]


def structural_signatures() -> List[StructuralSignature]:
    """The shipped catalog. Order = detection preference (specific -> generic):
    constant-bearing crypto/hash signatures first, loop-shape libc signatures
    last. A fresh list is returned so callers can reorder/extend without
    mutating the module's catalog."""
    return list(_STRUCTURAL_SIGNATURES)


def classify_by_structure(func: "IRFunction") -> Optional[StructuralSignature]:
    """Run each structural signature in catalog order; return the FIRST match, or
    None. ``func`` may be pre- or post-SSA (predicates normalise names through
    :func:`aletheia.dataflow.ssa_base_name`). A predicate that raises on a
    malformed function is treated as a non-match -- one bad function never aborts
    a whole-image sweep (house style: fail closed, never crash the analysis)."""
    for sig in _STRUCTURAL_SIGNATURES:
        try:
            if sig.predicate(func):
                return sig
        except Exception:                # noqa: BLE001 - a predicate must not crash a scan
            continue
    return None


def classify_functions_by_structure(
        funcs: List["IRFunction"]) -> Dict[int, StructuralSignature]:
    """Batch :func:`classify_by_structure` over ``funcs``; return
    ``{IRFunction.start: StructuralSignature}`` for the matched functions only
    (unmatched functions are simply absent)."""
    out: Dict[int, StructuralSignature] = {}
    for func in funcs:
        sig = classify_by_structure(func)
        if sig is not None:
            out[func.start] = sig
    return out
