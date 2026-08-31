"""Recursive-descent x64 disassembler with CFG + cross-reference recovery -- the
static-analysis counterpart to Aletheia's dynamic dump/unpack tools.

Feed it a dumped or unpacked image (see :mod:`aletheia.dump`) and it recovers
instructions, basic blocks, functions-by-reachability, and the call/jump graph.
Two decode strategies:

* **Linear sweep** (:func:`disassemble_linear`) -- decode a byte buffer straight
  through, advancing one byte past any undecodable position. Fast, complete, but
  blind to data-in-code.
* **Recursive descent** (:func:`disassemble_recursive`) -- start at the entry
  point(s) and *follow control flow*: direct calls/jmps/jccs to their targets plus
  the fallthrough, stopping a trace at ret, an undecodable byte, an unmapped
  address, or an already-visited address. This only decodes bytes the program can
  actually reach, so it does not mistake inlined data for code.

**Direct-branch targets (the load-bearing arithmetic).** A relative branch encodes
a displacement measured from the address of the *next* instruction (the END of the
branch), so ``target = insn.address + insn.size + rel``. Capstone already resolves
this into the operand's absolute immediate, and that is what we store in
``Instruction.target`` (``None`` for indirect branches like ``call rax`` /
``jmp [rip+x]`` and for non-branches). ``test_disasm`` pins the exact value on a
hand-assembled blob so an off-by-the-instruction-length error can't creep in.

**Dependency.** Uses `capstone` (the standard x86 decoder; hand-rolling one is out
of scope). It is imported lazily so ``import aletheia.disasm`` succeeds even where
capstone isn't installed -- a clear error is raised only when a decode function is
actually called.

House style mirrors :mod:`aletheia.dump` / :mod:`aletheia.imports`: pure functions
over a ``read_code(addr, size) -> bytes`` callable (empty/short bytes == unmapped),
so recursive descent runs against a synthetic address->bytes closure with no live
process, and :func:`disasm_pe` is the thin adapter that maps a real on-disk PE.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple, Union

try:                                # lazy + graceful: import must never hard-fail
    import capstone
except ImportError:                 # pragma: no cover - env-dependent
    capstone = None

ReadCode = Callable[[int, int], bytes]

# Arch-independent capstone instruction-group ids (stable across architectures;
# see capstone's CS_GRP_* -- mirrored here so the Instruction helpers don't need
# capstone imported to answer is_call/is_jmp/etc.).
_GRP_JUMP = 1
_GRP_CALL = 2
_GRP_RET = 3

_MAX_INSN_LEN = 15                  # longest legal x86/x64 instruction, in bytes


def _require_capstone():
    if capstone is None:            # pragma: no cover - env-dependent
        raise RuntimeError(
            "capstone is required for disassembly but is not installed; "
            "`pip install capstone` to use aletheia.disasm.")
    return capstone


def _mode(bits: int) -> int:
    cs = _require_capstone()
    if bits == 64:
        return cs.CS_MODE_64
    if bits == 32:
        return cs.CS_MODE_32
    if bits == 16:
        return cs.CS_MODE_16
    raise ValueError(f"unsupported bitness {bits!r} (want 16/32/64)")


def _new_md(bits: int):
    cs = _require_capstone()
    md = cs.Cs(cs.CS_ARCH_X86, _mode(bits))
    md.detail = True                # need operands + groups for target/classification
    return md


# ===========================================================================
# instruction model
# ===========================================================================
@dataclass
class Instruction:
    """A single decoded instruction.

    ``target`` is the absolute destination of a *direct* branch (call/jmp/jcc with
    an immediate operand), computed END-relative by capstone; ``None`` for indirect
    branches and non-branches. ``groups`` carries capstone's instruction-group ids,
    which back the classification helpers below."""
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes
    target: Optional[int] = None
    groups: Tuple[int, ...] = ()

    @property
    def is_call(self) -> bool:
        return _GRP_CALL in self.groups

    @property
    def is_ret(self) -> bool:
        return _GRP_RET in self.groups

    @property
    def is_jmp(self) -> bool:
        """Unconditional jump (no fallthrough)."""
        return _GRP_JUMP in self.groups and self.mnemonic == "jmp"

    @property
    def is_cond_jmp(self) -> bool:
        """Conditional branch -- jcc, and also loop/jrcxz (fallthrough + target)."""
        return _GRP_JUMP in self.groups and self.mnemonic != "jmp"

    @property
    def is_branch(self) -> bool:
        """A call or any jump (conditional or not)."""
        return self.is_call or (_GRP_JUMP in self.groups)

    @property
    def end(self) -> int:
        return self.address + self.size

    def __str__(self) -> str:
        s = f"{self.address:#x}: {self.mnemonic} {self.op_str}".rstrip()
        if self.target is not None:
            s += f"  ; -> {self.target:#x}"
        return s


def _make_instruction(insn) -> Instruction:
    """Wrap a capstone instruction, computing the direct-branch target."""
    groups = tuple(insn.groups) if insn.groups else ()
    target: Optional[int] = None
    if (_GRP_JUMP in groups or _GRP_CALL in groups) and insn.operands:
        op0 = insn.operands[0]
        if op0.type == capstone.x86.X86_OP_IMM:
            # capstone's immediate for a relative branch IS the absolute target
            # (address + size + displacement) -- END-relative, already resolved.
            target = op0.imm
    return Instruction(
        address=insn.address, size=insn.size, mnemonic=insn.mnemonic,
        op_str=insn.op_str, bytes=bytes(insn.bytes), target=target, groups=groups)


# ===========================================================================
# linear sweep
# ===========================================================================
def disassemble_linear(code: bytes, base: int, bits: int = 64) -> List[Instruction]:
    """Linear-sweep ``code`` as if mapped at virtual address ``base``.

    Decodes straight through; on an undecodable byte it advances a single byte and
    resumes (the classic linear-sweep recovery), so a data gap does not truncate
    everything after it."""
    md = _new_md(bits)
    out: List[Instruction] = []
    n = len(code)
    offset = 0
    while offset < n:
        produced = 0
        for insn in md.disasm(code[offset:], base + offset):
            out.append(_make_instruction(insn))
            produced += insn.size
        offset += produced if produced else 1
    return out


# ===========================================================================
# recursive descent
# ===========================================================================
def disassemble_recursive(read_code: ReadCode, entry_points: Iterable[int],
                          bits: int = 64,
                          max_insns: int = 200000) -> Dict[int, Instruction]:
    """Recursively descend from ``entry_points``, following reachable control flow.

    ``read_code(addr, size) -> bytes`` serves image bytes at an absolute address;
    empty or short bytes mean the address is unmapped and that trace stops. Each
    trace follows the fallthrough plus any direct branch target, and stops at a
    ret, an undecodable byte, an unmapped address, or an address already decoded.
    ``max_insns`` bounds runaway. Returns ``{address: Instruction}``."""
    md = _new_md(bits)
    visited: Dict[int, Instruction] = {}
    worklist: List[int] = [a for a in entry_points]

    while worklist:
        addr = worklist.pop()
        if addr in visited:
            continue
        if len(visited) >= max_insns:
            break
        try:
            data = read_code(addr, _MAX_INSN_LEN)
        except Exception:            # noqa: BLE001 - a failed read == unmapped
            continue
        if not data:                 # unmapped -> stop this trace
            continue
        try:
            insn = next(md.disasm(data, addr, count=1))
        except StopIteration:        # undecodable byte -> stop this trace
            continue
        ins = _make_instruction(insn)
        visited[addr] = ins

        if ins.is_ret:
            continue                 # end of trace, no successors
        # fallthrough: everything except an unconditional jump and a ret
        if not ins.is_jmp:
            worklist.append(ins.end)
        # branch target: direct call/jmp/jcc
        if ins.target is not None:
            worklist.append(ins.target)

    return visited


# ===========================================================================
# CFG reconstruction
# ===========================================================================
@dataclass
class BasicBlock:
    """A maximal straight-line run: entered only at ``start``, left only at ``end``.

    ``successors`` are the addresses control can flow to from the terminating
    instruction -- fallthrough and/or direct branch target -- restricted to blocks
    that actually exist in the input (external targets are dropped)."""
    start: int
    end: int
    instructions: List[Instruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)


InstrInput = Union[Dict[int, Instruction], List[Instruction]]


def _as_map(instrs: InstrInput) -> Dict[int, Instruction]:
    if isinstance(instrs, dict):
        return instrs
    return {i.address: i for i in instrs}


def build_cfg(instrs: InstrInput) -> List[BasicBlock]:
    """Partition ``instrs`` into basic blocks and wire successor edges.

    Leaders (block starts) are: the first instruction, every direct branch/call
    target present in the input, and the instruction after every jump/ret. A block
    also breaks on a non-contiguous address gap. ``call`` does NOT terminate a
    block (control returns to the fallthrough); its target is recorded as a
    cross-reference, not a CFG successor -- keeping this an intra-procedural graph.
    Blocks are returned sorted by start address."""
    by_addr = _as_map(instrs)
    if not by_addr:
        return []
    addrs = sorted(by_addr)

    leaders = {addrs[0]}
    for a in addrs:
        ins = by_addr[a]
        if ins.is_jmp or ins.is_cond_jmp:
            if ins.target in by_addr:
                leaders.add(ins.target)
            if ins.end in by_addr:            # instr after a jump is a leader
                leaders.add(ins.end)
        elif ins.is_ret:
            if ins.end in by_addr:            # instr after a ret is a leader
                leaders.add(ins.end)
        elif ins.is_call:
            if ins.target is not None and ins.target in by_addr:
                leaders.add(ins.target)       # a call target is a function entry

    blocks: List[BasicBlock] = []
    cur: List[Instruction] = []
    prev: Optional[Instruction] = None
    for a in addrs:
        ins = by_addr[a]
        gap = prev is not None and a != prev.end
        if cur and (a in leaders or gap):
            blocks.append(_finish_block(cur, by_addr))
            cur = []
        cur.append(ins)
        prev = ins
    if cur:
        blocks.append(_finish_block(cur, by_addr))
    return blocks


def _finish_block(insns: List[Instruction],
                  by_addr: Dict[int, Instruction]) -> BasicBlock:
    last = insns[-1]
    succ: List[int] = []
    if last.is_ret:
        pass                                   # no successors
    elif last.is_jmp:
        if last.target in by_addr:
            succ.append(last.target)
    elif last.is_cond_jmp:
        if last.target in by_addr:
            succ.append(last.target)           # taken branch
        if last.end in by_addr:
            succ.append(last.end)              # fallthrough
    else:                                      # normal or call: falls through
        if last.end in by_addr:
            succ.append(last.end)
    return BasicBlock(start=insns[0].address, end=last.end,
                      instructions=list(insns), successors=succ)


# ===========================================================================
# cross-references
# ===========================================================================
def compute_xrefs(instrs: InstrInput) -> Dict[int, List[int]]:
    """Map each direct branch/call target -> sorted list of source addresses."""
    by_addr = _as_map(instrs)
    xrefs: Dict[int, List[int]] = {}
    for ins in by_addr.values():
        if ins.is_branch and ins.target is not None:
            xrefs.setdefault(ins.target, []).append(ins.address)
    for srcs in xrefs.values():
        srcs.sort()
    return xrefs


# ===========================================================================
# PE convenience
# ===========================================================================
@dataclass
class DisasmResult:
    instructions: Dict[int, Instruction]
    blocks: List[BasicBlock]
    xrefs: Dict[int, List[int]]
    entry: int


def _bits_for(arch: str) -> int:
    if arch == "x64":
        return 64
    if arch == "x86":
        return 32
    raise ValueError(f"disasm_pe supports x86/x64, not {arch!r}")


def disasm_pe(path: str) -> DisasmResult:
    """Recursive-descent disassemble a PE from its entry point.

    Reads the on-disk file and maps *virtual* addresses back to file bytes: an
    address ``A`` is ``image_base + rva``, and ``rva`` is translated to a file
    offset through the section table (each section's ``raw_ptr``, bounded by its
    ``raw_size`` so we never read past a section's on-disk bytes into virtual-only
    padding). Descent starts at ``image_base + entry_rva`` and follows reachable
    control flow. Returns instructions + CFG + xrefs."""
    from aletheia import pe  # local import: keep module import capstone-only-lazy

    with open(path, "rb") as fh:
        data = fh.read()
    info = pe.parse_bytes(data)
    if not info.ok:
        raise ValueError(f"not a parseable PE: {info.error}")
    bits = _bits_for(info.arch)
    image_base = info.image_base
    sections = info.sections

    def read_code(addr: int, size: int) -> bytes:
        rva = addr - image_base
        if rva < 0:
            return b""
        for s in sections:
            if not s.raw_size or not s.contains_rva(rva):
                continue
            off_in_sec = rva - s.vaddr
            if off_in_sec >= s.raw_size:        # in virtual padding, no file bytes
                return b""
            avail = s.raw_size - off_in_sec
            start = s.raw_ptr + off_in_sec
            return data[start:start + min(size, avail)]
        return b""

    entry = image_base + info.entry_rva
    instrs = disassemble_recursive(read_code, [entry], bits=bits)
    blocks = build_cfg(instrs)
    xrefs = compute_xrefs(instrs)
    return DisasmResult(instructions=instrs, blocks=blocks, xrefs=xrefs, entry=entry)
