"""x64 instruction -> intermediate representation (IR) lifter.

A downstream decompilation / data-flow pass wants something far more regular than
raw x86: a small, **bounded** set of operations where every side effect is
*explicit*. No implicit ``RFLAGS`` update buried inside ``add``; no implicit
memory dereference hidden inside ``mov``; no register aliasing left for the reader
to remember. This module is that translator -- the static-analysis sibling of
Ghidra's P-Code or Binary Ninja's LLIL.

Each decoded x64 instruction (an :class:`aletheia.disasm.Instruction`) lifts to
**one or more** :class:`IRInsn` ops. Registers, memory locations, immediates and
flags are all uniform :class:`Value` nodes, so a later SSA pass can rename them
mechanically.

--------------------------------------------------------------------------------
Design commitments (all of these are load-bearing for the SSA pass that follows)
--------------------------------------------------------------------------------
* **At most one ``dst`` per op.** An instruction that writes two locations (``push``
  writes ``rsp`` *and* memory; a full-width ``mul`` writes ``rdx:rax``) expands to
  several ops, each with a single destination.
* **Flag writes are explicit.** Arithmetic/logic ops are followed by ``SETFLAG``
  ops, one per affected flag, whose ``dst`` is the ``FLAG`` value written.
* **Reads are explicit.** ``add rax, rbx`` lifts to ``ADD dst=rax, args=(rax, rbx)``
  -- the read of ``rax`` appears as an operand, not an implicit source.
* **Memory access is never implicit.** A memory *source* is pulled into a ``TEMP``
  with a ``LOAD`` first; a memory *destination* is written with a ``STORE`` last.
  The one exception is ``lea``, which computes an *address*: it lifts to a single
  ``ASSIGN`` whose source is a ``MEM`` value used **without** a ``LOAD`` -- i.e. a
  ``MEM`` node appearing directly as an ``ASSIGN`` source denotes the effective
  address, not the contents.

--------------------------------------------------------------------------------
Operand parsing: capstone re-decode (NOT ``op_str`` string parsing)
--------------------------------------------------------------------------------
The :class:`~aletheia.disasm.Instruction` we are handed carries the raw ``bytes``
and its ``address``. To read operands *structurally* we re-decode those bytes with
capstone (``detail=True``) and walk ``cins.operands`` -- reading ``op.type`` /
``op.reg`` / ``op.imm`` / ``op.mem`` directly. We never parse the capstone-formatted
``op_str`` text. Sub-registers are canonicalised: ``al`` / ``ax`` / ``eax`` / ``rax``
all resolve to the 64-bit GPR name ``"rax"`` with the *access width* carried in
``Value.size`` (bits). capstone is imported lazily (same pattern as
:mod:`aletheia.disasm`): importing this module never hard-fails; a clear error is
raised only when :func:`lift_instruction` is actually called without capstone.

--------------------------------------------------------------------------------
Honest scope + simplifications (do not mistake these for full coverage)
--------------------------------------------------------------------------------
* **Flag *values* are modelled opaquely.** A ``SETFLAG`` records *which* flag is
  written and *which operands it depends on* (its ``args``) -- it does NOT encode
  the exact boolean formula. ``SETFLAG dst=OF, args=(a, b)`` after a ``sub`` means
  "OF is some function of ``a`` and ``b``"; it does not spell out the signed-overflow
  computation. Downstream data-flow folds these symbolically. Logical ops (``and`` /
  ``or`` / ``xor`` / ``test``) architecturally *clear* CF and OF and leave AF
  undefined; we emit ``SETFLAG`` for CF/OF (value symbolic, not pinned to 0) and
  omit AF. ``div`` / ``idiv`` leave all flags undefined, so we emit no ``SETFLAG``.
* **Sub-register writes are widened to the parent GPR.** ``mov al, 1`` lifts with
  ``dst`` name ``"rax"`` size 8 -- the partial-write semantics (that the upper 56
  bits of RAX are preserved) are left for the SSA pass to model. The high-byte
  registers ``ah`` / ``bh`` / ``ch`` / ``dh`` are folded onto ``rax`` / ``rbx`` /
  ``rcx`` / ``rdx`` (size 8); their high-byte *offset* is not represented -- a
  stated simplification.
* **``adc`` / ``sbb``** reuse the ``ADD`` / ``SUB`` ops with an explicit ``CF``
  read appended to ``args`` (there is no dedicated ADC/SBB op).
* **Full-width ``mul`` / ``imul`` / ``div`` / ``idiv``** expand to two ops writing
  ``rax`` (low / quotient) and ``rdx`` (high / remainder); the two ops share the
  same symbolic ``args`` and are told apart by their ``dst``. The 8-bit forms
  (which use ``ax`` / ``al`` / ``ah``) are approximated by the same rax/rdx shape.
* **String ops** (``movs`` / ``stos`` / ``lods`` / ``cmps`` / ``scas``) are a
  documented gap -- lifted as ``UNDEF``.  # TODO: string ops (rep-loop expansion)
* **FPU / MMX / SSE / AVX (incl. VEX-prefixed), x87 stack, and rare privileged
  ops** (``wbinvd`` / ``invd`` / ``invlpg`` / ``cpuid`` / ``rdtsc`` / ``cdq`` / ...)
  are lifted as ``UNDEF`` carrying the mnemonic+operands in ``text``. This is scope
  management, not a claim of coverage; downstream passes tolerate ``UNDEF``.

SSA construction is explicitly NOT done here -- this emits *pre-SSA linear IR*.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

try:                                # lazy + graceful, mirroring aletheia.disasm
    import capstone
except ImportError:                 # pragma: no cover - env-dependent
    capstone = None


def _require_capstone():
    if capstone is None:            # pragma: no cover - env-dependent
        raise RuntimeError(
            "capstone is required for IR lifting but is not installed; "
            "`pip install capstone` to use aletheia.ir.")
    return capstone


# ===========================================================================
# value + op model
# ===========================================================================
class VTag(IntEnum):
    REG = 1     # named GPR / sub-register (canonicalised to the 64-bit name)
    IMM = 2     # concrete integer
    MEM = 3     # dereferenced memory (base + index*scale + disp), size in BITS
    FLAG = 4    # named flag (CF, PF, AF, ZF, SF, OF, DF)
    TEMP = 5    # SSA temporary (numbered per-instruction here; renamed later)


@dataclass(frozen=True)
class Value:
    tag: VTag
    name: str = ""                       # register / flag / temp name; "" for IMM/MEM
    imm: int = 0                         # IMM value
    size: int = 0                        # width in bits (8/16/32/64/128)
    # MEM addressing (base/index are themselves REG/IMM Values, or None)
    base: Optional["Value"] = None
    index: Optional["Value"] = None
    scale: int = 1
    disp: int = 0
    seg: str = ""                        # "fs" / "gs" / ""


class Op(IntEnum):
    NOP = 0
    ASSIGN = 1     # dst = src (bit-for-bit); a MEM src == effective address (lea)
    LOAD = 2       # dst = *addr   (args[0] is a MEM Value; sized by MEM.size)
    STORE = 3      # *addr = src   (dst is the MEM Value; args[0] is the source)
    ADD = 4
    SUB = 5
    AND = 6
    OR = 7
    XOR = 8
    SHL = 9
    SHR = 10
    SAR = 11
    ROL = 12
    ROR = 13
    MUL = 14
    IMUL = 15
    DIV = 16
    IDIV = 17
    NEG = 18
    NOT = 19
    CMP = 20       # sets flags = f(a - b), no dst
    TEST = 21      # sets flags = f(a & b), no dst
    SXT = 22       # sign-extend
    ZXT = 23       # zero-extend
    TRUNC = 24
    CALL = 30      # args[0] = target (REG/MEM indirect, IMM direct); opaque effects
    RET = 31       # args = () or (IMM,) for a `ret n` stack-cleanup
    JMP = 32       # args[0] = target Value
    BR = 33        # args = (cond, *flag/reg reads); then_ea taken, else_ea fallthrough
    SETFLAG = 40   # dst = FLAG; args = the operands the flag value depends on
    UNDEF = 50     # not lifted yet; mnemonic+operands in `text`
    SYSCALL = 51
    INT = 52       # int N; args[0] = IMM vector
    HLT = 53
    FENCE = 54


@dataclass
class IRInsn:
    ea: int                              # source x64 address that produced this op
    op: Op
    dst: Optional[Value] = None
    args: Tuple[Value, ...] = ()
    then_ea: int = 0                     # BR: taken target
    else_ea: int = 0                     # BR: fallthrough
    text: str = ""                       # UNDEF / debug

    def __str__(self) -> str:            # pragma: no cover - debug convenience
        d = f"{_vstr(self.dst)} = " if self.dst is not None else ""
        a = ", ".join(_vstr(v) for v in self.args)
        s = f"{self.ea:#x}: {d}{self.op.name} {a}".rstrip()
        if self.op is Op.BR:
            s += f"  [taken {self.then_ea:#x}, else {self.else_ea:#x}]"
        if self.text:
            s += f"  ; {self.text}"
        return s


@dataclass
class IRBlock:
    start: int                           # basic-block start EA
    insns: List[IRInsn] = field(default_factory=list)
    succs: List[int] = field(default_factory=list)   # successor block starts


@dataclass
class IRFunction:
    start: int
    blocks: Dict[int, IRBlock] = field(default_factory=dict)   # keyed by block start
    entry: int = 0


def _vstr(v: Optional[Value]) -> str:    # pragma: no cover - debug convenience
    if v is None:
        return ""
    if v.tag is VTag.IMM:
        return f"{v.imm:#x}"
    if v.tag is VTag.MEM:
        parts = []
        if v.base is not None:
            parts.append(_vstr(v.base))
        if v.index is not None:
            parts.append(f"{_vstr(v.index)}*{v.scale}")
        if v.disp or not parts:
            parts.append(f"{v.disp:#x}")
        seg = f"{v.seg}:" if v.seg else ""
        return f"{seg}[{'+'.join(parts)}]"
    return v.name


# ===========================================================================
# register canonicalisation
# ===========================================================================
# Every sub-register maps to its 64-bit parent name; the *access width* is taken
# from the capstone operand size (op.size * 8), not from this table.
_SUBREGS: Dict[str, List[str]] = {
    "rax": ["al", "ah", "ax", "eax", "rax"],
    "rbx": ["bl", "bh", "bx", "ebx", "rbx"],
    "rcx": ["cl", "ch", "cx", "ecx", "rcx"],
    "rdx": ["dl", "dh", "dx", "edx", "rdx"],
    "rsi": ["sil", "si", "esi", "rsi"],
    "rdi": ["dil", "di", "edi", "rdi"],
    "rbp": ["bpl", "bp", "ebp", "rbp"],
    "rsp": ["spl", "sp", "esp", "rsp"],
}
for _n in range(8, 16):
    _SUBREGS[f"r{_n}"] = [f"r{_n}b", f"r{_n}w", f"r{_n}d", f"r{_n}"]

_CANON: Dict[str, str] = {}
for _canon, _subs in _SUBREGS.items():
    for _s in _subs:
        _CANON[_s] = _canon


def _canon_reg(name: Optional[str]) -> str:
    """Canonical 64-bit GPR name for a sub-register; unknown names pass through
    unchanged (e.g. ``rip``, segment regs, ``xmm0`` -- the last only reached via
    UNDEF paths)."""
    if not name:
        return ""
    return _CANON.get(name, name)


# ===========================================================================
# small constructors + per-instruction temp allocation
# ===========================================================================
def _reg(name: str, size: int) -> Value:
    return Value(VTag.REG, name=_canon_reg(name), size=size)


def _imm(v: int, size: int) -> Value:
    return Value(VTag.IMM, imm=v, size=size)


def _flag(name: str) -> Value:
    return Value(VTag.FLAG, name=name)


class _Ctx:
    """Holds the source EA and hands out per-instruction ``TEMP`` values. Temp names
    embed the EA so they are unique across a function without a global counter."""
    __slots__ = ("ea", "_n")

    def __init__(self, ea: int) -> None:
        self.ea = ea
        self._n = 0

    def temp(self, size: int) -> Value:
        v = Value(VTag.TEMP, name=f"t{self.ea:x}_{self._n}", size=size)
        self._n += 1
        return v


# ===========================================================================
# capstone operand -> Value
# ===========================================================================
def _operand_to_value(insn, op, arch_bits: int = 64) -> Value:
    """Map ONE capstone x86 operand to a :class:`Value` (REG / IMM / MEM).

    ``insn`` is the capstone instruction (needed for ``reg_name``); ``op`` is one
    entry of ``insn.operands``. Register names are canonicalised; the width in bits
    is ``op.size * 8`` (the access width -- so ``al`` reports 8, ``eax`` 32)."""
    cs = capstone
    x = cs.x86
    if op.type == x.X86_OP_REG:
        return _reg(insn.reg_name(op.reg), op.size * 8)
    if op.type == x.X86_OP_IMM:
        return _imm(op.imm, op.size * 8)
    if op.type == x.X86_OP_MEM:
        m = op.mem
        base = _reg(insn.reg_name(m.base), arch_bits) if m.base else None
        index = _reg(insn.reg_name(m.index), arch_bits) if m.index else None
        seg = insn.reg_name(m.segment) if m.segment else ""
        return Value(VTag.MEM, size=op.size * 8, base=base, index=index,
                     scale=m.scale or 1, disp=m.disp, seg=seg or "")
    # fs/gs-only, X86_OP_INVALID, or anything exotic -> an opaque zero MEM marker.
    return Value(VTag.MEM, size=(op.size or (arch_bits // 8)) * 8)


# ===========================================================================
# materialisation helpers (make memory access explicit)
# ===========================================================================
def _read(ctx: _Ctx, out: List[IRInsn], v: Value) -> Value:
    """Value usable as a source: a MEM operand is first LOADed into a temp; a
    REG/IMM operand is returned unchanged."""
    if v.tag is VTag.MEM:
        t = ctx.temp(v.size)
        out.append(IRInsn(ctx.ea, Op.LOAD, dst=t, args=(v,)))
        return t
    return v


def _write(ctx: _Ctx, out: List[IRInsn], dst_op: Value, val: Value) -> None:
    """Write ``val`` into ``dst_op``: a STORE for memory, an ASSIGN for a register."""
    if dst_op.tag is VTag.MEM:
        out.append(IRInsn(ctx.ea, Op.STORE, dst=dst_op, args=(val,)))
    else:
        out.append(IRInsn(ctx.ea, Op.ASSIGN, dst=dst_op, args=(val,)))


def _setflags(ctx: _Ctx, out: List[IRInsn], flags, srcargs) -> None:
    src = tuple(srcargs)
    for f in flags:
        out.append(IRInsn(ctx.ea, Op.SETFLAG, dst=_flag(f), args=src))


def _binop_core(ctx: _Ctx, out: List[IRInsn], dst_op: Value, src_val: Value,
                op: Op, flags, extra: Tuple[Value, ...] = ()) -> None:
    """Read-modify-write ``dst_op`` with ``op(dst, src, *extra)`` then set ``flags``.

    A register destination is written directly (its own value is the first read
    operand -- an explicit read). A memory destination is LOADed into a temp, the op
    computes into a fresh temp, and the result is STOREd back."""
    if dst_op.tag is VTag.MEM:
        cur = ctx.temp(dst_op.size)
        out.append(IRInsn(ctx.ea, Op.LOAD, dst=cur, args=(dst_op,)))
        args = (cur, src_val) + extra
        res = ctx.temp(dst_op.size)
        out.append(IRInsn(ctx.ea, op, dst=res, args=args))
        out.append(IRInsn(ctx.ea, Op.STORE, dst=dst_op, args=(res,)))
    else:
        args = (dst_op, src_val) + extra
        out.append(IRInsn(ctx.ea, op, dst=dst_op, args=args))
    if flags:
        _setflags(ctx, out, flags, args)


def _unary_rmw(ctx: _Ctx, out: List[IRInsn], dst_op: Value, op: Op, flags) -> None:
    """Read-modify-write ``dst_op`` with a one-operand op (``neg`` / ``not``)."""
    if dst_op.tag is VTag.MEM:
        cur = ctx.temp(dst_op.size)
        out.append(IRInsn(ctx.ea, Op.LOAD, dst=cur, args=(dst_op,)))
        args = (cur,)
        res = ctx.temp(dst_op.size)
        out.append(IRInsn(ctx.ea, op, dst=res, args=args))
        out.append(IRInsn(ctx.ea, Op.STORE, dst=dst_op, args=(res,)))
    else:
        args = (dst_op,)
        out.append(IRInsn(ctx.ea, op, dst=dst_op, args=args))
    if flags:
        _setflags(ctx, out, flags, args)


# ===========================================================================
# flag sets + dispatch tables
# ===========================================================================
FL_ARITH = ("OF", "SF", "ZF", "AF", "PF", "CF")   # add/sub/adc/sbb/neg/cmp
FL_LOGIC = ("OF", "SF", "ZF", "PF", "CF")          # and/or/xor/test (AF undefined)
FL_INCDEC = ("OF", "SF", "ZF", "AF", "PF")         # inc/dec (CF unaffected)
FL_SHIFT = ("CF", "OF", "SF", "ZF", "PF")          # shl/shr/sar
FL_ROTATE = ("CF", "OF")                            # rol/ror
FL_MUL = ("CF", "OF")                               # mul/imul (others undefined)

# name -> (Op, flag-set, uses_carry_in)
_ALU2 = {
    "add": (Op.ADD, FL_ARITH, False),
    "sub": (Op.SUB, FL_ARITH, False),
    "adc": (Op.ADD, FL_ARITH, True),    # modelled as ADD + explicit CF read
    "sbb": (Op.SUB, FL_ARITH, True),    # modelled as SUB + explicit CF read
    "and": (Op.AND, FL_LOGIC, False),
    "or": (Op.OR, FL_LOGIC, False),
    "xor": (Op.XOR, FL_LOGIC, False),
}

_SHIFTS = {
    "shl": (Op.SHL, FL_SHIFT), "sal": (Op.SHL, FL_SHIFT),
    "shr": (Op.SHR, FL_SHIFT), "sar": (Op.SAR, FL_SHIFT),
    "rol": (Op.ROL, FL_ROTATE), "ror": (Op.ROR, FL_ROTATE),
}

# jcc mnemonic -> (predicate token, tuple of flags the predicate reads)
_JCC = {
    "je": ("eq", ("ZF",)), "jz": ("eq", ("ZF",)),
    "jne": ("ne", ("ZF",)), "jnz": ("ne", ("ZF",)),
    "jl": ("lt", ("SF", "OF")), "jnge": ("lt", ("SF", "OF")),
    "jle": ("le", ("ZF", "SF", "OF")), "jng": ("le", ("ZF", "SF", "OF")),
    "jg": ("gt", ("ZF", "SF", "OF")), "jnle": ("gt", ("ZF", "SF", "OF")),
    "jge": ("ge", ("SF", "OF")), "jnl": ("ge", ("SF", "OF")),
    "jb": ("b", ("CF",)), "jc": ("b", ("CF",)), "jnae": ("b", ("CF",)),
    "jae": ("ae", ("CF",)), "jnc": ("ae", ("CF",)), "jnb": ("ae", ("CF",)),
    "jbe": ("be", ("CF", "ZF")), "jna": ("be", ("CF", "ZF")),
    "ja": ("a", ("CF", "ZF")), "jnbe": ("a", ("CF", "ZF")),
    "js": ("s", ("SF",)), "jns": ("ns", ("SF",)),
    "jo": ("o", ("OF",)), "jno": ("no", ("OF",)),
    "jp": ("p", ("PF",)), "jpe": ("p", ("PF",)),
    "jnp": ("np", ("PF",)), "jpo": ("np", ("PF",)),
}

# treated as no-ops (control-flow-neutral, no data effect worth modelling)
_NOPS = {"nop", "endbr64", "endbr32", "pause", "fnop", "cldemote"}
_FENCES = {"mfence", "lfence", "sfence"}


# ===========================================================================
# the lifter
# ===========================================================================
def _md(arch_bits: int):
    cs = _require_capstone()
    key = (id(cs), arch_bits)
    md = _MD_CACHE.get(key)
    if md is None:
        mode = {64: cs.CS_MODE_64, 32: cs.CS_MODE_32, 16: cs.CS_MODE_16}.get(arch_bits)
        if mode is None:
            raise ValueError(f"unsupported bitness {arch_bits!r} (want 16/32/64)")
        md = cs.Cs(cs.CS_ARCH_X86, mode)
        md.detail = True
        _MD_CACHE[key] = md
    return md


_MD_CACHE: Dict[tuple, object] = {}


def _branch_target(insn, cins, arch_bits: int) -> Value:
    """Target Value of a jmp/call: the resolved absolute IMM for a direct branch
    (``insn.target``), else the REG/MEM operand for an indirect one."""
    op0 = cins.operands[0]
    if op0.type == capstone.x86.X86_OP_IMM:
        tgt = insn.target if insn.target is not None else op0.imm
        return _imm(tgt, arch_bits)
    return _operand_to_value(cins, op0, arch_bits)


def lift_instruction(insn: "Instruction", arch_bits: int = 64) -> List[IRInsn]:
    """Lift one decoded x64 instruction to a list of bounded-op :class:`IRInsn`.

    ``insn`` is an :class:`aletheia.disasm.Instruction` (carries ``address`` +
    ``bytes`` + resolved branch ``target``). The bytes are re-decoded with capstone
    to read operands structurally. Anything outside the first-class set (SSE/AVX/FPU,
    string ops, rare privileged ops, or an undecodable byte) becomes a single
    ``UNDEF`` op carrying ``mnemonic + op_str`` in ``text``."""
    cs = _require_capstone()
    ea = insn.address
    text = f"{insn.mnemonic} {insn.op_str}".strip()

    try:
        cins = next(_md(arch_bits).disasm(bytes(insn.bytes), ea, count=1))
    except StopIteration:               # undecodable -> opaque
        return [IRInsn(ea, Op.UNDEF, text=text)]

    ctx = _Ctx(ea)
    out: List[IRInsn] = []
    try:
        if _lift_dispatch(ctx, out, insn, cins, arch_bits):
            return out
    except Exception:                   # noqa: BLE001 - never crash a whole analysis
        return [IRInsn(ea, Op.UNDEF, text=text)]
    return [IRInsn(ea, Op.UNDEF, text=text)]


def _lift_dispatch(ctx: _Ctx, out: List[IRInsn], insn, cins, arch_bits: int) -> bool:
    """Fill ``out`` for a recognised instruction; return True if handled, False to
    fall through to UNDEF. Split out so :func:`lift_instruction` can guard it."""
    m = cins.mnemonic
    ops = [_operand_to_value(cins, o, arch_bits) for o in cins.operands]

    # -- data movement -----------------------------------------------------
    if m in ("mov", "movabs"):
        dst, src = ops[0], ops[1]
        if dst.tag is VTag.MEM:
            out.append(IRInsn(ctx.ea, Op.STORE, dst=dst, args=(src,)))
        elif src.tag is VTag.MEM:
            out.append(IRInsn(ctx.ea, Op.LOAD, dst=dst, args=(src,)))
        else:
            out.append(IRInsn(ctx.ea, Op.ASSIGN, dst=dst, args=(src,)))
        return True

    if m in ("movzx", "movsx", "movsxd"):
        dst, src = ops[0], ops[1]
        s = _read(ctx, out, src)
        op = Op.ZXT if m == "movzx" else Op.SXT
        out.append(IRInsn(ctx.ea, op, dst=dst, args=(s,)))
        return True

    if m == "lea":
        # ops[1] is a MEM value used as an ADDRESS: ASSIGN, no LOAD.
        out.append(IRInsn(ctx.ea, Op.ASSIGN, dst=ops[0], args=(ops[1],)))
        return True

    if m == "push":
        src = _read(ctx, out, ops[0])
        slot = ops[0].size // 8 or (arch_bits // 8)
        rsp = _reg("rsp", arch_bits)
        out.append(IRInsn(ctx.ea, Op.SUB, dst=rsp, args=(rsp, _imm(slot, arch_bits))))
        stack = Value(VTag.MEM, size=slot * 8, base=_reg("rsp", arch_bits), scale=1)
        out.append(IRInsn(ctx.ea, Op.STORE, dst=stack, args=(src,)))
        return True

    if m == "pop":
        dst = ops[0]
        slot = dst.size // 8 or (arch_bits // 8)
        stack = Value(VTag.MEM, size=slot * 8, base=_reg("rsp", arch_bits), scale=1)
        if dst.tag is VTag.MEM:
            t = ctx.temp(slot * 8)
            out.append(IRInsn(ctx.ea, Op.LOAD, dst=t, args=(stack,)))
            out.append(IRInsn(ctx.ea, Op.STORE, dst=dst, args=(t,)))
        else:
            out.append(IRInsn(ctx.ea, Op.LOAD, dst=dst, args=(stack,)))
        rsp = _reg("rsp", arch_bits)
        out.append(IRInsn(ctx.ea, Op.ADD, dst=rsp, args=(rsp, _imm(slot, arch_bits))))
        return True

    if m == "xchg":
        a, b = ops[0], ops[1]
        ta = ctx.temp(a.size or b.size)
        if a.tag is VTag.MEM:
            out.append(IRInsn(ctx.ea, Op.LOAD, dst=ta, args=(a,)))
        else:
            out.append(IRInsn(ctx.ea, Op.ASSIGN, dst=ta, args=(a,)))
        rb = _read(ctx, out, b)
        _write(ctx, out, a, rb)
        _write(ctx, out, b, ta)
        return True

    # -- arithmetic / logic ------------------------------------------------
    if m in _ALU2:
        op, flags, uses_cf = _ALU2[m]
        src = _read(ctx, out, ops[1])
        extra = (_flag("CF"),) if uses_cf else ()
        _binop_core(ctx, out, ops[0], src, op, flags, extra)
        return True

    if m in _SHIFTS:
        op, flags = _SHIFTS[m]
        count = ops[1] if len(ops) > 1 else _imm(1, 8)
        count = _read(ctx, out, count)
        _binop_core(ctx, out, ops[0], count, op, flags)
        return True

    if m == "inc":
        _binop_core(ctx, out, ops[0], _imm(1, ops[0].size or arch_bits),
                    Op.ADD, FL_INCDEC)
        return True
    if m == "dec":
        _binop_core(ctx, out, ops[0], _imm(1, ops[0].size or arch_bits),
                    Op.SUB, FL_INCDEC)
        return True
    if m == "neg":
        _unary_rmw(ctx, out, ops[0], Op.NEG, FL_ARITH)
        return True
    if m == "not":
        _unary_rmw(ctx, out, ops[0], Op.NOT, ())
        return True

    if m == "imul":
        _lift_mul(ctx, out, cins, ops, Op.IMUL, arch_bits)
        return True
    if m == "mul":
        _lift_mul(ctx, out, cins, ops, Op.MUL, arch_bits)
        return True
    if m in ("div", "idiv"):
        _lift_div(ctx, out, ops, Op.IDIV if m == "idiv" else Op.DIV, arch_bits)
        return True

    if m == "cmp":
        a = _read(ctx, out, ops[0])
        b = _read(ctx, out, ops[1])
        out.append(IRInsn(ctx.ea, Op.CMP, dst=None, args=(a, b)))
        _setflags(ctx, out, FL_ARITH, (a, b))
        return True
    if m == "test":
        a = _read(ctx, out, ops[0])
        b = _read(ctx, out, ops[1])
        out.append(IRInsn(ctx.ea, Op.TEST, dst=None, args=(a, b)))
        _setflags(ctx, out, FL_LOGIC, (a, b))
        return True
    if m == "bt":
        a = _read(ctx, out, ops[0])
        b = _read(ctx, out, ops[1])
        out.append(IRInsn(ctx.ea, Op.TEST, dst=None, args=(a, b)))
        _setflags(ctx, out, ("CF",), (a, b))     # bt copies the tested bit into CF
        return True

    # -- control flow ------------------------------------------------------
    if m == "jmp":
        out.append(IRInsn(ctx.ea, Op.JMP, args=(_branch_target(insn, cins, arch_bits),)))
        return True
    if insn.is_call:
        out.append(IRInsn(ctx.ea, Op.CALL, args=(_branch_target(insn, cins, arch_bits),)))
        return True
    if m in ("ret", "retn", "retf", "retfq"):
        args = (ops[0],) if ops else ()
        out.append(IRInsn(ctx.ea, Op.RET, args=args))
        return True
    if m in _JCC:
        token, flags = _JCC[m]
        cond = Value(VTag.TEMP, name=f"cc_{token}", size=8)
        flagvals = tuple(_flag(f) for f in flags)
        out.append(IRInsn(ctx.ea, Op.BR, dst=None, args=(cond,) + flagvals,
                          then_ea=insn.target or 0, else_ea=insn.end))
        return True
    if m in ("jrcxz", "jecxz", "jcxz"):
        rsize = {"jrcxz": 64, "jecxz": 32, "jcxz": 16}[m]
        cond = Value(VTag.TEMP, name="cc_rcxz", size=8)
        out.append(IRInsn(ctx.ea, Op.BR, dst=None,
                          args=(cond, _reg("rcx", rsize), _imm(0, rsize)),
                          then_ea=insn.target or 0, else_ea=insn.end))
        return True
    if m in ("loop", "loope", "loopne"):
        rcx = _reg("rcx", arch_bits)
        # loop does not affect flags -> a bare SUB with no SETFLAG.
        out.append(IRInsn(ctx.ea, Op.SUB, dst=rcx, args=(rcx, _imm(1, arch_bits))))
        token = {"loop": "rcxnz", "loope": "rcxnz_e", "loopne": "rcxnz_ne"}[m]
        cond = Value(VTag.TEMP, name=f"cc_{token}", size=8)
        args = (cond, rcx, _imm(0, arch_bits))
        if m in ("loope", "loopne"):
            args = args + (_flag("ZF"),)
        out.append(IRInsn(ctx.ea, Op.BR, dst=None, args=args,
                          then_ea=insn.target or 0, else_ea=insn.end))
        return True

    # -- privileged / misc -------------------------------------------------
    if m in ("syscall", "sysenter", "sysret", "sysexit"):
        out.append(IRInsn(ctx.ea, Op.SYSCALL))
        return True
    if m in ("int", "int1", "int3", "into", "icebp"):
        if m == "int3":
            vec = 3
        elif m == "into":
            vec = 4
        elif m in ("int1", "icebp"):
            vec = 1
        else:
            vec = ops[0].imm if ops else 0
        out.append(IRInsn(ctx.ea, Op.INT, args=(_imm(vec, 8),)))
        return True
    if m == "hlt":
        out.append(IRInsn(ctx.ea, Op.HLT))
        return True
    if m in _NOPS:
        out.append(IRInsn(ctx.ea, Op.NOP))
        return True
    if m in _FENCES:
        out.append(IRInsn(ctx.ea, Op.FENCE))
        return True

    # -- string ops: documented gap ---------------------------------------
    # TODO: string ops -- movs/stos/lods/cmps/scas + rep-loop expansion.
    # Falls through to the UNDEF path below (same as SSE/AVX/FPU/x87 and any
    # unrecognised mnemonic). Returning False lets lift_instruction emit one UNDEF.
    return False


def _lift_mul(ctx: _Ctx, out: List[IRInsn], cins, ops, op: Op, arch_bits: int) -> None:
    """mul / imul in its 1-, 2-, and 3-operand forms.

    * 3-operand ``imul r, r/m, imm`` -> ``r = r/m * imm`` (low half only).
    * 2-operand ``imul r, r/m``      -> ``r = r * r/m``   (low half only).
    * 1-operand ``mul/imul r/m``     -> ``rdx:rax = rax * r/m``: two ops, one
      writing ``rax`` (low), one writing ``rdx`` (high), sharing symbolic args.
    """
    if len(ops) == 3:
        a = _read(ctx, out, ops[1])
        b = ops[2]
        out.append(IRInsn(ctx.ea, op, dst=ops[0], args=(a, b)))
        _setflags(ctx, out, FL_MUL, (a, b))
        return
    if len(ops) == 2:
        a = ops[0]
        b = _read(ctx, out, ops[1])
        out.append(IRInsn(ctx.ea, op, dst=ops[0], args=(a, b)))
        _setflags(ctx, out, FL_MUL, (a, b))
        return
    # 1-operand: implicit rax (and rdx for the high half).
    s = ops[0].size or arch_bits
    src = _read(ctx, out, ops[0])
    rax = _reg("rax", s)
    args = (rax, src)
    out.append(IRInsn(ctx.ea, op, dst=rax, args=args))
    if s >= 16:                          # 16/32/64-bit forms also write rdx (high)
        out.append(IRInsn(ctx.ea, op, dst=_reg("rdx", s), args=args))
    _setflags(ctx, out, FL_MUL, args)


def _lift_div(ctx: _Ctx, out: List[IRInsn], ops, op: Op, arch_bits: int) -> None:
    """div / idiv (1-operand): ``rax = rdx:rax / r/m`` (quotient) and
    ``rdx = rdx:rax % r/m`` (remainder). All flags are architecturally undefined,
    so NO ``SETFLAG`` is emitted. (The 8-bit form's ax/al/ah mapping is
    approximated by the same rax/rdx shape -- a stated simplification.)"""
    s = ops[0].size or arch_bits
    src = _read(ctx, out, ops[0])
    rax = _reg("rax", s)
    rdx = _reg("rdx", s)
    args = (rdx, rax, src)
    out.append(IRInsn(ctx.ea, op, dst=rax, args=args))    # quotient
    out.append(IRInsn(ctx.ea, op, dst=rdx, args=args))    # remainder


# ===========================================================================
# block / function lifting
# ===========================================================================
def lift_block(block: "BasicBlock",
               insns: Optional[object] = None) -> IRBlock:
    """Lift a :class:`aletheia.disasm.BasicBlock` to an :class:`IRBlock`.

    Iterates the block's own instructions (falling back to ``insns`` -- a
    ``{ea: Instruction}`` map or a list -- to recover them if the block carries
    none), lifts each, and flattens the ops into ``IRBlock.insns``. Successors are
    copied verbatim from the disassembler's CFG (``block.successors``)."""
    src = list(block.instructions) if getattr(block, "instructions", None) else []
    if not src and insns is not None:
        by_ea = insns if isinstance(insns, dict) else {i.address: i for i in insns}
        a = block.start
        while a in by_ea and a < block.end:
            i = by_ea[a]
            src.append(i)
            a = i.end
    ir = IRBlock(start=block.start, insns=[], succs=list(block.successors))
    for i in src:
        ir.insns.extend(lift_instruction(i))
    return ir


def lift_function(func_start: int, blocks: "List[BasicBlock]",
                  insns_by_ea: "Dict[int, Instruction]") -> IRFunction:
    """Lift a function to an :class:`IRFunction` by walking the CFG from
    ``func_start``.

    ``blocks`` is the list of :class:`~aletheia.disasm.BasicBlock` for the image;
    ``insns_by_ea`` is a ``{address: Instruction}`` map (used as a fallback source
    for blocks that carry no instruction list). Only blocks reachable from
    ``func_start`` via successor edges are included -- an intra-procedural graph."""
    by_start = {b.start: b for b in blocks}
    fn = IRFunction(start=func_start, blocks={}, entry=func_start)
    if func_start not in by_start:
        return fn
    seen = set()
    work = [func_start]
    while work:
        s = work.pop()
        if s in seen or s not in by_start:
            continue
        seen.add(s)
        blk = by_start[s]
        fn.blocks[s] = lift_block(blk, insns_by_ea)
        for succ in blk.successors:
            if succ not in seen:
                work.append(succ)
    return fn


__all__ = [
    "VTag", "Value", "Op", "IRInsn", "IRBlock", "IRFunction",
    "lift_instruction", "lift_block", "lift_function",
]
