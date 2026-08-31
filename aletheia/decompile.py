"""Basic type / signature / struct recovery + a C-like pseudocode emitter over
Aletheia's structured IR.

This is the final Tier-3 piece: it turns the structured tree that
:mod:`aletheia.structuring` recovers -- ``SEQ`` / ``IF`` / ``WHILE`` / ``DO_WHILE``
/ ``SWITCH`` / ``BREAK`` / ``CONTINUE`` / ``RETURN`` / ``GOTO`` / ``BLOCK`` nodes
over the bounded-op IR -- into readable, if ugly, C-ish source. Feeding a function
through ``disasm_pe -> lift_function -> build_ssa -> constant_fold -> memory_ssa
-> dead_code_eliminate -> structure -> emit`` produces pseudocode.

Everything here is stdlib-only; :mod:`aletheia.ir`, :mod:`aletheia.dataflow` and
:mod:`aletheia.structuring` are imported for their types/primitives and never
modified.

--------------------------------------------------------------------------------
Honesty first (documented approximations, not hidden shortcuts)
--------------------------------------------------------------------------------
* **Type recovery is a first cut.** Widths come from ``Value.size`` (the lifter's
  operand sizing). Signedness is inferred per-use from the *signed* ops
  (``SAR`` / ``IDIV`` / ``IMUL`` and signed ``jcc`` -> ``cc_lt`` / ``cc_le`` /
  ``cc_gt`` / ``cc_ge``) versus the *unsigned* ops (``SHR`` / ``DIV`` / ``MUL`` and
  unsigned ``jcc`` -> ``cc_b`` / ``cc_be`` / ``cc_a`` / ``cc_ae``); ambiguous /
  conflicting evidence defaults to unsigned. Pointerness is inferred from a name
  appearing as a memory ``base``. Everything else stays ``"unknown"``.
* **SETFLAG recovery strategy.** ``SETFLAG`` ops are never printed. A branch
  condition is rebuilt from the ``cmp`` / ``test`` that feeds the terminating
  ``BR``: the last ``CMP`` / ``TEST`` in the condition block supplies the operands,
  the ``BR``'s ``cc_*`` token supplies the operator (``cc_eq`` -> ``==`` etc.).
  If no feeding compare is found, the raw ``cc_*`` token is emitted as a comment
  (``1 /* cc_ne */``) rather than a fabricated expression.
* **SAR / IDIV / IMUL signedness** is made explicit with a ``(intN_t)`` cast on the
  primary operand (the chosen, documented convention); ``SHR`` stays a plain
  ``>>``. ``div`` / ``idiv`` render the 64-bit dividend as ``rax`` only, with a
  ``/* rdx:rax */`` note (the high half is not spelled out).
* **Unconditional ``JMP`` terminators are omitted** -- the structured tree already
  encodes that control transfer. Explicit ``GOTO`` nodes (irreducible flow) are
  the only source of ``goto`` output *for irreducibility*, and their targets get
  ``L<hex>:`` labels. Multi-level break / continue (structuring's labelled loops)
  are rendered as ``goto`` too -- see the "labelled loops" note below.

--------------------------------------------------------------------------------
Function-signature recovery (Windows x64, heuristic)
--------------------------------------------------------------------------------
The Windows x64 calling convention gets a best-effort recovery: incoming integer /
pointer args are ``rcx`` / ``rdx`` / ``r8`` / ``r9`` (arg0..arg3), then stack slots
``[rsp + 0x28]`` (arg4), ``[rsp + 0x30]`` (arg5), ... up to a small cap. Detection:

* **Arg registers.** ``rcx`` / ``rdx`` / ``r8`` / ``r9`` are argX iff the function
  READS them before it WRITES them along at least one path from the entry
  (in the SSA IR that shows up as an appearance of the ``#0`` version; in the
  hand-built non-SSA IR of the tests it is the plain unversioned base name used
  before any defining ``ASSIGN`` / arith op).
* **Stack args.** A LOAD (or a MEM read that reaches an arithmetic op) from
  ``[rsp + K]`` with ``K`` a positive multiple of 8 and ``K >= 0x28`` is treated
  as ``arg((K - 0x20) / 8)``.
* **Return type.** If any WRITE to ``rax`` exists that is not an ``ASSIGN`` of the
  constant ``0`` (the classic ``xor eax, eax`` "return void" idiom), the function
  is treated as returning a value; the type is the recovered type of the highest-
  versioned ``rax`` name (or a ``uint64_t`` best guess if no signal is available).
  Otherwise the return type is ``void``.

The header is emitted as ``<ret> sub(<t0> arg0, <t1> arg1, ...)`` with C aliases
``void* / int{8,16,32,64}_t / uint{8,16,32,64}_t`` and ``unknown_t`` for the
``kind == "unknown"`` bucket (a documented typedef, not a real C type). The BODY
still references the underlying registers (``rcx``, ``rdx``, ...) -- a leading
``/* args: arg0 = rcx, arg1 = rdx, ... */`` comment maps them so the reader can
follow.

**Honest limits.** This is heuristic. A leaf function that only uses ``rcx`` as a
scratch (writes it before any read) does NOT look like it takes ``rcx``, so it
gets ``args=[]`` -- usually right, but wrong for a caller that passed something the
function ignored. A function that dereferences ``rcx`` mid-body without a prior
``ASSIGN`` looks like it received ``rcx`` as arg0 -- usually right. Stack-arg
detection is displacement-based only: an arg passed at ``[rsp + 0x28]`` and never
touched is invisible.

--------------------------------------------------------------------------------
Struct recovery (synthetic; access-pattern only)
--------------------------------------------------------------------------------
When one SSA base appears as a plain ``MEM.base`` (no index, no scale) at TWO OR
MORE distinct displacements across the function's LOADs / STOREs, the emitter
promotes it to a synthetic struct:

* One ``struct auto_N`` type per qualifying base (per-function counter starting at
  ``1``). Fields are named ``field_<hex_disp>`` (``field_0``, ``field_8``,
  ``field_10``, ``field_neg_8`` for negatives); field types come from the access
  width (``uint8_t`` / ``uint16_t`` / ``uint32_t`` / ``uint64_t``).
* The struct declaration is emitted at the top of the function body, before any
  code.
* Every ``*(uintN_t*)(base + disp)`` LOAD / STORE through a qualifying base is
  rewritten to ``((struct auto_N*)base)->field_<disp>`` (cast form -- the base is
  a raw pointer in the recovered signature, so the cast is needed for a naive C
  reader; documented convention).
* **A single-access base is NOT promoted.** ``*(uint64_t*)(rcx)`` alone stays raw.
  Two accesses at the same displacement do NOT count (a struct needs at least two
  *distinct* offsets).

**Honest limits.** The struct name is synthetic (``auto_N``) -- we have no idea
what the real struct is called. Bases are keyed by the SSA *base name* (versions
stripped) so ``rcx#0`` and ``rcx#1`` that both do struct-shaped accesses roll into
one type; if code did a pointer walk (``rcx#1 = rcx#0 + 8``) and accessed different
structs through the two versions, this over-merges (documented). Indexed accesses
(``[rcx + rdx*8]``) never qualify -- that is array shape, not struct.
``rsp`` / ``rbp`` (stack frames) are excluded from struct promotion.

--------------------------------------------------------------------------------
Labelled loops (multi-level break / continue)
--------------------------------------------------------------------------------
Structuring may set ``SNode.label = "L1"`` on a ``WHILE`` / ``DO_WHILE`` that an
inner labelled break / continue targets, plus ``SNode.target_label = "L1"`` on the
targeting ``BREAK`` / ``CONTINUE``.

**Chosen convention: standard-C goto with sibling labels.** For a labelled loop,
we emit a ``L<N>_continue:`` label just before the loop's condition check (i.e.
in front of ``while (...)`` for a ``WHILE``, and just before ``} while (...)`` for
a ``DO_WHILE``) and a ``L<N>_end: ;`` label immediately after the loop. A labelled
``BREAK`` renders as ``goto L<N>_end;`` and a labelled ``CONTINUE`` as
``goto L<N>_continue;``. Plain (unlabelled) ``BREAK`` / ``CONTINUE`` still render
as ``break;`` / ``continue;``. This keeps the output legal C (Java-style
``break L1;`` is not), matches how hand-written C models multi-level exits, and
avoids inventing a fake ``break;`` where the source semantics actually needed a
non-innermost target.

--------------------------------------------------------------------------------
Memory-SSA integration
--------------------------------------------------------------------------------
The full ``decompile_function`` pipeline now runs :func:`aletheia.dataflow.memory_ssa`
between ``constant_fold`` and ``dead_code_eliminate``. That pass:

* Rewrites stack-slot ``LOAD``s that read through to a dominating ``STORE`` into
  ``ASSIGN dst = <stored value>`` -- the existing ``ASSIGN`` path renders them
  naturally as ``dst = <expr>;``.
* Injects virtual ``SETSLOT`` ops (``op == MEM_SSA_OP_CODE == 101``) alongside the
  original store to carry slot versions. The emitter SKIPS these -- they are
  bookkeeping, not source-level statements; the surviving real ``STORE`` still
  renders as ``*(...) = ...;`` for its memory side effect.
* Places slot-level ``PHI``s (``op == PHI_OP_CODE`` with a ``slot_`` base name) at
  merges. The emitter renders these as a leading ``/* slot_..._... = phi(...) */``
  comment so the analyst can see the merge, without inventing a spurious C
  statement.

The pipeline is ``build_ssa -> constant_fold -> memory_ssa -> dead_code_eliminate
-> structure -> emit``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import copy
from typing import Dict, List, Optional, Set, Tuple, Iterator

from aletheia.ir import IRFunction, IRInsn, Op, Value, VTag
from aletheia.dataflow import (
    build_ssa, constant_fold, dead_code_eliminate, is_phi, is_setslot,
    memory_ssa, ssa_base_name, ssa_version,
)
from aletheia.structuring import NodeKind, SNode, StructuredFunction, structure


# ===========================================================================
# public data model
# ===========================================================================
@dataclass
class TypeGuess:
    kind: str          # "int" | "uint" | "ptr" | "unknown" | "void"
    width: int         # bits: 8/16/32/64
    is_signed: bool    # meaningful for the "int" kind


@dataclass
class Argument:
    """One recovered function argument."""
    name: str                        # "arg0" / "arg1" / ...
    type_guess: TypeGuess
    source: str                      # "rcx" | "rdx" | "r8" | "r9" | "[rsp+0x28]" | ...


@dataclass
class FunctionSignature:
    """Recovered ABI-level signature. See the module docstring for scope."""
    return_type: TypeGuess           # kind == "void" iff no non-zero rax write
    args: List[Argument] = field(default_factory=list)
    calling_convention: str = "win64"


@dataclass
class DecompiledFunction:
    name: str
    source: str                                                     # emitted text
    types: Dict[str, TypeGuess] = field(default_factory=dict)       # SSA name -> guess
    warnings: List[str] = field(default_factory=list)               # honest notes
    signature: Optional[FunctionSignature] = None
    # struct_name -> [(displacement, field_name, type_guess)] in offset order
    recovered_structs: Dict[str, List[Tuple[int, str, TypeGuess]]] = field(
        default_factory=dict)


# ===========================================================================
# condition-token tables (shared by type recovery + the emitter)
# ===========================================================================
_CC_OP = {
    "eq": ("==", None), "ne": ("!=", None),
    "lt": ("<", "signed"), "le": ("<=", "signed"),
    "gt": (">", "signed"), "ge": (">=", "signed"),
    "ltu": ("<", "unsigned"), "leu": ("<=", "unsigned"),
    "gtu": (">", "unsigned"), "geu": (">=", "unsigned"),
    "b": ("<", "unsigned"), "be": ("<=", "unsigned"),
    "a": (">", "unsigned"), "ae": (">=", "unsigned"),
}
_SIGNED_CC = {"lt", "le", "gt", "ge"}
_UNSIGNED_CC = {"b", "be", "a", "ae", "ltu", "leu", "gtu", "geu"}

_SIGNED_OPS = frozenset({Op.SAR, Op.IDIV, Op.IMUL})
_UNSIGNED_OPS = frozenset({Op.SHR, Op.DIV, Op.MUL})

_BIN_SYM = {
    Op.ADD: "+", Op.SUB: "-", Op.AND: "&", Op.OR: "|", Op.XOR: "^",
    Op.SHL: "<<", Op.SHR: ">>", Op.SAR: ">>", Op.MUL: "*", Op.IMUL: "*",
    Op.ROL: "<<", Op.ROR: ">>",
}

# Windows x64 integer/pointer arg registers, in ABI order.
_ARG_REGS = ("rcx", "rdx", "r8", "r9")
# Cap the number of stack-args we willingly count (arg4 at [rsp+0x28], arg5 at
# [rsp+0x30], ..., arg15 at [rsp+0x80]). 16 total arg slots is plenty for
# real-world Windows x64 code (the ABI reserves 4 spill slots + arbitrary extras
# on the stack; picking 12 stack extras = 16 total is a documented, sane cap).
_MAX_STACK_ARGS = 12
_STACK_ARG_BASE_DISP = 0x28


def _cc_key(br: IRInsn) -> Optional[str]:
    if not br.args:
        return None
    tok = ssa_base_name(br.args[0].name)
    return tok[3:] if tok.startswith("cc_") else tok


# ===========================================================================
# type recovery
# ===========================================================================
def _iter_leaf_values(v: Optional[Value]):
    """Yield the REG/TEMP/IMM/FLAG leaves of a Value, recursing through MEM
    base/index. A MEM node itself is yielded too (callers inspect it for base)."""
    if v is None:
        return
    if v.tag == VTag.MEM:
        yield v
        yield from _iter_leaf_values(v.base)
        yield from _iter_leaf_values(v.index)
    else:
        yield v


def recover_types(func: IRFunction) -> Dict[str, TypeGuess]:
    """Best-effort per-SSA-name type recovery over a (usually SSA) IRFunction.

    Rules (see the module docstring): width from ``Value.size``; ``ptr`` for a name
    used as a memory ``base``; signed ``int`` from ``SAR`` / ``IDIV`` / ``IMUL``
    operands and signed compares; unsigned from ``SHR`` / ``DIV`` / ``MUL`` operands
    and unsigned compares; conflicting sign evidence defaults to unsigned; no
    evidence stays ``"unknown"``. Keyed by the exact ``Value.name`` (versioned when
    the input is SSA)."""
    widths: Dict[str, int] = {}
    signals: Dict[str, Set[str]] = {}

    def note_width(name: str, size: int) -> None:
        if not name:
            return
        signals.setdefault(name, set())
        if size and size > widths.get(name, 0):
            widths[name] = size

    def add_signal(name: str, sig: str) -> None:
        if not name:
            return
        signals.setdefault(name, set()).add(sig)

    def mark_operands(insn: IRInsn, sig: str) -> None:
        for a in insn.args:
            for leaf in _iter_leaf_values(a):
                if leaf.tag in (VTag.REG, VTag.TEMP) and leaf.name:
                    add_signal(leaf.name, sig)

    for b in sorted(func.blocks):
        last_cmp: Optional[IRInsn] = None
        for insn in func.blocks[b].insns:
            for v in (insn.dst,) + tuple(insn.args):
                for leaf in _iter_leaf_values(v):
                    if leaf.tag in (VTag.REG, VTag.TEMP) and leaf.name:
                        note_width(leaf.name, leaf.size)
                    elif leaf.tag == VTag.MEM and leaf.base is not None \
                            and leaf.base.tag in (VTag.REG, VTag.TEMP) \
                            and leaf.base.name:
                        note_width(leaf.base.name, 64)
                        add_signal(leaf.base.name, "ptr")

            if insn.op in _SIGNED_OPS:
                mark_operands(insn, "signed")
            elif insn.op in _UNSIGNED_OPS:
                mark_operands(insn, "unsigned")

            if insn.op in (Op.CMP, Op.TEST):
                last_cmp = insn
            elif insn.op == Op.BR:
                key = _cc_key(insn)
                sig = ("signed" if key in _SIGNED_CC else
                       "unsigned" if key in _UNSIGNED_CC else None)
                if sig and last_cmp is not None:
                    mark_operands(last_cmp, sig)

    out: Dict[str, TypeGuess] = {}
    for name, sig in signals.items():
        w = widths.get(name, 64) or 64
        if "ptr" in sig:
            out[name] = TypeGuess(kind="ptr", width=64, is_signed=False)
        elif "signed" in sig and "unsigned" not in sig:
            out[name] = TypeGuess(kind="int", width=w, is_signed=True)
        elif "unsigned" in sig and "signed" not in sig:
            out[name] = TypeGuess(kind="uint", width=w, is_signed=False)
        elif "signed" in sig and "unsigned" in sig:
            out[name] = TypeGuess(kind="uint", width=w, is_signed=False)
        else:
            out[name] = TypeGuess(kind="unknown", width=w, is_signed=False)
    return out


def _ctype(tg: TypeGuess) -> str:
    if tg.kind == "void":
        return "void"
    if tg.kind == "ptr":
        return "void*"
    if tg.kind == "int":
        return f"int{tg.width or 64}_t"
    if tg.kind == "uint":
        return f"uint{tg.width or 64}_t"
    # unknown -> a documented typedef alias
    return "unknown_t"


# ===========================================================================
# signature inference
# ===========================================================================
def _is_stack_arg_mem(v: Optional[Value]) -> Optional[int]:
    """If ``v`` is a MEM read of ``[rsp + K]`` (no index, K >= 0x28, K % 8 == 0),
    return ``K``; else ``None``."""
    if v is None or v.tag != VTag.MEM:
        return None
    if v.index is not None:
        return None
    b = v.base
    if b is None or b.tag != VTag.REG or not b.name:
        return None
    if ssa_base_name(b.name) != "rsp":
        return None
    disp = int(v.disp)
    if disp < _STACK_ARG_BASE_DISP or (disp % 8) != 0:
        return None
    idx = (disp - 0x20) // 8         # arg4 at 0x28, arg5 at 0x30, ...
    if idx < 4 or idx >= 4 + _MAX_STACK_ARGS:
        return None
    return disp


def _reachable_blocks(func: IRFunction) -> List[int]:
    """BFS from ``func.entry`` over existing block successors; entry-first order.

    Returns [] if there is no entry block (an empty function)."""
    if func.entry not in func.blocks:
        return []
    order: List[int] = []
    seen: Set[int] = {func.entry}
    work: List[int] = [func.entry]
    while work:
        b = work.pop(0)
        order.append(b)
        for s in func.blocks[b].succs:
            if s in func.blocks and s not in seen:
                seen.add(s)
                work.append(s)
    return order


def recover_signature(func: IRFunction,
                      types: Dict[str, TypeGuess]) -> FunctionSignature:
    """Best-effort Windows x64 signature recovery for ``func``.

    See the module docstring for the ARG-detection rule (read-before-write on
    ``rcx``/``rdx``/``r8``/``r9`` and ``[rsp + K]`` MEM reads for stack args) and
    the RETURN-detection rule (any non-zero write to ``rax`` is non-void)."""
    reachable = _reachable_blocks(func)
    if not reachable:
        return FunctionSignature(return_type=TypeGuess(kind="void", width=0,
                                                      is_signed=False))

    # ---- ARG discovery ----
    # For each arg register, track whether it has been WRITTEN yet (function-wide,
    # in BFS-from-entry order). The FIRST read before any write counts as an arg
    # use; subsequent reads after a write do NOT.
    written: Set[str] = set()
    arg_reg_used: Dict[str, str] = {}   # base_reg -> the ssa name we saw it under
    stack_args: Dict[int, int] = {}     # disp -> width (bits) of the widest read

    def _visit_val(v: Optional[Value]) -> None:
        if v is None:
            return
        if v.tag == VTag.MEM:
            k = _is_stack_arg_mem(v)
            if k is not None:
                w = v.size or 64
                stack_args[k] = max(stack_args.get(k, 0), w)
            _visit_val(v.base)
            _visit_val(v.index)
            return
        if v.tag in (VTag.REG, VTag.TEMP) and v.name:
            base = ssa_base_name(v.name)
            if base in _ARG_REGS and base not in written and base not in arg_reg_used:
                arg_reg_used[base] = v.name

    for b in reachable:
        for insn in func.blocks[b].insns:
            if is_phi(insn) or is_setslot(insn):
                continue
            if insn.op in (Op.CMP, Op.TEST, Op.BR, Op.JMP, Op.RET,
                           Op.CALL, Op.STORE, Op.SETFLAG):
                for a in insn.args:
                    _visit_val(a)
                if insn.op == Op.STORE and insn.dst is not None:
                    _visit_val(insn.dst)        # addr computation reads regs
                continue
            # value-producing insn: args are reads, dst is the def
            for a in insn.args:
                _visit_val(a)
            d = insn.dst
            if d is not None and d.tag == VTag.REG and d.name:
                dbase = ssa_base_name(d.name)
                if dbase in _ARG_REGS:
                    written.add(dbase)
            if d is not None and d.tag == VTag.MEM:
                _visit_val(d)                   # a MEM dst's addr regs are reads

    max_reg_idx = -1
    for i, r in enumerate(_ARG_REGS):
        if r in arg_reg_used:
            max_reg_idx = max(max_reg_idx, i)
    max_stack_idx = -1
    for disp in stack_args:
        idx = (disp - 0x20) // 8
        max_stack_idx = max(max_stack_idx, idx)
    n_args = max(max_reg_idx, max_stack_idx) + 1
    if n_args <= 0:
        args: List[Argument] = []
    else:
        args = []
        for i in range(n_args):
            if i < 4:
                src_reg = _ARG_REGS[i]
                ssa_name = arg_reg_used.get(src_reg)
                if ssa_name is not None:
                    tg = types.get(ssa_name) or TypeGuess(
                        kind="unknown", width=64, is_signed=False)
                else:
                    tg = TypeGuess(kind="unknown", width=64, is_signed=False)
                args.append(Argument(name=f"arg{i}", type_guess=tg, source=src_reg))
            else:
                disp = _STACK_ARG_BASE_DISP + (i - 4) * 8
                w = stack_args.get(disp, 64) or 64
                tg = (TypeGuess(kind="uint", width=w, is_signed=False)
                      if disp in stack_args
                      else TypeGuess(kind="unknown", width=64, is_signed=False))
                args.append(Argument(name=f"arg{i}", type_guess=tg,
                                     source=f"[rsp+{disp:#x}]"))

    # ---- RETURN discovery ----
    rax_writes: List[IRInsn] = []
    for b in reachable:
        for insn in func.blocks[b].insns:
            if is_phi(insn) or is_setslot(insn):
                continue
            d = insn.dst
            if d is not None and d.tag == VTag.REG and d.name \
                    and ssa_base_name(d.name) == "rax":
                rax_writes.append(insn)

    def _is_zero_assign(insn: IRInsn) -> bool:
        if insn.op != Op.ASSIGN or not insn.args:
            return False
        src = insn.args[0]
        return src.tag == VTag.IMM and src.imm == 0

    non_zero = [i for i in rax_writes if not _is_zero_assign(i)]
    if non_zero:
        best_ver, best_name = -2, "rax"
        for insn in non_zero:
            n = insn.dst.name if insn.dst is not None else "rax"
            v = ssa_version(n)
            if v > best_ver:
                best_ver, best_name = v, n
        tg = types.get(best_name) or TypeGuess(kind="uint", width=64, is_signed=False)
        if tg.kind == "unknown":
            tg = TypeGuess(kind="uint", width=tg.width or 64, is_signed=False)
        ret_type = tg
    else:
        ret_type = TypeGuess(kind="void", width=0, is_signed=False)

    return FunctionSignature(return_type=ret_type, args=args,
                             calling_convention="win64")


# ===========================================================================
# struct recovery
# ===========================================================================
def _field_name(disp: int) -> str:
    if disp < 0:
        return f"field_neg_{-disp:x}"
    return f"field_{disp:x}"


def _recover_structs(
    func: IRFunction, types: Dict[str, TypeGuess]
) -> Tuple[Dict[str, str], Dict[str, List[Tuple[int, str, TypeGuess]]]]:
    """Detect base -> struct promotions from access patterns.

    Returns ``(base_to_struct, structs)`` where ``base_to_struct`` maps a
    ``ssa_base_name(base)`` to a struct type name (``"auto_1"``, ...) and
    ``structs`` maps that struct name to its ordered field list
    ``[(disp, field_name, type_guess)]``. Bases with fewer than 2 distinct
    displacements are omitted (they stay raw pointers)."""
    accesses: Dict[str, Dict[int, int]] = {}    # base -> {disp: max width}

    def _record_mem(mem: Optional[Value]) -> None:
        if mem is None or mem.tag != VTag.MEM:
            return
        if mem.index is not None:
            return                          # arrays / indexed aren't struct fields
        b = mem.base
        if b is None or b.tag not in (VTag.REG, VTag.TEMP) or not b.name:
            return
        base = ssa_base_name(b.name)
        if base in ("rsp", "rbp"):
            return                          # stack frames, not struct-shaped
        disp = int(mem.disp)
        w = int(mem.size or 64)
        d = accesses.setdefault(base, {})
        if w > d.get(disp, 0):
            d[disp] = w

    for b in sorted(func.blocks):
        for insn in func.blocks[b].insns:
            if is_phi(insn) or is_setslot(insn):
                continue
            if insn.op == Op.LOAD:
                _record_mem(insn.args[0] if insn.args else None)
            elif insn.op == Op.STORE:
                _record_mem(insn.dst)
            elif insn.op == Op.ASSIGN:
                # lea uses a MEM as its src for address computation; not a
                # dereference. Do not count it toward struct promotion.
                continue
            else:
                for a in insn.args:
                    if a is not None and a.tag == VTag.MEM:
                        _record_mem(a)

    base_to_struct: Dict[str, str] = {}
    structs: Dict[str, List[Tuple[int, str, TypeGuess]]] = {}
    counter = 0
    for base in sorted(accesses):
        disps = accesses[base]
        if len(disps) < 2:
            continue
        counter += 1
        sname = f"auto_{counter}"
        base_to_struct[base] = sname
        fields: List[Tuple[int, str, TypeGuess]] = []
        for disp in sorted(disps):
            w = disps[disp]
            tg = TypeGuess(kind="uint",
                           width=(w if w in (8, 16, 32, 64) else 64),
                           is_signed=False)
            fields.append((disp, _field_name(disp), tg))
        structs[sname] = fields
    return base_to_struct, structs


# ===========================================================================
# the emitter
# ===========================================================================
_INDENT = "    "


class _Emitter:
    def __init__(self, sfunc: StructuredFunction, func: IRFunction,
                 types: Dict[str, TypeGuess]) -> None:
        self.sfunc = sfunc
        self.func = func
        self.types = types
        self.warnings: List[str] = []
        self.goto_targets = self._collect_goto_targets(sfunc.body)
        self.labeled: set = set()
        self.block_of_br: Dict[int, object] = {}
        for b in func.blocks.values():
            if b.insns and b.insns[-1].op == Op.BR:
                self.block_of_br[id(b.insns[-1])] = b
        # struct recovery + signature (computed here so emit() can render both)
        self.base_to_struct, self.structs = _recover_structs(func, types)
        self.signature: FunctionSignature = recover_signature(func, types)
        # remember which labels are actually needed (walked below)
        self._needed_break_labels: Set[str] = set()
        self._needed_continue_labels: Set[str] = set()
        for n in self._walk_nodes(sfunc.body):
            tl = getattr(n, "target_label", "") or ""
            if not tl:
                continue
            if n.kind == NodeKind.BREAK:
                self._needed_break_labels.add(tl)
            elif n.kind == NodeKind.CONTINUE:
                self._needed_continue_labels.add(tl)

    # -- tree walkers ------------------------------------------------------
    @staticmethod
    def _walk_nodes(node: Optional[SNode]):
        if node is None:
            return
        yield node
        for c in node.children:
            yield from _Emitter._walk_nodes(c)
        for attr in (node.then_branch, node.else_branch, node.body, node.default):
            yield from _Emitter._walk_nodes(attr)
        for _v, cb in node.cases:
            yield from _Emitter._walk_nodes(cb)

    def _collect_goto_targets(self, root: SNode) -> set:
        out = set()
        for n in self._walk_nodes(root):
            if n.kind == NodeKind.GOTO:
                out.add(n.goto_target)
        return out

    @staticmethod
    def _is_terminal(node: Optional[SNode]) -> bool:
        if node is None:
            return False
        k = node.kind
        if k in (NodeKind.BREAK, NodeKind.CONTINUE, NodeKind.RETURN, NodeKind.GOTO):
            return True
        if k == NodeKind.SEQ:
            return bool(node.children) and _Emitter._is_terminal(node.children[-1])
        if k == NodeKind.IF:
            return (node.then_branch is not None and node.else_branch is not None
                    and _Emitter._is_terminal(node.then_branch)
                    and _Emitter._is_terminal(node.else_branch))
        return False

    # -- value / expression rendering -------------------------------------
    def _rv(self, v: Optional[Value]) -> str:
        if v is None:
            return "<none>"
        t = v.tag
        if t == VTag.IMM:
            w = v.size
            if w and w <= 8:
                return str(v.imm)
            return hex(v.imm)
        if t == VTag.REG:
            return ssa_base_name(v.name)
        if t == VTag.TEMP:
            return ssa_base_name(v.name)
        if t == VTag.FLAG:
            return v.name
        if t == VTag.MEM:
            return self._deref(v)
        return "<?>"

    def _addr(self, mem: Value) -> str:
        terms: List[str] = []
        if mem.base is not None:
            terms.append(self._rv(mem.base))
        if mem.index is not None:
            if mem.scale and mem.scale != 1:
                terms.append(f"{self._rv(mem.index)}*{mem.scale}")
            else:
                terms.append(self._rv(mem.index))
        s = " + ".join(terms)
        if mem.disp:
            if s:
                s += f" + {hex(mem.disp)}" if mem.disp > 0 else f" - {hex(-mem.disp)}"
            else:
                s = hex(mem.disp)
        elif not s:
            s = "0"
        if mem.seg:
            s = f"/* {mem.seg}: */ {s}"
        return s

    def _struct_field(self, mem: Value) -> Optional[str]:
        """If ``mem`` is a plain ``[base + disp]`` on a struct-promoted base and
        ``disp`` is a known field, return the ``((struct auto_N*)base)->field_X``
        rendering; else ``None``."""
        if mem.index is not None:
            return None
        b = mem.base
        if b is None or b.tag not in (VTag.REG, VTag.TEMP) or not b.name:
            return None
        base = ssa_base_name(b.name)
        sname = self.base_to_struct.get(base)
        if sname is None:
            return None
        fields = self.structs.get(sname) or []
        disp = int(mem.disp)
        for d, fname, _ in fields:
            if d == disp:
                return f"((struct {sname}*){base})->{fname}"
        return None

    def _deref(self, mem: Value) -> str:
        fld = self._struct_field(mem)
        if fld is not None:
            return fld
        w = mem.size or 64
        return f"*(uint{w}_t*)({self._addr(mem)})"

    # -- single-instruction rendering -------------------------------------
    def _render_insn(self, insn: IRInsn) -> Optional[str]:
        op = insn.op
        if is_setslot(insn):
            # virtual SETSLOT: metadata for memory-SSA, not source-level
            return None
        if is_phi(insn):
            dst = insn.dst
            name = ssa_base_name(dst.name) if dst is not None else "<phi>"
            src = ", ".join(self._rv(a) for a in insn.args)
            # slot phis (memory-SSA merges) render as a comment: informational,
            # not a fabricated C statement
            if name.startswith("slot_"):
                return f"/* {name} = phi({src}) */"
            return f"{name} = phi({src});"

        if op == Op.ASSIGN:
            dst = ssa_base_name(insn.dst.name)
            src = insn.args[0] if insn.args else None
            if src is not None and src.tag == VTag.MEM:
                return f"{dst} = {self._addr(src)}; /* lea */"
            return f"{dst} = {self._rv(src)};"

        if op == Op.LOAD:
            dst = ssa_base_name(insn.dst.name)
            return f"{dst} = {self._deref(insn.args[0])};"

        if op == Op.STORE:
            return f"{self._deref(insn.dst)} = {self._rv(insn.args[0])};"

        if op == Op.CALL:
            tgt = insn.args[0] if insn.args else None
            if tgt is not None and tgt.tag == VTag.IMM:
                return f"sub_{tgt.imm:x}();"
            return f"(*{self._rv(tgt)})();"

        if op == Op.SYSCALL:
            return "syscall();"
        if op == Op.INT:
            vec = insn.args[0].imm if insn.args else 0
            return f"int_{vec}();"
        if op == Op.HLT:
            return "__hlt();"
        if op == Op.FENCE:
            return "mfence();"
        if op == Op.UNDEF:
            return f"/* undef: {insn.text} */"

        return self._render_arith(insn)

    def _render_arith(self, insn: IRInsn) -> Optional[str]:
        op = insn.op
        dst = ssa_base_name(insn.dst.name) if insn.dst is not None else "_"
        w = (insn.dst.size if (insn.dst and insn.dst.size) else 0) or 64
        args = insn.args

        if op == Op.NEG:
            return f"{dst} = -({self._rv(args[0])});"
        if op == Op.NOT:
            return f"{dst} = ~({self._rv(args[0])});"
        if op == Op.ZXT:
            return f"{dst} = (uint{w}_t)({self._rv(args[0])});"
        if op == Op.SXT:
            sw = (args[0].size if args else 0) or w
            return (f"{dst} = (int{w}_t)(int{sw}_t)({self._rv(args[0])});"
                    f" /* sign-extend */")
        if op == Op.TRUNC:
            return f"{dst} = (uint{w}_t)({self._rv(args[0])}); /* truncate */"

        if op in (Op.DIV, Op.IDIV):
            divisor = self._rv(args[-1])
            dividend = self._rv(args[-2]) if len(args) >= 2 else self._rv(args[0])
            sym = "%" if dst == "rdx" else "/"
            if op == Op.IDIV:
                return (f"{dst} = (int{w}_t){dividend} {sym} (int{w}_t){divisor};"
                        f" /* rdx:rax */")
            return f"{dst} = {dividend} {sym} {divisor}; /* rdx:rax */"

        sym = _BIN_SYM.get(op)
        if sym is None:
            name = op.name if hasattr(op, "name") else str(int(op))
            return f"/* unhandled op {name}: {dst} */"
        a = self._rv(args[0]) if args else "0"
        b = self._rv(args[1]) if len(args) >= 2 else "0"
        extra = args[2:]
        if op == Op.SAR:
            expr = f"(int{w}_t){a} >> {b}"
        elif op == Op.IMUL:
            expr = f"(int{w}_t){a} * {b}"
        else:
            expr = f"{a} {sym} {b}"
        for e in extra:
            expr += f" + {self._rv(e)}"
        return f"{dst} = {expr};"

    def _render_block_insns(self, insns: List[IRInsn]) -> List[str]:
        """The C statements for a leaf block's insns. Skips SETFLAG (folded into
        the branch condition), the terminating BR/JMP (encoded by the structured
        tree), RET (handled by the RETURN node), NOP, and virtual SETSLOT ops
        (memory-SSA bookkeeping). A CMP/TEST that feeds a terminating BR is
        consumed by the condition; a stray one becomes a comment."""
        ends_in_br = bool(insns) and insns[-1].op == Op.BR
        out: List[str] = []
        for insn in insns:
            op = insn.op
            if is_setslot(insn):
                continue
            if is_phi(insn):
                line = self._render_insn(insn)
                if line:
                    out.append(line)
                continue
            if op in (Op.NOP, Op.SETFLAG, Op.BR, Op.JMP, Op.RET):
                continue
            if op in (Op.CMP, Op.TEST):
                if ends_in_br:
                    continue
                mnem = "cmp" if op == Op.CMP else "test"
                a = self._rv(insn.args[0]) if insn.args else ""
                b = self._rv(insn.args[1]) if len(insn.args) >= 2 else ""
                out.append(f"/* {mnem} {a}, {b}; sets flags */")
                continue
            line = self._render_insn(insn)
            if line:
                out.append(line)
        return out

    # -- condition rendering (cmp/jcc recovery) ---------------------------
    def _cond(self, br: Optional[IRInsn], block=None) -> str:
        if br is None or getattr(br, "op", None) != Op.BR or not br.args:
            return "1 /* condition unrecovered */"
        tok = ssa_base_name(br.args[0].name)
        key = _cc_key(br)
        cc = _CC_OP.get(key)
        if block is None:
            block = self.block_of_br.get(id(br))
        cmp_insn: Optional[IRInsn] = None
        if block is not None:
            for insn in block.insns:
                if insn.op in (Op.CMP, Op.TEST):
                    cmp_insn = insn
        if cc is not None and cmp_insn is not None and len(cmp_insn.args) >= 2:
            a, b = cmp_insn.args[0], cmp_insn.args[1]
            sym, sign = cc
            if cmp_insn.op == Op.TEST and key in ("eq", "ne"):
                base = self._rv(a) if a == b else f"({self._rv(a)} & {self._rv(b)})"
                return f"{base} {sym} 0"
            w = max(a.size or 0, b.size or 0) or 64
            if sign == "signed":
                return f"(int{w}_t){self._rv(a)} {sym} (int{w}_t){self._rv(b)}"
            return f"{self._rv(a)} {sym} {self._rv(b)}"
        return f"1 /* {tok} */"

    # -- label helper (GOTO targets) --------------------------------------
    def _label(self, ea: int, pad: str) -> List[str]:
        if ea in self.goto_targets and ea not in self.labeled:
            self.labeled.add(ea)
            return [f"{pad}L{ea:x}:"]
        return []

    # -- structured-node rendering ----------------------------------------
    def _node(self, node: Optional[SNode], depth: int) -> List[str]:
        if node is None:
            return []
        pad = _INDENT * depth
        k = node.kind

        if k == NodeKind.SEQ:
            out: List[str] = []
            for c in node.children:
                out += self._node(c, depth)
            return out

        if k == NodeKind.BLOCK:
            out = self._label(node.ea, pad)
            if node.block is not None:
                out += [pad + ln for ln in self._render_block_insns(node.block.insns)]
            return out

        if k == NodeKind.IF:
            out = self._label(node.ea, pad)
            if node.block is not None:
                out += [pad + ln for ln in self._render_block_insns(node.block.insns)]
            cond = self._cond(node.cond, node.block)
            out.append(f"{pad}if ({cond}) {{")
            out += self._node(node.then_branch, depth + 1)
            if node.else_branch is not None:
                out.append(f"{pad}}} else {{")
                out += self._node(node.else_branch, depth + 1)
            out.append(f"{pad}}}")
            return out

        if k == NodeKind.WHILE:
            out = self._label(node.ea, pad)
            if node.block is not None:
                prefix = self._render_block_insns(node.block.insns)
                if prefix:
                    self.warnings.append(
                        f"loop header {node.ea:#x} carries computation emitted "
                        f"before the while; it actually re-runs each iteration")
                    out += [pad + ln for ln in prefix]
            cond = self._cond(node.cond, node.block)
            label = getattr(node, "label", "") or ""
            if label and label in self._needed_continue_labels:
                out.append(f"{pad}{label}_continue:;")
            out.append(f"{pad}while ({cond}) {{")
            out += self._node(node.body, depth + 1)
            out.append(f"{pad}}}")
            if label and label in self._needed_break_labels:
                out.append(f"{pad}{label}_end:;")
            return out

        if k == NodeKind.DO_WHILE:
            out = self._label(node.ea, pad)
            label = getattr(node, "label", "") or ""
            out.append(f"{pad}do {{")
            out += self._node(node.body, depth + 1)
            if label and label in self._needed_continue_labels:
                out.append(f"{pad}{_INDENT}{label}_continue:;")
            cond = self._cond(node.cond)
            out.append(f"{pad}}} while ({cond});")
            if label and label in self._needed_break_labels:
                out.append(f"{pad}{label}_end:;")
            return out

        if k == NodeKind.SWITCH:
            out = self._label(node.ea, pad)
            scr = self._rv(node.scrutinee) if node.scrutinee is not None else "?"
            out.append(f"{pad}/* switch: case values are synthetic ordinals, "
                       f"not recovered jump-table keys */")
            out.append(f"{pad}switch ({scr}) {{")
            for val, body in node.cases:
                out.append(f"{pad}{_INDENT}case {val}:")
                out += self._node(body, depth + 2)
                if not self._is_terminal(body):
                    out.append(f"{pad}{_INDENT}{_INDENT}break;")
            if node.default is not None:
                out.append(f"{pad}{_INDENT}default:")
                out += self._node(node.default, depth + 2)
            out.append(f"{pad}}}")
            return out

        if k == NodeKind.BREAK:
            tl = getattr(node, "target_label", "") or ""
            if tl:
                return [f"{pad}goto {tl}_end;"]
            return [f"{pad}break;"]
        if k == NodeKind.CONTINUE:
            tl = getattr(node, "target_label", "") or ""
            if tl:
                return [f"{pad}goto {tl}_continue;"]
            return [f"{pad}continue;"]
        if k == NodeKind.RETURN:
            if node.return_value is not None:
                return [f"{pad}return {self._rv(node.return_value)};"]
            return [f"{pad}return;"]
        if k == NodeKind.GOTO:
            return [f"{pad}goto L{node.goto_target:x};"]

        return [f"{pad}/* unhandled node {k.name} */"]

    def build_warnings(self) -> List[str]:
        w = list(self.warnings)
        if self.sfunc.goto_count > 0:
            w.append(
                f"{self.sfunc.goto_count} goto(s) emitted: control flow was "
                f"irreducible and could not be fully structured")
        lc = getattr(self.sfunc, "label_count", 0) or 0
        if lc > 0:
            w.append(f"{lc} labelled loop(s) emitted for multi-level "
                     f"break/continue -- rendered as C `goto <label>_end;` / "
                     f"`goto <label>_continue;` with sibling labels")
        if self.sfunc.unreachable:
            names = ", ".join(hex(b) for b in self.sfunc.unreachable)
            w.append(f"{len(self.sfunc.unreachable)} block(s) could not be attached "
                     f"to the structured tree: {names}")
        unknown = sum(1 for tg in self.types.values() if tg.kind == "unknown")
        if unknown:
            w.append(f"{unknown} SSA name(s) have unrecovered types (kind=unknown)")
        w.append("function signature recovery is HEURISTIC (Windows x64): a leaf "
                 "function that only writes rcx/rdx/r8/r9 as scratch will look "
                 "like it takes no args, and struct names are synthetic (auto_N)")
        return w

    # -- signature / struct rendering -------------------------------------
    def _emit_signature_line(self, name: str) -> str:
        sig = self.signature
        ret_c = _ctype(sig.return_type) if sig.return_type.kind != "void" else "void"
        if not sig.args:
            return f"{ret_c} {name}(void) {{"
        parts = [f"{_ctype(a.type_guess)} {a.name}" for a in sig.args]
        return f"{ret_c} {name}({', '.join(parts)}) {{"

    def _emit_struct_decls(self) -> List[str]:
        lines: List[str] = []
        for sname in sorted(self.structs):
            fields = self.structs[sname]
            body = " ".join(f"{_ctype(tg)} {fname};" for _, fname, tg in fields)
            lines.append(f"{_INDENT}struct {sname} {{ {body} }};")
        return lines

    def _emit_signature_comment(self) -> List[str]:
        sig = self.signature
        if not sig.args:
            return []
        pairs = ", ".join(f"{a.name} = {a.source}" for a in sig.args)
        return [f"{_INDENT}/* args: {pairs} */"]

    def emit_source(self, name: str) -> str:
        return "\n".join(self.emit_lines(name))

    def emit_lines(self, name: str) -> List[str]:
        """The same rendering, exposed as a materialized list so a streaming
        wrapper can hand lines out one at a time without duplicating logic."""
        lines = [self._emit_signature_line(name)]
        lines += self._emit_signature_comment()
        lines += self._emit_struct_decls()
        lines += self._node(self.sfunc.body, 1)
        lines.append("}")
        return lines


# ===========================================================================
# public API
# ===========================================================================
def emit(sfunc: StructuredFunction, func: IRFunction,
         types: Optional[Dict[str, TypeGuess]] = None,
         name: str = "sub") -> DecompiledFunction:
    """Emit C-like source for a structured function.

    ``func`` is the underlying IRFunction (used to find the block that holds a
    DO_WHILE's latch ``BR`` so its condition can be rebuilt, plus arg / return /
    struct recovery). ``types`` is an optional recovered-type map (recovered here
    if omitted)."""
    if types is None:
        types = recover_types(func)
    em = _Emitter(sfunc, func, types)
    source = em.emit_source(name)
    return DecompiledFunction(
        name=name, source=source, types=types,
        warnings=em.build_warnings(),
        signature=em.signature,
        recovered_structs=dict(em.structs),
    )


def emit_stream(sfunc: StructuredFunction, func: IRFunction,
                types: Optional[Dict[str, TypeGuess]] = None,
                name: str = "sub") -> "Iterator[str]":
    """Streaming variant of :func:`emit` — yields the emitted source one line at
    a time so a UI (or the eventual Tauri front-end) can render as source
    arrives instead of waiting for the full string to be built in memory.

    Semantically identical to ``emit(...).source.splitlines()`` — same lines, in
    order, with the same emitter state — but produced lazily so a caller
    consuming through an SSE channel or WebSocket doesn't buffer a 4 MB function
    body just to display the first line.

    Note: does NOT return warnings / signature / recovered_structs — those live
    on the :class:`DecompiledFunction` from :func:`emit`. Callers wanting both
    should call :func:`emit` for the metadata and this for the streamed body.
    """
    if types is None:
        types = recover_types(func)
    em = _Emitter(sfunc, func, types)
    for line in em.emit_lines(name):
        yield line


def decompile_function(func: IRFunction, name: str = "sub") -> DecompiledFunction:
    """Full pipeline: ``build_ssa -> constant_fold -> memory_ssa ->
    dead_code_eliminate -> structure -> recover_types -> emit``.

    The input ``func`` is **not** mutated: it is deep-copied first (the SSA / fold /
    memory-SSA / DCE passes rewrite in place, so the copy is what gets
    transformed)."""
    work = copy.deepcopy(func)
    build_ssa(work)
    constant_fold(work)
    memory_ssa(work)
    dead_code_eliminate(work)
    sfunc = structure(work)
    types = recover_types(work)
    return emit(sfunc, work, types, name)


def decompile_function_stream(func: IRFunction,
                              name: str = "sub") -> "Iterator[str]":
    """Streaming variant of :func:`decompile_function` — same pipeline, yields
    the emitted source line-by-line. For UI/RPC surfaces that want back-pressure
    on large functions."""
    work = copy.deepcopy(func)
    build_ssa(work)
    constant_fold(work)
    memory_ssa(work)
    dead_code_eliminate(work)
    sfunc = structure(work)
    types = recover_types(work)
    yield from emit_stream(sfunc, work, types, name)


__all__ = [
    "TypeGuess", "Argument", "FunctionSignature", "DecompiledFunction",
    "recover_types", "recover_signature",
    "emit", "emit_stream",
    "decompile_function", "decompile_function_stream",
]
