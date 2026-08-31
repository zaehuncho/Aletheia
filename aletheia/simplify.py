"""Decompiler *simplification* passes over Aletheia's bounded-op SSA IR.

This is the deobfuscation sibling of :mod:`aletheia.dataflow`: where dataflow
gives the IR SSA form + generic clean-ups (DCE, constant folding), this module
recognises and rewrites the *specific* IR shapes that binary obfuscators
(Themida / VMProtect / Tigress / Obfuscator-LLVM) plant to make pseudocode
unreadable. Three passes, each a **pure static-analysis IR-to-IR rewrite** -- no
execution, no dynamic instrumentation, stdlib only:

    opaque_predicate_pass(func)   # kill always-true / always-false branches
    flattening_pass(func)         # undo control-flow flattening (dispatcher hops)
    mba_pass(func)                # collapse mixed boolean-arithmetic identities

and :func:`simplify`, which runs all three to a fixpoint.

--------------------------------------------------------------------------------
In-place, SSA-assuming, and honest about scope
--------------------------------------------------------------------------------
Every pass **mutates ``func`` in place** and returns a count (mirroring
:mod:`aletheia.dataflow`'s ``dead_code_eliminate`` / ``constant_fold`` style).
The passes are written to run *after* :func:`aletheia.dataflow.build_ssa` +
:func:`aletheia.dataflow.constant_fold`, but they key on **SSA base names**
(:func:`aletheia.dataflow.ssa_base_name`) and structural equality, so they are
correct on pre-SSA IR too -- SSA merely makes ``x`` and ``x`` the same versioned
name, which is exactly what the structural matchers already require.

Each pass is **idempotent**: once it has fired, the rewritten shape no longer
matches, so a second call finds nothing (fixpoint). :func:`simplify` loops the
three passes until a whole iteration makes no change (or ``max_passes``).

The cardinal rule here is **do not fabricate**. Every pass has an explicit "when
it bails" story (documented on each function). If pattern detection is not a
*provable* match, the count stays 0 and the IR is left byte-for-byte untouched.
These passes catch the *cheap, common* forms; they are emphatically NOT a
substitute for the symbolic executor a sibling task builds (see the per-pass
"Ceiling" notes).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from aletheia.ir import IRFunction, IRInsn, Op, Value, VTag
from aletheia.dataflow import (
    dead_code_eliminate,
    is_phi,
    ssa_base_name,
)

_SCALAR = (VTag.REG, VTag.TEMP, VTag.FLAG)


# ===========================================================================
# result type
# ===========================================================================
@dataclass
class SimplifyResult:
    opaque_removed: int = 0
    flattening_undone: int = 0     # number of dispatcher hops rewritten
    mba_rewrites: int = 0
    passes_run: int = 0            # top-level fixpoint iterations before quiescence


# ===========================================================================
# shared helpers
# ===========================================================================
def _build_def_map(func: IRFunction) -> Dict[str, IRInsn]:
    """``ssa-name -> defining IRInsn`` for every scalar (REG/TEMP/FLAG) def.

    In SSA there is exactly one def per name; on pre-SSA IR the last def wins
    (fine -- the structural matchers only ever look at a def to peel one arith
    layer, never to reason about reaching definitions)."""
    dm: Dict[str, IRInsn] = {}
    for blk in func.blocks.values():
        for insn in blk.insns:
            d = insn.dst
            if d is not None and d.tag in _SCALAR and d.name:
                dm[d.name] = insn
    return dm


def _def_insn(dm: Dict[str, IRInsn], v: Optional[Value]) -> Optional[IRInsn]:
    """The insn defining ``v`` (a scalar), or None. Phi defs return None -- we
    treat a phi result as an opaque leaf (never trace through a merge)."""
    if v is None or v.tag not in (VTag.REG, VTag.TEMP) or not v.name:
        return None
    di = dm.get(v.name)
    if di is None or is_phi(di):
        return None
    return di


def _same_val(u: Optional[Value], v: Optional[Value]) -> bool:
    """Structural value equality used for variable binding + ``x == x`` detection.

    IMMs compare by value; scalars by (tag, name); MEM by its full addressing
    shape. Size is intentionally ignored (a sub-register read of the same SSA
    name is the same value for our purposes)."""
    if u is None or v is None:
        return u is v
    if u.tag is VTag.IMM and v.tag is VTag.IMM:
        return u.imm == v.imm
    if u.tag in _SCALAR and v.tag in _SCALAR:
        return u.tag == v.tag and u.name == v.name
    if u.tag is VTag.MEM and v.tag is VTag.MEM:
        return (_same_val(u.base, v.base) and _same_val(u.index, v.index)
                and u.scale == v.scale and u.disp == v.disp and u.seg == v.seg)
    return False


# ===========================================================================
# Pass 1: opaque-predicate reduction
# ===========================================================================
# jcc predicate token -> "arithmetic (signed/subtract) compare" or "zero/eq".
_EQ_TOKENS = frozenset({"eq"})
_NE_TOKENS = frozenset({"ne"})


def _nearest_compare(blk, br_index: int) -> Optional[IRInsn]:
    """The CMP / TEST insn feeding a ``BR`` -- the nearest one *above* ``br_index``
    in the same block (the lifter always emits ``cmp/test`` then its ``setflag``s
    then the ``jcc`` inside one basic block). None if the block computes its
    condition some other way (``jrcxz`` / a boolean temp), in which case the
    opaque pass declines to reason about it."""
    for i in range(br_index - 1, -1, -1):
        op = blk.insns[i].op
        if op in (Op.CMP, Op.TEST):
            return blk.insns[i]
    return None


def _is_square(dm: Dict[str, IRInsn], v: Optional[Value]) -> bool:
    """True if ``v`` is provably ``t * t`` for some ``t`` (``MUL``/``IMUL`` whose
    two operands are the *same* SSA value)."""
    di = _def_insn(dm, v)
    if di is None or di.op not in (Op.MUL, Op.IMUL) or len(di.args) != 2:
        return False
    return _same_val(di.args[0], di.args[1]) and di.args[0].tag != VTag.IMM


def _provably_zero(dm: Dict[str, IRInsn], v: Optional[Value], depth: int = 0) -> bool:
    """True if ``v`` is provably 0 by construction (the value an obfuscator hides a
    constant behind). Cheap syntactic cases only:

    * an ``IMM 0``;
    * ``ASSIGN dst = IMM 0`` (or an ASSIGN copy of another provably-zero value);
    * ``x & 0`` / ``0 & x`` (``AND`` with a zero operand) -- the ``x & 0`` form;
    * ``x ^ x`` / ``x - x`` (``XOR``/``SUB`` of identical operands);
    * ``x * 0`` (``MUL``/``IMUL`` with a zero operand).

    Recursion is depth-bounded; anything else returns False (unknown, not zero)."""
    if v is None:
        return False
    if v.tag is VTag.IMM:
        return v.imm == 0
    if depth > 8:
        return False
    di = _def_insn(dm, v)
    if di is None:
        return False
    op = di.op
    if op is Op.ASSIGN and len(di.args) == 1:
        return _provably_zero(dm, di.args[0], depth + 1)
    if op is Op.AND and len(di.args) == 2:
        return (_provably_zero(dm, di.args[0], depth + 1)
                or _provably_zero(dm, di.args[1], depth + 1))
    if op in (Op.MUL, Op.IMUL) and len(di.args) == 2:
        return (_provably_zero(dm, di.args[0], depth + 1)
                or _provably_zero(dm, di.args[1], depth + 1))
    if op in (Op.XOR, Op.SUB) and len(di.args) == 2:
        return (_same_val(di.args[0], di.args[1])
                and di.args[0].tag != VTag.IMM)
    return False


def _br_token(br: IRInsn) -> Optional[str]:
    """The jcc predicate token of a ``BR`` (``cc_ge#0`` -> ``"ge"``), or None."""
    if not br.args:
        return None
    name = ssa_base_name(br.args[0].name) if br.args[0].name else ""
    if not name.startswith("cc_"):
        return None
    return name[3:]


def _evaluate_opaque(dm: Dict[str, IRInsn], token: str, cmp_insn: IRInsn
                     ) -> Optional[bool]:
    """Return True (branch always taken), False (never), or None (unknown) for a
    ``BR`` with predicate ``token`` fed by ``cmp_insn`` (a CMP or TEST).

    Pattern library (the cheap forms Themida/VMProtect plant):

    * ``x * x >= 0``  -> True   (signed square is non-negative; INT_MIN edge is a
                                 documented punt -- ``INT_MIN*INT_MIN`` overflows,
                                 but obfuscators seed the multiplicand, not it).
      ``x * x < 0``   -> False  (the negation).
    * ``x == x``      -> True ,  ``x != x`` -> False   (``cmp x, x``, identical
                                 SSA operands; NOT the ``test x, x`` zero form).
    * ``x - x == 0`` / ``x ^ x == 0`` / ``x & 0 == 0`` and any other provably-zero
      value compared ``== 0`` -> True ; ``!= 0`` -> False. (``test x, 0`` and
      ``test x, x`` zero-tests are covered here too.)

    Anything else -> None (no fabrication)."""
    if len(cmp_insn.args) != 2:
        return None
    a, b = cmp_insn.args
    is_test = cmp_insn.op is Op.TEST

    # -- signed square vs zero: x*x >= 0 (always) / x*x < 0 (never) ----------
    if not is_test and b.tag is VTag.IMM and b.imm == 0 and _is_square(dm, a):
        if token == "ge":
            return True
        if token == "lt":
            return False

    # -- x == x / x != x : a CMP of two identical (non-immediate) operands ---
    if not is_test and token in (_EQ_TOKENS | _NE_TOKENS):
        if _same_val(a, b) and a.tag != VTag.IMM:
            return token in _EQ_TOKENS

    # -- equality against a provably-zero value -----------------------------
    if token in (_EQ_TOKENS | _NE_TOKENS):
        zero_target = None
        if is_test:
            # test P, Q sets ZF iff (P & Q) == 0. Two provable-zero forms:
            #   test x, x   -> ZF iff x == 0        (target = x)
            #   test x, 0   -> P & 0 == 0 always    (the & result is provably 0)
            if _same_val(a, b) and a.tag != VTag.IMM:
                zero_target = a
            elif (a.tag is VTag.IMM and a.imm == 0) or (b.tag is VTag.IMM and b.imm == 0):
                # the AND result itself is provably zero -> ZF always set
                return token in _EQ_TOKENS
        else:
            # cmp C, 0  /  cmp 0, C  -> ZF iff C == 0
            if b.tag is VTag.IMM and b.imm == 0:
                zero_target = a
            elif a.tag is VTag.IMM and a.imm == 0:
                zero_target = b
        if zero_target is not None and _provably_zero(dm, zero_target):
            return token in _EQ_TOKENS

    return None


def _retarget_branch(func: IRFunction, blk, br: IRInsn, take_then: bool) -> None:
    """Rewrite ``br`` (a ``BR``) into an unconditional ``JMP`` to the surviving
    edge and delete the dead edge from ``blk.succs``. ``take_then`` picks the
    ``then_ea`` (always-true) vs ``else_ea`` (always-false) side."""
    target_ea = br.then_ea if take_then else br.else_ea
    dead_ea = br.else_ea if take_then else br.then_ea
    br.op = Op.JMP
    br.dst = None
    br.args = (Value(VTag.IMM, imm=target_ea, size=64),)
    if dead_ea != target_ea:
        blk.succs = [s for s in blk.succs if s != dead_ea]
    if target_ea not in blk.succs:
        blk.succs.append(target_ea)


def opaque_predicate_pass(func: IRFunction) -> int:
    """Reduce provably always-true / always-false ``BR`` branches to ``JMP``.

    For each block ending in ``BR``: recover the predicate token, find the CMP /
    TEST feeding it, trace the compared operands via SSA def-use, and consult the
    :func:`_evaluate_opaque` pattern library. A provable verdict rewrites the
    branch to an unconditional jump (dead edge deleted from ``succs``) and bumps
    the counter. Returns the number of branches reduced.

    Bails (leaves the branch untouched) when: the block's condition is not a
    ``cc_*`` token, there is no CMP/TEST feeding it, or no library pattern proves
    a constant verdict. Idempotent -- a reduced branch is a ``JMP`` and is never
    revisited.

    Ceiling: only the cheap syntactic forms above. Arbitrary opaque predicates
    (``7*x*x - 1 != y*y`` and friends) need the symbolic executor from the sibling
    task; this pass deliberately does not attempt them."""
    dm = _build_def_map(func)
    reduced = 0
    for blk in func.blocks.values():
        if not blk.insns:
            continue
        br = blk.insns[-1]
        if br.op is not Op.BR:
            continue
        token = _br_token(br)
        if token is None:
            continue
        cmp_insn = _nearest_compare(blk, len(blk.insns) - 1)
        if cmp_insn is None:
            continue
        verdict = _evaluate_opaque(dm, token, cmp_insn)
        if verdict is None:
            continue
        _retarget_branch(func, blk, br, take_then=verdict)
        reduced += 1
    return reduced


# ===========================================================================
# Pass 2: control-flow-flattening reversal
# ===========================================================================
def _reachable(func: IRFunction) -> set:
    if func.entry not in func.blocks:
        return set()
    seen, work = set(), [func.entry]
    while work:
        b = work.pop()
        if b in seen:
            continue
        seen.add(b)
        for s in func.blocks[b].succs:
            if s in func.blocks and s not in seen:
                work.append(s)
    return seen


def _prune_unreachable(func: IRFunction) -> None:
    """Drop blocks no longer reachable from ``func.entry`` (the flattening
    dispatcher, once every chunk bypasses it)."""
    live = _reachable(func)
    for b in list(func.blocks):
        if b not in live:
            del func.blocks[b]


def _dispatch_table(func: IRFunction, dea: int, dm: Dict[str, IRInsn]
                    ) -> Optional[Tuple[str, Dict[int, int]]]:
    """Reconstruct ``(state_base_name, {case_value: target_block})`` for a
    candidate dispatcher block ``dea``, or None if it is not a reconstructable
    flattening dispatcher.

    Detection (all must hold, else None -> bail):

    * the block's terminator is an **indirect** ``JMP`` (target is not an IMM);
    * the jump target is a scalar register/temp -- NOT a memory load. If it traces
      to a ``LOAD`` (state kept in memory) we bail: memory state needs alias
      analysis we do not fake;
    * the block carries a reconstructable **case table**: one ``CMP state, IMM k``
      marker per successor, in successor order (the compares a switch lowers to,
      recovered here from the block's own body). The marker count must equal the
      successor count, or the table is ambiguous and we bail.

    This models the case table a real jump-table / cmp-chain analysis would
    recover; multi-block cmp-chain dispatchers are a documented miss (bail)."""
    blk = func.blocks[dea]
    if not blk.insns:
        return None
    term = blk.insns[-1]
    if term.op is not Op.JMP or not term.args:
        return None
    tgt = term.args[0]
    if tgt.tag is VTag.IMM:                      # direct jump: not a dispatcher
        return None
    if tgt.tag is VTag.MEM:                       # jmp [table+idx*8]: memory state
        return None
    if tgt.tag not in (VTag.REG, VTag.TEMP) or not tgt.name:
        return None
    di = _def_insn(dm, tgt)
    if di is not None and di.op is Op.LOAD:       # state read from memory -> bail
        return None
    state_base = ssa_base_name(tgt.name)

    keys: List[int] = []
    for ins in blk.insns[:-1]:
        if (ins.op is Op.CMP and len(ins.args) == 2
                and ins.args[1].tag is VTag.IMM
                and ins.args[0].name
                and ssa_base_name(ins.args[0].name) == state_base):
            keys.append(ins.args[1].imm)
    targets = list(blk.succs)
    if not keys or len(keys) != len(targets):     # table not reconstructable
        return None
    return state_base, dict(zip(keys, targets))


def _chunk_state_const(chunk, state_base: str) -> Optional[int]:
    """The constant a chunk unconditionally assigns to the state variable (the
    last ``ASSIGN state = IMM`` in the block), or None if it never sets state to a
    constant register value (e.g. it writes state via memory -> not rewritable)."""
    kval = None
    for ins in chunk.insns:
        if (ins.op is Op.ASSIGN and ins.dst is not None
                and ins.dst.tag in (VTag.REG, VTag.TEMP) and ins.dst.name
                and ssa_base_name(ins.dst.name) == state_base
                and len(ins.args) == 1 and ins.args[0].tag is VTag.IMM):
            kval = ins.args[0].imm
    return kval


def flattening_pass(func: IRFunction) -> int:
    """Undo one layer of control-flow flattening: rewrite each dispatcher *hop*
    into the direct jump the obfuscator hid.

    For every reconstructable dispatcher (see :func:`_dispatch_table`), find each
    **chunk** -- a block whose terminator is a direct ``JMP`` back to the
    dispatcher and which unconditionally sets ``state = K`` -- look ``K`` up in the
    case table, and rewrite the chunk's terminator to jump *directly* to that
    case's target (``succs`` updated to match). Once every chunk bypasses it the
    dispatcher becomes unreachable and is pruned, so the subsequent
    :func:`aletheia.dataflow.dead_code_eliminate` sweeps the now-dead ``state = K``
    writes and the structuring pass sees a plain reducible CFG.

    Returns the number of hops rewritten. Bails cleanly (returns 0, mutates
    nothing) on any of the documented failure modes:

    * **no dispatcher** -- no block ends in an indirect ``JMP`` through a register;
    * **state variable not obvious** -- the indirect jump goes through a memory
      operand, or through a value that traces to a ``LOAD`` (state kept in memory);
    * **case table not reconstructable** -- the dispatcher carries no ``CMP state,
      IMM`` markers, or a number that does not match its successor count;
    * **a chunk reads/writes state via memory** -- it has no ``ASSIGN state = IMM``,
      so its outgoing value is unknown and it is left alone (no fabrication);
    * **case value absent from the table** -- that chunk is skipped, unrewritten.

    Idempotent: after success the chunks jump to real targets and the dispatcher
    is gone, so a re-run finds no dispatcher and returns 0."""
    dm = _build_def_map(func)
    dispatchers = []
    for dea in list(func.blocks):
        tab = _dispatch_table(func, dea, dm)
        if tab is not None:
            dispatchers.append((dea, tab[0], tab[1]))

    rewritten = 0
    for dea, state_base, table in dispatchers:
        for cea in list(func.blocks):
            if cea == dea:
                continue
            chunk = func.blocks[cea]
            if not chunk.insns:
                continue
            term = chunk.insns[-1]
            if (term.op is not Op.JMP or not term.args
                    or term.args[0].tag is not VTag.IMM
                    or term.args[0].imm != dea):
                continue                          # not a jump back to this dispatcher
            kval = _chunk_state_const(chunk, state_base)
            if kval is None or kval not in table:
                continue                          # unknown state value -> no fabrication
            newt = table[kval]
            term.args = (Value(VTag.IMM, imm=newt,
                               size=term.args[0].size or 64),)
            chunk.succs = [newt]
            rewritten += 1

    if rewritten:
        _prune_unreachable(func)
    return rewritten


# ===========================================================================
# Pass 3: mixed boolean-arithmetic (MBA) equivalences
# ===========================================================================
# Pattern-AST matcher. A pattern is one of:
#   ("var", name)                 - matches any Value, binds name (re-use must eq)
#   ("imm", k)                    - matches IMM == k
#   ("op", Op, pA, pB, comm)      - matches a value defined by Op(a, b)
#   ("not", p)                    - matches a value defined by NOT(a)
#   ("neg", p)                    - matches a value defined by NEG(a)
#   ("double", p)                 - matches a value equal to 2 * p (see _match_double)
def _match(pat, value, dm, binds) -> bool:
    kind = pat[0]
    if kind == "var":
        name = pat[1]
        if name in binds:
            return _same_val(binds[name], value)
        binds[name] = value
        return True
    if kind == "imm":
        return value is not None and value.tag is VTag.IMM and value.imm == pat[1]
    if kind == "not":
        di = _def_insn(dm, value)
        if di is None or di.op is not Op.NOT or len(di.args) != 1:
            return False
        return _match(pat[1], di.args[0], dm, binds)
    if kind == "neg":
        di = _def_insn(dm, value)
        if di is None or di.op is not Op.NEG or len(di.args) != 1:
            return False
        return _match(pat[1], di.args[0], dm, binds)
    if kind == "double":
        return _match_double(pat[1], value, dm, binds)
    if kind == "op":
        _, op, pa, pb, comm = pat
        di = _def_insn(dm, value)
        if di is None or di.op is not op or len(di.args) != 2:
            return False
        return _match_pair(pa, pb, di.args[0], di.args[1], comm, dm, binds)
    return False


def _match_pair(pa, pb, va, vb, comm, dm, binds) -> bool:
    """Match ordered (pa,pb) against (va,vb); if ``comm`` also try the swap. Binds
    are snapshotted so a failed first ordering does not leak partial bindings."""
    snap = dict(binds)
    if _match(pa, va, dm, binds) and _match(pb, vb, dm, binds):
        return True
    if not comm:
        binds.clear()
        binds.update(snap)
        return False
    binds.clear()
    binds.update(snap)
    if _match(pa, vb, dm, binds) and _match(pb, va, dm, binds):
        return True
    binds.clear()
    binds.update(snap)
    return False


def _match_double(inner_pat, value, dm, binds) -> bool:
    """Match ``value == 2 * inner`` where the obfuscator may render the doubling as
    ``t + t`` (ADD), ``t << 1`` (SHL) or ``t * 2`` (MUL/IMUL)."""
    di = _def_insn(dm, value)
    if di is None:
        return False
    if di.op is Op.ADD and len(di.args) == 2 and _same_val(di.args[0], di.args[1]):
        return _match(inner_pat, di.args[0], dm, binds)
    if (di.op is Op.SHL and len(di.args) == 2
            and di.args[1].tag is VTag.IMM and di.args[1].imm == 1):
        return _match(inner_pat, di.args[0], dm, binds)
    if di.op in (Op.MUL, Op.IMUL) and len(di.args) == 2:
        a, b = di.args
        if b.tag is VTag.IMM and b.imm == 2:
            return _match(inner_pat, a, dm, binds)
        if a.tag is VTag.IMM and a.imm == 2:
            return _match(inner_pat, b, dm, binds)
    return False


def _V(name):
    return ("var", name)


# The rewrite catalog. Each entry:
#   (root_op, pA, pB, commutative, result_op, result_vars, citation)
# The insn must be `root_op(a, b)` with (pA,pB) ~ (a,b); on a match the insn is
# rewritten to `result_op(*[binds[v] for v in result_vars])`.
#
# Identities are from Warren, *Hacker's Delight* (2nd ed., ch. 2 -- "HD"), and
# Zhou, Main, Gu & Johnson, "Information Hiding in Software with Mixed
# Boolean-Arithmetic Transforms", WISA 2007 ("Zhou07"). Each is a ring/bitwise
# identity over fixed-width two's-complement integers.
_MBA_RULES = [
    # -x = ~x + 1                                  (two's complement; HD 2-2)
    (Op.ADD, ("not", _V("x")), ("imm", 1), True,
     Op.NEG, ("x",), "~x + 1 = -x  [HD 2-2]"),

    # x + y = (x ^ y) + 2*(x & y)                  (sum = xor + 2*carry; HD 2-16)
    (Op.ADD, ("op", Op.XOR, _V("x"), _V("y"), True),
     ("double", ("op", Op.AND, _V("x"), _V("y"), True)), True,
     Op.ADD, ("x", "y"), "(x^y) + 2*(x&y) = x + y  [HD 2-16, Zhou07]"),

    # x + y = (x | y) + (x & y)                    (HD 2-16)
    (Op.ADD, ("op", Op.OR, _V("x"), _V("y"), True),
     ("op", Op.AND, _V("x"), _V("y"), True), True,
     Op.ADD, ("x", "y"), "(x|y) + (x&y) = x + y  [HD 2-16]"),

    # x + y = 2*(x | y) - (x ^ y)                  (Zhou07)
    (Op.SUB, ("double", ("op", Op.OR, _V("x"), _V("y"), True)),
     ("op", Op.XOR, _V("x"), _V("y"), True), False,
     Op.ADD, ("x", "y"), "2*(x|y) - (x^y) = x + y  [Zhou07]"),

    # x | y = (x ^ y) + (x & y)                    (union = xor + intersection)
    (Op.ADD, ("op", Op.XOR, _V("x"), _V("y"), True),
     ("op", Op.AND, _V("x"), _V("y"), True), True,
     Op.OR, ("x", "y"), "(x^y) + (x&y) = x | y  [HD 2-16]"),

    # x ^ y = (x | y) - (x & y)                    (HD 2-16)
    (Op.SUB, ("op", Op.OR, _V("x"), _V("y"), True),
     ("op", Op.AND, _V("x"), _V("y"), True), False,
     Op.XOR, ("x", "y"), "(x|y) - (x&y) = x ^ y  [HD 2-16]"),

    # x & y = (x | y) - (x ^ y)                    (intersection = union - xor)
    (Op.SUB, ("op", Op.OR, _V("x"), _V("y"), True),
     ("op", Op.XOR, _V("x"), _V("y"), True), False,
     Op.AND, ("x", "y"), "(x|y) - (x^y) = x & y  [HD 2-16]"),

    # x ^ y = (x & ~y) | (~x & y)                  (definition of xor)
    (Op.OR, ("op", Op.AND, _V("x"), ("not", _V("y")), True),
     ("op", Op.AND, ("not", _V("x")), _V("y"), True), True,
     Op.XOR, ("x", "y"), "(x&~y) | (~x&y) = x ^ y  [xor definition]"),

    # x ^ y = (x | y) & ~(x & y)                   (union minus intersection)
    (Op.AND, ("op", Op.OR, _V("x"), _V("y"), True),
     ("not", ("op", Op.AND, _V("x"), _V("y"), True)), True,
     Op.XOR, ("x", "y"), "(x|y) & ~(x&y) = x ^ y  [standard]"),

    # x - y = (x ^ y) - 2*(~x & y)                 (Zhou07)
    (Op.SUB, ("op", Op.XOR, _V("x"), _V("y"), True),
     ("double", ("op", Op.AND, ("not", _V("x")), _V("y"), True)), False,
     Op.SUB, ("x", "y"), "(x^y) - 2*(~x&y) = x - y  [Zhou07]"),
]


def mba_pass(func: IRFunction) -> int:
    """Collapse mixed boolean-arithmetic identities to their simple form.

    For each ``ADD``/``SUB``/``AND``/``OR``/``XOR`` insn, reconstruct its operand
    sub-expressions via SSA def-use and test the :data:`_MBA_RULES` catalog
    (structural match, commutativity-aware). On the first match the insn is
    rewritten in place to the collapsed op over the bound leaf operands (e.g.
    ``(x^y) + 2*(x&y)`` becomes ``ADD x, y``); the now-dead intermediate insns are
    left for :func:`aletheia.dataflow.dead_code_eliminate`. Returns the number of
    rewrites.

    Bails per-insn: a plain ``x + y`` (operands are leaves, not the MBA sub-trees)
    matches nothing and is untouched. Idempotent -- the collapsed form is a bare
    binop whose operands no longer match any (compound) rule LHS.

    Ceiling: a fixed syntactic catalog of ~10 published two-operand identities. It
    does not solve arbitrary linear MBA (that wants the algebraic/SMT normaliser
    of the sibling task), nor does it do value numbering, so it only fires when the
    two occurrences of ``x`` are the *same* SSA name."""
    dm = _build_def_map(func)
    rewrites = 0
    for blk in func.blocks.values():
        for insn in blk.insns:
            if is_phi(insn) or len(insn.args) != 2:
                continue
            for (root_op, pa, pb, comm, res_op, res_vars, _cite) in _MBA_RULES:
                if insn.op is not root_op:
                    continue
                binds: Dict[str, Value] = {}
                if _match_pair(pa, pb, insn.args[0], insn.args[1], comm, dm, binds):
                    if all(v in binds for v in res_vars):
                        insn.op = res_op
                        insn.args = tuple(binds[v] for v in res_vars)
                        rewrites += 1
                        break
    return rewrites


# ===========================================================================
# driver
# ===========================================================================
def simplify(func: IRFunction, max_passes: int = 8) -> SimplifyResult:
    """Run all three simplification passes to fixpoint (up to ``max_passes``).

    Mutates ``func`` in place; returns the aggregate counts plus ``passes_run``
    (the number of productive top-level iterations before quiescence). Passes run
    in the order flattening -> opaque -> MBA each iteration, so a rewrite one pass
    exposes for another (an opaque branch that turns a block into a flattening
    chunk, say) is consumed on the following iteration -- which is exactly why a
    genuinely cascading input reports ``passes_run > 1``.

    Does NOT call ``build_ssa``/``constant_fold``/``dead_code_eliminate`` for you;
    the caller owns the surrounding pipeline. (Flattening does prune the dead
    dispatcher itself, so a follow-up DCE can sweep the freed state writes.)"""
    res = SimplifyResult()
    for _ in range(max(1, max_passes)):
        f = flattening_pass(func)
        o = opaque_predicate_pass(func)
        m = mba_pass(func)
        res.flattening_undone += f
        res.opaque_removed += o
        res.mba_rewrites += m
        if f + o + m == 0:
            break
        res.passes_run += 1
    return res


__all__ = [
    "SimplifyResult",
    "simplify",
    "opaque_predicate_pass",
    "flattening_pass",
    "mba_pass",
]
