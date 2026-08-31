"""SSA construction + textbook data-flow passes over Aletheia's bounded-op IR.

This is the compiler-course sibling of :mod:`aletheia.ir`: it takes the *pre-SSA*
linear IR the lifter emits (registers, flags, temps and memory as uniform
:class:`~aletheia.ir.Value` nodes) and gives it the shape a decompiler wants --
single-assignment names, a dominator tree, dominance frontiers, phi nodes -- then
runs two cheap optimisations on top (dead-code elimination and constant folding +
copy propagation). Everything here is stdlib-only; :mod:`aletheia.ir` is imported
for its types and never modified.

Pipeline (run in this order)::

    build_ssa(func)              # in place: versions every def/use, inserts phis
    dead_code_eliminate(func)    # mark-sweep over the SSA graph; returns #removed
    constant_fold(func)          # fold IMM arithmetic + copy-propagate; #rewrites

--------------------------------------------------------------------------------
The phi op: an int sentinel, not an enum member
--------------------------------------------------------------------------------
Phi is a *data-flow-layer* construct -- it does not exist in the pre-SSA IR the
lifter emits. It would be natural to add ``Op.SETPHI`` to :class:`aletheia.ir.Op`,
but (a) we may not modify ``ir.py`` and (b) Python forbids extending an
``IntEnum`` that already has members (``class Op2(Op): SETPHI = 100`` raises
``TypeError``, verified). So a phi is carried as a *virtual opcode*: an ``int``
sentinel :data:`PHI_OP_CODE` (= 100, well past ir.py's highest assignment, 54)
stored directly in ``IRInsn.op``. Real ops stay genuine ``Op`` members, so
``insn.op is Op.STORE`` etc. keep working; a phi is recognised with
:func:`is_phi` / ``insn.op == PHI_OP_CODE``. Use ``==`` (not ``is``) when
comparing an op that *might* be a phi against an ``Op`` member.

--------------------------------------------------------------------------------
What is (and is not) an SSA variable -- honest scope
--------------------------------------------------------------------------------
Registers (``VTag.REG``), flags (``VTag.FLAG``) and temps (``VTag.TEMP``) are
versioned as SSA variables, keyed by ``(tag, name)``. **Memory is deliberately
NOT versioned** (no memory-SSA / phi over ``[rbp-8]`` slots). Sound memory SSA
needs alias analysis -- deciding whether two address expressions can name the same
byte -- which is out of scope for a first cut and unsound to fake. Instead:

* a ``STORE`` is treated as an opaque side effect (a DCE *root*): its stored value
  and the *registers inside its address expression* are renamed as uses, but the
  memory location itself gets no version and no phi;
* a ``LOAD`` produces a normal versioned scalar dst; the registers in its address
  are renamed as uses.

This is the standard "registers in SSA, memory left concrete" first cut. It is
honest and useful (address-register data-flow is still tracked) but it means a
value round-tripped through memory (``store`` then ``load``) is *not* connected in
the SSA graph. Documented, not hidden.

--------------------------------------------------------------------------------
Opt-in memory SSA (stack-slot precise) -- :func:`memory_ssa`
--------------------------------------------------------------------------------
:func:`memory_ssa` is an **add-on pass** (run it *after* :func:`build_ssa`) that
tightens exactly the one honest gap above for the case that matters most: **stack
locals**. It versions memory locations whose address is a stable frame slot --
``[rsp + K]`` or ``[rbp + K]`` where ``rsp`` / ``rbp`` are not reassigned away from
the frame across the function -- so a value round-tripped ``store [rsp-8], rax`` ->
``load rbx, [rsp-8]`` becomes connected: the load is rewritten to read the stored
value directly (or a phi over stored values at a merge). Two slots alias iff they
share the same frame base and displacement -- there is **no partial-overlap
reasoning** (an 8-bit and a 64-bit store at the same disp are treated as distinct
slots, not overlapping).

**Honest non-coverage (unchanged -- still opaque, never connected):** heap and
heap-adjacent memory (``[rax + K]`` for an arbitrary register) is *not* versioned
-- exactly as before. Neither are indexed stack accesses (``[rsp + rcx*4 + K]``:
the runtime index defeats a compile-time slot identity -- they act only as a
conservative may-alias *barrier* over that frame base, never as a precise def).
memcpy/``rep movs``-shaped **bulk copies** are not modelled (the lifter emits them
as ``UNDEF``), and there is **no escape analysis**: if a stack address is taken and
written through a pointer or by a ``CALL``, this pass does not see the aliasing.
The pass is deliberately scoped to the stack-slot case, where locals live and where
the emitter's current output is worst; everything else stays as opaque as it is
today.

Other inherited simplifications: partial sub-register writes are treated as full
defs of the parent GPR (the lifter already widens ``mov al,1`` to ``dst=rax``; the
upper-bit preservation is not modelled here either), and the synthetic ``cc_*``
condition tokens on ``BR`` are uses with no def, so they rename to version ``#0``.

--------------------------------------------------------------------------------
SSA name encoding
--------------------------------------------------------------------------------
A version is an integer suffix on ``Value.name``: ``rax`` -> ``rax#3``. Version
``#0`` means "live-in / no reaching definition in the function" (the implicit
bottom of every rename stack). :func:`ssa_base_name` / :func:`ssa_version`
recover the pieces.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
from typing import Dict, List, Optional, Set, Tuple, Union

from aletheia.ir import IRBlock, IRFunction, IRInsn, Op, Value, VTag

# Virtual opcode for a phi node (see module docstring). 100 is well past the
# highest real Op value (Op.FENCE == 54) and is not a member value of Op.
PHI_OP_CODE: int = 100

# Value tags that name an SSA variable (memory is intentionally excluded).
_SSA_TAGS = (VTag.REG, VTag.FLAG, VTag.TEMP)

# A "variable" identity: (tag, base-name). Names don't collide across tags in the
# lifter's output (GPRs vs 2-letter flags vs ``t..``/``cc_..`` temps), but keying
# on the tag too keeps it unambiguous.
Var = Tuple[VTag, str]


# ===========================================================================
# SSA name helpers
# ===========================================================================
def ssa_base_name(name: Union[str, Value]) -> str:
    """Strip a ``#N`` SSA version suffix. Accepts a name string or a ``Value``.

    ``"rax#7" -> "rax"``, ``"rcx" -> "rcx"``. A ``Value`` is unwrapped to its
    ``.name`` first (so ``ssa_base_name(insn.dst)`` works too)."""
    if hasattr(name, "name"):                # a Value -> use its name field
        name = name.name
    if not isinstance(name, str):
        return name
    i = name.rfind("#")
    if i != -1 and name[i + 1:].isdigit():
        return name[:i]
    return name


def ssa_version(name: Union[str, Value]) -> int:
    """Extract the ``N`` from a ``base#N`` SSA name, or ``-1`` if unversioned.

    ``"rax#7" -> 7``, ``"rcx" -> -1``."""
    if hasattr(name, "name"):
        name = name.name
    if not isinstance(name, str):
        return -1
    i = name.rfind("#")
    if i != -1 and name[i + 1:].isdigit():
        return int(name[i + 1:])
    return -1


def is_phi(insn: IRInsn) -> bool:
    """True if ``insn`` is a phi node (virtual :data:`PHI_OP_CODE` opcode)."""
    return insn.op == PHI_OP_CODE


# ===========================================================================
# CFG utilities (reachability, predecessors, dominators, frontiers)
# ===========================================================================
def _reachable(func: IRFunction) -> Set[int]:
    """Block starts reachable from ``func.entry`` via ``succs`` (existing blocks
    only)."""
    if func.entry not in func.blocks:
        return set()
    seen: Set[int] = set()
    work = [func.entry]
    while work:
        b = work.pop()
        if b in seen:
            continue
        seen.add(b)
        for s in func.blocks[b].succs:
            if s in func.blocks and s not in seen:
                work.append(s)
    return seen


def _predecessors(func: IRFunction, reachable: Set[int]) -> Dict[int, List[int]]:
    preds: Dict[int, List[int]] = {b: [] for b in reachable}
    for b in reachable:
        for s in func.blocks[b].succs:
            if s in reachable:
                preds[s].append(b)
    return preds


def _postorder(func: IRFunction, reachable: Set[int]) -> List[int]:
    """Iterative DFS post-order over the reachable sub-CFG from the entry."""
    entry = func.entry
    order: List[int] = []
    visited = {entry}
    stack: List[Tuple[int, iter]] = [(entry, iter(func.blocks[entry].succs))]
    while stack:
        node, it = stack[-1]
        advanced = False
        for s in it:
            if s in reachable and s not in visited:
                visited.add(s)
                stack.append((s, iter(func.blocks[s].succs)))
                advanced = True
                break
        if not advanced:
            order.append(node)
            stack.pop()
    return order


def dominators(func: IRFunction) -> Dict[int, int]:
    """Immediate dominators via the Cooper/Harvey/Kennedy iterative algorithm.

    Returns ``{block_start: idom_block_start}`` over blocks reachable from the
    entry; the entry maps to itself. (Cooper, Harvey & Kennedy, "A Simple, Fast
    Dominance Algorithm", 2001 -- the standard ~30-line data-flow version.)"""
    reachable = _reachable(func)
    if not reachable:
        return {}
    entry = func.entry
    order = _postorder(func, reachable)          # post-order
    po_num = {b: i for i, b in enumerate(order)}  # entry gets the highest number
    rpo = list(reversed(order))                  # reverse post-order
    preds = _predecessors(func, reachable)

    idom: Dict[int, int] = {entry: entry}

    def intersect(a: int, b: int) -> int:
        while a != b:
            while po_num[a] < po_num[b]:
                a = idom[a]
            while po_num[b] < po_num[a]:
                b = idom[b]
        return a

    changed = True
    while changed:
        changed = False
        for b in rpo:
            if b == entry:
                continue
            new_idom: Optional[int] = None
            for p in preds[b]:
                if p in idom:                    # only already-processed preds
                    new_idom = p if new_idom is None else intersect(p, new_idom)
            if new_idom is not None and idom.get(b) != new_idom:
                idom[b] = new_idom
                changed = True
    return idom


def dominance_frontiers(func: IRFunction,
                        idom: Dict[int, int]) -> Dict[int, Set[int]]:
    """Cytron et al. dominance frontiers from an immediate-dominator map.

    ``DF(n)`` is the set of blocks where ``n``'s dominance stops: a join ``j``
    is in ``DF(p)`` for each predecessor ``p`` of ``j`` on the walk up the
    dom-tree from ``p`` to (but not including) ``idom(j)``."""
    reachable = set(idom)
    df: Dict[int, Set[int]] = {b: set() for b in reachable}
    preds = _predecessors(func, reachable)
    for b in reachable:
        if len(preds[b]) < 2:                    # frontiers are seeded at joins
            continue
        for p in preds[b]:
            runner = p
            while runner != idom[b] and runner in idom:
                df[runner].add(b)
                runner = idom[runner]
    return df


# ===========================================================================
# use / def extraction
# ===========================================================================
def _collect_var_names(v: Optional[Value], out: Set[str]) -> None:
    """Collect SSA-variable *names* referenced by a Value (recursing into MEM
    base/index). IMMs contribute nothing."""
    if v is None:
        return
    if v.tag == VTag.MEM:
        _collect_var_names(v.base, out)
        _collect_var_names(v.index, out)
    elif v.tag in _SSA_TAGS and v.name:
        out.add(v.name)


def _collect_vars(v: Optional[Value], out: Set[Var]) -> None:
    """Like :func:`_collect_var_names` but yields ``(tag, name)`` identities."""
    if v is None:
        return
    if v.tag == VTag.MEM:
        _collect_vars(v.base, out)
        _collect_vars(v.index, out)
    elif v.tag in _SSA_TAGS and v.name:
        out.add((v.tag, v.name))


def _use_vars(insn: IRInsn) -> Set[Var]:
    """Variables *read* by ``insn``: every arg (recursively), plus the address
    registers of a STORE's destination MEM. A scalar ``dst`` is a def, not a
    use."""
    out: Set[Var] = set()
    for a in insn.args:
        _collect_vars(a, out)
    if insn.op == Op.STORE and insn.dst is not None:
        _collect_vars(insn.dst, out)             # base/index of the target MEM
    return out


def _use_names(insn: IRInsn) -> Set[str]:
    out: Set[str] = set()
    for a in insn.args:
        _collect_var_names(a, out)
    if insn.op == Op.STORE and insn.dst is not None:
        _collect_var_names(insn.dst, out)
    return out


def _def_var(insn: IRInsn) -> Optional[Var]:
    """The SSA variable ``insn`` defines, or None. A scalar (REG/FLAG/TEMP) dst is
    a def; a MEM dst (STORE) is not (memory is not versioned)."""
    d = insn.dst
    if d is not None and d.tag in _SSA_TAGS and d.name:
        return (d.tag, d.name)
    return None


def _def_name(insn: IRInsn) -> Optional[str]:
    d = insn.dst
    if d is not None and d.tag in _SSA_TAGS and d.name:
        return d.name
    return None


# ===========================================================================
# liveness (for pruned SSA phi placement)
# ===========================================================================
def _liveness(func: IRFunction, reachable: Set[int]
              ) -> Tuple[Dict[int, Set[Var]], Dict[int, Set[Var]]]:
    """Classic backward live-variable data flow over SSA-eligible variables,
    computed on the *pre-phi* IR. Returns ``(live_in, live_out)`` per block.

    Used to *prune* phi placement: a phi for V is only inserted at a join where V
    is actually live-in, avoiding dead phis (pruned SSA)."""
    use: Dict[int, Set[Var]] = {}
    dfn: Dict[int, Set[Var]] = {}
    for b in reachable:
        killed: Set[Var] = set()
        upward: Set[Var] = set()
        for insn in func.blocks[b].insns:
            for v in _use_vars(insn):
                if v not in killed:              # upward-exposed use
                    upward.add(v)
            d = _def_var(insn)
            if d is not None:
                killed.add(d)
        use[b] = upward
        dfn[b] = killed

    live_in: Dict[int, Set[Var]] = {b: set() for b in reachable}
    live_out: Dict[int, Set[Var]] = {b: set() for b in reachable}
    changed = True
    while changed:
        changed = False
        for b in reachable:
            lo: Set[Var] = set()
            for s in func.blocks[b].succs:
                if s in reachable:
                    lo |= live_in[s]
            li = use[b] | (lo - dfn[b])
            if li != live_in[b] or lo != live_out[b]:
                live_in[b] = li
                live_out[b] = lo
                changed = True
    return live_in, live_out


# ===========================================================================
# SSA construction
# ===========================================================================
def build_ssa(func: IRFunction) -> IRFunction:
    """Convert ``func`` to SSA form **in place** and return it.

    In-place: the passed ``IRFunction`` is mutated (dst/args renamed with ``#N``
    versions; phi ``IRInsn``s prepended to each block). Callers who need to keep
    the pre-SSA IR should ``copy.deepcopy(func)`` first.

    Canonical Cytron construction: dominator tree -> dominance frontiers ->
    (pruned) phi placement at the iterated dominance frontier of each variable's
    def sites -> dominator-tree renaming. Memory is not versioned (see module
    docstring); registers, flags and temps are."""
    reachable = _reachable(func)
    if not reachable:
        return func

    idom = dominators(func)
    df = dominance_frontiers(func, idom)
    preds = _predecessors(func, reachable)
    live_in, _ = _liveness(func, reachable)

    # ---- gather def sites + a prototype Value per variable ----------------
    blocks_defining: Dict[Var, Set[int]] = defaultdict(set)
    var_proto: Dict[Var, Value] = {}
    for b in reachable:
        for insn in func.blocks[b].insns:
            d = _def_var(insn)
            if d is not None:
                blocks_defining[d].add(b)
                var_proto.setdefault(d, insn.dst)

    # ---- phi placement (pruned Cytron worklist) ---------------------------
    # phis[b] holds freshly-built phi IRInsns; phi_meta maps a phi to its variable.
    phis: Dict[int, List[IRInsn]] = {b: [] for b in reachable}
    pred_order: Dict[int, List[int]] = {b: sorted(preds[b]) for b in reachable}
    phi_meta: Dict[int, Var] = {}

    for var, defsites in blocks_defining.items():
        has_phi: Set[int] = set()                # IDF blocks already visited
        ever: Set[int] = set(defsites)           # ever queued (avoid re-add)
        work = list(defsites)
        while work:
            n = work.pop()
            for y in df.get(n, ()):
                if y not in has_phi:
                    has_phi.add(y)
                    if var in live_in.get(y, ()):    # prune: only if live-in
                        order = pred_order[y]
                        phi = IRInsn(ea=y, op=PHI_OP_CODE,
                                     dst=var_proto[var],       # versioned at rename
                                     args=[None] * len(order))  # filled at rename
                        phis[y].append(phi)
                        phi_meta[id(phi)] = var
                if y not in ever:
                    ever.add(y)
                    work.append(y)

    # ---- rename (iterative dominator-tree walk) ---------------------------
    children: Dict[int, List[int]] = defaultdict(list)
    for b in reachable:
        if b != func.entry and b in idom:
            children[idom[b]].append(b)

    stacks: Dict[Var, List[int]] = defaultdict(lambda: [0])  # [-1] == current ver
    counter: Dict[Var, int] = defaultdict(int)               # last handed-out ver

    def clone(var: Var, ver: int) -> Value:
        base = var[1]
        return replace(var_proto[var], name=f"{base}#{ver}")

    def rename_use(v: Optional[Value]) -> Optional[Value]:
        if v is None:
            return v
        if v.tag == VTag.MEM:
            return replace(v,
                           base=rename_use(v.base) if v.base is not None else None,
                           index=rename_use(v.index) if v.index is not None else None)
        if v.tag in _SSA_TAGS and v.name:
            ver = stacks[(v.tag, v.name)][-1]
            return replace(v, name=f"{v.name}#{ver}")
        return v                                  # IMM (or nameless)

    # explicit stack of ("enter", block) / ("exit", pushed-vars) work items so a
    # deep dominator tree can't blow Python's recursion limit.
    work_stack: List[Tuple[str, object]] = [("enter", func.entry)]
    while work_stack:
        kind, payload = work_stack.pop()
        if kind == "exit":
            for var in payload:                   # unwind this block's versions
                stacks[var].pop()
            continue

        b = payload
        pushed: List[Var] = []

        # 1. phi dsts are defs at the top of the block
        for phi in phis[b]:
            var = phi_meta[id(phi)]
            counter[var] += 1
            ver = counter[var]
            stacks[var].append(ver)
            pushed.append(var)
            phi.dst = clone(var, ver)

        # 2. ordinary insns: rename uses, then version the def
        for insn in func.blocks[b].insns:
            insn.args = tuple(rename_use(a) for a in insn.args)
            if insn.op == Op.STORE and insn.dst is not None:
                insn.dst = rename_use(insn.dst)   # address regs are uses
            else:
                dv = _def_var(insn)
                if dv is not None:
                    counter[dv] += 1
                    ver = counter[dv]
                    stacks[dv].append(ver)
                    pushed.append(dv)
                    insn.dst = replace(insn.dst, name=f"{dv[1]}#{ver}")

        # 3. fill this block's slot in each successor's phis
        for s in func.blocks[b].succs:
            if s in phis and phis[s] and b in pred_order[s]:
                j = pred_order[s].index(b)
                for phi in phis[s]:
                    var = phi_meta[id(phi)]
                    phi.args[j] = clone(var, stacks[var][-1])

        # 4. schedule exit (pops versions) then dom-tree children
        work_stack.append(("exit", pushed))
        for c in sorted(children[b]):
            work_stack.append(("enter", c))

    # ---- finalise: freeze phi args, prepend phis to each block ------------
    for b in reachable:
        for phi in phis[b]:
            var = phi_meta[id(phi)]
            phi.args = tuple(
                a if a is not None else clone(var, 0)   # unfilled pred -> live-in
                for a in phi.args)
        if phis[b]:
            func.blocks[b].insns = phis[b] + func.blocks[b].insns

    return func


# ===========================================================================
# dead-code elimination (mark-sweep over the SSA graph)
# ===========================================================================
# Ops that visibly escape the function or steer control flow -- always live
# "roots". CMP/TEST are kept (they seed the SETFLAG chain and have no dst to
# sweep anyway); SETFLAG is kept wholesale -- see the note in dead_code_eliminate.
_ROOT_OPS = frozenset({
    Op.STORE, Op.CALL, Op.RET, Op.JMP, Op.BR, Op.SYSCALL, Op.INT, Op.HLT,
    Op.FENCE, Op.CMP, Op.TEST, Op.UNDEF, Op.NOP, Op.SETFLAG,
})


def dead_code_eliminate(func: IRFunction) -> int:
    """Remove pure value defs whose SSA name never reaches a side effect.

    Standard mark-sweep: every side-effecting / control op (:data:`_ROOT_OPS`) is
    a live root; a pure def (ASSIGN / LOAD / arithmetic / phi) is live only if its
    dst name is used, transitively, by something live. The marking loop is itself
    the fixpoint, so a single sweep suffices. Returns the number of insns removed.

    Trade-off (documented, conservative first cut): **all SETFLAG ops are kept**.
    Proving a flag def dead needs proving no downstream ``BR`` reads it; rather
    than risk dropping a live flag, we keep every SETFLAG (and, because a kept
    SETFLAG's operands are then "used", the arithmetic feeding a flag is kept even
    when its value result is otherwise dead). Tighter flag DCE is future work."""
    # name -> the insn that defines it (SSA: exactly one def per name)
    def_map: Dict[str, IRInsn] = {}
    all_insns: List[IRInsn] = []
    for b in sorted(func.blocks):
        for insn in func.blocks[b].insns:
            all_insns.append(insn)
            dn = _def_name(insn)
            if dn is not None:
                def_map[dn] = insn

    live_ids: Set[int] = set()
    work: List[IRInsn] = []
    for insn in all_insns:
        if is_phi(insn):
            continue                              # phis are pure defs, not roots
        if insn.op in _ROOT_OPS:
            live_ids.add(id(insn))
            work.append(insn)

    while work:
        insn = work.pop()
        for name in _use_names(insn):
            d = def_map.get(name)
            if d is not None and id(d) not in live_ids:
                live_ids.add(id(d))
                work.append(d)

    removed = 0
    for b in func.blocks:
        blk = func.blocks[b]
        kept = [i for i in blk.insns if id(i) in live_ids]
        removed += len(blk.insns) - len(kept)
        blk.insns = kept
    return removed


# ===========================================================================
# constant folding + copy propagation
# ===========================================================================
_FOLD_BINARY = frozenset({Op.ADD, Op.SUB, Op.AND, Op.OR, Op.XOR, Op.SHL, Op.SHR})
_FOLD_UNARY = frozenset({Op.NEG, Op.NOT})


def _mask(bits: int) -> int:
    return (1 << bits) - 1 if bits and bits > 0 else (1 << 64) - 1


def _op_width(insn: IRInsn) -> int:
    if insn.dst is not None and insn.dst.size:
        return insn.dst.size
    sizes = [a.size for a in insn.args if a.size]
    return max(sizes) if sizes else 64


def _fold_value(insn: IRInsn) -> Optional[int]:
    """Compute the constant result of ``insn`` if all its relevant operands are
    IMMs, else None. Wrap-around is applied to the operand width. Only the ops the
    task enumerates are handled (no signed SHR/SAR, no MUL/DIV, no SXT)."""
    op = insn.op
    w = _op_width(insn)
    m = _mask(w)

    if op in _FOLD_BINARY:
        if len(insn.args) != 2:                   # e.g. adc's extra CF -> skip
            return None
        x, y = insn.args
        if x.tag != VTag.IMM or y.tag != VTag.IMM:
            return None
        a, b = x.imm, y.imm
        if op == Op.ADD:
            return (a + b) & m
        if op == Op.SUB:
            return (a - b) & m
        if op == Op.AND:
            return (a & b) & m
        if op == Op.OR:
            return (a | b) & m
        if op == Op.XOR:
            return (a ^ b) & m
        if op == Op.SHL:
            return (a << (b & 63)) & m
        if op == Op.SHR:                          # logical (unsigned) shift only
            return ((a & m) >> (b & 63)) & m
        return None

    if op in _FOLD_UNARY:
        if len(insn.args) != 1 or insn.args[0].tag != VTag.IMM:
            return None
        a = insn.args[0].imm
        return ((-a) & m) if op == Op.NEG else ((~a) & m)

    if op == Op.ZXT:                              # zero-extend: value unchanged
        if len(insn.args) != 1 or insn.args[0].tag != VTag.IMM:
            return None
        src = insn.args[0].size or w
        return insn.args[0].imm & _mask(src)

    if op == Op.TRUNC:                            # keep low dst-width bits
        if len(insn.args) != 1 or insn.args[0].tag != VTag.IMM:
            return None
        return insn.args[0].imm & m

    return None


def constant_fold(func: IRFunction) -> int:
    """Constant-fold IMM arithmetic and copy-propagate IMM assignments, to a
    fixpoint. Returns the number of rewrites (folds + propagations) made.

    Two rules, re-run until nothing changes:

    * **Fold**: an op from the handled set (ADD/SUB/AND/OR/XOR/SHL/SHR, NEG/NOT,
      ZXT/TRUNC) whose relevant operands are all ``IMM`` is rewritten to
      ``ASSIGN dst = IMM(result)``, wrapped to the operand width.
    * **Copy-propagate**: for an ``ASSIGN dst = IMM(k)``, every later scalar use
      of ``dst`` is replaced by ``IMM(k)``.

    Because the input is SSA (one def per name), copy propagation is sound across
    blocks, not just within one -- so this runs function-wide, not block-local.
    The source ``ASSIGN dst = IMM(k)`` is left in place (its own DCE is
    :func:`dead_code_eliminate`'s job). Substitution is only into top-level scalar
    operands: constants are never pushed into a MEM address's base/index (that
    would change the addressing form), and flags are never affected (only REG/TEMP
    names are propagated)."""
    all_insns: List[IRInsn] = []
    for b in sorted(func.blocks):
        all_insns.extend(func.blocks[b].insns)

    total = 0
    while True:
        # constant environment: SSA name -> (value, width) for ASSIGN dst = IMM
        const_of: Dict[str, Tuple[int, int]] = {}
        for insn in all_insns:
            if (insn.op == Op.ASSIGN and insn.dst is not None
                    and insn.dst.tag in (VTag.REG, VTag.TEMP)
                    and len(insn.args) == 1 and insn.args[0].tag == VTag.IMM):
                const_of[insn.dst.name] = (insn.args[0].imm, insn.args[0].size)

        changed = 0

        # copy propagation into scalar REG/TEMP operands
        for insn in all_insns:
            if not insn.args:
                continue
            new_args = list(insn.args)
            touched = False
            for i, a in enumerate(new_args):
                if a.tag in (VTag.REG, VTag.TEMP) and a.name in const_of:
                    val, _sz = const_of[a.name]
                    new_args[i] = Value(VTag.IMM, imm=val, size=a.size)
                    touched = True
                    changed += 1
            if touched:
                insn.args = tuple(new_args)

        # fold now-constant arithmetic
        for insn in all_insns:
            if insn.op == Op.ASSIGN or is_phi(insn):
                continue
            res = _fold_value(insn)
            if res is not None:
                width = insn.dst.size if (insn.dst and insn.dst.size) else _op_width(insn)
                insn.op = Op.ASSIGN
                insn.args = (Value(VTag.IMM, imm=res, size=width),)
                changed += 1

        total += changed
        if changed == 0:
            break
    return total


# ===========================================================================
# memory SSA -- stack-slot precise (opt-in; run AFTER build_ssa)
# ===========================================================================
# Virtual opcode for a slot "definition" produced by a STORE: a SETSLOT op whose
# ``dst`` is the slot's next SSA version and ``args`` is the stored value. 101 is
# one past PHI_OP_CODE (100) and, like it, is NOT a member value of Op -- so
# ``insn.op is Op.STORE`` etc. keep working and a SETSLOT is recognised only by
# ``insn.op == MEM_SSA_OP_CODE`` / :func:`is_setslot`. (This is the documented
# sentinel-opcode choice from the two the task offered: a virtual SETSLOT, not an
# Op.ASSIGN over a FLAG-shaped Value.) A memory phi reuses the existing
# PHI_OP_CODE, so no third opcode is minted.
MEM_SSA_OP_CODE: int = 101

# Frame base registers whose slots this pass will version.
_FRAME_BASES = ("rsp", "rbp")


@dataclass(frozen=True)
class MemSlot:
    """A tracked memory location -- one stack slot.

    ``base_name`` is the SSA *base* name of the addressing register (``'rsp'`` or
    ``'rbp'`` -- the ``#N`` version is stripped, and the pass only tracks a base
    whose frame value is stable, so every access shares one version). ``disp`` is
    the constant displacement, normalised to a signed int (``[rsp - 8]`` ==
    ``[rsp + -8]`` -> ``disp == -8``). ``width`` is the access size in bits
    (8/16/32/64/128).

    Two slots alias iff they have the **same ``base_name`` and the same ``disp``**
    -- there is no partial-overlap reasoning (a byte store and a qword store at the
    same disp are distinct slots, not overlapping). This is the stack-slot-precise
    first cut: **heap / heap-adjacent memory (``[rax + K]`` for an arbitrary
    register) is NOT modelled** -- it stays opaque exactly as the non-memory-SSA
    path leaves it -- and indexed stack accesses (``[rsp + reg*scale + K]``) are
    not precise slots either (see the module docstring)."""
    base_name: str
    disp: int
    width: int


# Sentinel value returned by :func:`collect_memory_slots` for a STORE/LOAD memory
# operand that was recognised but is NOT a tracked stack slot (heap base, indexed
# stack access, or a slot on a frame base that failed the stability check). It is a
# distinct MemSlot instance; test for it with ``is`` (identity), not ``==``.
UNTRACKED = MemSlot(base_name="", disp=0, width=0)


def is_setslot(insn: IRInsn) -> bool:
    """True if ``insn`` is a virtual SETSLOT slot-definition (see
    :data:`MEM_SSA_OP_CODE`)."""
    return insn.op == MEM_SSA_OP_CODE


def _slot_key(base_name: str, disp: int, width: int) -> str:
    """The versioned-variable name stem for a slot: ``slot_<base>_<disp>_<width>``."""
    return f"slot_{base_name}_{disp}_{width}"


def _iter_mem_operands(insn: IRInsn):
    """Yield the MEM Values that ``insn`` addresses: its ``dst`` (a STORE target)
    and any MEM among its ``args`` (a LOAD source, or a raw MEM operand)."""
    d = insn.dst
    if d is not None and d.tag == VTag.MEM:
        yield d
    for a in insn.args:
        if a is not None and a.tag == VTag.MEM:
            yield a


def _frame_stability(func: IRFunction) -> Set[str]:
    """Which of ``rsp`` / ``rbp`` have a *stable* frame value across ``func`` and so
    may be tracked. A base is UNSTABLE (bailed, function-wide) if either:

    * it is the ``dst`` of an ``ASSIGN`` whose source is not the register ``rsp``
      (``mov rsp, rax`` bails rsp; ``mov rbp, rax`` bails rbp; but the framing
      prologue ``mov rbp, rsp`` -- source *is* rsp -- is allowed), or
    * it appears as a memory-addressing base at **more than one** SSA version (e.g.
      a ``sub rsp, N`` mid-body followed by rsp-relative accesses on both sides):
      keying a slot on the bare base name would then alias two different addresses,
      so we refuse to track that base rather than be unsound.

    Real functions with a dynamic stack pointer are the honest edge case this
    guards; they simply get no stack memory SSA (count 0 for that base)."""
    versions: Dict[str, Set[int]] = {b: set() for b in _FRAME_BASES}
    bad: Set[str] = set()
    for blk in func.blocks.values():
        for insn in blk.insns:
            d = insn.dst
            if (insn.op == Op.ASSIGN and d is not None and d.tag == VTag.REG
                    and d.name):
                dbase = ssa_base_name(d.name)
                if dbase in _FRAME_BASES:
                    src = insn.args[0] if insn.args else None
                    src_is_rsp = (src is not None and src.tag == VTag.REG
                                  and ssa_base_name(src.name) == "rsp")
                    if not src_is_rsp:
                        bad.add(dbase)
            for mem in _iter_mem_operands(insn):
                b = mem.base
                if b is not None and b.tag == VTag.REG and b.name:
                    bn = ssa_base_name(b.name)
                    if bn in _FRAME_BASES:
                        versions[bn].add(ssa_version(b.name))
    return {b for b in _FRAME_BASES
            if b not in bad and len(versions[b]) <= 1}


def _classify_mem(mem: Optional[Value], stable: Set[str]):
    """Classify one MEM operand. Returns one of:

    * ``None``                                   -- not a MEM at all;
    * ``("slot", key, base, disp, width)``       -- a tracked stack slot;
    * ``("indexed", base, disp, width)``         -- a stable frame base but with an
      index register (a may-alias barrier, not a precise slot);
    * ``("heap", base_or_None, disp, width, idx)`` -- any other memory (arbitrary /
      unstable base, or no register base): opaque, never versioned."""
    if mem is None or mem.tag != VTag.MEM:
        return None
    b = mem.base
    base = (ssa_base_name(b.name)
            if (b is not None and b.tag == VTag.REG and b.name) else None)
    disp = int(mem.disp)
    width = mem.size or 64
    if base is not None and base in stable:
        if mem.index is not None:
            return ("indexed", base, disp, width)
        return ("slot", _slot_key(base, disp, width), base, disp, width)
    return ("heap", base, disp, width, mem.index is not None)


def collect_memory_slots(func: IRFunction) -> Dict[str, MemSlot]:
    """Walk the (SSA) IR and collect the stack-slot MEM operands :func:`memory_ssa`
    will version.

    Keys are ``"slot_<base>_<disp>_<width>"`` strings (the versioned-variable name
    stem). A tracked slot maps to its :class:`MemSlot`; any STORE/LOAD memory
    operand that does *not* resolve to a stable ``rsp``/``rbp`` ``+K`` slot -- a
    heap base, an indexed stack access, or a slot on a frame base that failed the
    stability check -- maps to the :data:`UNTRACKED` sentinel (keyed by its own
    ``base``/``disp``/``width``, with an ``_i`` suffix when indexed). Run this after
    :func:`build_ssa`; it does not mutate ``func``."""
    stable = _frame_stability(func)
    out: Dict[str, MemSlot] = {}
    for blk in func.blocks.values():
        for insn in blk.insns:
            if insn.op == Op.STORE:
                mems = [insn.dst]
            elif insn.op == Op.LOAD:
                mems = [insn.args[0]] if insn.args else []
            else:
                continue
            for mem in mems:
                c = _classify_mem(mem, stable)
                if c is None:
                    continue
                if c[0] == "slot":
                    _, key, base, disp, width = c
                    out[key] = MemSlot(base_name=base, disp=disp, width=width)
                elif c[0] == "indexed":
                    _, base, disp, width = c
                    out.setdefault(_slot_key(base, disp, width) + "_i", UNTRACKED)
                else:                                   # heap
                    _, base, disp, width, idx = c
                    key = _slot_key(base if base is not None else "none", disp, width)
                    out.setdefault(key + ("_i" if idx else ""), UNTRACKED)
    return out


def memory_ssa(func: IRFunction) -> int:
    """Version stack-slot memory in place and connect ``store`` -> ``load`` pairs.

    Run **after** :func:`build_ssa`. For every stable frame slot (``[rsp/rbp + K]``
    with a stable base -- see :func:`_frame_stability`):

    * each tracked ``STORE`` gains a virtual ``SETSLOT`` op (:data:`MEM_SSA_OP_CODE`)
      whose ``dst`` is the slot's next SSA version and whose arg is the stored
      value; the original ``STORE`` is kept (its memory side effect is real);
    * each tracked ``LOAD`` is resolved against the reaching slot definition found
      by a Cytron-style dominator-tree walk (with iterated-dominance-frontier phi
      placement for merges, pruned by slot liveness). A load reaching a store reads
      **through** to that store's source value -- the ``LOAD`` is rewritten to
      ``ASSIGN dst = <stored value>`` (the MEM operand is gone); a load reaching a
      phi becomes ``ASSIGN dst = <slot phi result>``; a load with no reaching
      in-function store (a live-in slot) is left untouched.

    Killing stores fall out for free (the nearest dominating store on the rename
    stack wins). Indexed stack accesses and ``CALL``s are conservative barriers /
    gaps (see the module docstring) -- never precise defs. Heap memory is untouched.

    Returns the number of loads substituted (loads whose MEM operand was replaced by
    a stored value or a slot phi). Idempotent: a second run finds the SETSLOT markers
    from the first and returns 0 without re-injecting anything."""
    reachable = _reachable(func)
    if not reachable:
        return 0
    # idempotency guard: SETSLOT markers exist iff a previous run already processed
    # a tracked store (and thus placed any phis) -- bail before re-injecting.
    for b in reachable:
        for insn in func.blocks[b].insns:
            if insn.op == MEM_SSA_OP_CODE:
                return 0

    stable = _frame_stability(func)
    if not stable:
        return 0

    idom = dominators(func)
    df = dominance_frontiers(func, idom)
    preds = _predecessors(func, reachable)
    pred_order: Dict[int, List[int]] = {b: sorted(preds[b]) for b in reachable}

    # ---- slot inventory: def sites, widths, and per-block slot liveness ----
    slot_width: Dict[str, int] = {}
    store_sites: Dict[str, Set[int]] = defaultdict(set)
    slot_use: Dict[int, Set[str]] = {b: set() for b in reachable}   # upward-exposed
    slot_def: Dict[int, Set[str]] = {b: set() for b in reachable}
    any_tracked = False
    for b in reachable:
        killed: Set[str] = set()
        for insn in func.blocks[b].insns:
            if insn.op == Op.STORE:
                c = _classify_mem(insn.dst, stable)
                if c is not None and c[0] == "slot":
                    key, width = c[1], c[4]
                    slot_width[key] = width
                    store_sites[key].add(b)
                    slot_def[b].add(key)
                    killed.add(key)
                    any_tracked = True
            elif insn.op == Op.LOAD:
                c = _classify_mem(insn.args[0] if insn.args else None, stable)
                if c is not None and c[0] == "slot":
                    key, width = c[1], c[4]
                    slot_width[key] = width
                    if key not in killed:
                        slot_use[b].add(key)
                    any_tracked = True
    if not any_tracked:
        return 0

    # ---- slot liveness (backward fixpoint; prunes dead phis) --------------
    live_in: Dict[int, Set[str]] = {b: set() for b in reachable}
    live_out: Dict[int, Set[str]] = {b: set() for b in reachable}
    changed = True
    while changed:
        changed = False
        for b in reachable:
            lo: Set[str] = set()
            for s in func.blocks[b].succs:
                if s in reachable:
                    lo |= live_in[s]
            li = slot_use[b] | (lo - slot_def[b])
            if li != live_in[b] or lo != live_out[b]:
                live_in[b], live_out[b] = li, lo
                changed = True

    def slot_val(key: str, ver: int) -> Value:
        return Value(VTag.TEMP, name=f"{key}#{ver}", size=slot_width.get(key, 64))

    # ---- phi placement (pruned Cytron IDF worklist per slot) --------------
    phis: Dict[int, List[IRInsn]] = {b: [] for b in reachable}
    phi_meta: Dict[int, str] = {}
    for key, defsites in store_sites.items():
        has_phi: Set[int] = set()
        ever: Set[int] = set(defsites)
        work = list(defsites)
        while work:
            n = work.pop()
            for y in df.get(n, ()):
                if y not in has_phi:
                    has_phi.add(y)
                    if key in live_in.get(y, ()):
                        phi = IRInsn(ea=y, op=PHI_OP_CODE, dst=None,
                                     args=[None] * len(pred_order[y]))
                        phis[y].append(phi)
                        phi_meta[id(phi)] = key
                if y not in ever:
                    ever.add(y)
                    work.append(y)

    # ---- rename: iterative dominator-tree walk ---------------------------
    # Each slot's stack holds (kind, value) reaching-def records:
    #   'store'   -> the stored source Value (read through on a load / phi arg)
    #   'phi'     -> the slot phi's dst Value (a load becomes a use of it)
    #   'live_in' -> the slot's #0 Value (no in-function def reaches; no substitute)
    #   'barrier' -> an opaque slot version from an indexed may-alias store
    children: Dict[int, List[int]] = defaultdict(list)
    for b in reachable:
        if b != func.entry and b in idom:
            children[idom[b]].append(b)

    stacks: Dict[str, List[Tuple[str, Value]]] = {}
    counter: Dict[str, int] = defaultdict(int)
    new_insns: Dict[int, List[IRInsn]] = {}

    def stack_of(key: str) -> List[Tuple[str, Value]]:
        st = stacks.get(key)
        if st is None:
            st = [("live_in", slot_val(key, 0))]
            stacks[key] = st
        return st

    def fresh(key: str, kind: str, value: Value) -> None:
        counter[key] += 1
        stack_of(key).append((kind, value))

    subs = 0
    work_stack: List[Tuple[str, object]] = [("enter", func.entry)]
    while work_stack:
        kind, payload = work_stack.pop()
        if kind == "exit":
            for key in payload:                      # unwind this block's defs
                stack_of(key).pop()
            continue

        b = payload
        pushed: List[str] = []
        out_list: List[IRInsn] = []

        # 1. memory-phi dsts are defs at the top of the block
        for phi in phis[b]:
            key = phi_meta[id(phi)]
            counter[key] += 1
            ver = counter[key]
            dst = slot_val(key, ver)
            phi.dst = dst
            stack_of(key).append(("phi", dst))
            pushed.append(key)

        # 2. ordinary insns: resolve loads, mark stores, honour barriers
        for insn in func.blocks[b].insns:
            if insn.op == Op.STORE:
                c = _classify_mem(insn.dst, stable)
                out_list.append(insn)                # keep the real store
                if c is not None and c[0] == "slot":
                    key = c[1]
                    sv = insn.args[0] if insn.args else slot_val(key, 0)
                    counter[key] += 1
                    ver = counter[key]
                    out_list.append(IRInsn(ea=insn.ea, op=MEM_SSA_OP_CODE,
                                           dst=slot_val(key, ver), args=(sv,)))
                    stack_of(key).append(("store", sv))
                    pushed.append(key)
                elif c is not None and c[0] == "indexed":
                    # may-alias barrier: havoc every tracked slot on this base
                    for k2 in [k for k in slot_width
                               if k.startswith(f"slot_{c[1]}_")]:
                        counter[k2] += 1
                        bv = slot_val(k2, counter[k2])
                        stack_of(k2).append(("barrier", bv))
                        pushed.append(k2)
                continue

            if insn.op == Op.LOAD:
                c = _classify_mem(insn.args[0] if insn.args else None, stable)
                if c is not None and c[0] == "slot":
                    kind2, value = stack_of(c[1])[-1]
                    if kind2 in ("store", "phi"):
                        out_list.append(replace(insn, op=Op.ASSIGN, args=(value,)))
                        subs += 1
                        continue
                out_list.append(insn)                # live-in / barrier: untouched
                continue

            out_list.append(insn)

        new_insns[b] = out_list

        # 3. fill this block's slot in each successor's phis
        for s in func.blocks[b].succs:
            if s in phis and phis[s] and b in pred_order[s]:
                j = pred_order[s].index(b)
                for phi in phis[s]:
                    key = phi_meta[id(phi)]
                    phi.args[j] = stack_of(key)[-1][1]

        # 4. schedule exit (pops) then dom-tree children
        work_stack.append(("exit", pushed))
        for c in sorted(children[b]):
            work_stack.append(("enter", c))

    # ---- finalise: freeze phi args, prepend phis, install new insn lists --
    for b in reachable:
        for phi in phis[b]:
            key = phi_meta[id(phi)]
            phi.args = tuple(
                a if a is not None else slot_val(key, 0)   # unfilled pred -> live-in
                for a in phi.args)
        func.blocks[b].insns = phis[b] + new_insns[b]

    return subs


__all__ = [
    "PHI_OP_CODE",
    "MEM_SSA_OP_CODE",
    "MemSlot",
    "UNTRACKED",
    "is_phi",
    "is_setslot",
    "ssa_base_name",
    "ssa_version",
    "dominators",
    "dominance_frontiers",
    "build_ssa",
    "dead_code_eliminate",
    "constant_fold",
    "collect_memory_slots",
    "memory_ssa",
]
