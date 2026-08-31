"""Control-flow *structuring* over Aletheia's bounded-op IR.

This is the decompiler-course sibling of :mod:`aletheia.dataflow`: it takes an
:class:`~aletheia.ir.IRFunction` (SSA or not -- structuring reads only the CFG
*shape* plus each block's terminator kind) and recovers a **structured tree** of
``Sequence`` / ``IfThenElse`` / ``While`` / ``DoWhile`` / ``Switch`` / ``Break`` /
``Continue`` / ``Return`` / ``Goto`` nodes that a downstream pseudocode emitter can
walk to print C-ish source. It is the classic interval / region approach
(Cifuentes-style): find natural loops from back-edges, fold each loop into a
``WHILE`` / ``DO_WHILE`` node, then recover ``IF`` nodes from two-way branches
using immediate **post-dominators** as the merge point, and collapse straight-line
chains into a ``SEQ``.

--------------------------------------------------------------------------------
What is recovered, and what falls back to GOTO (honest scope)
--------------------------------------------------------------------------------
* **Reducible flow** -- pre-test loops (condition at the header), post-test loops
  (condition at the latch), nested loops, two-way ``if`` / ``if-else``, and
  straight-line sequences -- is recovered structurally.
* **``break`` / ``continue``** are emitted for edges that leave the innermost
  active loop (to its follow node) or jump back to the innermost header. An edge
  that targets an **outer** loop's header or follow is a multi-level break/continue:
  the outer loop is given a unique **label** (``L1``, ``L2``, ...) and we emit a
  ``BREAK`` / ``CONTINUE`` carrying ``target_label`` (Java-style labelled
  break/continue), instead of the old ``GOTO`` fallback. A label is materialised
  only when at least one break/continue actually names it, and ``label_count``
  counts those. (The old behaviour -- a ``GOTO`` with a ``goto_count`` bump -- is
  gone for this case; ``goto_count`` now covers only genuinely irreducible flow.)
* **Irreducible flow** (multi-entry cycles, unstructured gotos) has no structured
  form; whenever the walk reaches a block it has already emitted, it emits a
  ``GOTO`` to that block's start EA and bumps ``goto_count``. This is the honest
  answer for obfuscated code -- we never fabricate a tree.
* **Switch / jump tables** -- a block whose terminator is an **indirect** ``JMP``
  (>= 2 successors), or a chain of equality compares, is folded into a ``SWITCH``.
  Case-value recovery now recognises the following lowerings; how each dispatcher
  was recovered is reported in ``StructuredFunction.switch_recovery`` (keyed by the
  switch head block's EA):

  - ``"cmp_chain"`` -- a cascade ``CMP scrutinee, K1; je c1; CMP scrutinee, K2;
    je c2; ... ; <default>`` on ONE scrutinee (**>= 2** equality compares required,
    so a plain ``if``/``else`` is never mis-read). Real case values ``K1, K2, ...``
    are recovered, paired with the ``je`` targets, and the final ``else`` block is
    the ``default`` arm. Each intermediate compare block must be private to the
    chain (single predecessor).
  - ``"jump_table"`` -- the indirect ``JMP`` target is produced by a table load
    ``LOAD tgt, [base + index*scale + disp]`` (scale 4/8). The scrutinee is the
    ``index`` register. Case values are the ordinals ``0..N-1`` -- which is what a
    dense jump table *means* -- now **documented as a recognised jump table** rather
    than an unexplained fallback.
  - ``"range_plus_table"`` -- ``CMP idx, MAX; jae/ja default`` guarding an indirect
    jump-table dispatcher. Folded into one ``SWITCH`` at the range-check block:
    ordinal cases from the inner table, ``default`` = the out-of-range arm. The
    dispatcher block must be private to the range check (single predecessor).
  - ``"bail"`` -- an indirect ``JMP`` with >= 2 successors but no recognisable table
    structure. One case per successor with **synthetic ordinal** values (exactly the
    old best-effort behaviour); no ``default`` distinguished. We never fabricate a
    real mapping.
  - ``"ordinal"`` -- a reserved diagnostic value meaning "ordinals kept, no recovery
    attempted". Not emitted by the current implementation (every unrecognised
    indirect dispatcher is reported as ``"bail"``, i.e. recovery *was* attempted and
    failed); kept in the value space for API stability.

  Honest limits: only the three concrete lowerings above are decoded; anything else
  (computed/obfuscated dispatch, sparse tables with a secondary index table,
  hand-rolled binary-search switches) falls to ``"bail"`` and keeps ordinals.

--------------------------------------------------------------------------------
Design choices
--------------------------------------------------------------------------------
* **Reduction order: loops first, then conditionals, then sequences.** Loops must
  fold before conditionals so a header's loop-exit branch is consumed by the loop
  (as the pre-test condition / an implicit exit) rather than mis-read as an ``if``.
  The recursion realises this order implicitly: on reaching a not-yet-active loop
  header the walker builds the whole loop (bounding the body by the loop's follow
  node) before it ever treats that header's terminator as an ``if``.
* **``cond`` is the terminating ``BR`` IRInsn.** For an ``IF`` / ``WHILE`` the
  condition is the block's ``Op.BR`` instruction (it carries the ``cc_*`` token and
  the flag/reg reads); for a ``DO_WHILE`` it is the *latch's* ``BR``. The
  condition-computing block itself is kept in ``SNode.block`` (``IF`` / ``WHILE``)
  so a self-contained emitter can print the preceding ``cmp`` / ``setflag`` insns
  without holding the ``IRFunction``.
* **Post-dominators** are computed by reversing the CFG (adding a single virtual
  exit joining every ``RET`` / sink block) and running :func:`dominators` from
  :mod:`aletheia.dataflow` on the reversed graph -- the standard trick, reusing the
  primitive rather than reinventing it.

Stdlib only; :mod:`aletheia.ir` / :mod:`aletheia.dataflow` are imported for types
and primitives and are never modified. :func:`structure` does **not** run
``build_ssa`` -- the caller decides whether the IR is already SSA form.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Set, Tuple

from aletheia.ir import IRBlock, IRFunction, IRInsn, Op, Value, VTag
from aletheia.dataflow import dominators


# ===========================================================================
# structured-tree node model
# ===========================================================================
class NodeKind(IntEnum):
    SEQ = 1        # ordered children
    IF = 2         # cond + then + else? (else optional)
    WHILE = 3      # cond + body   (pre-test)
    DO_WHILE = 4   # body + cond   (post-test)
    SWITCH = 5     # scrutinee + cases[] + default?
    BREAK = 6
    CONTINUE = 7
    RETURN = 8     # optional return value(s)
    GOTO = 9       # fallback for irreducible flow; target = block start EA
    BLOCK = 10     # a leaf: a linear IRBlock (no branch), just the insns


@dataclass
class SNode:
    kind: NodeKind
    ea: int = 0                    # source block start (0 for pure control nodes)
    # BLOCK / IF / WHILE: the source IRBlock (for IF/WHILE this is the
    # condition-computing header block; its terminator is `cond`).
    block: Optional[IRBlock] = None
    # SEQ
    children: List["SNode"] = field(default_factory=list)
    # IF / WHILE / DO_WHILE: `cond` is the terminating BR IRInsn (see module doc).
    cond: Optional[object] = None
    then_branch: Optional["SNode"] = None
    else_branch: Optional["SNode"] = None
    # WHILE / DO_WHILE
    body: Optional["SNode"] = None
    # SWITCH
    scrutinee: Optional[object] = None
    cases: List[Tuple[int, "SNode"]] = field(default_factory=list)  # (value, body)
    default: Optional["SNode"] = None
    # GOTO
    goto_target: int = 0
    # RETURN
    return_value: Optional[object] = None
    # labelled loops (backward-compat: default "" == unlabelled, unreferenced)
    label: str = ""                # non-empty on a WHILE/DO_WHILE that a labelled
                                   #   break/continue names (e.g. "L1")
    target_label: str = ""         # non-empty on a BREAK/CONTINUE that targets an
                                   #   OUTER loop by label (multi-level break/continue)


@dataclass
class StructuredFunction:
    entry: int                     # func.entry
    body: SNode                    # the root (usually SEQ or IF)
    unreachable: List[int]         # block starts we could not attach (diagnostic)
    goto_count: int                # how many GOTOs we had to emit (irreducibility)
    label_count: int = 0           # loop labels emitted (multi-level break/continue)
    # dispatcher-block EA -> how its switch was recovered:
    #   "cmp_chain" | "jump_table" | "range_plus_table" | "bail" | "ordinal"
    switch_recovery: Dict[int, str] = field(default_factory=dict)


# ===========================================================================
# small CFG utilities (local; the heavy primitives are reused from dataflow)
# ===========================================================================
def _reachable(func: IRFunction) -> Set[int]:
    """Block starts reachable from ``func.entry`` via ``succs`` (existing blocks)."""
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


def _preds(func: IRFunction, reachable: Set[int]) -> Dict[int, List[int]]:
    preds: Dict[int, List[int]] = {b: [] for b in reachable}
    for b in reachable:
        for s in func.blocks[b].succs:
            if s in reachable:
                preds[s].append(b)
    return preds


def post_order(func: IRFunction) -> List[int]:
    """Iterative DFS post-order over blocks reachable from ``func.entry``.

    In a DFS post-order the entry is emitted **last** (it is only finished after
    all its descendants), so ``post_order(func)[-1] == func.entry``; the reverse of
    this list is a reverse-post-order suitable for forward data-flow."""
    reachable = _reachable(func)
    if not reachable:
        return []
    entry = func.entry
    order: List[int] = []
    visited = {entry}
    stack: List[Tuple[int, "iterator"]] = [(entry, iter(func.blocks[entry].succs))]
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


def _dominates(a: int, b: int, idom: Dict[int, int]) -> bool:
    """True if block ``a`` dominates block ``b`` (walking ``b`` up the idom tree)."""
    if a not in idom or b not in idom:
        return False
    x = b
    while True:
        if x == a:
            return True
        p = idom.get(x)
        if p is None or p == x:      # reached the entry (idom[entry] == entry)
            return x == a
        x = p


# ===========================================================================
# post-dominators (reverse-graph dominators, reusing dataflow.dominators)
# ===========================================================================
# A key that cannot collide with a real EA (EAs are non-negative).
_VEXIT = -1


def _is_sink(func: IRFunction, b: int, reachable: Set[int]) -> bool:
    """A block that leaves the function: a RET / HLT terminator, or no successor
    that stays inside the reachable sub-CFG."""
    blk = func.blocks[b]
    if blk.insns and blk.insns[-1].op in (Op.RET, Op.HLT):
        return True
    return not any(s in reachable for s in blk.succs)


def immediate_post_dominators(func: IRFunction) -> Dict[int, int]:
    """Immediate post-dominators: ``dominators`` run on the reversed CFG.

    The reversed graph is rooted at a single virtual exit (:data:`_VEXIT`) joined
    to every sink block, so multiple ``ret`` sites share one post-dom root. The
    result maps ``block -> its immediate post-dominator`` (possibly ``_VEXIT`` for a
    block that only post-dominates the function's end). Blocks with no post-dom
    inside the function are simply absent."""
    reachable = _reachable(func)
    if not reachable:
        return {}
    rev = IRFunction(start=_VEXIT, entry=_VEXIT, blocks={})
    rev.blocks[_VEXIT] = IRBlock(start=_VEXIT, insns=[], succs=[])
    for b in reachable:
        rev.blocks[b] = IRBlock(start=b, insns=[], succs=[])
    # reverse every intra-reachable edge
    for b in reachable:
        for s in func.blocks[b].succs:
            if s in reachable:
                rev.blocks[s].succs.append(b)
    # virtual exit -> every sink
    sinks = [b for b in reachable if _is_sink(func, b, reachable)]
    if not sinks:                    # a pure infinite loop: no natural root
        sinks = [b for b in reachable
                 if not any(s in reachable for s in func.blocks[b].succs)]
    rev.blocks[_VEXIT].succs = sorted(set(sinks))
    return dominators(rev)


# ===========================================================================
# loops
# ===========================================================================
def is_loop_header(func: IRFunction, block_start: int,
                   idom: Dict[int, int]) -> bool:
    """True if ``block_start`` is the target of a back-edge -- i.e. some reachable
    predecessor ``u`` has an edge ``u -> block_start`` where ``block_start``
    dominates ``u``."""
    reachable = _reachable(func)
    if block_start not in reachable:
        return False
    preds = _preds(func, reachable)
    return any(_dominates(block_start, u, idom) for u in preds.get(block_start, ()))


def _natural_loop_body(header: int, latch: int,
                       preds: Dict[int, List[int]]) -> Set[int]:
    """Textbook natural-loop body for the back-edge ``latch -> header``: the header
    plus every block that can reach ``latch`` without passing through ``header``."""
    loop = {header}
    stack: List[int] = []
    if latch != header:
        loop.add(latch)
        stack.append(latch)
    while stack:
        n = stack.pop()
        for p in preds.get(n, ()):
            if p not in loop:
                loop.add(p)
                stack.append(p)
    return loop


def natural_loops(func: IRFunction, idom: Dict[int, int]) -> Dict[int, Set[int]]:
    """Map ``loop-header -> set of block starts in the loop body``.

    A loop is seeded by each back-edge ``u -> v`` (an edge whose target ``v``
    dominates its source ``u``); its body is the standard natural loop of that
    back-edge. Multiple back-edges into the same header union into one body."""
    reachable = _reachable(func)
    preds = _preds(func, reachable)
    loops: Dict[int, Set[int]] = {}
    for b in reachable:
        for s in func.blocks[b].succs:
            if s in reachable and _dominates(s, b, idom):     # back-edge b -> s
                body = _natural_loop_body(s, b, preds)
                loops.setdefault(s, set()).update(body)
    return loops


# ===========================================================================
# the structurer
# ===========================================================================
@dataclass
class _Frame:
    header: int
    body: Set[int]
    follow: Optional[int]
    latch: Optional[int] = None      # set for DO_WHILE loops only
    label: str = ""                  # assigned lazily iff a multi-level break/
                                     #   continue names this loop; read by _build_loop


def _terminator(blk: IRBlock) -> Optional[IRInsn]:
    return blk.insns[-1] if blk.insns else None


def _is_terminal(node: Optional[SNode]) -> bool:
    """Does ``node`` definitely transfer control away (so a following merge is
    unreachable straight-line)? break / continue / return / goto are terminal; a
    SEQ is terminal iff its last child is; an IF is terminal iff both arms exist
    and both are terminal."""
    if node is None:
        return False
    k = node.kind
    if k in (NodeKind.BREAK, NodeKind.CONTINUE, NodeKind.RETURN, NodeKind.GOTO):
        return True
    if k == NodeKind.SEQ:
        return bool(node.children) and _is_terminal(node.children[-1])
    if k == NodeKind.IF:
        return (node.then_branch is not None and node.else_branch is not None
                and _is_terminal(node.then_branch) and _is_terminal(node.else_branch))
    return False


class _Structurer:
    def __init__(self, func: IRFunction) -> None:
        self.func = func
        self.reachable = _reachable(func)
        self.idom = dominators(func)
        self.ipdom = immediate_post_dominators(func)
        self.loops = natural_loops(func, self.idom)
        self.preds = _preds(func, self.reachable)
        self.visited: Set[int] = set()
        self.goto_count = 0
        self.label_count = 0
        self.switch_recovery: Dict[int, str] = {}

    # -- helpers -----------------------------------------------------------
    def _merge_of(self, b: int) -> Optional[int]:
        m = self.ipdom.get(b)
        if m is None or m == _VEXIT or m == b:
            return None
        return m

    def _label_for(self, frame: _Frame) -> str:
        """Lazily assign ``frame`` a unique, pass-scoped, monotonic loop label the
        first time a multi-level break/continue names it. Idempotent: a loop named
        by both a labelled break AND continue keeps one label (counted once)."""
        if not frame.label:
            self.label_count += 1
            frame.label = f"L{self.label_count}"
        return frame.label

    def _seq(self, nodes: List[SNode]) -> SNode:
        nodes = [n for n in nodes if n is not None]
        if len(nodes) == 1:
            return nodes[0]
        return SNode(NodeKind.SEQ, children=nodes)

    def _goto(self, target: int) -> SNode:
        self.goto_count += 1
        return SNode(NodeKind.GOTO, goto_target=target)

    # -- loop construction -------------------------------------------------
    def _classify_loop(self, header: int, body: Set[int]):
        """Return ``(kind, body_entry, follow, latch)``.

        kind is ``NodeKind.WHILE`` (pre-test: header BR exits the loop) or
        ``NodeKind.DO_WHILE`` (post-test: condition at a latch)."""
        hb = self.func.blocks[header]
        term = _terminator(hb)
        # candidate exits: edges leaving the body
        exits = [(s, t) for s in body for t in self.func.blocks[s].succs
                 if t not in body]

        if term is not None and term.op == Op.BR:
            taken, fall = term.then_ea, term.else_ea
            in_taken, in_fall = taken in body, fall in body
            # header conditionally exits AND the header is not itself the latch
            if in_taken and not in_fall and taken != header:
                return NodeKind.WHILE, taken, fall, None
            if in_fall and not in_taken and fall != header:
                return NodeKind.WHILE, fall, taken, None
            # single-block self-loop (header tests at the bottom) -> do-while
            if taken == header and not in_fall:
                return NodeKind.DO_WHILE, header, fall, header
            if fall == header and not in_taken:
                return NodeKind.DO_WHILE, header, taken, header

        # DO_WHILE: find a latch (a body block whose edge returns to the header),
        # preferring one that ends in BR (carries the loop condition).
        latches = [s for s in body
                   if header in self.func.blocks[s].succs and s != header]
        latch = None
        for cand in latches:
            if self._is_br(cand):
                latch = cand
                break
        if latch is None and latches:
            latch = latches[0]
        follow = None
        if latch is not None:
            for t in self.func.blocks[latch].succs:
                if t not in body:
                    follow = t
                    break
        if follow is None and exits:
            follow = exits[0][1]
        return NodeKind.DO_WHILE, header, follow, latch

    def _is_br(self, b: int) -> bool:
        term = _terminator(self.func.blocks[b])
        return term is not None and term.op == Op.BR

    def _build_loop(self, header: int, loopstack: List[_Frame]):
        """Fold the natural loop at ``header`` into a WHILE / DO_WHILE node.

        Returns ``(loop_node, follow)`` -- ``follow`` is the block to continue the
        enclosing region from (or ``None`` for an exit-less loop)."""
        body = self.loops[header]
        kind, body_entry, follow, latch = self._classify_loop(header, body)
        frame = _Frame(header=header, body=body, follow=follow, latch=latch)

        if kind == NodeKind.WHILE:
            self.visited.add(header)                 # header emitted as the WHILE cond
            hb = self.func.blocks[header]
            inner = self._walk(body_entry, None, loopstack + [frame])
            inner = self._strip_trailing_continue(inner)
            # frame.label is filled during the body walk above iff a multi-level
            # break/continue named this loop -- read it AFTER the walk.
            node = SNode(NodeKind.WHILE, ea=header, block=hb,
                         cond=_terminator(hb), body=inner, label=frame.label)
            return node, follow

        # DO_WHILE: walk from the header; the latch's terminator becomes the cond.
        inner = self._walk(header, None, loopstack + [frame], start_header=header)
        inner = self._strip_trailing_continue(inner)
        cond = _terminator(self.func.blocks[latch]) if latch is not None else None
        cond = cond if (cond is not None and cond.op == Op.BR) else None
        node = SNode(NodeKind.DO_WHILE, ea=header, cond=cond, body=inner,
                     label=frame.label)
        return node, follow

    def _strip_trailing_continue(self, node: SNode) -> SNode:
        """Drop a redundant CONTINUE that is the last statement of a loop body (the
        natural latch jump back to the header needs no explicit ``continue``)."""
        if node.kind == NodeKind.CONTINUE:
            return SNode(NodeKind.SEQ, children=[])
        if node.kind == NodeKind.SEQ and node.children \
                and node.children[-1].kind == NodeKind.CONTINUE:
            node.children = node.children[:-1]
            if len(node.children) == 1:
                return node.children[0]
        return node

    # -- the recursive region walk ----------------------------------------
    def _walk(self, start: Optional[int], stop: Optional[int],
              loopstack: List[_Frame], start_header: Optional[int] = None) -> SNode:
        """Structure the region beginning at ``start``, stopping before ``stop``.

        ``loopstack`` is the stack of enclosing loops (innermost last).
        ``start_header`` (used only when entering a DO_WHILE body) permits the very
        first node to *be* the innermost header without being read as a
        back-edge/continue."""
        out: List[SNode] = []
        cur = start
        first = True
        headers = {f.header for f in loopstack}
        follows = {f.follow for f in loopstack if f.follow is not None}
        inner = loopstack[-1] if loopstack else None

        while cur is not None:
            is_start = first and cur == start_header
            first = False

            # Loop-control edges are recognised BEFORE the region `stop`, so a
            # branch that jumps to a loop's follow / header yields a proper
            # break / continue even when that node is also the region's merge.
            # 1. back-edge to the innermost header -> continue
            if inner is not None and cur == inner.header and not is_start:
                out.append(SNode(NodeKind.CONTINUE))
                break
            # 2. edge to an OUTER loop's header -> multi-level continue via a label
            if cur in headers and (inner is None or cur != inner.header) and not is_start:
                frame = next(f for f in loopstack if f.header == cur)
                out.append(SNode(NodeKind.CONTINUE,
                                 target_label=self._label_for(frame)))
                break
            # 3. edge to the innermost follow -> break
            if inner is not None and inner.follow is not None and cur == inner.follow:
                out.append(SNode(NodeKind.BREAK))
                break
            # 4. edge to an OUTER loop's follow -> multi-level break via a label
            if cur in follows and (inner is None or cur != inner.follow):
                frame = next(f for f in loopstack if f.follow == cur)
                out.append(SNode(NodeKind.BREAK,
                                 target_label=self._label_for(frame)))
                break

            if cur == stop:
                break
            # 5. a DO_WHILE latch: the test lives here; emit the block, stop the body
            if (inner is not None and inner.latch is not None
                    and cur == inner.latch and not is_start):
                self.visited.add(cur)
                out.append(SNode(NodeKind.BLOCK, ea=cur, block=self.func.blocks[cur]))
                break
            # 6. already emitted, or off the graph -> goto (irreducible / external)
            if cur not in self.reachable:
                out.append(self._goto(cur))
                break
            if cur in self.visited and not is_start:
                out.append(self._goto(cur))
                break
            # 7. a fresh loop header -> fold the whole loop first
            if cur in self.loops and cur not in headers:
                node, follow = self._build_loop(cur, loopstack)
                out.append(node)
                cur = follow
                continue
            # single-block DO_WHILE whose header is also its own latch
            if (inner is not None and inner.latch is not None
                    and cur == inner.latch and is_start):
                self.visited.add(cur)
                out.append(SNode(NodeKind.BLOCK, ea=cur, block=self.func.blocks[cur]))
                break

            cur = self._emit_block(cur, out, loopstack, is_start)

        return self._seq(out)

    # -- switch value recovery --------------------------------------------
    def _cc_token(self, term: Optional[IRInsn]) -> str:
        """The bare condition token of a BR (``'eq'`` / ``'ne'`` / ``'a'`` / ...):
        the first arg's name with any ``'cc_'`` prefix and ``'#N'`` SSA version
        stripped. ``''`` if there is no recognisable condition operand."""
        if term is None or not term.args or term.args[0] is None:
            return ""
        return self._strip_prefix(term.args[0].name, "cc_")

    @staticmethod
    def _strip_ver(name: str) -> str:
        i = name.rfind("#")
        if i != -1 and name[i + 1:].isdigit():
            return name[:i]
        return name

    @classmethod
    def _strip_prefix(cls, name: Optional[str], prefix: str) -> str:
        name = cls._strip_ver(name or "")
        return name[len(prefix):] if name.startswith(prefix) else name

    @classmethod
    def _reg_base(cls, v: Optional[Value]) -> str:
        """Version-stripped base name of a REG/TEMP Value, else ``''``."""
        if v is None or v.tag not in (VTag.REG, VTag.TEMP) or not v.name:
            return ""
        return cls._strip_ver(v.name)

    def _cmp_scrutinee_imm(self, blk: IRBlock):
        """For a block whose last ``CMP`` is ``CMP reg/temp, IMM``, return
        ``(scrutinee_value, imm_int)``; else ``None``. This is the compare that
        feeds the block's terminating ``BR``."""
        cmp_insn = None
        for insn in blk.insns:
            if insn.op == Op.CMP:
                cmp_insn = insn
        if cmp_insn is None or len(cmp_insn.args) < 2:
            return None
        a, b = cmp_insn.args[0], cmp_insn.args[1]
        if (a is not None and a.tag in (VTag.REG, VTag.TEMP) and a.name
                and b is not None and b.tag == VTag.IMM):
            return (a, b.imm)
        return None

    def _jump_table_index(self, blk: IRBlock, term: IRInsn) -> Optional[Value]:
        """If the indirect ``JMP`` in ``blk`` is fed by a table load
        ``LOAD tgt, [base + index*scale + disp]`` (scale 4 or 8), return the
        ``index`` Value -- the true switch scrutinee. Else ``None`` (the JMP target
        was not produced by a recognisable jump-table load)."""
        tgt = term.args[0] if term.args else None
        tgt_name = tgt.name if tgt is not None else None
        if not tgt_name:
            return None
        for insn in blk.insns:
            if (insn.op == Op.LOAD and insn.dst is not None
                    and insn.dst.name == tgt_name and insn.args):
                mem = insn.args[0]
                if (mem is not None and mem.tag == VTag.MEM
                        and mem.index is not None and mem.scale in (4, 8)):
                    return mem.index
        return None

    def _emit_switch(self, head_ea: int, block: IRBlock, scrutinee: Optional[Value],
                     pairs: List[Tuple[int, int]], default_ea: Optional[int],
                     loopstack: List[_Frame]):
        """Build a SWITCH SNode and return ``(node, continue_ea)``.

        ``pairs`` is the ordered ``(case_value, target_ea)`` list; ``default_ea`` is
        the default arm's block start (or ``None``). Case and default bodies are
        walked bounded by the switch's post-dominator merge; ``continue_ea`` is that
        merge iff some arm falls through, else ``None``."""
        merge = self._merge_of(head_ea)
        cases: List[Tuple[int, SNode]] = []
        any_fallthrough = False
        for val, s in pairs:
            body = (None if s == merge else self._walk(s, merge, loopstack))
            body = body if body is not None else SNode(NodeKind.SEQ, children=[])
            cases.append((val, body))
            if not _is_terminal(body):
                any_fallthrough = True
        default_node = None
        if default_ea is not None:
            if default_ea == merge:
                any_fallthrough = True            # default is the fall-through merge
            else:
                default_node = self._walk(default_ea, merge, loopstack)
                if not _is_terminal(default_node):
                    any_fallthrough = True
        node = SNode(NodeKind.SWITCH, ea=head_ea, block=block,
                     scrutinee=scrutinee, cases=cases, default=default_node)
        return node, (merge if any_fallthrough else None)

    def _try_cmp_chain(self, cur: int, blk: IRBlock, term: IRInsn):
        """Recognise a switch lowered as a cascade of ``CMP scrutinee, IMM; je case``
        blocks testing ONE scrutinee, terminating in a default (the last ``else``).

        Returns ``(pairs, default_ea, chain_blocks, scrutinee)`` -- ``pairs`` the
        ordered ``(case_value, target_ea)``, ``chain_blocks`` the intermediate
        compare blocks to mark consumed -- or ``None`` if the shape does not hold.
        Requires **>= 2** equality compares so a plain ``if``/``else`` (one compare)
        is never mis-read as a switch, and each intermediate compare block must be
        private to the chain (a single predecessor)."""
        first = self._cmp_scrutinee_imm(blk)
        if first is None or self._cc_token(term) != "eq":
            return None
        scrutinee = first[0]
        scrut_base = self._reg_base(scrutinee)
        if not scrut_base:
            return None
        pairs: List[Tuple[int, int]] = []
        chain_blocks: List[int] = []
        node_ea = cur
        seen: Set[int] = set()
        while True:
            b = self.func.blocks.get(node_ea)
            if b is None:
                return None
            t = _terminator(b)
            ci = self._cmp_scrutinee_imm(b) if b is not None else None
            is_compare = (t is not None and t.op == Op.BR
                          and self._cc_token(t) == "eq"
                          and ci is not None and self._reg_base(ci[0]) == scrut_base)
            if not is_compare:
                default_ea = node_ea              # first non-matching block = default
                break
            if node_ea != cur:
                # intermediate compare blocks must be private to the chain
                if (node_ea in self.loops or node_ea not in self.reachable
                        or node_ea in self.visited
                        or len(self.preds.get(node_ea, ())) != 1):
                    return None
                chain_blocks.append(node_ea)
            seen.add(node_ea)
            pairs.append((ci[1], t.then_ea))      # je -> case body is the taken arm
            node_ea = t.else_ea                   # else falls to the next compare
            if node_ea in seen:                   # cycle guard (not a clean chain)
                return None
        if len(pairs) < 2:
            return None
        return pairs, default_ea, chain_blocks, scrutinee

    def _try_range_plus_table(self, cur: int, blk: IRBlock, term: IRInsn):
        """Recognise ``CMP idx, MAX; jae/ja default`` guarding an indirect jump-table
        dispatch: one BR arm is the out-of-range default, the other is an indirect
        ``JMP`` block whose target is a recognisable jump-table load.

        Returns ``(dispatcher_ea, default_ea, index_value)`` or ``None``. The
        dispatcher must be private to this range check (single predecessor)."""
        if self._cc_token(term) not in ("a", "ae", "b", "be", "g", "ge", "l", "le"):
            return None
        if self._cmp_scrutinee_imm(blk) is None:
            return None
        for disp_ea, other_ea in ((term.then_ea, term.else_ea),
                                  (term.else_ea, term.then_ea)):
            db = self.func.blocks.get(disp_ea)
            if (db is None or disp_ea in self.loops or disp_ea in self.visited
                    or len(self.preds.get(disp_ea, ())) != 1):
                continue
            dt = _terminator(db)
            if (dt is None or dt.op != Op.JMP or not dt.args
                    or dt.args[0].tag == VTag.IMM or len(db.succs) < 2):
                continue
            idx = self._jump_table_index(db, dt)
            if idx is not None:
                return (disp_ea, other_ea, idx)
        return None

    def _emit_block(self, cur: int, out: List[SNode], loopstack: List[_Frame],
                    is_start: bool) -> Optional[int]:
        """Emit the structured form of a single block and return the next block to
        continue from (or ``None`` to end this region)."""
        self.visited.add(cur)
        blk = self.func.blocks[cur]
        term = _terminator(blk)

        # -- two-way conditional: switch lowerings first, then plain IF ---
        if term is not None and term.op == Op.BR:
            # (a) range check + jump table: CMP idx,MAX; jae default; jmp table[idx]
            rpt = self._try_range_plus_table(cur, blk, term)
            if rpt is not None:
                disp_ea, default_ea, idx = rpt
                db = self.func.blocks[disp_ea]
                self.visited.add(disp_ea)
                pairs = list(enumerate(sorted(set(db.succs))))
                node, cont = self._emit_switch(cur, blk, idx, pairs,
                                               default_ea, loopstack)
                self.switch_recovery[cur] = "range_plus_table"
                out.append(node)
                return cont
            # (b) cmp-chain switch: >= 2 `CMP scrutinee,IMM; je case` on one var
            chain = self._try_cmp_chain(cur, blk, term)
            if chain is not None:
                pairs, default_ea, chain_blocks, scrutinee = chain
                for cb in chain_blocks:
                    self.visited.add(cb)
                node, cont = self._emit_switch(cur, blk, scrutinee, pairs,
                                               default_ea, loopstack)
                self.switch_recovery[cur] = "cmp_chain"
                out.append(node)
                return cont
            # (c) ordinary two-way branch -> IF
            merge = self._merge_of(cur)
            then_ea, else_ea = term.then_ea, term.else_ea
            then_b = (None if then_ea == merge
                      else self._walk(then_ea, merge, loopstack))
            else_b = (None if else_ea == merge
                      else self._walk(else_ea, merge, loopstack))
            node = SNode(NodeKind.IF, ea=cur, block=blk, cond=term,
                         then_branch=then_b, else_branch=else_b)
            out.append(node)
            # if both arms leave, the merge is unreachable straight-line
            if (then_b is not None and else_b is not None
                    and _is_terminal(then_b) and _is_terminal(else_b)):
                return None
            return merge

        # -- indirect jmp with resolved successors -> SWITCH (value recovery) --
        if (term is not None and term.op == Op.JMP and term.args
                and term.args[0].tag != VTag.IMM and len(blk.succs) >= 2):
            idx = self._jump_table_index(blk, term)
            pairs = list(enumerate(sorted(set(blk.succs))))
            if idx is not None:
                scrutinee, method = idx, "jump_table"      # ordinals, but recognised
            else:
                scrutinee, method = term.args[0], "bail"   # unrecognised -> ordinals
            node, cont = self._emit_switch(cur, blk, scrutinee, pairs, None,
                                           loopstack)
            self.switch_recovery[cur] = method
            out.append(node)
            return cont

        # -- return -------------------------------------------------------
        if term is not None and term.op == Op.RET:
            out.append(SNode(NodeKind.BLOCK, ea=cur, block=blk))
            rv = term.args[0] if term.args else None
            out.append(SNode(NodeKind.RETURN, ea=cur, return_value=rv))
            return None

        # -- straight-line: single successor ------------------------------
        succs = [s for s in blk.succs if s in self.reachable]
        out.append(SNode(NodeKind.BLOCK, ea=cur, block=blk))
        if len(succs) == 1:
            return succs[0]
        if len(succs) == 0:
            return None
        # >1 successor but not a BR/switch we recognised: emit gotos, don't guess
        for s in succs:
            out.append(self._goto(s))
        return None


def structure(func: IRFunction) -> StructuredFunction:
    """Structure ``func`` into a :class:`StructuredFunction`.

    Reads only the CFG shape and each block's terminator kind, so it works on
    either pre-SSA or SSA IR. Never raises on irreducible flow: unstructurable
    edges become ``GOTO`` nodes (counted in ``goto_count``); blocks that end up
    unattached are listed in ``unreachable``."""
    if func.entry not in func.blocks:
        return StructuredFunction(entry=func.entry,
                                  body=SNode(NodeKind.SEQ, children=[]),
                                  unreachable=sorted(func.blocks), goto_count=0)
    s = _Structurer(func)
    body = s._walk(func.entry, None, [])
    unreachable = sorted(set(func.blocks) - s.visited)
    return StructuredFunction(entry=func.entry, body=body,
                              unreachable=unreachable, goto_count=s.goto_count,
                              label_count=s.label_count,
                              switch_recovery=s.switch_recovery)


__all__ = [
    "NodeKind", "SNode", "StructuredFunction",
    "structure", "is_loop_header", "natural_loops", "post_order",
    "immediate_post_dominators",
]
