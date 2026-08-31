"""Lightweight symbolic execution over Aletheia's pre-SSA bounded-op IR.

This is the "can we get *there*, and what would it take?" sibling of
:mod:`aletheia.dataflow` / :mod:`aletheia.structuring`.  It is an
**Angr/BAP-lite** primitive scoped strictly to what :mod:`aletheia.ir` already
gives us: a small symbolic-integer **term algebra** with constant folding, a
path-conditioned **interpreter** over the linear IR, and a CFG **path
enumerator** that together answer two questions:

* *Can execution reach this basic block?*  -- :func:`is_reachable`.
* *What path conditions must hold for it to?* -- :func:`path_condition`.

It works on the *pre-SSA* linear form the lifter emits (it does **not** run
``build_ssa``): it just interprets each :class:`~aletheia.ir.IRInsn` op in turn,
threading a :class:`SymState` of symbolic register / memory / flag values and an
accumulated list of path constraints.

--------------------------------------------------------------------------------
HONEST SCOPE -- this is NOT a solver.  Read this before trusting a "reachable".
--------------------------------------------------------------------------------
The satisfiability check is **structural**, not a decision procedure:

* After :func:`simplify`, any path-condition term that reduces to a concrete
  ``CONST(0)`` is *unsatisfiable* (that branch cannot be taken); anything else is
  *assumed satisfiable*.  So a concretely-false constraint (``5 == 6``) is caught
  and correctly rejected, but a genuinely-infeasible **symbolic** conjunction
  (e.g. ``x + y > 10  AND  x < 5  AND  y < 5``) is **not** solved -- every one of
  those terms passes the structural check, so the path is reported reachable.
* We add exactly **one** form of propagation on top of pure folding:
  **equality-with-constant substitution.**  When a branch asserts ``sym == C`` we
  record ``sym -> C`` and substitute it into every later (and earlier) constraint;
  a subsequent contradictory equality (``sym == D``, ``D != C``) then folds to
  ``CONST(0)`` and the path is correctly killed.  This is congruence on constant
  equalities only -- nothing more.

Consequence: **reachability here OVER-APPROXIMATES.**  Every block we call
*unreachable* is truly unreachable (we only say so when a constraint provably
folds to zero), but some blocks we call *reachable* may be infeasible under real
arithmetic that our tiny algebra cannot refute.  :class:`Reachability` carries an
``approximate`` flag and a note saying as much.  We never claim to be a solver.

Other modelled-opaquely gaps (each introduces fresh symbolic havoc rather than a
wrong answer): ``DIV`` / ``IDIV`` (no division term), ``ROL`` / ``ROR`` (no rotate
term), ``MUL`` high-half, ``SXT`` (sign-extend passes the value through
unchanged), and the ``UNDEF`` / ``SYSCALL`` / ``INT`` / ``HLT`` family.  A
``CALL``'s return register (``rax``) is havocked.  Branch predicates are recovered
precisely for ``jcc`` following a ``cmp`` / ``test`` (the common case); a branch
whose flags come from anything else, or an exotic predicate (``jo`` / ``jp`` ...),
becomes a fresh unconstrained symbolic boolean (both sides feasible -- honest
over-approximation).

Stdlib only.  :mod:`aletheia.ir` is imported for its types and never modified.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

from aletheia.ir import IRFunction, IRInsn, Op, Value, VTag


# ===========================================================================
# the term algebra
# ===========================================================================
class Kind(IntEnum):
    CONST = 1   # concrete integer (imm + width)
    SYM = 2     # named symbolic input, e.g. "arg0", "mem[0x1000]", "rcx0"
    OP = 3      # unary/binary operator (see Term.op)
    ITE = 4     # if-then-else: args = (cond, then, else)


@dataclass(frozen=True)
class Term:
    kind: Kind
    op: str = ""                     # for OP nodes (see the constructor names below)
    args: Tuple["Term", ...] = ()
    imm: int = 0                     # CONST value (already width-masked)
    name: str = ""                   # SYM name
    width: int = 64                  # bit width

    # -- rendering (debug / path-condition display) -----------------------
    def __str__(self) -> str:        # pragma: no cover - convenience
        if self.kind is Kind.CONST:
            return f"{self.imm:#x}" if self.imm > 9 else str(self.imm)
        if self.kind is Kind.SYM:
            return self.name
        if self.kind is Kind.ITE:
            return f"ite({self.args[0]}, {self.args[1]}, {self.args[2]})"
        if len(self.args) == 1:
            return f"{self.op}({self.args[0]})"
        return f"({self.args[0]} {self.op} {self.args[1]})"


def _mask(width: int) -> int:
    return (1 << width) - 1 if width and width > 0 else (1 << 64) - 1


def _to_signed(x: int, width: int) -> int:
    x &= _mask(width)
    if width and x >= (1 << (width - 1)):
        return x - (1 << width)
    return x


def _key(t: Term):
    """A total-order key used to canonicalise commutative operands so that
    ``add(a, b)`` and ``add(b, a)`` compare structurally equal."""
    return (int(t.kind), t.op, t.imm, t.name, t.width,
            tuple(_key(a) for a in t.args))


# -- leaf constructors -----------------------------------------------------
def k(n: int, width: int = 64) -> Term:
    """A concrete constant, masked to ``width``."""
    return Term(Kind.CONST, imm=n & _mask(width), width=width)


def sym(name: str, width: int = 64) -> Term:
    """A named symbolic input."""
    return Term(Kind.SYM, name=name, width=width)


def _is_const(t: Term, val: Optional[int] = None) -> bool:
    if t.kind is not Kind.CONST:
        return False
    return val is None or t.imm == (val & _mask(t.width))


# -- fold tables for concrete-only binary ops ------------------------------
def _fold_bin(op: str, a: int, b: int, w: int) -> int:
    m = _mask(w)
    if op == "add":
        return (a + b) & m
    if op == "sub":
        return (a - b) & m
    if op == "and":
        return (a & b) & m
    if op == "or":
        return (a | b) & m
    if op == "xor":
        return (a ^ b) & m
    if op == "mul":
        return (a * b) & m
    if op == "shl":
        return (a << (b & (w - 1))) & m if w else (a << b) & m
    if op == "shr":                             # logical (unsigned)
        return ((a & m) >> (b & (w - 1))) & m if w else (a & m) >> b
    if op == "sar":                             # arithmetic (signed)
        return (_to_signed(a, w) >> (b & (w - 1))) & m if w else _to_signed(a, w) >> b
    # comparisons -> boolean 0/1
    if op == "eq":
        return 1 if (a & m) == (b & m) else 0
    if op == "ne":
        return 1 if (a & m) != (b & m) else 0
    if op == "lt":
        return 1 if _to_signed(a, w) < _to_signed(b, w) else 0
    if op == "le":
        return 1 if _to_signed(a, w) <= _to_signed(b, w) else 0
    if op == "gt":
        return 1 if _to_signed(a, w) > _to_signed(b, w) else 0
    if op == "ge":
        return 1 if _to_signed(a, w) >= _to_signed(b, w) else 0
    if op == "ltu":
        return 1 if (a & m) < (b & m) else 0
    if op == "leu":
        return 1 if (a & m) <= (b & m) else 0
    if op == "gtu":
        return 1 if (a & m) > (b & m) else 0
    if op == "geu":
        return 1 if (a & m) >= (b & m) else 0
    raise ValueError(f"unknown binary op {op!r}")


_COMMUTATIVE = frozenset({"add", "and", "or", "xor", "mul", "eq", "ne"})
_COMPARISONS = frozenset({"eq", "ne", "lt", "le", "gt", "ge",
                          "ltu", "leu", "gtu", "geu"})
# result of a comparison on equal operands (x <op> x): reflexively true/false
_REFLEX = {"eq": 1, "ne": 0, "le": 1, "ge": 1, "leu": 1, "geu": 1,
           "lt": 0, "gt": 0, "ltu": 0, "gtu": 0}


def _bin(op: str, a: Term, b: Term, width: Optional[int] = None) -> Term:
    """Generic binary smart constructor: folds concrete args, applies the
    per-op identities registered below, and canonicalises commutative operands."""
    w = width if width is not None else max(a.width, b.width)
    rw = 1 if op in _COMPARISONS else w         # comparisons are 1-bit booleans

    if a.kind is Kind.CONST and b.kind is Kind.CONST:
        return k(_fold_bin(op, a.imm, b.imm, w), rw)

    # same-operand reflexive rules (documented simplifier rules)
    if _key(a) == _key(b):
        if op in ("sub", "xor"):
            return k(0, w)
        if op in ("and", "or"):
            return a
        if op in _COMPARISONS:
            return k(_REFLEX[op], rw)

    allones = _mask(w)
    # additive / bitwise identities with a constant operand
    if op == "add":
        if _is_const(a, 0):
            return b
        if _is_const(b, 0):
            return a
    elif op == "sub":
        if _is_const(b, 0):
            return a
    elif op == "or":
        if _is_const(a, 0):
            return b
        if _is_const(b, 0):
            return a
        if _is_const(a, allones) or _is_const(b, allones):
            return k(allones, w)
    elif op == "xor":
        if _is_const(a, 0):
            return b
        if _is_const(b, 0):
            return a
    elif op == "and":
        if _is_const(a, 0) or _is_const(b, 0):
            return k(0, w)
        if _is_const(a, allones):
            return b
        if _is_const(b, allones):
            return a
    elif op == "mul":
        if _is_const(a, 0) or _is_const(b, 0):
            return k(0, w)
        if _is_const(a, 1):
            return b
        if _is_const(b, 1):
            return a
    elif op in ("shl", "shr", "sar"):
        if _is_const(b, 0):
            return a

    args = (a, b)
    if op in _COMMUTATIVE:
        args = tuple(sorted((a, b), key=_key))
    return Term(Kind.OP, op=op, args=args, width=rw)


# -- named binary constructors --------------------------------------------
def add(a: Term, b: Term) -> Term: return _bin("add", a, b)
def sub(a: Term, b: Term) -> Term: return _bin("sub", a, b)
def and_(a: Term, b: Term) -> Term: return _bin("and", a, b)
def or_(a: Term, b: Term) -> Term: return _bin("or", a, b)
def xor(a: Term, b: Term) -> Term: return _bin("xor", a, b)
def shl(a: Term, b: Term) -> Term: return _bin("shl", a, b)
def shr(a: Term, b: Term) -> Term: return _bin("shr", a, b)
def sar(a: Term, b: Term) -> Term: return _bin("sar", a, b)
def mul(a: Term, b: Term) -> Term: return _bin("mul", a, b)
def eq(a: Term, b: Term) -> Term: return _bin("eq", a, b)
def ne(a: Term, b: Term) -> Term: return _bin("ne", a, b)
def lt(a: Term, b: Term) -> Term: return _bin("lt", a, b)
def le(a: Term, b: Term) -> Term: return _bin("le", a, b)
def gt(a: Term, b: Term) -> Term: return _bin("gt", a, b)
def ge(a: Term, b: Term) -> Term: return _bin("ge", a, b)
def ltu(a: Term, b: Term) -> Term: return _bin("ltu", a, b)
def leu(a: Term, b: Term) -> Term: return _bin("leu", a, b)
def gtu(a: Term, b: Term) -> Term: return _bin("gtu", a, b)
def geu(a: Term, b: Term) -> Term: return _bin("geu", a, b)


# -- unary constructors ----------------------------------------------------
def neg(a: Term) -> Term:
    if a.kind is Kind.CONST:
        return k((-a.imm) & _mask(a.width), a.width)
    if a.kind is Kind.OP and a.op == "neg":         # neg(neg(x)) -> x
        return a.args[0]
    return Term(Kind.OP, op="neg", args=(a,), width=a.width)


def not_(a: Term) -> Term:
    if a.kind is Kind.CONST:
        return k((~a.imm) & _mask(a.width), a.width)
    if a.kind is Kind.OP and a.op == "not":         # not(not(x)) -> x
        return a.args[0]
    return Term(Kind.OP, op="not", args=(a,), width=a.width)


def ite(cond: Term, t: Term, f: Term) -> Term:
    if cond.kind is Kind.CONST:
        return t if cond.imm != 0 else f
    if _key(t) == _key(f):
        return t
    return Term(Kind.ITE, op="ite", args=(cond, t, f), width=max(t.width, f.width))


# rebuild dispatch, used by simplify() and _subst()
_BIN_CTORS = {
    "add": add, "sub": sub, "and": and_, "or": or_, "xor": xor,
    "shl": shl, "shr": shr, "sar": sar, "mul": mul,
    "eq": eq, "ne": ne, "lt": lt, "le": le, "gt": gt, "ge": ge,
    "ltu": ltu, "leu": leu, "gtu": gtu, "geu": geu,
}


def _rebuild(op: str, args: Tuple[Term, ...]) -> Term:
    if op in _BIN_CTORS:
        return _BIN_CTORS[op](args[0], args[1])
    if op == "neg":
        return neg(args[0])
    if op == "not":
        return not_(args[0])
    if op == "ite":
        return ite(args[0], args[1], args[2])
    return Term(Kind.OP, op=op, args=args)


# ===========================================================================
# simplify -- a bounded fixpoint that re-applies the constructor rewrites
# ===========================================================================
# The rewrite ruleset (documented; the constructors above implement them and
# simplify() drives them to a fixpoint bottom-up):
SIMPLIFIER_RULES: Tuple[str, ...] = (
    "constant-fold: op(CONST, CONST) -> CONST (width-wrapped)",
    "add(x, 0) -> x",
    "sub(x, 0) -> x",
    "sub(x, x) -> 0",
    "and(x, 0) -> 0 ;  and(x, ~0) -> x",
    "and(x, x) -> x",
    "or(x, 0) -> x ;  or(x, ~0) -> ~0",
    "or(x, x) -> x",
    "xor(x, 0) -> x",
    "xor(x, x) -> 0",
    "mul(x, 0) -> 0 ;  mul(x, 1) -> x",
    "shl/shr/sar(x, 0) -> x",
    "neg(neg(x)) -> x",
    "not(not(x)) -> x",
    "eq(x, x) -> 1 ;  ne(x, x) -> 0",
    "lt/gt/ltu/gtu(x, x) -> 0 ;  le/ge/leu/geu(x, x) -> 1",
    "ite(CONST, t, f) -> t|f ;  ite(c, t, t) -> t",
    "canonicalise commutative operands (add/and/or/xor/mul/eq/ne)",
)


def _simplify_once(t: Term) -> Term:
    if t.kind in (Kind.CONST, Kind.SYM):
        return t
    new_args = tuple(_simplify_once(a) for a in t.args)
    return _rebuild(t.op, new_args)


def simplify(t: Term, _max_iters: int = 64) -> Term:
    """Fixpoint simplification: repeatedly rebuild the term bottom-up (which
    re-applies every rule in :data:`SIMPLIFIER_RULES`) until it stops changing."""
    cur = t
    for _ in range(_max_iters):
        nxt = _simplify_once(cur)
        if _key(nxt) == _key(cur):
            return nxt
        cur = nxt
    return cur


def _subst(t: Term, sigma: Dict[str, Term]) -> Term:
    """Substitute ``sym-name -> Term`` bindings, rebuilding through the
    constructors so newly-concrete subterms fold immediately."""
    if t.kind is Kind.SYM:
        return sigma.get(t.name, t)
    if t.kind in (Kind.OP, Kind.ITE):
        return _rebuild(t.op, tuple(_subst(a, sigma) for a in t.args))
    return t


def is_unsat(t: Term) -> bool:
    """Structural unsat test: ``t`` is unsatisfiable iff it simplifies to a
    concrete ``CONST(0)``.  (Over-approximates SAT -- see the module docstring.)"""
    s = simplify(t)
    return s.kind is Kind.CONST and s.imm == 0


def _as_const_equality(t: Term) -> Optional[Tuple[str, Term]]:
    """If ``t`` is ``eq(SYM, CONST)`` (either arg order), return ``(name, const)``."""
    if t.kind is Kind.OP and t.op == "eq" and len(t.args) == 2:
        a, b = t.args
        if a.kind is Kind.SYM and b.kind is Kind.CONST:
            return a.name, b
        if b.kind is Kind.SYM and a.kind is Kind.CONST:
            return b.name, a
    return None


# ===========================================================================
# symbolic machine state
# ===========================================================================
_HAVOC_CTR = itertools.count()


def _fresh(prefix: str, width: int = 64) -> Term:
    return sym(f"{prefix}#{next(_HAVOC_CTR)}", width)


@dataclass
class SymState:
    regs: Dict[str, Term] = field(default_factory=dict)      # canonical GPR -> Term
    mem: Dict[Term, Term] = field(default_factory=dict)      # address Term -> Term
    flags: Dict[str, Term] = field(default_factory=dict)     # ZF/SF/CF/OF/PF -> Term
    path_cond: List[Term] = field(default_factory=list)      # all must hold
    # -- interpreter bookkeeping (not part of the "public" 4-field model) --
    subst: Dict[str, Term] = field(default_factory=dict)     # sym -> const bindings
    last_cmp: Optional[Tuple[str, Term, Term]] = None        # ("cmp"|"test", a, b)
    warnings: List[str] = field(default_factory=list)        # havoc / opaque notes


def _copy(s: SymState) -> SymState:
    return SymState(regs=dict(s.regs), mem=dict(s.mem), flags=dict(s.flags),
                    path_cond=list(s.path_cond), subst=dict(s.subst),
                    last_cmp=s.last_cmp, warnings=list(s.warnings))


# ---------------------------------------------------------------------------
# initial state
# ---------------------------------------------------------------------------
# Windows x64 integer arg registers, in order.
_ARG_REGS = ("rcx", "rdx", "r8", "r9")


def initial_state(func: IRFunction,
                  arg_names: Optional[List[str]] = None) -> SymState:
    """Build the entry state.

    ``arg0..arg3`` map to ``rcx / rdx / r8 / r9``; further args live in the
    home/stack slots ``[rsp+0x28], [rsp+0x30], ...`` and are seeded into memory.
    If ``arg_names`` is given its entries name the args in order, else they are
    ``arg0, arg1, ...``.  Every *unwritten* register reads back as ``sym("<n>0")``
    lazily; memory starts empty apart from the seeded stack args, and any load
    from an unknown address mints a fresh symbol."""
    names = list(arg_names) if arg_names is not None else [f"arg{i}" for i in range(4)]
    st = SymState()
    for i, nm in enumerate(names):
        if i < len(_ARG_REGS):
            st.regs[_ARG_REGS[i]] = sym(nm, 64)
        else:
            # home-space stack slot: [rsp + 0x28 + 8*(i-4)]
            disp = 0x28 + 8 * (i - len(_ARG_REGS))
            addr = simplify(add(sym("rsp0", 64), k(disp, 64)))
            st.mem[addr] = sym(nm, 64)
    return st


# ---------------------------------------------------------------------------
# operand evaluation
# ---------------------------------------------------------------------------
def _reg_term(state: SymState, name: str, width: int) -> Term:
    if name in state.regs:
        return state.regs[name]
    return sym(f"{name}0", width or 64)          # unwritten register -> live-in sym


def _addr_term(state: SymState, mem: Value) -> Term:
    """Effective-address Term of a MEM value: ``base + index*scale + disp``."""
    w = 64
    term = k(mem.disp & _mask(w), w)
    if mem.base is not None:
        term = add(_eval(state, mem.base), term)
    if mem.index is not None:
        idx = _eval(state, mem.index)
        if mem.scale and mem.scale != 1:
            idx = mul(idx, k(mem.scale, w))
        term = add(term, idx)
    return simplify(term)


def _eval(state: SymState, v: Optional[Value]) -> Term:
    """Evaluate an IR ``Value`` (as a *source*) to a Term in the current state.

    A ``MEM`` here is treated as loaded contents (``LOAD`` / arithmetic sources);
    ``lea``'s address-of semantics is handled in :func:`step` for ``ASSIGN``."""
    if v is None:
        return _fresh("undef")
    if v.tag is VTag.IMM:
        return k(v.imm, v.size or 64)
    if v.tag is VTag.REG or v.tag is VTag.TEMP:
        return _reg_term(state, v.name, v.size)
    if v.tag is VTag.FLAG:
        return state.flags.get(v.name, sym(f"{v.name}0", 1))
    if v.tag is VTag.MEM:
        addr = _addr_term(state, v)
        if addr in state.mem:
            return state.mem[addr]
        fresh = sym(f"mem[{addr}]", v.size or 64)
        state.mem[addr] = fresh                  # future loads see the same symbol
        return fresh
    return _fresh("val")


# ---------------------------------------------------------------------------
# per-op step
# ---------------------------------------------------------------------------
_ARITH2 = {Op.ADD: add, Op.SUB: sub, Op.AND: and_, Op.OR: or_, Op.XOR: xor,
           Op.SHL: shl, Op.SHR: shr, Op.SAR: sar, Op.MUL: mul, Op.IMUL: mul}


def _store_reg(state: SymState, dst: Value, value: Term) -> None:
    if dst.tag is VTag.FLAG:
        state.flags[dst.name] = value
    else:                                        # REG / TEMP
        state.regs[dst.name] = value


def _havoc_dst(state: SymState, insn: IRInsn, why: str) -> None:
    d = insn.dst
    if d is not None and d.tag in (VTag.REG, VTag.TEMP):
        state.regs[d.name] = _fresh(f"havoc_{d.name}", d.size or 64)
    elif d is not None and d.tag is VTag.FLAG:
        state.flags[d.name] = _fresh(f"havoc_{d.name}", 1)
    state.warnings.append(f"{why} @ {insn.ea:#x} ({insn.op.name}) -> havoc")


def step(state: SymState, insn: IRInsn) -> SymState:
    """Symbolically execute one data-effect ``IRInsn``, returning a NEW state.

    Control primitives (``BR`` / ``JMP`` / ``RET`` / ``CALL``) carry no data
    effect handled here -- the path walker owns them (see :func:`symexec_path`);
    given one, this returns an unchanged copy.  Havoc ops (``UNDEF`` / ``SYSCALL``
    / ``INT`` / ``HLT`` / ``FENCE``) mint fresh symbols on any dst they name."""
    s = _copy(state)
    op = insn.op

    # -- pure move / address-of ------------------------------------------
    if op is Op.ASSIGN:
        src = insn.args[0] if insn.args else None
        if src is not None and src.tag is VTag.MEM:
            value = _addr_term(s, src)           # lea: MEM source == its address
        else:
            value = _eval(s, src)
        if insn.dst is not None:
            _store_reg(s, insn.dst, value)
        return s

    if op is Op.LOAD:
        value = _eval(s, insn.args[0])           # _eval on a MEM does the load
        if insn.dst is not None:
            _store_reg(s, insn.dst, value)
        return s

    if op is Op.STORE:
        addr = _addr_term(s, insn.dst)
        s.mem[addr] = _eval(s, insn.args[0])
        return s

    # -- binary arithmetic / logic ---------------------------------------
    if op in _ARITH2:
        ctor = _ARITH2[op]
        w = (insn.dst.size if insn.dst is not None and insn.dst.size else 64)
        a = _eval(s, insn.args[0]) if insn.args else k(0, w)
        b = _eval(s, insn.args[1]) if len(insn.args) > 1 else k(0, w)
        value = ctor(a, b)
        if len(insn.args) > 2:                   # adc/sbb carry-in (best effort)
            c = _eval(s, insn.args[2])
            value = ctor(value, c) if op in (Op.ADD, Op.SUB) else value
        if insn.dst is not None:
            _store_reg(s, insn.dst, value)
        return s

    if op is Op.NEG:
        if insn.dst is not None:
            _store_reg(s, insn.dst, neg(_eval(s, insn.args[0])))
        return s
    if op is Op.NOT:
        if insn.dst is not None:
            _store_reg(s, insn.dst, not_(_eval(s, insn.args[0])))
        return s

    # -- width casts ------------------------------------------------------
    if op in (Op.ZXT, Op.SXT):
        # zero-extend keeps the value; sign-extend is passed through (documented
        # approximation -- we cannot express arbitrary sign extension in-algebra).
        if insn.dst is not None:
            _store_reg(s, insn.dst, _eval(s, insn.args[0]))
        return s
    if op is Op.TRUNC:
        w = insn.dst.size if insn.dst is not None and insn.dst.size else 64
        if insn.dst is not None:
            _store_reg(s, insn.dst, and_(_eval(s, insn.args[0]), k(_mask(w), w)))
        return s

    # -- comparisons: record context + best-effort flag terms ------------
    if op is Op.CMP:
        a = _eval(s, insn.args[0])
        b = _eval(s, insn.args[1])
        s.last_cmp = ("cmp", a, b)
        w = max(a.width, b.width)
        s.flags["ZF"] = eq(a, b)
        s.flags["CF"] = ltu(a, b)
        s.flags["SF"] = lt(sub(a, b), k(0, w))
        s.flags["OF"] = _fresh("OF", 1)
        s.flags["PF"] = _fresh("PF", 1)
        return s
    if op is Op.TEST:
        a = _eval(s, insn.args[0])
        b = _eval(s, insn.args[1])
        s.last_cmp = ("test", a, b)
        w = max(a.width, b.width)
        conj = and_(a, b)
        s.flags["ZF"] = eq(conj, k(0, w))
        s.flags["CF"] = k(0, 1)
        s.flags["OF"] = k(0, 1)
        s.flags["SF"] = lt(conj, k(0, w))
        s.flags["PF"] = _fresh("PF", 1)
        return s

    if op is Op.SETFLAG:
        # flag value: derived from the standing cmp/test context when available,
        # else opaque.  (Branch precision comes from last_cmp, not from here.)
        if insn.dst is not None:
            s.flags[insn.dst.name] = _flag_value(s, insn.dst.name)
        return s

    # -- unmodelled arithmetic -> havoc ----------------------------------
    if op in (Op.DIV, Op.IDIV, Op.ROL, Op.ROR):
        _havoc_dst(s, insn, f"unmodelled {op.name}")
        return s

    # -- havoc family -----------------------------------------------------
    if op in (Op.UNDEF, Op.SYSCALL, Op.INT, Op.HLT):
        _havoc_dst(s, insn, "opaque op")
        return s

    # -- no data effect ---------------------------------------------------
    if op in (Op.NOP, Op.FENCE, Op.CMP, Op.CALL, Op.RET, Op.JMP, Op.BR):
        return s

    return s


def _flag_value(state: SymState, name: str) -> Term:
    lc = state.last_cmp
    if lc is None:
        return sym(f"{name}_flag", 1)
    kind, a, b = lc
    w = max(a.width, b.width)
    if kind == "cmp":
        if name == "ZF":
            return eq(a, b)
        if name == "CF":
            return ltu(a, b)
        if name == "SF":
            return lt(sub(a, b), k(0, w))
    else:                                        # test
        conj = and_(a, b)
        if name == "ZF":
            return eq(conj, k(0, w))
        if name in ("CF", "OF"):
            return k(0, 1)
        if name == "SF":
            return lt(conj, k(0, w))
    return sym(f"{name}_flag", 1)


# ===========================================================================
# branch-condition recovery
# ===========================================================================
# jcc predicate token -> its negation (used for the else / fall-through side).
_NEG_TOKEN = {
    "eq": "ne", "ne": "eq", "lt": "ge", "ge": "lt", "le": "gt", "gt": "le",
    "b": "ae", "ae": "b", "be": "a", "a": "be", "s": "ns", "ns": "s",
    "o": "no", "no": "o", "p": "np", "np": "p",
}


def _cmp_predicate(token: str, a: Term, b: Term) -> Optional[Term]:
    """Taken-condition for a ``jcc`` whose flags came from ``cmp`` (a - b)."""
    w = max(a.width, b.width)
    table = {
        "eq": lambda: eq(a, b), "ne": lambda: ne(a, b),
        "lt": lambda: lt(a, b), "le": lambda: le(a, b),
        "gt": lambda: gt(a, b), "ge": lambda: ge(a, b),
        "b": lambda: ltu(a, b), "ae": lambda: geu(a, b),
        "be": lambda: leu(a, b), "a": lambda: gtu(a, b),
        "s": lambda: lt(sub(a, b), k(0, w)),
        "ns": lambda: ge(sub(a, b), k(0, w)),
    }
    fn = table.get(token)
    return fn() if fn is not None else None      # o/no/p/np -> unrecoverable


def _test_predicate(token: str, a: Term, b: Term) -> Optional[Term]:
    """Taken-condition for a ``jcc`` whose flags came from ``test`` (a & b);
    CF and OF are architecturally cleared by ``test``."""
    w = max(a.width, b.width)
    conj = and_(a, b)
    table = {
        "eq": lambda: eq(conj, k(0, w)), "ne": lambda: ne(conj, k(0, w)),
        "s": lambda: lt(conj, k(0, w)), "ns": lambda: ge(conj, k(0, w)),
        "b": lambda: k(0, 1),                    # CF cleared -> jb never taken
        "ae": lambda: k(1, 1),                   # CF cleared -> jae always taken
        "a": lambda: ne(conj, k(0, w)),          # CF=0, so a  <=> ZF=0
        "be": lambda: eq(conj, k(0, w)),         # CF=0, so be <=> ZF=1
    }
    fn = table.get(token)
    return fn() if fn is not None else None


def _branch_condition(state: SymState, br: IRInsn, taken: bool) -> Term:
    """The Term that must hold for ``br`` to go to ``then_ea`` (``taken=True``)
    or ``else_ea`` (``taken=False``)."""
    cond = br.args[0] if br.args else None
    token = ""
    if cond is not None and cond.name.startswith("cc_"):
        token = cond.name[3:]

    # rcx-counted branches (jrcxz / loop): reconstruct from the reg/imm operands
    if token.startswith("rcx"):
        if len(br.args) >= 3:
            v1 = _eval(state, br.args[1])
            v2 = _eval(state, br.args[2])
            base = eq(v1, v2) if token == "rcxz" else ne(v1, v2)
        else:
            base = _fresh(f"cc_{token}", 1)
        return base if taken else _negate(base)

    use_token = token if taken else _NEG_TOKEN.get(token, "")
    lc = state.last_cmp
    pred: Optional[Term] = None
    if lc is not None and use_token:
        kind, a, b = lc
        pred = (_cmp_predicate if kind == "cmp" else _test_predicate)(use_token, a, b)
    if pred is not None:
        return pred

    # No usable comparison context (flags from arith, or an exotic predicate):
    # emit a fresh unconstrained boolean -- honest over-approximation.
    return _fresh(f"cc_{token or 'x'}_{'t' if taken else 'f'}", 1)


def _negate(t: Term) -> Term:
    """Boolean negation used only for the rcx-counted fallback path."""
    if t.kind is Kind.OP and t.op in _NEG_TOKEN and len(t.args) == 2:
        return _BIN_CTORS[_NEG_TOKEN[t.op]](t.args[0], t.args[1])
    return eq(t, k(0, t.width))


# ===========================================================================
# path execution
# ===========================================================================
def _add_constraint(state: SymState, term: Term) -> Optional[SymState]:
    """Add ``term`` to the path condition, using constant-equality substitution
    for the satisfiability check.  Returns a NEW state, or ``None`` if the path is
    contradictory.

    The stored ``path_cond`` keeps each constraint in its natural (un-substituted)
    form so :func:`path_condition` can render ``x == 5`` rather than a folded
    ``true``; the substitution map is applied only to *detect* contradictions."""
    s = _copy(state)
    checked = simplify(_subst(term, s.subst))
    if checked.kind is Kind.CONST:
        if checked.imm == 0:
            return None                          # provably false -> infeasible
        return s                                 # implied by bindings -> no new info

    stored = simplify(term)
    s.path_cond.append(stored)

    binding = _as_const_equality(stored)
    if binding is not None:
        name, cval = binding
        if name in s.subst and _key(s.subst[name]) != _key(cval):
            return None                          # sym == C and sym == D (D != C)
        s.subst[name] = cval
        # re-check (do NOT rewrite) every stored constraint against the new
        # binding: an earlier symbolic term may now fold to a contradiction.
        for t in s.path_cond:
            chk = simplify(_subst(t, s.subst))
            if chk.kind is Kind.CONST and chk.imm == 0:
                return None
    return s


def symexec_path(func: IRFunction, path: List[int],
                 init: Optional[SymState] = None) -> Optional[SymState]:
    """Execute a chosen ``path`` (block-start EAs, in order).

    Each block's data insns are stepped; at a terminating ``BR`` the condition for
    continuing to the *next* block on the path is added to ``path_cond`` (the taken
    side for ``then_ea``, its negation for ``else_ea``).  ``JMP`` is followed;
    ``RET`` ends; ``CALL`` havocks ``rax``.  Returns ``None`` the moment a
    constraint is provably false; otherwise the final :class:`SymState`."""
    state = init if init is not None else initial_state(func)
    for i, bea in enumerate(path):
        blk = func.blocks.get(bea)
        if blk is None:
            return None
        nxt = path[i + 1] if i + 1 < len(path) else None
        for insn in blk.insns:
            op = insn.op
            if op is Op.BR:
                if nxt is not None:
                    taken = (nxt == insn.then_ea)
                    if not taken and nxt != insn.else_ea:
                        # path edge matches neither recorded target: unconstrained
                        continue
                    cond = _branch_condition(state, insn, taken)
                    nxt_state = _add_constraint(state, cond)
                    if nxt_state is None:
                        return None
                    state = nxt_state
                continue
            if op in (Op.JMP, Op.RET):
                continue
            if op is Op.CALL:
                state = _copy(state)
                state.regs["rax"] = _fresh("call_ret", 64)
                state.warnings.append(f"call @ {insn.ea:#x} -> rax havoc")
                continue
            state = step(state, insn)
    return state


# ===========================================================================
# reachability + input queries
# ===========================================================================
def enumerate_paths(func: IRFunction, target_block: int,
                    max_paths: int = 128, max_depth: int = 64) -> List[List[int]]:
    """DFS every simple path from ``func.entry`` to ``target_block``.

    Loops are approximated by allowing each block to appear at most twice on a
    path (i.e. at most one traversal of a back-edge), and paths are bounded by
    ``max_depth`` blocks and ``max_paths`` results (documented approximations)."""
    results: List[List[int]] = []
    if func.entry not in func.blocks or target_block not in func.blocks:
        return results

    def dfs(node: int, path: List[int], counts: Dict[int, int]) -> None:
        if len(results) >= max_paths or len(path) >= max_depth:
            return
        path = path + [node]
        counts = dict(counts)
        counts[node] = counts.get(node, 0) + 1
        if node == target_block:
            results.append(path)
            return
        for s in func.blocks[node].succs:
            if s not in func.blocks:
                continue
            if counts.get(s, 0) >= 2:            # one back-edge revisit at most
                continue
            dfs(s, path, counts)

    dfs(func.entry, [], {})
    return results


@dataclass
class Reachability:
    """Result of a reachability query.  ``approximate`` is always True: a *True*
    ``reachable`` may be infeasible under real arithmetic our algebra cannot
    refute (a *False* is sound -- see the module docstring)."""
    target: int
    reachable: bool
    path: Optional[List[int]] = None
    conditions: List[Term] = field(default_factory=list)
    approximate: bool = True
    note: str = ("structural SAT only: unreachable is sound, reachable "
                 "over-approximates (no linear-arithmetic solver)")


def analyze_reachability(func: IRFunction, target_block: int,
                         max_paths: int = 128, max_depth: int = 64,
                         init: Optional[SymState] = None) -> Reachability:
    """Full reachability result: the first satisfiable path and its conditions."""
    for path in enumerate_paths(func, target_block, max_paths, max_depth):
        st = symexec_path(func, path, init=_copy(init) if init is not None else None)
        if st is not None:
            return Reachability(target=target_block, reachable=True, path=path,
                                conditions=[simplify(t) for t in st.path_cond])
    return Reachability(target=target_block, reachable=False, path=None,
                        conditions=[])


def is_reachable(func: IRFunction, target_block: int,
                 max_paths: int = 128, max_depth: int = 64,
                 init: Optional[SymState] = None) -> bool:
    """True iff at least one enumerated path to ``target_block`` is not
    contradictory under the structural SAT check."""
    return analyze_reachability(func, target_block, max_paths, max_depth,
                                init).reachable


def path_condition(func: IRFunction, target_block: int,
                   max_paths: int = 128, max_depth: int = 64,
                   init: Optional[SymState] = None) -> Optional[List[Term]]:
    """The simplified, ANDed path condition of the first satisfiable path that
    reaches ``target_block`` (``None`` if the block is unreachable)."""
    r = analyze_reachability(func, target_block, max_paths, max_depth, init)
    return r.conditions if r.reachable else None


__all__ = [
    # term algebra
    "Kind", "Term", "k", "sym",
    "add", "sub", "and_", "or_", "xor", "shl", "shr", "sar", "mul",
    "neg", "not_", "eq", "ne", "lt", "le", "gt", "ge",
    "ltu", "leu", "gtu", "geu", "ite",
    "simplify", "is_unsat", "SIMPLIFIER_RULES",
    # interpreter
    "SymState", "initial_state", "step", "symexec_path",
    # reachability
    "enumerate_paths", "is_reachable", "path_condition",
    "analyze_reachability", "Reachability",
]
