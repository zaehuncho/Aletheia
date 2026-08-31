"""Project model + JSON persistence for Aletheia -- the document behind an editor window.

A :class:`Project` gathers the outputs of the existing analyzer modules for ONE
input file into a single mutable model, adds a small user-annotation layer
(comments + renames/labels), and can save/load itself to a JSON project file.
There is no new analysis logic here: every field is produced by a module under
``aletheia/`` (``pe``, ``detect``, ``disasm``, ``extract``, ``signatures``,
``imports``, ``behavior``, ``unpack``); this module is pure data plumbing over
what they return.

--------------------------------------------------------------------------------
What ROUND-TRIPS through JSON vs what is RECOMPUTED
--------------------------------------------------------------------------------
Persisted verbatim (survive save -> load):

* ``path`` and ``binary_sha256`` -- the file identity. ``binary_sha256`` is the
  sha256 of the file at ``path`` computed *at save time*.
* ``functions`` -- the recovered :class:`Function` partition (JSON-safe ints/strs).
* ``comments`` / ``labels`` -- the user-annotation layer.
* ``imports`` -- :class:`ResolvedImport` rows (all scalar fields).
* ``behavior`` -- :class:`BehaviorEvent` rows (its ``args`` is already a
  str->str dict, i.e. JSON-native).
* ``signatures`` -- :class:`Match` rows. Each hit's matched *bytes* are stored
  base64-encoded (bytes are not JSON types) and decoded back on load.
* ``strings`` -- :class:`FoundString` rows.
* ``resources`` -- :class:`ResourceEntry` rows. SEE the resource-bytes note below.
* ``unpack`` -- :class:`UnpackResult`, MINUS its ``dump: bytes`` field. The raw
  dumped image is intentionally NOT written into the JSON (it can be tens of MB
  of binary); instead its length is recorded as ``dump_size`` for reference, and
  on load ``unpack.dump`` comes back as ``None``.

NOT persisted -- recomputed on demand with ``refresh_pe()``:

* ``pe`` (:class:`PEInfo`) -- carries parsed structure best re-derived from the
  live file; cheap to re-parse.
* ``verdict`` (:class:`Verdict`) -- cheap to redo from ``pe`` + raw bytes.

After ``load``/``from_json`` both ``pe`` and ``verdict`` are ``None`` until the
caller calls ``refresh_pe()`` (which repopulates both).

--------------------------------------------------------------------------------
Resource-bytes decision
--------------------------------------------------------------------------------
:class:`ResourceEntry` does NOT carry any raw resource data -- it is pure
metadata: ``type``/``name``/``lang`` plus the leaf's declared ``rva``/``size``
and the file ``offset`` the RVA maps to. There are therefore no data bytes to
either base64 or drop; we keep the whole record (offset + size + labels)
verbatim. (Had it carried bytes, they would have been dropped in favour of
offset+size, matching the ``unpack.dump`` policy -- the raw payload is
re-readable from the file, the JSON stays small.)

--------------------------------------------------------------------------------
Function-partition imperfection (stated honestly)
--------------------------------------------------------------------------------
Recovering functions from a stripped binary is a well-known heuristic. Starts are
taken as the PE entry plus every direct CALL target (exactly the set
``signatures.identify_in_pe`` uses). Each function's extent is a *straight-line*
walk from its start to the first unconditional terminator (``ret`` / ``jmp``), the
next function start, or an address gap -- whichever comes first. This is a
"good-enough" partition: it does not chase conditional-branch bodies that jump
forward past a terminator, tail-call merges are approximate, and an unmapped call
target (its trace never decoded) yields no function at all rather than a
zero-size stub. It is deliberately conservative -- it records what is clean.
"""
from __future__ import annotations

import base64
import bisect
import hashlib
import json
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Dict, List, Optional

# Import MODULES (not names) so callers/tests can monkeypatch e.g.
# ``aletheia.detect.analyze`` and have from_pe pick up the patched function.
from aletheia import detect, disasm, extract, pe, signatures
from aletheia.behavior import BehaviorEvent
from aletheia.detect import Verdict
from aletheia.extract import FoundString, ResourceEntry
from aletheia.imports import ResolvedImport
from aletheia.pe import PEInfo
from aletheia.signatures import Match
from aletheia.unpack import UnpackResult

SCHEMA_VERSION = 1


# ===========================================================================
# model dataclasses
# ===========================================================================
@dataclass
class Function:
    """One recovered function. ``end`` is exclusive; ``size == end - start``.
    ``source`` records how it was discovered/named: ``"disasm"`` (a call target
    with no better name), ``"signature"`` (a FLIRT-style id hit), ``"entry"`` (the
    PE entry point), or ``"user"`` (added via :meth:`Project.add_function`)."""
    start: int
    end: int
    name: str
    basic_blocks: List[int] = field(default_factory=list)   # block start addrs
    xrefs_to: List[int] = field(default_factory=list)        # callers
    xrefs_from: List[int] = field(default_factory=list)      # outgoing targets
    size: int = 0
    source: str = "disasm"


@dataclass
class Comment:
    addr: int
    text: str
    author: str = "user"


@dataclass
class Label:
    addr: int
    name: str


@dataclass
class ArtifactSummary:
    n_strings: int
    n_resources: int
    n_signatures: int
    n_imports: int
    n_behavior_events: int
    oep: Optional[int]


# ===========================================================================
# helpers
# ===========================================================================
def _encode(obj):
    """JSON helper: turn a dataclass INSTANCE into a dict via ``asdict``; leave
    plain JSON-native values untouched. Used for the fields whose dataclasses are
    already JSON-safe (functions, comments, labels, imports, behavior, strings,
    resources). The byte-bearing dataclasses (Match, UnpackResult) get bespoke
    encoders below."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    return obj


def _sha256_file(path: str) -> Optional[str]:
    """sha256 hex of the file at ``path``, or ``None`` if it cannot be read."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _match_to_dict(m: Match) -> dict:
    return {
        "rule_name": m.rule_name,
        "tags": list(m.tags),
        "strings": [[pid, off, base64.b64encode(b).decode("ascii")]
                    for (pid, off, b) in m.strings],
    }


def _match_from_dict(d: dict) -> Match:
    return Match(
        rule_name=d["rule_name"],
        tags=tuple(d.get("tags", ())),
        strings=[(pid, off, base64.b64decode(b))
                 for (pid, off, b) in d.get("strings", [])],
    )


def _unpack_to_dict(u: UnpackResult) -> dict:
    # Drop the raw dump bytes; keep only its length as a reference.
    return {
        "detected": u.detected,
        "oep": u.oep,
        "main_base": u.main_base,
        "exit_code": u.exit_code,
        "dump_size": len(u.dump) if u.dump else 0,
    }


def _unpack_from_dict(d: dict) -> UnpackResult:
    # dump is never persisted -> comes back None (dump_size stays in the JSON only).
    return UnpackResult(
        detected=d["detected"],
        oep=d.get("oep"),
        main_base=d.get("main_base", 0),
        exit_code=d.get("exit_code"),
        dump=None,
    )


def _function_extent(by_addr: Dict[int, "disasm.Instruction"], start: int,
                     boundaries: set):
    """Straight-line walk from ``start``: stop at the first ret / unconditional
    jmp, at another function start (``boundaries``), or at an address gap. Returns
    ``(end_exclusive, [addrs of the instructions walked])``."""
    addr = start
    end = start
    body: List[int] = []
    while addr in by_addr:
        ins = by_addr[addr]
        body.append(addr)
        end = ins.end
        if ins.is_ret or ins.is_jmp:          # unconditional terminator
            break
        nxt = ins.end
        if nxt != start and nxt in boundaries:  # reached the next function
            break
        if nxt not in by_addr:                 # gap / end of decoded stream
            break
        addr = nxt
    return end, body


def _name_for(start: int, entry: int, names: Dict[int, str]):
    """(name, source) for a function start. Signature id wins, then the PE entry,
    then a synthetic ``sub_<addr>``. A user rename overrides this later."""
    if start in names:
        return names[start], "signature"
    if start == entry:
        return "entry", "entry"
    return f"sub_{start:x}", "disasm"


# ===========================================================================
# the Project
# ===========================================================================
class Project:
    """The analysis model for one input file (see the module docstring)."""

    def __init__(self, path: str) -> None:
        self.path: str = path
        self.pe: Optional[PEInfo] = None
        self.verdict: Optional[Verdict] = None
        self.functions: Dict[int, Function] = {}
        self.strings: List[FoundString] = []
        self.resources: List[ResourceEntry] = []
        self.signatures: List[Match] = []          # byte-pattern matches
        self.imports: List[ResolvedImport] = []    # empty until attach_imports
        self.behavior: List[BehaviorEvent] = []    # empty until attach_behavior
        self.unpack: Optional[UnpackResult] = None  # None until attach_unpack
        self.comments: Dict[int, Comment] = {}
        self.labels: Dict[int, Label] = {}
        self.errors: Dict[str, str] = {}
        self.binary_sha256: Optional[str] = None
        self.binary_matches: Optional[bool] = None
        # In-memory only (never persisted): the raw disasm result, so
        # add_function() can cheaply fill blocks/xrefs for a user-supplied start.
        self._disasm: Optional["disasm.DisasmResult"] = None

    # -- construction from the analyzers -----------------------------------
    @classmethod
    def from_pe(cls, path: str) -> "Project":
        """Run every static analyzer over ``path`` and wrap the results. Each
        analyzer is isolated in try/except so one failure records itself on
        ``self.errors`` (keyed by stage) without torpedoing the rest."""
        proj = cls(path)

        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            raw = b""
            proj.errors["read"] = repr(exc)

        try:
            proj.pe = pe.parse(path)
        except Exception as exc:                    # noqa: BLE001
            proj.errors["pe"] = repr(exc)

        try:
            if proj.pe is not None:
                proj.verdict = detect.analyze(proj.pe, raw)
        except Exception as exc:                    # noqa: BLE001
            proj.errors["verdict"] = repr(exc)

        try:
            ex = extract.extract_all(path)
            proj.strings = list(ex.strings)
            proj.resources = list(ex.resources)
        except Exception as exc:                    # noqa: BLE001
            proj.errors["extract"] = repr(exc)

        try:
            proj.signatures = list(signatures.scan_pe(path))
        except Exception as exc:                    # noqa: BLE001
            proj.errors["signatures"] = repr(exc)

        dis = None
        try:
            dis = disasm.disasm_pe(path)
        except Exception as exc:                    # noqa: BLE001
            proj.errors["disasm"] = repr(exc)

        names: Dict[int, str] = {}
        try:
            names = signatures.identify_in_pe(path, signatures.DEMO_SIGDB)
        except Exception as exc:                    # noqa: BLE001
            proj.errors["identify"] = repr(exc)

        if dis is not None:
            proj._disasm = dis
            proj._build_functions(dis, names)

        return proj

    def _build_functions(self, dis: "disasm.DisasmResult",
                         names: Dict[int, str]) -> None:
        by_addr = dis.instructions
        entry = dis.entry
        call_targets = {ins.target for ins in by_addr.values()
                        if ins.is_call and ins.target is not None}
        starts = sorted(s for s in ({entry} | call_targets) if s in by_addr)
        boundaries = set(starts)
        for s in starts:
            end, body = _function_extent(by_addr, s, boundaries)
            bbs = sorted(b.start for b in dis.blocks if s <= b.start < end)
            xfrom = sorted({by_addr[a].target for a in body
                            if by_addr[a].target is not None})
            xto = list(dis.xrefs.get(s, []))
            name, source = _name_for(s, entry, names)
            self.functions[s] = Function(
                start=s, end=end, name=name, basic_blocks=bbs,
                xrefs_to=xto, xrefs_from=xfrom, size=end - s, source=source)

    # -- lookups ------------------------------------------------------------
    def function_at(self, addr: int) -> Optional[Function]:
        """The function whose ``[start, end)`` contains ``addr`` (bisect on the
        sorted starts). ``None`` if ``addr`` precedes every function or falls in
        a gap between two functions."""
        starts = sorted(self.functions)
        if not starts:
            return None
        i = bisect.bisect_right(starts, addr) - 1
        if i < 0:
            return None
        fn = self.functions[starts[i]]
        return fn if fn.start <= addr < fn.end else None

    def label_for(self, addr: int) -> Optional[str]:
        """A user :class:`Label` wins; else the :class:`Function` name if ``addr``
        is a function start; else ``None``."""
        if addr in self.labels:
            return self.labels[addr].name
        if addr in self.functions:
            return self.functions[addr].name
        return None

    # -- annotation layer ---------------------------------------------------
    def rename(self, addr: int, name: str) -> None:
        """Set/replace the :class:`Label` at ``addr``; if ``addr`` is a function
        start, also update that :class:`Function`'s name (its ``source`` provenance
        is left intact -- the label is the user override that ``label_for`` returns
        first)."""
        self.labels[addr] = Label(addr=addr, name=name)
        if addr in self.functions:
            self.functions[addr].name = name

    def comment(self, addr: int, text: str) -> None:
        self.comments[addr] = Comment(addr=addr, text=text)

    def remove_comment(self, addr: int) -> None:
        self.comments.pop(addr, None)

    def add_function(self, start: int, name: Optional[str] = None) -> None:
        """Record a user-declared function at ``start`` (``source="user"``). Does
        NOT re-run disassembly; if the in-memory ``DisasmResult`` from ``from_pe``
        is still around and ``start`` was decoded, its basic blocks / xrefs are
        filled cheaply, otherwise they are left empty."""
        end, bbs, xto, xfrom = start, [], [], []
        dis = self._disasm
        if dis is not None and start in dis.instructions:
            boundaries = set(self.functions) | {start}
            end, body = _function_extent(dis.instructions, start, boundaries)
            bbs = sorted(b.start for b in dis.blocks if start <= b.start < end)
            xfrom = sorted({dis.instructions[a].target for a in body
                            if dis.instructions[a].target is not None})
            xto = list(dis.xrefs.get(start, []))
        self.functions[start] = Function(
            start=start, end=end, name=name or f"sub_{start:x}",
            basic_blocks=bbs, xrefs_to=xto, xrefs_from=xfrom,
            size=end - start, source="user")

    # -- attach dynamic-layer artifacts ------------------------------------
    def attach_imports(self, imports: List[ResolvedImport]) -> None:
        self.imports = list(imports)

    def attach_behavior(self, events: List[BehaviorEvent]) -> None:
        self.behavior = list(events)

    def attach_unpack(self, result: UnpackResult) -> None:
        self.unpack = result

    # -- summary ------------------------------------------------------------
    def summary(self) -> ArtifactSummary:
        return ArtifactSummary(
            n_strings=len(self.strings),
            n_resources=len(self.resources),
            n_signatures=len(self.signatures),
            n_imports=len(self.imports),
            n_behavior_events=len(self.behavior),
            oep=self.unpack.oep if self.unpack else None,
        )

    # -- persistence --------------------------------------------------------
    def to_json(self) -> str:
        """Serialize the persisted fields to a JSON string. Recomputes
        ``binary_sha256`` from the current file at ``self.path`` (the 'save time'
        hash) and stores it on ``self`` as well."""
        self.binary_sha256 = _sha256_file(self.path)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "path": self.path,
            "binary_sha256": self.binary_sha256,
            "functions": [_encode(f) for f in self.functions.values()],
            "comments": [_encode(c) for c in self.comments.values()],
            "labels": [_encode(l) for l in self.labels.values()],
            "imports": [_encode(i) for i in self.imports],
            "behavior": [_encode(e) for e in self.behavior],
            "signatures": [_match_to_dict(m) for m in self.signatures],
            "strings": [_encode(s) for s in self.strings],
            "resources": [_encode(r) for r in self.resources],
            "unpack": _unpack_to_dict(self.unpack) if self.unpack else None,
        }
        return json.dumps(payload, indent=2)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())

    @classmethod
    def from_json(cls, s: str) -> "Project":
        """Rebuild a Project from a JSON string. ``pe`` and ``verdict`` are left
        ``None`` (call :meth:`refresh_pe`). Sets ``binary_matches`` by comparing
        the stored hash against the current file at ``path``."""
        d = json.loads(s)
        proj = cls(d.get("path", ""))
        proj.binary_sha256 = d.get("binary_sha256")

        proj.functions = {}
        for fd in d.get("functions", []):
            fn = Function(**fd)
            proj.functions[fn.start] = fn

        proj.comments = {}
        for cd in d.get("comments", []):
            c = Comment(**cd)
            proj.comments[c.addr] = c

        proj.labels = {}
        for ld in d.get("labels", []):
            lab = Label(**ld)
            proj.labels[lab.addr] = lab

        proj.imports = [ResolvedImport(**i) for i in d.get("imports", [])]
        proj.behavior = [BehaviorEvent(**e) for e in d.get("behavior", [])]
        proj.signatures = [_match_from_dict(m) for m in d.get("signatures", [])]
        proj.strings = [FoundString(**s2) for s2 in d.get("strings", [])]
        proj.resources = [ResourceEntry(**r) for r in d.get("resources", [])]
        up = d.get("unpack")
        proj.unpack = _unpack_from_dict(up) if up else None

        # binary integrity check against the current file on disk
        current = _sha256_file(proj.path)
        if current is None:
            proj.binary_matches = False
            proj.errors["binary"] = f"file missing/unreadable at load: {proj.path!r}"
        else:
            proj.binary_matches = (current == proj.binary_sha256)
        return proj

    @classmethod
    def load(cls, path: str) -> "Project":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_json(fh.read())

    # -- recompute the non-persisted fields --------------------------------
    def refresh_pe(self) -> None:
        """Re-run ``pe.parse`` (and, since it is cheap and needs the same bytes,
        ``detect.analyze``) to repopulate ``self.pe`` / ``self.verdict``."""
        self.pe = pe.parse(self.path)
        try:
            with open(self.path, "rb") as fh:
                raw = fh.read()
        except OSError:
            raw = b""
        if self.pe is not None:
            self.verdict = detect.analyze(self.pe, raw)
