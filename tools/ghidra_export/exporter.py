"""Ghidra exporter -- turn an Aletheia :class:`~aletheia.project.Project` into a
Ghidra-consumable annotation script.

This is the interop half of the "Aletheia unpacks, Ghidra decompiles" story:
Aletheia does the runtime work Ghidra is blind to (unpacking, IAT resolution,
behaviour tracing) and Ghidra owns the deep static decompiler. This module bridges
them by writing two sibling artifacts:

* ``aletheia_export.json`` -- a machine-readable dump of everything Ghidra can
  consume: the recovered function partition, the user annotation layer
  (labels + comments), resolved imports (with an optional ``purpose`` tag), and any
  per-function decompiled source Aletheia produced.
* ``aletheia_import.py`` -- a small **standalone Jython 2.7** script (Ghidra ships
  Jython, not CPython 3) that the analyst runs *inside* Ghidra. It auto-locates the
  JSON sibling and replays every annotation through Ghidra's flat program API
  (``createFunction`` / ``createLabel`` / ``setPreComment`` / ``setPlateComment``).

Design notes
------------
* **Stdlib only.** No templating engine: the Jython script is assembled from a
  static body constant plus a small ``.format``-filled header. The body is never
  run through ``%``/``.format`` on the CPython side, so its own ``%``/``{}`` are
  left untouched.
* **Read-only over the Project.** Nothing here mutates the Project or any
  ``aletheia/`` module; it is pure serialization. ``ResolvedImport.purpose`` is a
  soon-to-land, optional tag read best-effort via ``getattr``.
* **Address rebasing is deferred to Ghidra.** The export records the image base the
  addresses were captured against (from ``project.pe.image_base`` when available,
  else ``null``). The Jython side rebases to the *currently open* program's image
  base, so an analyst who loaded the same binary at a different base still lands on
  the right addresses; a ``null`` base means "addresses are as-loaded, trust them".
"""
from __future__ import annotations

import datetime
import hashlib
import json
import pathlib
from typing import Any, Dict, List, Optional

EXPORT_VERSION = 1
JSON_NAME = "aletheia_export.json"
SCRIPT_NAME = "aletheia_import.py"


# ===========================================================================
# small helpers
# ===========================================================================
def _sha256(path: str) -> Optional[str]:
    """sha256 hex of the file at ``path``, or ``None`` if it cannot be read."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _addr_key(addr: int) -> str:
    """Canonical JSON object key for an address (hex, ``int(k, 0)``-parseable)."""
    return "0x%x" % int(addr)


def _normalize_purpose(purpose: Any) -> Optional[str]:
    """Coerce an import's ``purpose`` to a clean ``str`` or ``None``.

    ``ResolvedImport.purpose`` is an ``aletheia.imports.Purpose`` (a str-enum whose
    default is ``UNKNOWN``); older/hand-built rows may carry a plain string or
    nothing at all -- so this is read best-effort. An ``Enum`` collapses to its
    ``.value``; the ``UNKNOWN``/empty sentinel becomes ``None`` so only a
    *meaningful* classification survives (and only those get a Ghidra comment)."""
    val = getattr(purpose, "value", purpose)     # Enum -> its value; str/None stay
    if val is None:
        return None
    val = str(val)
    if val.strip().lower() in ("", "unknown"):
        return None
    return val


def _decompiled_source(val: Any) -> Optional[str]:
    """Pull emitted source text out of a DecompiledFunction-like object or a plain
    string. Returns ``None`` when there is nothing usable."""
    if val is None:
        return None
    src = getattr(val, "source", None)
    if isinstance(src, str):
        return src
    if isinstance(val, str):
        return val
    return None


def _collect_decompiled(project: Any) -> List[Dict[str, Any]]:
    """Best-effort read of any per-function decompiled source hung off the Project.

    The Project model has no first-class field for decompiler output, so this reads
    an optional ``project.decompiled`` attribute (never required). It accepts:

    * a mapping ``{start_addr_or_name: DecompiledFunction | source_str}``
    * an iterable of ``DecompiledFunction`` (matched to a function by ``.name``)
    * an iterable of ``(start_or_name, source)`` pairs

    Anything that cannot be tied to a known function ``start`` is dropped. Returns a
    ``start``-sorted list of ``{"start": int, "source": str}`` dicts (empty when the
    Project carries no decompiled source)."""
    raw = getattr(project, "decompiled", None)
    if not raw:
        return []

    name_to_start: Dict[str, int] = {}
    for start, fn in getattr(project, "functions", {}).items():
        name = getattr(fn, "name", None)
        if name:
            name_to_start.setdefault(name, start)

    def resolve_start(key: Any) -> Optional[int]:
        if isinstance(key, bool):            # avoid True/False -> 1/0 surprises
            return None
        if isinstance(key, int):
            return key
        if isinstance(key, str):
            return name_to_start.get(key)
        return None

    out: List[Dict[str, Any]] = []
    if isinstance(raw, dict):
        items = list(raw.items())
    else:
        items = []
        for item in raw:
            if isinstance(item, (tuple, list)) and len(item) == 2:
                items.append((item[0], item[1]))
            else:                             # a bare DecompiledFunction -> by name
                items.append((getattr(item, "name", None), item))

    for key, val in items:
        start = resolve_start(key)
        src = _decompiled_source(val)
        if start is not None and src is not None:
            out.append({"start": int(start), "source": src})

    out.sort(key=lambda d: d["start"])
    return out


# ===========================================================================
# payload
# ===========================================================================
def build_payload(project: Any) -> Dict[str, Any]:
    """Serialize the Ghidra-consumable subset of a Project to a plain dict (the
    exact structure written to ``aletheia_export.json``)."""
    pe = getattr(project, "pe", None)
    image_base = getattr(pe, "image_base", None) if pe is not None else None

    sha = getattr(project, "binary_sha256", None)
    if not sha:
        sha = _sha256(getattr(project, "path", "") or "")

    functions: List[Dict[str, Any]] = []
    for fn in sorted(project.functions.values(), key=lambda f: f.start):
        functions.append({
            "start": int(fn.start),
            "end": int(fn.end),
            "name": fn.name,
            "source": fn.source,
            "size": int(fn.size),
            "blocks": [int(b) for b in fn.basic_blocks],
        })

    labels = {_addr_key(lab.addr): lab.name
              for lab in project.labels.values()}
    comments = {_addr_key(c.addr): c.text
                for c in project.comments.values()}

    imports: List[Dict[str, Any]] = []
    for imp in getattr(project, "imports", []):
        imports.append({
            "slot_addr": int(imp.slot_addr),
            "module": imp.module_name,
            "func": imp.func_name,
            "purpose": _normalize_purpose(getattr(imp, "purpose", None)),
        })

    return {
        "aletheia_export_version": EXPORT_VERSION,
        "generated": datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "path": getattr(project, "path", ""),
        "binary_sha256": sha,
        "image_base": int(image_base) if image_base else None,
        "functions": functions,
        "labels": labels,
        "comments": comments,
        "imports": imports,
        "decompiled": _collect_decompiled(project),
    }


# ===========================================================================
# the Jython 2.7 side -- header + static body
# ===========================================================================
# NOTE: the body below is written to run under Ghidra's Jython 2.7, but is kept
# valid Python 3 *syntax* so the exporter's tests can compile() it as a shape check.
# It is emitted verbatim -- do NOT run ``%``/``.format`` over it (its own ``%`` and
# ``{}`` are load-bearing at Ghidra runtime).
_SCRIPT_HEADER = '''\
# ---------------------------------------------------------------------------
# aletheia_import.py -- generated by Aletheia's Ghidra exporter. DO NOT EDIT.
#
#   source project : {path}
#   binary sha256  : {sha}
#   image base     : {image_base}
#   generated (UTC): {generated}
#   contents       : {n_func} functions / {n_lab} labels / {n_com} comments /
#                    {n_imp} imports / {n_dec} decompiled
#
# HOW TO RUN (inside Ghidra):
#   1. Open the SAME target binary in Ghidra (CodeBrowser) and let auto-analysis
#      finish. The exported addresses were captured against the image base noted
#      above; this script rebases them onto whatever base your program loaded at.
#   2. Window -> Script Manager -> (toolbar) "Create New Script" is NOT needed;
#      instead add this file's directory via the "Manage Script Directories"
#      (bundle) button, then find `aletheia_import.py` in the list and Run it.
#   3. The script auto-locates its sibling `aletheia_export.json`. If it cannot,
#      it will prompt you to pick the JSON file.
#
# Ghidra ships Jython 2.7 (NOT CPython 3); this script targets that runtime.
# ---------------------------------------------------------------------------
#@category Aletheia
#@keybinding
#@menupath Tools.Aletheia.Import annotations
#@toolbar
'''

_SCRIPT_BODY = r'''
from __future__ import print_function

import json
import os


def _script_dir():
    """Directory of THIS script -- via the GhidraScript source file first
    (reliable under Ghidra), falling back to __file__ for plain-CPython runs."""
    try:
        return str(getSourceFile().getParentFile().getAbsolutePath())
    except Exception:
        pass
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except Exception:
        return None


def _read_json(path):
    fh = open(path, "rb")
    try:
        return json.loads(fh.read().decode("utf-8"))
    finally:
        fh.close()


def _load_export():
    """Locate + parse aletheia_export.json: same dir as the script, else prompt."""
    d = _script_dir()
    if d:
        cand = os.path.join(d, "aletheia_export.json")
        if os.path.isfile(cand):
            return _read_json(cand), cand
    try:
        picked = askFile("Select aletheia_export.json", "Open")
        path = picked.getAbsolutePath()
        return _read_json(path), path
    except Exception as exc:
        print("[aletheia] could not locate aletheia_export.json: %s" % (exc,))
        return None, None


def run():
    from ghidra.program.model.symbol import SourceType

    data, src = _load_export()
    if data is None:
        print("[aletheia] nothing to do -- no export JSON.")
        return
    print("[aletheia] loaded %s" % (src,))

    # Rebase: exported addresses were captured against data["image_base"]; move
    # them onto the currently open program's base. A null export base means the
    # addresses are already as-loaded, so pass them straight through.
    prog_base = currentProgram.getImageBase().getOffset()
    export_base = data.get("image_base")

    def gaddr(a):
        a = long(a)
        if export_base is not None:
            return toAddr(prog_base + (a - long(export_base)))
        return toAddr(a)

    n_func = n_lab = n_com = n_imp = n_dec = 0

    # -- functions ----------------------------------------------------------
    for fn in data.get("functions", []):
        try:
            start = fn.get("start")
            if start is None:
                continue
            name = fn.get("name") or ("sub_%x" % long(start))
            addr = gaddr(start)
            f = None
            try:
                f = createFunction(addr, name)     # None if it already exists
            except Exception:
                f = None
            if f is None:
                f = getFunctionAt(addr)            # swallow "already exists"
            if f is None:
                print("[aletheia] no function at %s (no code?)" % (addr,))
                continue
            try:
                if f.getName() != name:
                    f.setName(name, SourceType.USER_DEFINED)
            except Exception as exc:
                print("[aletheia] rename failed at %s: %s" % (addr, exc))
            n_func += 1
        except Exception as exc:
            print("[aletheia] function error: %s" % (exc,))

    # -- labels -------------------------------------------------------------
    for addr_str, name in (data.get("labels") or {}).items():
        try:
            createLabel(gaddr(int(addr_str, 0)), name, True)
            n_lab += 1
        except Exception as exc:
            print("[aletheia] label error at %s: %s" % (addr_str, exc))

    # -- comments -----------------------------------------------------------
    for addr_str, text in (data.get("comments") or {}).items():
        try:
            setPreComment(gaddr(int(addr_str, 0)), text)
            n_com += 1
        except Exception as exc:
            print("[aletheia] comment error at %s: %s" % (addr_str, exc))

    # -- imports (only those carrying a purpose tag) ------------------------
    for imp in data.get("imports", []):
        purpose = imp.get("purpose")
        if not purpose:
            continue
        try:
            module = imp.get("module") or "?"
            func = imp.get("func") or "?"
            note = "[%s] %s!%s" % (str(purpose).upper(), module, func)
            setPreComment(gaddr(imp.get("slot_addr")), note)
            n_imp += 1
        except Exception as exc:
            print("[aletheia] import error: %s" % (exc,))

    # -- decompiled source -> plate comment above the function --------------
    for dec in data.get("decompiled", []):
        try:
            start = dec.get("start")
            if start is None:
                continue
            setPlateComment(gaddr(start), dec.get("source") or "")
            n_dec += 1
        except Exception as exc:
            print("[aletheia] decompiled error: %s" % (exc,))

    print("[aletheia] done: %d functions annotated / %d labels / %d comments / "
          "%d imports / %d decompiled" % (n_func, n_lab, n_com, n_imp, n_dec))


run()
'''


def render_script(payload: Dict[str, Any]) -> str:
    """Assemble the full Jython script text for a given export ``payload``."""
    header = _SCRIPT_HEADER.format(
        path=payload.get("path", ""),
        sha=payload.get("binary_sha256"),
        image_base=(("0x%x" % payload["image_base"])
                    if payload.get("image_base") else "null (as-loaded)"),
        generated=payload.get("generated", ""),
        n_func=len(payload.get("functions", [])),
        n_lab=len(payload.get("labels", {})),
        n_com=len(payload.get("comments", {})),
        n_imp=sum(1 for i in payload.get("imports", []) if i.get("purpose")),
        n_dec=len(payload.get("decompiled", [])),
    )
    return header + _SCRIPT_BODY


# ===========================================================================
# public entry point
# ===========================================================================
def export_project(project: Any, out_dir: "pathlib.Path") -> Dict[str, "pathlib.Path"]:
    """Write ``aletheia_export.json`` + ``aletheia_import.py`` into ``out_dir``.

    Returns ``{"json": <path>, "script": <path>}`` of what was written. See the
    module docstring for the split of responsibilities between the two files."""
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = build_payload(project)

    json_path = out_dir / JSON_NAME
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    script_path = out_dir / SCRIPT_NAME
    script_path.write_text(render_script(payload), encoding="utf-8")

    return {"json": json_path, "script": script_path}


__all__ = ["export_project", "build_payload", "render_script",
           "EXPORT_VERSION", "JSON_NAME", "SCRIPT_NAME"]
