"""Tests for the Ghidra exporter (``tools/ghidra_export/exporter.py``).

These are *shape* tests: they build a small in-memory :class:`Project`, run the
exporter, and check the two emitted artifacts -- the JSON dump and the Jython
``aletheia_import.py`` script. The script is only ``compile()``-checked (syntax),
never executed: running it needs Ghidra's Jython runtime + a loaded program, which
CI does not have. Undefined Ghidra globals (``createFunction`` / ``toAddr`` / ...)
are therefore expected and fine -- ``compile`` catches syntax, not name errors.
"""
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aletheia.decompile import DecompiledFunction  # noqa: E402
from aletheia.imports import ResolvedImport  # noqa: E402
from aletheia.project import Function, Project  # noqa: E402
from tools.ghidra_export.exporter import (  # noqa: E402
    JSON_NAME, SCRIPT_NAME, build_payload, export_project,
)

BASE = 0x140000000
F1 = BASE + 0x1000     # entry
F2 = BASE + 0x1010     # renamed to "checkflag"
F3 = BASE + 0x1020     # leaf


def _make_project(tmp_path):
    """A hand-built Project: 3 functions, 2 labels, 2 comments, 2 imports (one
    carrying a ``purpose`` tag), and one attached decompiled function."""
    # a real file on disk so build_payload can hash it
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ" + b"\x00" * 128)

    proj = Project(str(target))
    # a stub PEInfo just to exercise the image_base branch
    proj.pe = types.SimpleNamespace(image_base=BASE)

    proj.functions[F1] = Function(start=F1, end=F1 + 0x10, name="entry",
                                  basic_blocks=[F1], xrefs_to=[], xrefs_from=[F2],
                                  size=0x10, source="entry")
    proj.functions[F2] = Function(start=F2, end=F2 + 0x10, name="sub_140001010",
                                  basic_blocks=[F2], xrefs_to=[F1], xrefs_from=[F3],
                                  size=0x10, source="disasm")
    proj.functions[F3] = Function(start=F3, end=F3 + 0x06, name="sub_140001020",
                                  basic_blocks=[F3], xrefs_to=[F2], xrefs_from=[],
                                  size=0x06, source="disasm")

    # annotation layer: a rename (label + function name) and a standalone label
    proj.rename(F2, "checkflag")
    proj.rename(BASE + 0x1234, "loop_top")

    # comments
    proj.comment(F1, "real entry point")
    proj.comment(BASE + 0x1050, "compares against the magic constant")

    # imports -- one with a (soon-to-land, best-effort) purpose tag, one without
    imp_a = ResolvedImport(slot_addr=BASE + 0x3000, slot_rva=0,
                           module_name="kernel32.dll", func_name="VirtualAllocEx",
                           ordinal=None, value=0x7FF000001000)
    imp_a.purpose = "process-injection"          # attribute the exporter reads via getattr
    imp_b = ResolvedImport(slot_addr=BASE + 0x3008, slot_rva=8,
                           module_name="kernel32.dll", func_name="LoadLibraryA",
                           ordinal=None, value=0x7FF000002000)
    proj.attach_imports([imp_a, imp_b])

    # one attached decompiled function (Project has no first-class field for it;
    # the exporter reads an optional ``.decompiled`` attribute)
    dec = DecompiledFunction(name="checkflag",
                             source="int64_t checkflag(void) {\n    return 1;\n}")
    proj.decompiled = {F2: dec}

    return proj


# ===========================================================================
# the export
# ===========================================================================
def test_export_writes_both_files(tmp_path):
    proj = _make_project(tmp_path)
    out = tmp_path / "export"
    result = export_project(proj, out)

    assert set(result) == {"json", "script"}
    assert result["json"].name == JSON_NAME
    assert result["script"].name == SCRIPT_NAME
    assert result["json"].is_file()
    assert result["script"].is_file()


def test_json_parses_and_has_top_level_shape(tmp_path):
    proj = _make_project(tmp_path)
    out = tmp_path / "export"
    result = export_project(proj, out)

    data = json.loads(result["json"].read_text(encoding="utf-8"))
    for key in ("path", "binary_sha256", "image_base", "functions", "labels",
                "comments", "imports", "decompiled"):
        assert key in data, "missing top-level key %r" % key

    assert data["path"] == proj.path
    assert isinstance(data["binary_sha256"], str) and len(data["binary_sha256"]) == 64
    assert data["image_base"] == BASE


def test_json_functions_shape(tmp_path):
    proj = _make_project(tmp_path)
    data = json.loads(
        export_project(proj, tmp_path / "e")["json"].read_text(encoding="utf-8"))

    fns = {f["start"]: f for f in data["functions"]}
    assert set(fns) == {F1, F2, F3}
    for f in data["functions"]:
        assert set(f) == {"start", "end", "name", "source", "size", "blocks"}
        assert isinstance(f["blocks"], list)
    # the rename propagated into the function record
    assert fns[F2]["name"] == "checkflag"
    assert fns[F1]["source"] == "entry"
    assert fns[F3]["size"] == 0x06


def test_json_labels_and_comments(tmp_path):
    proj = _make_project(tmp_path)
    data = json.loads(
        export_project(proj, tmp_path / "e")["json"].read_text(encoding="utf-8"))

    # labels keyed by hex address string, int(k, 0)-parseable
    labels = data["labels"]
    assert labels["0x%x" % F2] == "checkflag"
    assert labels["0x%x" % (BASE + 0x1234)] == "loop_top"
    for k in labels:
        assert int(k, 0) >= 0                     # every key parses as an address

    comments = data["comments"]
    assert comments["0x%x" % F1] == "real entry point"
    assert comments["0x%x" % (BASE + 0x1050)] == "compares against the magic constant"


def test_json_imports_shape_and_purpose(tmp_path):
    proj = _make_project(tmp_path)
    data = json.loads(
        export_project(proj, tmp_path / "e")["json"].read_text(encoding="utf-8"))

    imports = {i["slot_addr"]: i for i in data["imports"]}
    assert len(imports) == 2
    for i in data["imports"]:
        assert set(i) == {"slot_addr", "module", "func", "purpose"}

    a = imports[BASE + 0x3000]
    assert a["module"] == "kernel32.dll"
    assert a["func"] == "VirtualAllocEx"
    assert a["purpose"] == "process-injection"

    b = imports[BASE + 0x3008]
    assert b["func"] == "LoadLibraryA"
    assert b["purpose"] is None                   # no purpose attribute -> null


def test_json_decompiled_block(tmp_path):
    proj = _make_project(tmp_path)
    data = json.loads(
        export_project(proj, tmp_path / "e")["json"].read_text(encoding="utf-8"))

    assert len(data["decompiled"]) == 1
    dec = data["decompiled"][0]
    assert set(dec) == {"start", "source"}
    assert dec["start"] == F2
    assert dec["source"].startswith("int64_t checkflag(void)")


def test_decompiled_can_be_attached_by_name_list(tmp_path):
    """The exporter also accepts an iterable of DecompiledFunction, matched to a
    function by name (not just a {start: fn} dict)."""
    proj = _make_project(tmp_path)
    proj.decompiled = [DecompiledFunction(name="checkflag",
                                          source="void checkflag(void) {}")]
    data = build_payload(proj)
    assert len(data["decompiled"]) == 1
    assert data["decompiled"][0]["start"] == F2   # resolved "checkflag" -> F2


def test_decompiled_absent_yields_empty_list(tmp_path):
    proj = _make_project(tmp_path)
    del proj.decompiled
    data = build_payload(proj)
    assert data["decompiled"] == []


# ===========================================================================
# the emitted Jython script
# ===========================================================================
def test_script_is_syntactically_valid_python(tmp_path):
    proj = _make_project(tmp_path)
    script = export_project(proj, tmp_path / "e")["script"]
    src = script.read_text(encoding="utf-8")
    # compile() catches SYNTAX errors; undefined Ghidra globals are not caught
    # (and are expected -- this is a shape test, not an execution test).
    compile(src, str(script), "exec")


def test_script_header_references_project_and_calls_api(tmp_path):
    proj = _make_project(tmp_path)
    script = export_project(proj, tmp_path / "e")["script"]
    src = script.read_text(encoding="utf-8")

    # header provenance
    assert proj.path in src
    assert "Jython 2.7" in src
    assert "Script Manager" in src

    # it actually drives the documented Ghidra API surface
    for api in ("createFunction", "createLabel", "setPreComment",
                "setPlateComment", "getFunctionAt", "toAddr"):
        assert api in src, "script never calls %s" % api

    # it auto-locates the sibling JSON and has an ask-file fallback
    assert JSON_NAME in src
    assert "askFile" in src
