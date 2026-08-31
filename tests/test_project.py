"""Tests for aletheia.project: the analysis-model + JSON persistence layer.

A tiny hand-assembled on-disk x64 PE (entry at RVA 0x1000, with two direct-call
targets so ``from_pe`` recovers three functions) is written to a tmp file and run
through ``Project.from_pe``. That exercises the real analyzers end to end; the
annotation layer, attach/summary, and the save/load round-trip are then checked
on top of it.

Requires capstone (``from_pe`` disassembles); the module itself imports without
it. The synthetic-PE builder is copied from test_signatures/test_detect (test
modules do not import each other).
"""
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

pytest.importorskip("capstone")

from aletheia import detect, project as project_mod  # noqa: E402
from aletheia.behavior import BehaviorEvent  # noqa: E402
from aletheia.imports import ResolvedImport  # noqa: E402
from aletheia.project import (  # noqa: E402
    ArtifactSummary, Comment, Function, Label, Project,
)
from aletheia.signatures import Match  # noqa: E402
from aletheia.unpack import UnpackResult  # noqa: E402

BASE = 0x140000000


# ---------------------------------------------------------------------------
# synthetic on-disk PE (same builder shape as test_signatures._make_pe)
# ---------------------------------------------------------------------------
# RVA 0x1000 (entry): push rbp; mov rbp,rsp; call +7 (-> 0x1010); pop rbp; ret
# RVA 0x1010:          sub rsp,28h; call +7 (-> 0x1020); add rsp,28h; ret
# RVA 0x1020:          push rbp; mov rbp,rsp; pop rbp; ret
_TEXT = bytes.fromhex(
    "55" "4889E5" "E807000000" "5D" "C3"      # 0x1000..0x100A
    "9090909090"                              # pad to 0x1010
    "4883EC28" "E807000000" "4883C428" "C3"   # 0x1010..0x101D
    "9090"                                    # pad to 0x1020
    "55" "4889E5" "5D" "C3")                  # 0x1020..0x1025


def _make_pe(text: bytes = _TEXT) -> bytes:
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)          # e_lfanew = 64
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)                       # PE32+
    struct.pack_into("<I", opt, 16, 0x1000)                     # entry RVA
    struct.pack_into("<Q", opt, 24, BASE)                       # image base
    struct.pack_into("<I", opt, 108, 16)                        # num data dirs
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x0022)
    raw0 = 512
    hdr = (b".text\x00\x00\x00" + struct.pack("<IIII", len(text), 0x1000,
           len(text), raw0) + b"\x00" * 12 + struct.pack("<I", 0x60000020))
    head = dos + b"PE\x00\x00" + coff + bytes(opt) + hdr
    return head + b"\x00" * (raw0 - len(head)) + text


@pytest.fixture()
def synth(tmp_path):
    path = tmp_path / "synth.exe"
    path.write_bytes(_make_pe())
    return str(path)


@pytest.fixture()
def proj(synth):
    return Project.from_pe(synth)


ENTRY = BASE + 0x1000
F_MID = BASE + 0x1010
F_LEAF = BASE + 0x1020


# ===========================================================================
# from_pe wiring
# ===========================================================================
def test_from_pe_populates_pe_verdict_and_functions(proj):
    assert proj.pe is not None and proj.pe.ok and proj.pe.arch == "x64"
    assert proj.verdict is not None                     # detect.analyze ran
    assert not proj.errors, proj.errors
    # entry + the two call targets -> three recovered functions
    assert set(proj.functions) == {ENTRY, F_MID, F_LEAF}
    ef = proj.functions[ENTRY]
    assert ef.start == ENTRY and ef.end > ef.start and ef.size == ef.end - ef.start
    assert ef.source in {"signature", "entry", "disasm"}
    # the entry calls into 0x1010; that edge shows up as an outgoing xref
    assert F_MID in ef.xrefs_from
    # 0x1010 is called from inside the entry function -> caller recorded
    assert proj.functions[F_MID].xrefs_to


def test_from_pe_records_errors_when_an_analyzer_raises(synth, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("synthetic analyzer failure")

    # patch the module attribute project.py resolves at call time
    monkeypatch.setattr(detect, "analyze", boom)
    p = Project.from_pe(synth)
    assert "verdict" in p.errors
    assert "synthetic analyzer failure" in p.errors["verdict"]
    # a single analyzer failure must not torpedo the rest of the project
    assert p.pe is not None and p.pe.ok
    assert p.functions                                  # disasm still ran


# ===========================================================================
# lookups
# ===========================================================================
def test_function_at_containment_and_bounds(proj):
    assert proj.function_at(ENTRY) is proj.functions[ENTRY]
    # an address mid-body resolves to the containing function
    mid = ENTRY + 2
    assert proj.function_at(mid) is proj.functions[ENTRY]
    assert proj.function_at(F_LEAF) is proj.functions[F_LEAF]
    # below every function start -> None
    assert proj.function_at(0) is None
    # in the gap after the last function's end -> None
    assert proj.function_at(BASE + 0x9000) is None


def test_label_for_precedence(proj):
    # no user label -> falls back to the function name at a start
    assert proj.label_for(ENTRY) == proj.functions[ENTRY].name
    # a non-start, non-labelled address -> None
    assert proj.label_for(BASE + 0x7777) is None


# ===========================================================================
# annotation layer
# ===========================================================================
def test_rename_updates_label_and_function(proj):
    proj.rename(ENTRY, "foo")
    assert proj.functions[ENTRY].name == "foo"
    assert ENTRY in proj.labels and proj.labels[ENTRY].name == "foo"
    assert proj.label_for(ENTRY) == "foo"
    # a rename of a non-function address is still a valid label
    proj.rename(BASE + 0x1234, "bar")
    assert proj.label_for(BASE + 0x1234) == "bar"


def test_comment_roundtrip(proj):
    proj.comment(F_MID, "checks the flag")
    assert proj.comments[F_MID].text == "checks the flag"
    assert proj.comments[F_MID].author == "user"
    proj.remove_comment(F_MID)
    assert F_MID not in proj.comments
    proj.remove_comment(F_MID)                           # idempotent, no raise


def test_add_function_user_source(proj):
    proj.add_function(BASE + 0x1020, name="leaf")        # existing start, decoded
    proj.add_function(BASE + 0x4000)                     # unknown start
    assert proj.functions[BASE + 0x1020].source == "user"
    assert proj.functions[BASE + 0x1020].name == "leaf"
    unknown = proj.functions[BASE + 0x4000]
    assert unknown.source == "user" and unknown.name == "sub_140004000"
    assert unknown.basic_blocks == [] and unknown.size == 0


# ===========================================================================
# attach + summary
# ===========================================================================
def _sample_imports():
    return [
        ResolvedImport(slot_addr=BASE + 0x3000, slot_rva=0, module_name="kernel32.dll",
                       func_name="LoadLibraryA", ordinal=None, value=0x7FF000001000),
        ResolvedImport(slot_addr=BASE + 0x3008, slot_rva=8, module_name="kernel32.dll",
                       func_name=None, ordinal=42, value=0x7FF000002000),
    ]


def _sample_behavior():
    return [
        BehaviorEvent(seq=0, tid=1234, module="ntdll", func="LdrLoadDll",
                      category="loader", args={"dll": "KERNEL32.dll"},
                      detail="dll=KERNEL32.dll", ret_addr=BASE + 0x1500),
    ]


def _sample_unpack():
    return UnpackResult(detected=True, oep=BASE + 0x2222, main_base=BASE,
                        exit_code=0, dump=b"\xCC" * 4096)


def test_attach_and_summary(proj):
    proj.attach_imports(_sample_imports())
    proj.attach_behavior(_sample_behavior())
    proj.attach_unpack(_sample_unpack())

    s = proj.summary()
    assert isinstance(s, ArtifactSummary)
    assert s.n_imports == 2
    assert s.n_behavior_events == 1
    assert s.oep == BASE + 0x2222
    assert s.n_strings == len(proj.strings)
    assert s.n_signatures == len(proj.signatures)


# ===========================================================================
# save -> load round-trip
# ===========================================================================
def test_save_load_roundtrip(proj, synth, tmp_path):
    proj.comment(ENTRY, "the real entry")
    proj.rename(F_MID, "checkflag")
    proj.attach_imports(_sample_imports())
    proj.attach_behavior(_sample_behavior())
    proj.attach_unpack(_sample_unpack())

    out = tmp_path / "proj.aletheia.json"
    proj.save(str(out))
    loaded = Project.load(str(out))

    # pe/verdict are NOT persisted -> None until refresh
    assert loaded.pe is None and loaded.verdict is None

    # annotation layer preserved
    assert loaded.comments[ENTRY].text == "the real entry"
    assert loaded.labels[F_MID].name == "checkflag"

    # functions preserved (keys + a representative record)
    assert set(loaded.functions) == set(proj.functions)
    assert loaded.functions[F_MID].name == "checkflag"
    assert loaded.functions[ENTRY].xrefs_from == proj.functions[ENTRY].xrefs_from

    # imports / behavior preserved
    assert [i.func_name for i in loaded.imports] == [i.func_name for i in proj.imports]
    assert loaded.behavior[0].args == {"dll": "KERNEL32.dll"}

    # unpack SHAPE preserved; raw dump bytes intentionally dropped
    assert loaded.unpack.detected is True
    assert loaded.unpack.oep == BASE + 0x2222
    assert loaded.unpack.main_base == BASE
    assert loaded.unpack.exit_code == 0
    assert loaded.unpack.dump is None

    # signatures survive the byte-base64 round-trip (if any fired on this PE)
    assert len(loaded.signatures) == len(proj.signatures)
    for a, b in zip(loaded.signatures, proj.signatures):
        assert a.rule_name == b.rule_name and a.strings == b.strings

    # file unchanged -> the integrity check passes
    assert loaded.binary_matches is True

    # refresh recomputes the dropped fields
    loaded.refresh_pe()
    assert loaded.pe is not None and loaded.pe.ok
    assert loaded.verdict is not None


def test_binary_matches_false_when_file_edited(proj, synth, tmp_path):
    out = tmp_path / "proj.json"
    proj.save(str(out))

    # append a byte to the analysed file -> hash diverges from the saved one
    with open(synth, "ab") as fh:
        fh.write(b"\x00")

    reloaded = Project.load(str(out))
    assert reloaded.binary_matches is False


def test_binary_matches_false_when_file_missing(proj, tmp_path):
    out = tmp_path / "proj.json"
    proj.save(str(out))
    # point the saved project at a now-deleted file
    Path(proj.path).unlink()
    reloaded = Project.load(str(out))
    assert reloaded.binary_matches is False
    assert "binary" in reloaded.errors


def test_signature_matches_survive_base64_roundtrip(proj):
    # the synthetic PE fires no content rules, so inject a Match with real (and
    # deliberately non-ASCII / NUL-bearing) matched bytes to prove the base64
    # encode/decode of Match.strings round-trips exactly.
    proj.signatures = [
        Match(rule_name="crypto-constants", tags=("crypto",),
              strings=[("$aes_sbox", 0x40, b"\x63\x7c\x77\x00\xf2\xff"),
                       ("$md5_init", 0x80, b"\x01\x23\x45\x67")]),
    ]
    loaded = Project.from_json(proj.to_json())
    assert len(loaded.signatures) == 1
    m = loaded.signatures[0]
    assert m.rule_name == "crypto-constants"
    assert m.tags == ("crypto",)                        # tuple, not list
    assert m.strings == proj.signatures[0].strings      # bytes preserved exactly


def test_from_json_is_inverse_of_to_json(proj):
    proj.comment(ENTRY, "x")
    proj.rename(F_LEAF, "leaf")
    round = project_mod.Project.from_json(proj.to_json())
    assert round.path == proj.path
    assert set(round.functions) == set(proj.functions)
    assert round.comments[ENTRY].text == "x"
    assert round.labels[F_LEAF].name == "leaf"
