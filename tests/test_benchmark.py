"""Tests for the packer benchmark harness (``tools/benchmark/runner.py``).

These verify the HARNESS -- that it iterates packers, records results, renders
markdown, and degrades cleanly when a real packer is missing. They do NOT
require UPX / MPRESS / any real packer to be installed: the raw baseline is
enough to exercise every code path in the runner.

The synthetic PE is the same shape used by ``tests/test_project.py`` (three
functions at RVA 0x1000 / 0x1010 / 0x1020) so the benchmark actually has
something to count.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

pytest.importorskip("capstone")

from tools.benchmark import packers as packers_mod  # noqa: E402
from tools.benchmark.runner import (  # noqa: E402
    BenchmarkReport,
    PackerRun,
    benchmark,
    render_markdown,
)

BASE = 0x140000000

# ---------------------------------------------------------------------------
# synthetic on-disk PE (copied from tests/test_project.py -- test modules do
# not import each other in this repo)
# ---------------------------------------------------------------------------
_TEXT = bytes.fromhex(
    "55" "4889E5" "E807000000" "5D" "C3"      # 0x1000..0x100A: entry
    "9090909090"
    "4883EC28" "E807000000" "4883C428" "C3"   # 0x1010..0x101D: middle
    "9090"
    "55" "4889E5" "5D" "C3")                  # 0x1020..0x1025: leaf


def _make_pe(text: bytes = _TEXT) -> bytes:
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<Q", opt, 24, BASE)
    struct.pack_into("<I", opt, 108, 16)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x0022)
    raw0 = 512
    hdr = (b".text\x00\x00\x00" + struct.pack("<IIII", len(text), 0x1000,
           len(text), raw0) + b"\x00" * 12 + struct.pack("<I", 0x60000020))
    head = dos + b"PE\x00\x00" + coff + bytes(opt) + hdr
    return head + b"\x00" * (raw0 - len(head)) + text


@pytest.fixture()
def synth_pe(tmp_path: Path) -> Path:
    p = tmp_path / "synth.exe"
    p.write_bytes(_make_pe())
    return p


# ===========================================================================
# raw-only path: the runner works with no external packers installed
# ===========================================================================
def test_benchmark_raw_only_records_a_sensible_row(synth_pe, tmp_path):
    """The raw baseline runs, gets a verdict, counts functions, and its
    ``unpack_ok`` field is None (raw is never dynamically unpacked)."""
    out_dir = tmp_path / "bench_out"
    report = benchmark(str(synth_pe), packers=[], out_dir=str(out_dir))

    assert isinstance(report, BenchmarkReport)
    assert report.input_path == synth_pe.resolve()
    assert len(report.input_sha256) == 64                # sha-256 hex length
    assert report.generated.endswith("Z")
    # raw only -> exactly one row
    assert len(report.runs) == 1
    raw = report.runs[0]
    assert isinstance(raw, PackerRun)
    assert raw.packer_name == "raw"
    assert raw.pack_error is None
    # the synthetic PE has three functions -- from_pe must have found them
    assert raw.n_functions >= 3
    # raw is never unpacked in the harness
    assert raw.unpack_ok is None
    assert raw.unpack_oep is None
    # pipeline actually ran
    assert raw.aletheia_seconds > 0
    # verdict string is populated (detect.analyze always returns a summary)
    assert raw.aletheia_verdict

    # summary contains the raw row (ratio is trivially ~1.0)
    assert "raw" in report.summary
    assert report.summary["raw"] == pytest.approx(1.0)

    # report files got written
    assert (out_dir / "benchmark_report.json").is_file()
    assert (out_dir / "benchmark_report.md").is_file()


# ===========================================================================
# missing packers degrade cleanly (warnings, no crash)
# ===========================================================================
def test_benchmark_skips_unavailable_packers_with_a_warning(
        synth_pe, tmp_path, monkeypatch):
    """Ask for ``upx`` on a host where UPX may or may not be installed. If it
    isn't, the row is skipped and a warning is recorded -- the benchmark still
    finishes with the raw baseline. If it IS installed we cannot assert the
    packed row's numbers, so we only check that the harness didn't crash."""
    # Force UPX to look unavailable, no matter what the host has installed.
    monkeypatch.setattr(packers_mod.UpxPacker, "available", lambda self: False)
    # Themida-demo is ALWAYS unavailable (it's the deliberately-disabled adapter).
    report = benchmark(str(synth_pe), packers=["upx", "themida-demo"],
                       out_dir=None)
    # Only the raw baseline should appear in runs; both packers get warnings.
    assert [r.packer_name for r in report.runs] == ["raw"]
    joined = " | ".join(report.warnings)
    assert "upx" in joined and "themida-demo" in joined
    assert all("skipped" in w for w in report.warnings)


# ===========================================================================
# render_markdown emits the expected columns
# ===========================================================================
def test_render_markdown_has_the_expected_columns(synth_pe):
    """The rendered table headers must contain each documented column so the
    README can reliably paste this in."""
    report = benchmark(str(synth_pe), packers=[])
    md = render_markdown(report)
    # header line
    assert "| Packer" in md and "| Verdict" in md and "| Fns" in md
    assert "| Imports" in md and "| Decomp bytes" in md
    assert "| Unpack" in md and "| Wall" in md
    # the raw baseline row is present
    assert "| raw" in md
    # recovery-ratio callout is present
    assert "Recovery ratio" in md
    # honest-limitation callout at the bottom
    assert "not a semantic score" in md


# ===========================================================================
# unknown packer name is loud, not silent
# ===========================================================================
def test_unknown_packer_name_raises(synth_pe):
    with pytest.raises(KeyError):
        benchmark(str(synth_pe), packers=["not-a-real-packer"])
