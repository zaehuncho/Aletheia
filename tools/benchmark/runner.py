"""Aletheia packer benchmark harness -- turns "we can unpack" into a number.

For a chosen input PE, the harness runs the ORIGINAL through Aletheia's static
pipeline (the ``raw`` baseline row) and then, for every requested packer, packs
the input and re-runs the pipeline against the packed variant. The output is a
JSON + markdown report comparing per-packer recovery to the raw baseline.

What "recovery" means here (be honest)
--------------------------------------
Four crude, tool-invariant scalars per variant:

* ``n_functions``          -- how many functions ``Project.from_pe`` recovered.
* ``n_imports_resolved``   -- ``pe.import_func_count`` from the static parse.
                              This is the number of imports Aletheia can SEE
                              on the file as it sits on disk. A packer that
                              elides the import table drives this to a handful
                              (typically only ``LoadLibrary``/``GetProcAddress``);
                              on-disk IAT rebuild from a live-process dump is
                              out of scope for this harness.
* ``n_decompiled_bytes``   -- sum of ``len(DecompiledFunction.source)`` across
                              every recovered function that decompiles inside
                              the per-function timeout. CHARACTER count, not a
                              semantic-fidelity score -- a bigger number is
                              not by itself "better decompilation".
* ``unpack_ok``            -- did ``aletheia.unpack.run_unpack`` reach a
                              candidate OEP on this variant? None for the raw
                              baseline (never run), True/False for packed
                              variants.

The per-packer ``summary`` ratio is ``(fns + imports + decomp_bytes)`` on the
packed variant divided by the same sum on raw. A packer whose ratio is 1.0 is
transparent (Aletheia sees just as much as it does on the original); a ratio
near 0 means the packer hid most of the file from static analysis; a big
``unpack_ok=True`` alongside a low ratio is the harness's honest picture of
"static coverage is gone, dynamic recovery finds the entry".

Bounds
------
* Decompile per function is timeout-guarded (a threaded worker with a join
  deadline) so a runaway decompile doesn't hang the whole benchmark.
* Unpack is single-stepped and gets a ``max_steps`` budget -- documented in
  ``aletheia.unpack``; on an ordinary program it would step forever otherwise.
* Everything is stdlib -- ``subprocess`` / ``pathlib`` / ``hashlib`` / ``shutil``.

Only the RAW path is tested off-Windows-toolchain: the packers themselves are
graceful about being absent (see ``packers.py``); the runner just records a
warning and skips their rows.
"""
from __future__ import annotations

import copy
import datetime as _dt
import hashlib
import json
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# Re-use tools.benchmark.packers no matter how the harness is imported. Prefer
# the package-qualified path (tools.benchmark.packers) so the runner works when
# imported as a submodule; fall back to a sibling import when invoked as a
# top-level script from inside tools/benchmark.
try:
    from tools.benchmark import packers as _packers_mod
except ImportError:  # pragma: no cover - script-mode fallback
    import packers as _packers_mod  # type: ignore

Packer = _packers_mod.Packer
ALL_PACKERS = _packers_mod.ALL_PACKERS
get_packer = _packers_mod.get_packer


# ===========================================================================
# result dataclasses
# ===========================================================================
@dataclass
class PackerRun:
    """One row of the benchmark report -- everything measured about one variant."""

    packer_name: str
    input_path: Path
    packed_path: Path
    packed_size: int
    pack_seconds: float
    pack_error: Optional[str]           # None on success
    aletheia_verdict: str
    n_functions: int
    n_imports_resolved: int
    n_decompiled_bytes: int
    unpack_ok: Optional[bool]           # None for raw (never attempted)
    unpack_oep: Optional[int]
    aletheia_seconds: float             # wall clock of the full pipeline


@dataclass
class BenchmarkReport:
    """The report as a whole -- input identity, per-variant rows, per-packer
    recovery ratios, and any warnings (skipped packers, pack failures)."""

    input_path: Path
    input_sha256: str
    generated: str                       # ISO-8601 UTC
    runs: List[PackerRun] = field(default_factory=list)
    summary: Dict[str, float] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


# ===========================================================================
# small utilities
# ===========================================================================
def _sha256_file(path: Path) -> str:
    """SHA-256 of a file, streamed so we do not read a 100MB binary into RAM."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _utc_now_iso() -> str:
    """ISO-8601 UTC timestamp with second precision (no microseconds; a report
    header does not need them and they clutter the JSON)."""
    return _dt.datetime.now(_dt.timezone.utc).replace(
        microsecond=0, tzinfo=None).isoformat() + "Z"


def _timed(fn, *a, **kw):
    """Run ``fn(*a, **kw)`` and return ``(result, elapsed_seconds)``."""
    t0 = time.perf_counter()
    r = fn(*a, **kw)
    return r, time.perf_counter() - t0


# ===========================================================================
# per-function decompile with a hard timeout
# ===========================================================================
# Sane bounds for one function's decompile. The runner never lets a single
# function eat more than DECOMPILE_TIMEOUT_S of wall clock; a hit function is
# skipped and its bytes contribute zero to the total. Cap on the number of
# functions decompiled per variant keeps the wall clock bounded even on a huge
# input file. Both are conservative defaults tuned for a benchmark, not an
# exhaustive analysis.
DECOMPILE_TIMEOUT_S = 3.0
DECOMPILE_MAX_FUNCS = 500
# Very large functions are almost always thunks / unrolled data blobs; the
# decompile pipeline can churn on them for no useful signal.
DECOMPILE_MAX_FN_SIZE = 8192


def _decompile_with_timeout(ir_fn, name: str, timeout: float):
    """Run ``decompile_function`` in a worker thread with a ``join(timeout)``
    deadline. Returns the ``DecompiledFunction`` on success or None on timeout /
    exception. A timed-out thread is abandoned in the background (Python cannot
    interrupt pure-Python work); the benchmark itself proceeds regardless."""
    from aletheia.decompile import decompile_function  # lazy: imports ir/dataflow

    result: Dict[str, object] = {"df": None, "err": None}

    def _worker():
        try:
            result["df"] = decompile_function(ir_fn, name=name)
        except Exception as exc:  # noqa: BLE001 - benchmark must not crash on one bad fn
            result["err"] = repr(exc)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        return None
    return result["df"]


def _sum_decompiled_bytes(project) -> int:
    """Iterate every function on ``project``, lift its IR from the cached
    DisasmResult (skip functions the disasm didn't decode), decompile with a
    per-function timeout, and sum ``len(source)`` across successes.

    Character count is the metric -- documented as such in the module docstring.
    A function that hits the timeout or blows up contributes zero."""
    if not project.functions:
        return 0
    dis = getattr(project, "_disasm", None)
    if dis is None:
        return 0
    from aletheia import ir as _ir

    total = 0
    count = 0
    for fn in project.functions.values():
        if count >= DECOMPILE_MAX_FUNCS:
            break
        if fn.size and fn.size > DECOMPILE_MAX_FN_SIZE:
            continue
        if fn.start not in dis.instructions:
            continue
        try:
            ir_fn = _ir.lift_function(fn.start, dis.blocks, dis.instructions)
        except Exception:  # noqa: BLE001 - lifting is best-effort per fn
            continue
        # deep-copy the IR before decompile: decompile_function copies internally
        # but a defensive copy costs nothing here and keeps the disasm cache clean
        # in case the pipeline ever changes.
        df = _decompile_with_timeout(copy.deepcopy(ir_fn), fn.name,
                                     DECOMPILE_TIMEOUT_S)
        if df is not None:
            total += len(df.source)
        count += 1
    return total


# ===========================================================================
# unpack budget for the benchmark
# ===========================================================================
# aletheia.unpack single-steps from the entry point. That is O(instructions)
# and only bounded by the packer's own stub. We give it a generous but finite
# budget for the harness so a program that never leaves its image doesn't hang
# the benchmark.
UNPACK_MAX_STEPS = 200_000


def _try_unpack(packed_path: Path) -> tuple[Optional[bool], Optional[int]]:
    """Run ``aletheia.unpack.run_unpack`` against ``packed_path`` under the
    harness's step budget. Returns ``(detected, oep)``. Any failure (Windows-only
    debugger absent, sample won't launch, whatever) is caught: the harness records
    ``detected=False, oep=None`` and moves on -- an unpack that fails is data,
    not a fatal error."""
    try:
        from aletheia.unpack import run_unpack
    except Exception:  # noqa: BLE001 - platform doesn't have the debugger
        return False, None
    try:
        res = run_unpack(f'"{packed_path}"', dump_payload=False,
                         terminate_on_detect=True,
                         max_steps=UNPACK_MAX_STEPS)
    except Exception:  # noqa: BLE001 - live spawn can fail a hundred ways
        return False, None
    return bool(res.detected), res.oep


# ===========================================================================
# one row: pack -> analyze -> measure
# ===========================================================================
def _analyze_one(packer: Packer, input_path: Path, work_dir: Path,
                 decompile: bool, do_unpack: bool) -> PackerRun:
    """Pack the input with ``packer`` into ``work_dir`` and run the full
    pipeline. Returns the ``PackerRun`` row (never raises: every stage is
    guarded and records its failure on the row instead)."""
    packed_path = work_dir / f"{input_path.stem}.{packer.name}{input_path.suffix or '.bin'}"

    # -- 1. pack (or copy for raw) -----------------------------------------
    t0 = time.perf_counter()
    ok, err = packer.pack(input_path, packed_path)
    pack_seconds = time.perf_counter() - t0

    if not ok:
        return PackerRun(
            packer_name=packer.name, input_path=input_path,
            packed_path=packed_path, packed_size=0,
            pack_seconds=pack_seconds, pack_error=err or "pack failed",
            aletheia_verdict="", n_functions=0, n_imports_resolved=0,
            n_decompiled_bytes=0, unpack_ok=None, unpack_oep=None,
            aletheia_seconds=0.0)

    try:
        packed_size = packed_path.stat().st_size
    except OSError:
        packed_size = 0

    # -- 2. aletheia pipeline over the packed file -------------------------
    from aletheia.project import Project  # lazy: capstone is optional at import

    t0 = time.perf_counter()
    verdict_str = ""
    n_fns = 0
    n_imports = 0
    n_bytes = 0
    try:
        proj = Project.from_pe(str(packed_path))
        if proj.verdict is not None:
            verdict_str = proj.verdict.summary()
        n_fns = len(proj.functions)
        if proj.pe is not None:
            n_imports = int(getattr(proj.pe, "import_func_count", 0))
        if decompile:
            n_bytes = _sum_decompiled_bytes(proj)
    except Exception as exc:  # noqa: BLE001 - benchmark must not crash on one bad file
        verdict_str = f"(pipeline error: {exc!r})"
    aletheia_seconds = time.perf_counter() - t0

    # -- 3. optional dynamic unpack (skipped for raw) ----------------------
    unpack_ok: Optional[bool] = None
    unpack_oep: Optional[int] = None
    if do_unpack:
        unpack_ok, unpack_oep = _try_unpack(packed_path)

    return PackerRun(
        packer_name=packer.name, input_path=input_path,
        packed_path=packed_path, packed_size=packed_size,
        pack_seconds=pack_seconds, pack_error=None,
        aletheia_verdict=verdict_str, n_functions=n_fns,
        n_imports_resolved=n_imports, n_decompiled_bytes=n_bytes,
        unpack_ok=unpack_ok, unpack_oep=unpack_oep,
        aletheia_seconds=aletheia_seconds)


# ===========================================================================
# public entry points
# ===========================================================================
def _select_packers(requested: Optional[List[str]]) -> List[str]:
    """Normalize the requested packer list. ``None`` -> every registered packer
    except ``raw`` (which is always inserted at the front). An empty list means
    "no packers, raw only". An unknown name raises ``KeyError`` -- surfacing a
    typo beats silently ignoring it."""
    if requested is None:
        names = [n for n in ALL_PACKERS if n != "raw"]
    else:
        names = list(requested)
    for n in names:
        if n not in ALL_PACKERS:
            raise KeyError(f"unknown packer {n!r} (known: {sorted(ALL_PACKERS)})")
    return names


def benchmark(input_path: str, packers: Optional[List[str]] = None,
              out_dir: Optional[str] = None,
              decompile: bool = True) -> BenchmarkReport:
    """Run the benchmark and return the report.

    ``input_path`` is packed once per requested packer and then re-analyzed.
    The ``raw`` baseline is always the first row. If ``out_dir`` is given the
    report is written to ``benchmark_report.json`` and ``benchmark_report.md``
    inside it. ``decompile=False`` skips the (relatively expensive)
    per-function decompile step and reports ``n_decompiled_bytes=0``."""
    in_path = Path(input_path).resolve()
    if not in_path.is_file():
        raise FileNotFoundError(f"input PE not found: {in_path}")

    warnings: List[str] = []
    packer_names = _select_packers(packers)

    # Work dir: either <out_dir>/packed/ if the caller wants results kept, or a
    # sibling of the input for the transient run. We DO write next to the input
    # -- the samples/ dir is .gitignored precisely so this is fine.
    if out_dir is not None:
        work_root = Path(out_dir).resolve()
        work_root.mkdir(parents=True, exist_ok=True)
        work_dir = work_root / "packed"
    else:
        work_dir = in_path.parent / f".aletheia_bench_{in_path.stem}"
    work_dir.mkdir(parents=True, exist_ok=True)

    # -- raw baseline always runs first -----------------------------------
    runs: List[PackerRun] = []
    raw = get_packer("raw")
    runs.append(_analyze_one(raw, in_path, work_dir,
                             decompile=decompile, do_unpack=False))

    # -- requested packers, alphabetical order for reproducibility --------
    for name in sorted(packer_names):
        if name == "raw":
            continue                                # already run as baseline
        packer = get_packer(name)
        if not packer.available():
            warnings.append(f"{name}: skipped (tool not available)")
            continue
        runs.append(_analyze_one(packer, in_path, work_dir,
                                 decompile=decompile, do_unpack=True))
        if runs[-1].pack_error:
            warnings.append(f"{name}: pack failed: {runs[-1].pack_error}")

    # -- summary: per-packer recovery ratio vs raw ------------------------
    def _score(r: PackerRun) -> float:
        return float(r.n_functions + r.n_imports_resolved + r.n_decompiled_bytes)

    raw_row = runs[0]
    raw_score = _score(raw_row) or 1.0                # avoid div-by-zero
    summary: Dict[str, float] = {}
    for r in runs:
        summary[r.packer_name] = round(_score(r) / raw_score, 4)

    report = BenchmarkReport(
        input_path=in_path, input_sha256=_sha256_file(in_path),
        generated=_utc_now_iso(), runs=runs, summary=summary,
        warnings=warnings)

    if out_dir is not None:
        _write_report_files(report, Path(out_dir).resolve())
    return report


# ===========================================================================
# rendering
# ===========================================================================
def _fmt_int(n: int) -> str:
    return f"{n:>6d}"


def _fmt_secs(s: float) -> str:
    return f"{s:.1f}s"


def _fmt_unpack(ok: Optional[bool]) -> str:
    if ok is None:
        return "-"
    return "OK" if ok else "FAIL"


def render_markdown(report: BenchmarkReport) -> str:
    """Emit a self-contained markdown block: header + table + per-packer
    ratios + any warnings. Suitable to paste into the top-level README."""
    lines: List[str] = []
    lines.append(f"# Aletheia benchmark: `{report.input_path.name}`")
    lines.append("")
    lines.append(f"- Input: `{report.input_path}`")
    lines.append(f"- SHA-256: `{report.input_sha256}`")
    lines.append(f"- Generated: {report.generated}")
    lines.append("")
    lines.append("| Packer     | Verdict                       | Fns    | Imports | Decomp bytes | Unpack | Wall  |")
    lines.append("|------------|-------------------------------|-------:|--------:|-------------:|:------:|------:|")
    for r in report.runs:
        if r.pack_error:
            verdict = f"(pack failed: {r.pack_error[:40]})"
        else:
            verdict = r.aletheia_verdict or "-"
        lines.append(
            f"| {r.packer_name:<10} | {verdict:<29.29} "
            f"| {r.n_functions:>6d} | {r.n_imports_resolved:>7d} "
            f"| {r.n_decompiled_bytes:>12d} "
            f"| {_fmt_unpack(r.unpack_ok):^6} | {_fmt_secs(r.aletheia_seconds):>5} |")
    lines.append("")
    lines.append("**Recovery ratio vs raw** (higher = Aletheia sees more of the packed file):")
    lines.append("")
    for name, ratio in report.summary.items():
        lines.append(f"- `{name}`: {ratio:.2%}")
    if report.warnings:
        lines.append("")
        lines.append("**Warnings:**")
        for w in report.warnings:
            lines.append(f"- {w}")
    lines.append("")
    lines.append("_Recovery ratio = (functions + imports + decompiled bytes) / raw."
                 " Decompiled bytes are characters of pseudo-C, not a semantic score."
                 " Unpack = did `aletheia.unpack.run_unpack` reach a candidate OEP._")
    return "\n".join(lines) + "\n"


def _report_to_json(report: BenchmarkReport) -> str:
    """Serialize the report to JSON. Path objects are strings; dataclasses are
    dicts via ``asdict``."""
    def _default(o):
        if isinstance(o, Path):
            return str(o)
        raise TypeError(f"not JSON-serializable: {type(o)!r}")

    payload = {
        "input_path": str(report.input_path),
        "input_sha256": report.input_sha256,
        "generated": report.generated,
        "runs": [
            {**asdict(r),
             "input_path": str(r.input_path),
             "packed_path": str(r.packed_path)}
            for r in report.runs
        ],
        "summary": report.summary,
        "warnings": list(report.warnings),
    }
    return json.dumps(payload, indent=2, default=_default)


def _write_report_files(report: BenchmarkReport, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "benchmark_report.json").write_text(
        _report_to_json(report), encoding="utf-8")
    (out_dir / "benchmark_report.md").write_text(
        render_markdown(report), encoding="utf-8")


# ===========================================================================
# CLI (invoked directly: python -m tools.benchmark.runner <input.exe> ...)
# ===========================================================================
def _main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        sys.stderr.write(
            "usage: python -m tools.benchmark.runner <input.exe> "
            "[--out DIR] [--packers upx,mpress,lethe] [--no-decompile]\n")
        return 2

    input_path = args[0]
    out_dir: Optional[str] = None
    packer_list: Optional[List[str]] = None
    decompile = True
    i = 1
    while i < len(args):
        tok = args[i]
        if tok == "--out":
            out_dir = args[i + 1]
            i += 2
        elif tok == "--packers":
            packer_list = [p.strip() for p in args[i + 1].split(",") if p.strip()]
            i += 2
        elif tok == "--no-decompile":
            decompile = False
            i += 1
        else:
            sys.stderr.write(f"unknown flag: {tok}\n")
            return 2

    report = benchmark(input_path, packers=packer_list,
                       out_dir=out_dir, decompile=decompile)
    sys.stdout.write(render_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
