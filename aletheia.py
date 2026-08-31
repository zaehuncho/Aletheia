#!/usr/bin/env python3
"""Aletheia CLI.

    python aletheia.py <pe-file> [more...]                 # static triage (default)
    python aletheia.py dump-process <pid> [--out DIR]      # dump a live process's modules
    python aletheia.py ghidra-export <project.json> [--out DIR]  # emit a Ghidra script
    python aletheia.py benchmark <input.exe> [--out DIR] [--packers upx,mpress,lethe]

Triage is read-only and never runs the sample. `dump-process` attaches to a live
process and reconstructs each loaded module into a PE file (Windows only).
`ghidra-export` turns a saved Aletheia project into an `aletheia_export.json` +
`aletheia_import.py` pair the analyst runs inside Ghidra (see tools/ghidra_export).
`benchmark` packs the input with each supported packer and runs the whole
Aletheia pipeline against every variant, emitting a comparison table
(see tools/benchmark).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aletheia.detect import analyze  # noqa: E402
from aletheia.pe import parse  # noqa: E402


def _triage(path: str) -> int:
    print(f"\n=== {path} ===")
    pe = parse(path)
    if not pe.ok:
        print(f"  error: {pe.error}")
        return 1
    try:
        raw = Path(path).read_bytes()
    except OSError:
        raw = None
    v = analyze(pe, raw)
    print(f"  {pe.arch} {'DLL' if pe.is_dll else 'EXE'}"
          f"{' [.NET]' if pe.is_dotnet else ''}  |{len(pe.sections)} sections"
          f"  |overall entropy {pe.overall_entropy:.2f}")
    print(f"  imports: {pe.import_func_count} function(s) from "
          f"{len(pe.import_dlls)} DLL(s)")
    for s in pe.sections:
        print(f"    {s.name:<10} {s.flags}  raw={s.raw_size:>8}  "
              f"vsize={s.vsize:>8}  entropy={s.entropy:5.2f}")
    print(f"  VERDICT: {v.summary()}")
    for sig in v.signals:
        print(f"    - {sig}")
    return 0


def _dump_process(args: list) -> int:
    out = "dumps"
    if "--out" in args:
        i = args.index("--out")
        if i + 1 >= len(args):
            sys.stderr.write("--out requires a directory\n")
            return 2
        out = args[i + 1]
        args = args[:i] + args[i + 2:]
    if not args or not args[0].isdigit():
        sys.stderr.write("usage: aletheia.py dump-process <pid> [--out DIR]\n")
        return 2

    import os
    from aletheia.procdump import dump_process
    pid = int(args[0])
    os.makedirs(out, exist_ok=True)
    print(f"dumping process {pid} -> {out}/")
    try:
        results = dump_process(pid, out)
    except OSError as exc:
        sys.stderr.write(f"cannot dump process {pid}: {exc}\n")
        return 1
    for path, ok in results:
        print(f"  [{'ok' if ok else '--'}] {path}")
    good = sum(1 for _p, ok in results if ok)
    print(f"dumped {good}/{len(results)} modules")
    return 0 if good else 1


def _ghidra_export(args: list) -> int:
    out = "ghidra_export"
    if "--out" in args:
        i = args.index("--out")
        if i + 1 >= len(args):
            sys.stderr.write("--out requires a directory\n")
            return 2
        out = args[i + 1]
        args = args[:i] + args[i + 2:]
    if not args:
        sys.stderr.write(
            "usage: aletheia.py ghidra-export <project.json> [--out DIR]\n")
        return 2

    from aletheia.project import Project
    from tools.ghidra_export.exporter import export_project

    proj_path = args[0]
    try:
        proj = Project.load(proj_path)
    except OSError as exc:
        sys.stderr.write(f"cannot read project {proj_path}: {exc}\n")
        return 1
    # best-effort: repopulate pe (-> image_base for rebasing) from the on-disk
    # binary. Absent/renamed binary just leaves image_base null (as-loaded).
    try:
        proj.refresh_pe()
    except Exception:                               # noqa: BLE001
        pass

    written = export_project(proj, Path(out))
    print(f"wrote {written['json']}")
    print(f"wrote {written['script']}")
    print("open the target binary in Ghidra, then run aletheia_import.py from "
          "Window -> Script Manager")
    return 0


def _benchmark(args: list) -> int:
    # Delegate to the harness's own tiny CLI parser; keeps this file free of
    # benchmark-specific flag logic.
    from tools.benchmark.runner import _main as bench_main
    return bench_main(args)


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        sys.stderr.write("usage: aletheia.py <pe-file> [more...]\n"
                         "       aletheia.py dump-process <pid> [--out DIR]\n"
                         "       aletheia.py ghidra-export <project.json> [--out DIR]\n"
                         "       aletheia.py benchmark <input.exe> [--out DIR] "
                         "[--packers upx,mpress,lethe]\n")
        return 2
    if args[0] == "dump-process":
        return _dump_process(args[1:])
    if args[0] == "ghidra-export":
        return _ghidra_export(args[1:])
    if args[0] == "benchmark":
        return _benchmark(args[1:])
    rc = 0
    for path in args:
        rc = _triage(path) or rc
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
