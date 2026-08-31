# Aletheia packer benchmark

A tiny harness that turns "Aletheia can unpack this" into a **number the README
can quote**. Point it at a clean PE, tell it which packers to try, and it
runs the full Aletheia pipeline against each variant and emits a comparison
table.

```
python -m tools.benchmark.runner C:\Windows\System32\notepad.exe \
    --packers upx,mpress \
    --out logs\benchmark_notepad
```

That writes `logs\benchmark_notepad\benchmark_report.json` and
`benchmark_report.md`, and prints the same markdown to stdout.

## What it measures

For each variant (the raw baseline + every packed copy), the harness records:

| Column         | Source                                            | What it tells you |
|----------------|---------------------------------------------------|-------------------|
| `Verdict`      | `aletheia.detect.analyze(...).summary()`          | The static call: PACKED / likely clean / which packer |
| `Fns`          | `len(Project.from_pe(...).functions)`             | Functions recovered by the disasm walk |
| `Imports`      | `pe.import_func_count`                            | Import-table entries visible on disk |
| `Decomp bytes` | `sum(len(decompile_function(fn).source))`         | Characters of pseudo-C emitted across every function |
| `Unpack`       | `aletheia.unpack.run_unpack(...).detected`        | Did the dynamic layer reach a candidate OEP? |
| `Wall`         | wall-clock time of the full pipeline              | How long Aletheia took on this variant |

The `Recovery ratio` at the bottom of the table is
`(Fns + Imports + Decomp bytes) / same-sum-on-raw`. A ratio near 1.0 means the
packer was **transparent to static analysis** -- Aletheia saw just as much of
the packed file as the original. A ratio near 0 means the packer **hid** most
of the file from static tools; a large `Unpack = OK` alongside a low ratio is
the harness's honest picture: static coverage is gone, dynamic recovery
finds the entry point.

## What it does NOT measure (please be careful with the numbers)

* **`Decomp bytes` is CHARACTERS, not a semantic-fidelity score.** More bytes
  is not "better decompilation" -- it's just more pseudo-C text. Two packers
  producing the same character count can produce wildly different quality.
* **`Imports` is the on-disk count.** Packers elide the import table down to a
  couple of loader-only functions. This harness does not reconstruct the IAT
  from a live-process dump; if you want that number, drop into
  `aletheia.imports.resolve_imports` by hand on a captured dump.
* **Unpack single-steps** from the entry point. On an ordinary program that
  never leaves its own image, it just spends its `max_steps` budget and
  reports `detected=False`. That is the correct result -- the file isn't
  packed -- not a harness bug.
* **The benchmark is one measurement per variant.** No repeats, no confidence
  interval. Treat it like a rough calibration, not a validated metric.

## Supported packers

| Adapter              | Tool                      | `available()` check |
|----------------------|---------------------------|---------------------|
| `RawPasser` (`raw`)  | `shutil.copyfile`         | always True (baseline, always runs first) |
| `UpxPacker`          | `upx --best <in> -o <out>`| `shutil.which("upx")` |
| `MpressPacker`       | `mpress -s <staged-out>`  | `shutil.which("mpress")` -- Windows only |
| `ThemidaDemoPacker`  | (none -- no scriptable CLI)| always False, on purpose |
| `LethePacker`        | `python $LETHE_BIN pack <in> <out>` | `LETHE_BIN` env var points at an existing file |

Any adapter whose `available()` returns False is **skipped with a warning**.
The benchmark still runs the raw baseline and every packer that *is*
available -- missing tools are data, not a fatal error.

### Themida (manual workflow)

`ThemidaDemoPacker` ships disabled because Themida's demo GUI has no
scriptable command line. Workflow:

1. Pack your sample with Themida by hand (GUI).
2. Drop the packed file into `tools/benchmark/samples/` (or anywhere).
3. Run the benchmark pointing at that file with `--packers=""` (or default) --
   the "raw" row will now be the Themida-packed file, and the
   `Verdict` column will name it via the section-name signature.

## Running the harness

Programmatic:

```python
from tools.benchmark.runner import benchmark, render_markdown
report = benchmark("notepad.exe", packers=["upx", "mpress"],
                   out_dir="logs/bench_notepad")
print(render_markdown(report))
```

Command-line:

```
python -m tools.benchmark.runner <input.exe> [--out DIR] \
    [--packers upx,mpress,lethe] [--no-decompile]
```

* `--packers` -- comma-separated. Omit to run every registered packer that is
  available on this host. Pass `--packers=""` for a raw-only run.
* `--out DIR` -- write `benchmark_report.json` + `benchmark_report.md` there.
  The packed variants are dropped into `DIR/packed/`.
* `--no-decompile` -- skip the (relatively expensive) per-function decompile.
  `Decomp bytes` will report 0 for every row.

## First run

The simplest one-liner if you have nothing installed: point it at Notepad
(always present on Windows).

```
python -m tools.benchmark.runner "%WINDIR%\System32\notepad.exe" \
    --out logs\benchmark_notepad
```

You'll get a single-row raw baseline: verdict "likely clean", a few thousand
functions, a large decompiled-byte count, `Unpack = -`. That row is your
calibration -- every packer's row is scored against it.

## Sample files

See `tools/benchmark/samples/README.md`. Sample binaries are NOT committed
(the whole directory is in `.gitignore`) -- drop your own files there and
point the benchmark at them.
