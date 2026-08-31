# Aletheia → Ghidra export

Turn an Aletheia analysis (recovered functions, renames/labels, comments, resolved
imports, decompiled source) into a script that **replays those annotations inside a
Ghidra project**. This is the interop deliverable behind the *"Aletheia unpacks,
Ghidra decompiles"* story: Aletheia does the runtime work Ghidra is blind to
(unpacking, IAT resolution, behaviour tracing) and hands the results to Ghidra's
deep static decompiler.

The exporter writes **two sibling files** into an output directory:

| File | Runs where | What it is |
| --- | --- | --- |
| `aletheia_export.json` | — | machine-readable dump of everything Ghidra can consume |
| `aletheia_import.py`   | inside Ghidra (Jython 2.7) | replays the JSON via Ghidra's API |

Everything here is **stdlib-only** — no templating engine; the Jython script is a
static body plus a small generated header.

---

## Run it

### From the CLI

```console
$ python aletheia.py ghidra-export path/to/project.aletheia.json --out ghidra_out
wrote ghidra_out/aletheia_export.json
wrote ghidra_out/aletheia_import.py
open the target binary in Ghidra, then run aletheia_import.py from Window → Script Manager
```

`--out` defaults to `./ghidra_export`. The command loads the saved project, best-effort
re-parses the on-disk binary to recover its image base (for rebasing), and writes the
pair.

### From Python

```python
import pathlib
from aletheia.project import Project
from tools.ghidra_export.exporter import export_project

proj = Project.load("project.aletheia.json")
proj.refresh_pe()                       # optional: populates image_base for rebasing
written = export_project(proj, pathlib.Path("ghidra_out"))
# -> {"json": .../aletheia_export.json, "script": .../aletheia_import.py}
```

### Inside Ghidra (the analyst's steps)

1. Open the **same target binary** in Ghidra's CodeBrowser and let auto-analysis finish.
2. **Window → Script Manager → Manage Script Directories** (the bundle/list icon) and add
   the folder holding `aletheia_import.py` (both files must sit side by side).
3. Find `aletheia_import.py` in the list (category **Aletheia**) and **Run** it.
4. It auto-locates its sibling `aletheia_export.json`. If it can't (e.g. the two files
   were separated), it prompts you to pick the JSON.
5. The console prints a summary: `x functions annotated / y labels / z comments /
   w imports / v decompiled`.

---

## What the Ghidra script does

For each record in the JSON it calls Ghidra's flat-program API and **fails gracefully**
(logs to the console, keeps going) on any missing address:

- **functions** — `createFunction(toAddr(start), name)`; an "already exists" result is
  swallowed by falling back to `getFunctionAt(addr)`, then `setName(name, USER_DEFINED)`
  if the name differs.
- **labels** — `createLabel(toAddr(addr), name, True)`.
- **comments** — `setPreComment(toAddr(addr), text)`.
- **imports with a purpose** — a pre-comment at the IAT slot in the form
  `[<PURPOSE>] <module>!<func>`, so the classification is visible in the disassembly.
- **decompiled functions** — `setPlateComment(toAddr(start), source)`, so Aletheia's
  recovered C-ish source sits in a banner above the function in Ghidra's listing.

### Address rebasing

Ghidra may load the binary at a different image base than Aletheia captured. The export
records the capture-time base in `image_base`; the script rebases every address onto the
**currently open** program's base:

```
ghidra_addr = current_image_base + (aletheia_addr - export_image_base)
```

If `image_base` is `null` (unknown at export time — e.g. the project was exported without
`refresh_pe()`), the addresses are used **as-loaded**, on the assumption the analyst
opened the correct target at its native base.

---

## The JSON schema

```jsonc
{
  "aletheia_export_version": 1,
  "generated": "2026-08-30T10:00:09Z",   // ISO-8601 UTC
  "path": "C:\\...\\sample.exe",         // target binary path
  "binary_sha256": "480ced…",            // hash | null if unreadable
  "image_base": 5368709120,              // int | null (unknown at export time)
  "functions": [
    {"start": 5368713216, "end": 5368713227, "name": "entry",
     "source": "signature", "size": 11, "blocks": [5368713216]}
  ],
  "labels":   {"0x140001010": "checkflag"},           // addr-string -> name
  "comments": {"0x140001000": "real entry"},          // addr-string -> text
  "imports": [
    {"slot_addr": 5368721408, "module": "kernel32.dll",
     "func": "VirtualAllocEx", "purpose": "process-injection"}  // purpose: str | null
  ],
  "decompiled": [                                       // [] when none attached
    {"start": 5368713232, "source": "int64_t checkflag(void) { ... }"}
  ]
}
```

Notes:

- Address-map keys (`labels`, `comments`) are hex strings, parseable with `int(k, 0)`.
- `functions[].source` is Aletheia's *provenance* tag (`entry` / `signature` / `disasm`
  / `user`), **not** decompiled code — the decompiled C-ish text lives in `decompiled`.
- `imports[].purpose` comes from `ResolvedImport.purpose` (an `aletheia.imports.Purpose`
  enum). Its `UNKNOWN` default is normalized to `null`, so only a *meaningful*
  classification is exported (and only those become Ghidra comments). Read best-effort,
  so hand-built import rows without the field export `null` too.
- `decompiled` is populated from an optional `project.decompiled` attribute (a
  `{start_or_name: DecompiledFunction | source_str}` mapping, or an iterable of
  `DecompiledFunction` matched to a function by name). The core `Project` model has no
  first-class field for decompiler output yet, so this is a best-effort read.

---

## Limitations

- **Ghidra API compatibility.** The script uses the long-stable flat-program API
  (`createFunction`, `createLabel`, `setPreComment`, `setPlateComment`, `getFunctionAt`,
  `toAddr`, `askFile`, `currentProgram.getImageBase()`) plus
  `ghidra.program.model.symbol.SourceType`. These have been stable across Ghidra 10.x/11.x.
  It is written for **Ghidra's bundled Jython 2.7** — it will not run under a CPython 3
  interpreter, and Ghidra does not (yet) ship a first-party CPython 3 script provider.
- **No transaction wrapper.** Run through the Script Manager, which already opens a
  transaction; running headless would need `start()/end()` around the changes.
- **Decompiled source is a plate comment**, not a re-typed function signature — it is
  documentation in the listing, not something Ghidra re-analyzes.
- **The export is never executed by the test suite** — Ghidra isn't in CI, so the tests
  only check the JSON shape and that the script parses as valid Python.
