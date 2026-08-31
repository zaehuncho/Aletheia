# Aletheia project viewer

A single-file, zero-dependency HTML dashboard for Aletheia project exports
(the JSON written by `aletheia.project.Project.to_json()` / `.save()`).

## Use

1. Open `viewer/index.html` in Chrome or Firefox. No server, no install, no build.
2. Drag any project `.json` onto the page (or click **Open JSON…**).
3. Click **Load sample** to view the bundled `sample_project.json`
   (notepad.exe analysed by `Project.from_pe`). Browsers that block `fetch`
   on `file://` pages will say so — just drag the sample file in instead,
   or serve the folder with `python -m http.server`.

Everything renders locally; nothing leaves the browser. All JSON-sourced text
is inserted via `textContent`, so a hostile project file cannot script the page.

## What you'll see

Header: file identity, arch/EXE-DLL, colour-coded verdict badge, artifact counts.
Left: sections with entropy bars (green < 6.5 < yellow < 7.2 < red) and a
searchable function list. Centre: per-function detail — disassembly,
pseudocode, and a CFG rendered as SVG. Bottom: behavior timeline plus
imports / strings / signatures / resources tabs. Renames and comments made in
the viewer are **in-memory only** — it never writes back to disk.

## Honesty notes

`to_json()` does not persist the PE header/verdict, instruction listings,
decompiled source, or CFG edges. The viewer renders those only when a caller
embedded the optional extension keys `pe`, `verdict`, `disasm`, `decompiled`,
`cfg` (as the bundled sample does — its `disasm` block is size-capped, its
strings list trimmed, and its imports/behavior rows are synthetic demo data
attached via `attach_*`, since those only come from live runs). Without them,
each pane states plainly that the data is not in the export. `Project.from_json`
ignores the extension keys, so the sample still round-trips through Python —
`tests/test_viewer.py` pins that.
