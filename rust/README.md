# rust/ -- Aletheia Rust engine + Tauri UI

The production shape. `aletheia-core` is the analyzer library ported from the
Python reference at `../aletheia/`; `aletheia-app` is a Tauri + React + TS +
Tailwind desktop app that consumes it over IPC.

## Layout

```
rust/
  Cargo.toml               workspace root
  rust-toolchain.toml      pin MSVC (Tauri deps need it on Windows)
  aletheia-core/           the engine library
    src/lib.rs             crate facade + shared Error type
    src/pe.rs              PE reader (port of aletheia/pe.py)
    tests/parity_notepad.rs cross-language parity on real notepad.exe
  aletheia-app/            Tauri + React + TS + Tailwind app
    src/App.tsx            main React component; calls parse_pe over IPC
    src/index.css          Tailwind v4 @import + Aletheia brand tokens
    public/logo.svg        the mark, from docs/brand/
    vite.config.ts         port 1420 (Tauri default), @tailwindcss/vite plugin
    package.json           React 19 + Vite 8 + Tailwind 4 + @tauri-apps/api
    index.html             favicon wired to logo.svg
    src-tauri/             Rust half of the Tauri app
      Cargo.toml           depends on aletheia-core (path dep)
      src/lib.rs           IPC commands: parse_pe, engine_info
      tauri.conf.json      identifier com.aletheia.dev, 1200x800 window
```

## Build + run

```powershell
cd rust
cargo build                    # workspace: aletheia-core + aletheia-app
cargo test                     # runs all Rust tests

cd aletheia-app
npm ci                         # locked dependencies
npm run build                  # produces dist/ (Vite)
cargo tauri dev                # launches the desktop window
cargo tauri build              # produces a shipping .exe + installer
```

## Toolchain notes

- **MSVC toolchain required.** Tauri s deps (parking_lot_core, windows-sys, ...)
  need dlltool.exe which the GNU toolchain does not ship with. `rust-toolchain.toml`
  pins MSVC for this workspace so cross-machine builds do not surprise you.
- **Node 20+ / npm 10+.**
- **Windows target only for now.** Cross-compiling to macOS / Linux is a
  follow-on; Aletheia s analyzer is Windows-PE-focused, so this matches scope.

## Correctness contract

Every ported module must produce output equivalent to the Python reference on
the shared regression fixtures at `../tests/goldens/`. If Rust and Python
disagree, the Python side is correct until proven otherwise.

## First IPC seam (what works today)

- `parse_pe(path: string) -> PeInfo` -- reads a PE file, returns the header
  parse as JSON. Proves the whole stack (React -> Tauri IPC -> aletheia-core
  -> serde -> React state) works end-to-end.
- `engine_info() -> { engine, version, target_arch, target_os }` -- health
  check the header uses to show an engine-online indicator.

Follow-on ports (planned): detect.py -> detect.rs, disasm.py -> disasm.rs,
ir/dataflow/simplify/structuring/decompile ports, viewer-style panes in the
React UI, live drag-drop analysis, per-function decompiled source pane.
