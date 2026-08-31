<p align="center">
  <img src="docs/brand/logo-wordmark.svg" alt="Aletheia" width="480">
</p>

[![CI](https://github.com/zaehuncho/Aletheia/actions/workflows/ci.yml/badge.svg)](https://github.com/zaehuncho/Aletheia/actions/workflows/ci.yml) &nbsp; [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) &nbsp; [![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/) &nbsp; [![Rust MSVC](https://img.shields.io/badge/rust-stable--msvc-orange.svg)](https://www.rust-lang.org/) &nbsp; [![Tauri 2](https://img.shields.io/badge/tauri-2-24C8DB.svg)](https://tauri.app/)

**A defensive reverse-engineering workbench for Windows PEs.**
**Triage → dynamic unpacking → import reconstruction → disassembly → SSA IR → decompilation → readable C-ish source.**
**Native Rust + Tauri workbench UI; Python engine as the reference implementation; a clean-room VT-x/EPT hypervisor scaffold on the side.**

Where [Lethe](https://github.com/zaehuncho/Lethe) *conceals*, Aletheia *reveals* — the name is Greek for **truth / un-concealment**, the literal antonym of *lethe* (oblivion). Point it at a packed or suspicious binary and it tells you how it is protected, runs it under observation, dumps the code it hides, resolves the dumped imports, symbolically explores paths, folds obfuscator patterns out, and turns the recovered machine code into readable C-ish pseudocode.

Same category as [PE-sieve](https://github.com/hasherezade/pe-sieve), [Scylla](https://github.com/NtQuery/Scylla), [ScyllaHide](https://github.com/x64dbg/ScyllaHide), [Ghidra](https://ghidra-sre.org/), [Binary Ninja](https://binary.ninja/), and [angr](https://angr.io/) — but coherent, one repo, one command, and everything is honest about its limits.

---

## What ships

### The workbench (Rust + Tauri)

<sub>Native x86_64 Windows exe. Frameless custom chrome, cyan-on-black theme, drag-drop file open, drag-drop pane reorder, resizable panes persisted per-viewer, Ctrl+F find in disassembly + decompile, syntax-highlighted operands, entropy mini-bars, cursor-tracking welcome background.</sub>

| Pane | What |
|---|---|
| **Verdict** | Packed / clean with confidence + the exact signals that fed the score (`.vmp0` present, W^X sections, import elision, entry outside `.text`, high-entropy sections, non-standard section names). |
| **PE Header** | Arch, kind, machine, entry, entry-section, image base, section count, overall entropy. |
| **Sections** | Per-section entropy mini-bar, R/W/X flags, virtual vs raw size. |
| **Functions** | Every recursive-descent-discovered function with xref count + entry pill. Live filter. |
| **Disassembly** | Recursive-descent x64 with block markers, jump/call targets, xrefs. Syntax-highlighted operands. Ctrl+F find. |
| **Decompile** | Lightweight C-flavored lowering with if-then triangle collapse. Ctrl+F find with highlight. |
| **Imports** | Grouped by DLL, function names + ordinals + forwarders. |
| **Dynamic Analysis** | Run the sample under our Win32 debugger with the three unpack levers active. Auto-wraps DLLs via `rundll32`. |

Installers ship in every GitHub release (`Aletheia_x.y.z_x64-setup.exe` for NSIS, `Aletheia_x.y.z_x64_en-US.msi` for MSI).

### The engine (Rust — `rust/aletheia-core/`)

| Module | What |
|---|---|
| `pe.rs` | Zero-dep PE reader — sections, entropy, R/W/X, import table walk, RVA↔offset, `.NET` detection. Port of `aletheia/pe.py`. |
| `detect.rs` | Packer verdict — UPX, VMProtect, Themida/WinLicense, Enigma, ASPack, MPRESS, PECompact, MEW, FSG, Obsidium, Petite, Lethe. Byte-equivalent to `aletheia/detect.py`. |
| `disasm.rs` | iced-x86 recursive descent + CFG + xrefs. |
| `decompile.rs` | Lightweight x64 → C-flavored emitter with if-then triangle folding. |
| `unpack.rs` | Win32 Debug API single-stepper with three unpack levers — see below. |

### The engine (Python — `aletheia/`, reference implementation)

21 modules, 12,180 LoC, 387 pytest tests, 12 decompiler golden files.
Same behavior as the Rust engine for the ported modules; **the full**
**SSA-driven decompilation pipeline lives here** (`ir.py` + `dataflow.py` +
`simplify.py` + `structuring.py` + `decompile.py`) and hasn't been ported
to Rust yet. See the module table in [`docs/python-engine.md`](docs/python-engine.md).

### The hypervisor scaffold (C — `hv/`)

Clean-room Intel VT-x/EPT + AMD-V/NPT VMI hypervisor for observing a
sample from ring −1 (invisible to guest anti-debug). **Compiles clean**
(43 KB `aletheia_hv.sys`, valid x64 kernel driver, NATIVE subsystem)
but has never been signed, loaded, or run. See `hv/BRINGUP.md` for the
snapshotted-VM bring-up checklist and `hv/README.md` for the clean-room
provenance rules (Intel SDM Vol 3 / AMD APM Vol 2 cited inline).

---

## Dynamic unpack — the three levers

Beyond the classical write-then-execute detector, the Rust `unpack.rs`
layer adds three orthogonal signals:

| Lever | What it does | Default |
|---|---|---|
| **1 — anti-anti-debug** | Patches PEB.BeingDebugged + PEB.NtGlobalFlag before the target runs. `IsDebuggerPresent`-class and heap-flag scanners report clean. | **on** |
| **2 — guard pages** | `PAGE_GUARD` on every executable page; fires when a page written since load gets executed (Renovo-style). Off by default: interacts with Lever 3 on the shared BP replant pool. | **off** |
| **3 — ntdll API hooks** | Breakpoints `NtAllocateVirtualMemory` / `NtProtectVirtualMemory` / `NtCreateThreadEx`. Every executable alloc, W-to-X flip, and reflective thread spawn shows up in the result's event list. | **on** |

Combined with the in-image packer-target predicate (jump into a
`SizeOfRawData==0` reserved section or an RWX self-modifying section),
the detector handles:

- **UPX / ASPack / MPRESS / PECompact / MEW / FSG / Petite** — instant
  hit via packer-target predicate (14 ms on a UPX-packed canary in
  our unit tests).
- **VirtualAlloc-based reflective loaders** — hit via dynamic
  MEM_PRIVATE predicate (~3 s on the benign canary, ~milliseconds
  once we're near the payload).
- **DLLs** — auto-wrapped through `rundll32.exe "<path>",#1` so
  `DllMain` runs. Detection fires from there just as well.

Not handled without the (still-scaffold) HV layer:
**VMProtect Ultra / Themida Ultra / Enigma Maximum** — these virtualize
the code (there's no OEP to reach) and ship kernel-mode anti-debug that
user-mode can't cleanly defeat.

---

## Try it

### GUI

Grab the installer from the latest release, run it, drop a file on the
window. Left rail → Functions → click one. Right rail → Verdict + PE +
Imports. Bottom of the center → Decompile.

Drag the divider bars to resize any pane. Drag any pane's header onto
another pane's header to swap positions. Ctrl+F focuses find in the
top-most center pane.

### CLI (Python)

```bash
# 1. Static triage
python aletheia.py suspect.exe

# 2. Dump every loaded module of a live process
python aletheia.py dump-process <pid> --out dumps/

# 3. Full-pipeline benchmark on notepad.exe
python aletheia.py benchmark C:\Windows\System32\notepad.exe --out bench/

# 4. Ghidra interop — export as script + JSON for import
python aletheia.py ghidra-export project.json --out ghidra/

# 5. Full test suite
python -m pytest -q                                       # ~7s, 387 tests
```

### Engine, from Rust

```rust
use aletheia_core::{pe, detect, disasm, decompile, unpack};

let raw = std::fs::read("notepad.exe")?;
let info = pe::parse_bytes(&raw);
let verdict = detect::analyze(&info, Some(&raw));
println!("{}", verdict.summary());   // "likely clean (confidence 100%)"

// Dynamic unpack (Windows only)
let opts = unpack::UnpackOptions::default();
let result = unpack::run_unpack("\"C:\\path\\to\\sample.exe\"", &opts)?;
if result.detected {
    println!("OEP: {:#x} — {}", result.oep.unwrap(), result.reason);
}
```

---

## Real numbers, on real binaries

| Sample | Verdict | Static | Dynamic |
|---|---|---:|---:|
| `notepad.exe` (raw) | likely clean 100% | 30 ms | no detection (20 s budget, no false positive) |
| `aletheia_canary.exe` (raw) | likely clean 100% | 30 ms | detected 2.7 s (MEM_PRIVATE at OEP `0x…`) |
| `aletheia_canary_upx.exe` (UPX-packed) | PACKED 100% — UPX | 30 ms | detected **14 ms** (in-image UPX0 jump) |
| `notepad.exe` full pipeline (Python) | likely clean 100% | 6.3 s | — 203 functions decompiled, 4 MB of C-ish |

---

## Honest limits

Every heuristic that can lie says so on its output. The load-bearing ones:

- **Rust decompiler** is a lightweight lowering. If/else triangle collapse
  only; no SSA, no memory-SSA, no MBA fold, no signature/type inference.
  For the full pipeline, run the Python side.
- **Symbolic execution** is structural satisfiability only — path
  constraints like `x + y > 10 AND x < 5` are not SMT-solved.
- **PDB** — public symbols only, no globals / types / lines / C++ demangling.
- **Signatures** — structural predicates are heuristics, not proofs.
  Every match is cited on the return type.
- **HV** — scaffold only. Compiles clean, never been signed or loaded.
  See `hv/BRINGUP.md`. Do not `sc start` on a machine you care about.
- **Dynamic-unpack layer** doesn't reach VMProtect Ultra or Themida Ultra.
  That's the HV's job once the scaffold matures.

If Aletheia isn't sure of something, it says so — via `warnings`, inline
comments in the emitted pseudocode, or a phrase in the reason string.
No fabrication.

---

## Repository layout

```
rust/                        Native workbench + engine
  aletheia-core/               Rust engine: pe / detect / disasm / decompile / unpack
  aletheia-app/                Tauri + React workbench

aletheia/                    Python reference implementation (21 modules)
tools/                       Benchmark harness + Ghidra export
viewer/                      Offline HTML analysis dashboard
tests/                       387 tests, 12 golden files
  goldens/decompile/           pre-Rust behavior lock

hv/                          Clean-room VT-x/EPT + SVM/NPT HV scaffold
docs/                        Brand assets + engine docs
test-corpus/                 Benign write-then-execute canary
aletheia.py                  CLI dispatcher
LICENSE                      MIT
CHANGELOG.md                 Release notes
CONTRIBUTING.md              PR / issue guide
SECURITY.md                  Vulnerability disclosure policy
ROADMAP.md                   What's done, what's next
.github/workflows/ci.yml     pytest on push (Windows-latest, Python 3.12)
```

---

## Status

**v0.2.0** — Rust workbench released. Python engine locked by 12 golden
files (regen via `ALETHEIA_UPDATE_GOLDENS=1`). CI green on every push
(Windows-latest, Python 3.12).

## License

MIT — see [LICENSE](LICENSE).
