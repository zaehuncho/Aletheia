
## Status as of 2026-08-31

**Shipped since the last ROADMAP touch:**
- Rust engine ports of `pe.py`, `detect.py`, `disasm.py` — byte-verdict compatible.
- Rust `decompile.rs` — lightweight lowering with if-then triangle collapse.
- Rust `unpack.rs` — Win32 Debug API single-stepper + three levers (anti-anti-debug PEB patches, ntdll API hooks, guard-page write tracking) + in-image packer-target predicate + auto-rundll32 wrap for DLLs. Live-verified: UPX canary detected in 14 ms.
- Tauri workbench (`rust/aletheia-app/`) with drag-and-drop pane reorder, resizable persisted splits, Ctrl+F find, custom chrome, MSI + NSIS installers.
- HV scaffold (`hv/`) has a VM-gated WDK build path. It is not signed, loaded, or runtime-validated — see `hv/BRINGUP.md`.
- Test canary + benign write-then-execute demo (`test-corpus/canary/`).

**Next up:**
- Port `ir.py` + `dataflow.py` + `simplify.py` + `structuring.py` + `decompile.py` (SSA-driven full decompiler) to Rust.
- Fix the shared-BP-replant interaction between guard-page mode and API hooks so both can be `on` by default.
- HV Phase 2+ inside a snapshotted VM (test-sign, `sc create`, VMXON bring-up, write-then-execute state machine in `vmi.c`).
- Anti-debug lever 1 upgrade: hook `NtQueryInformationProcess(ProcessDebugPort)` for `CheckRemoteDebuggerPresent` coverage.

---
# Aletheia — Roadmap

The goal: a **completely custom, all-in-one defensive reverse-engineering suite** —
static triage, live debugging, memory dumping, dynamic unpacking, disassembly,
and (incrementally) decompilation, with hypervisor-level introspection at the top.

**Where Aletheia beats Ghidra:** Ghidra is a static decompiler and is *blind to
packed code* (it disassembles the packer stub, not the runtime-revealed real
code). Aletheia is *dynamic* — it runs, unpacks, and dumps the real code. The two
compose: **Aletheia unpacks → the clean dump goes to a decompiler (ours, or
Ghidra).** We own the runtime half Ghidra can't touch.

Legend: `[x]` done · `[ ]` planned · 🤖 great agent/workflow task · 🔬 research-grade

---

## Tier 0 — Foundations ✅ *(done)*
- [x] Static PE triage + packer detection (entropy, W^X, import elision, entry
      anomalies, signature DB) — `aletheia/detect.py`
- [x] Custom x64 Windows debugger (Debug API, breakpoints, memory, CONTEXT,
      single-step, callbacks) — `aletheia/debugger.py`
- [x] Memory→PE dumper ("dump at OEP" reconstruction) — `aletheia/dump.py`

## Tier 1 — Core dynamic analysis *(the "rip anything" essentials)*
- [ ] **Process-memory dumper** — attach to any live PID, enumerate modules
      (`EnumProcessModulesEx`), dump each to a reconstructed PE. 🤖 *"dump any
      running EXE/DLL"*
- [ ] **Dynamic unpacker** — page-guard the writable/executable regions, detect
      *write-then-execute*, dump at the discovered OEP + a behavior log. 🤖
- [ ] **Import reconstruction** — rebuild a dumped image's IAT (resolve the
      thunks back to `DLL!func`) so dumps are loadable/analyzable. 🤖
- [ ] **Behavior logging** — breakpoint the usual suspects (LoadLibrary/
      GetProcAddress/VirtualAlloc/VirtualProtect/CreateProcess/file/reg/net) into
      a timeline. 🤖
- [ ] **Anti-anti-debug** — neutralize a sample's own anti-debug checks
      (PEB.BeingDebugged, timing, NtGlobalFlag) so analysis survives. Defensive.

## Tier 2 — Static RE core *(the "disassembler" half)*
- [ ] **Disassembler** — capstone-backed recursive-descent disassembly with
      cross-references (already have capstone). 🤖
- [ ] **CFG reconstruction** — per-function basic-block graph. 🤖
- [ ] **Extractors** — strings, imports/exports, resources, symbols, entropy map. 🤖
- [ ] **Signature scanning** — YARA-style rules + FLIRT-like library-function ID
      (auto-name known library functions). 🤖
- [ ] **Analysis database** — a project model (functions, xrefs, comments,
      renames) the UI and scripts bind to.

## Tier 3 — Decompilation *(custom, incremental — we own the foundation)* 🔬
- [ ] **x64 → IR lifter** — generalize the existing Daedalus lifter into a proper
      analysis IR (SSA-friendly). *(the packer's lifter is the head start)*
- [ ] **Data-flow analysis** — SSA construction, dead-code elimination,
      expression propagation, constant folding.
- [ ] **Control-flow structuring** — recover if/else, loops, switches from the CFG.
- [ ] **Type recovery (basic)** + a **C-like pseudocode emitter**.
- *Ship "good enough" first; production-grade type recovery is the long tail.*

## Tier 4 — UI *(engine-first, then a results surface)*
- [ ] **Analysis workbench** — disasm + pseudocode views, an interactive CFG
      graph, memory map, behavior timeline, a dumped-payload browser.
- [ ] Built like Lethe's GUI: engine underneath, UI on top (QML/Qt or web).

## Tier 5 — Deep introspection *(hypervisor VMI — CLEAN-ROOM)*
- [ ] **Clean-room VT-x + EPT hypervisor** — from public references
      (hvpp / Bareflank / SimpleVisor / LibVMI / DRAKVUF). 🔬
- [ ] **VMI** — observe memory + execution of a detection-aware sample from
      ring -1 (invisible to the guest).
- [ ] **Hypervisor-assisted unpacking** — the same write-then-execute detection,
      below the OS.

## Tier 6 — Integration & ecosystem
- [ ] **Ghidra export** — write the dump + a load/annotation script (and/or a
      plugin that pulls Aletheia's dynamic data into Ghidra).
- [ ] **Automated pipeline** — submit sample → triage → unpack → dump → rebuild
      imports → disassemble → report (a Cuckoo/CAPE-style orchestration).
- [ ] **Scripting API** — let users script analyses (Ghidra/IDA-style).
- [ ] **Interop** — x64dbg / IDA import-export.

---

### Suggested execution order
Tier 1 in full (it's the differentiated, demoable core), then Tier 2's
disassembler + CFG, then start Tier 3 (IR), with the UI (Tier 4) coming online
once there's enough engine to show. Tier 5 (HV) is its own track and can proceed
in parallel. Most Tier 1–2 items are clean, well-scoped agent tasks.
