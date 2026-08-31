# Contributing to Aletheia

Thanks for reading this. Aletheia is a defensive reverse-engineering
toolkit, so the contribution bar is a little different from a typical
open-source project: correctness beats features, and honesty about
what a heuristic can and can't do beats a confident false positive.

## What we'll accept

- **Bug fixes** with a repro and a test that pins the fix. If the bug
  is a false-positive detection, the fix must not regress the true
  positives — this repo uses golden files for that (see below).
- **New protector / packer signatures** with:
  - A citation for the signature (paper, sample hash, disassembly of
    the loader — anything a reader can check independently).
  - A test on a synthetic PE that exhibits the tell.
  - A note in `docs/limits.md` if the signature is heuristic vs. exact.
- **Rust ports of Python modules.** The Python side is the reference
  implementation; every ported module must reproduce byte-identical
  output on the shared golden files in `tests/goldens/`. See
  `rust/aletheia-core/src/lib.rs` for the correctness contract.
- **Documentation** — especially where a limit is documented on a
  return type but missing from the user-facing README.

## What we won't accept

- **Detection-evasion tooling.** Aletheia is defensive: it analyzes
  and identifies. Anti-cheat evasion, HVCI bypasses, driver-based
  unhooking, and analogous offensive plumbing are out of scope and
  will be closed without review. See `SECURITY.md` for the boundary.
- **Signatures without citations.** "This byte pattern is UPX" without
  a reference sample or a UPX-source pointer is a maintenance liability
  we can't accept.
- **Silent behavior changes.** If a change alters what a public function
  emits on the golden files, the golden files need to be regenerated
  (`ALETHEIA_UPDATE_GOLDENS=1 python -m pytest -q`) *and* the PR
  description needs to explain why the new output is correct.

## Development

### Python side

```bash
python -m venv .venv
.\.venv\Scripts\activate                 # Windows
python -m pip install -e ".[dev]"        # from pyproject if present, else nothing to install
python -m pytest -q                      # 389 tests, ~8s
```

Zero required runtime deps beyond stdlib. `capstone` is optional (the
disassembler falls back cleanly). Type-checking via `pyright` if you
have it installed; not required.

### Rust side

Requires the `x86_64-pc-windows-msvc` toolchain (pinned in
`rust/rust-toolchain.toml`).

```bash
cd rust
cargo test  -p aletheia-core --release    # engine tests
cargo build -p aletheia-core --release    # engine only
```

For the workbench UI:

```bash
cd rust/aletheia-app
npm ci
npm run tauri -- dev                      # dev with hot reload
npm run bundle                            # release .exe + MSI + NSIS installer
```

The Tauri CLI is pinned in `package-lock.json`; do not install a global copy for release builds.

### HV side

The `hv/` tree is a clean-room defensive hypervisor scaffold. Build,
sign, load, and test it only inside a snapshotted VM with WDK 10 and
VS 2022. See `hv/BRINGUP.md` for the checklist and
`hv/README.md` for the clean-room provenance rules — TL;DR: cite the
SDM / APM section for every constant; never consult a proprietary or
anti-cheat HV source.

Inside that VM, `./build.ps1 -VmOnlyAcknowledged` makes the environment
boundary explicit. The driver is not part of normal desktop release artifacts.

## Coding conventions

- Match the surrounding code's naming, comment density, and idiom.
- Every public function that can lie carries a `warnings` field or a
  return-type note documenting when it lies and how much.
- Errors are typed enums with `#[error(...)]` messages, not `String`.
- `unsafe` blocks name the invariant they rely on in a `SAFETY:` comment.

## Signing your commits

We ask (don't require) that commits are signed with the same
`Co-Authored-By:` trailer the maintainers use. Not for legal reasons —
so future readers of `git blame` can trace who reviewed a heuristic.

## Reporting security issues

**Do not open a public issue for a security bug.** See `SECURITY.md`.

## License

By contributing, you agree that your contribution will be licensed
under the same MIT license as the rest of the project (see `LICENSE`).
