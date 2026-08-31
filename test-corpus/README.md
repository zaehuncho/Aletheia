# Aletheia test corpus

Small binaries used to validate the analyzer end-to-end. Every artifact
here is **benign** and intentionally exercises specific behaviors so we
can prove the detectors work.

## What is here

- `canary/` -- a tiny Windows console EXE that performs the classic
  *write-then-execute* unpacker pattern: `VirtualAlloc(RWX)` -> `memcpy`
  of a 4-byte "shellcode" (`xor rax,rax; ret`) -> `jmp` into it -> return.
  Prints an ALETHEIA_TEST_CANARY banner so no one confuses it for anything
  real. Written in Rust; source is checked in, the compiled `.exe` is not.

- `pack.ps1` -- packs the built canary with UPX (if `upx` is on PATH) and
  with Lethe (if `$env:LETHE_BIN` is set) so you have multiple test targets
  to drop into the debugger/unpacker.

## Build

```powershell
cd test-corpus\canary
cargo build --release
# -> target\release\aletheia_canary.exe
```

Then run it once directly to convince yourself it is harmless -- it prints
the banner, runs its four-byte "shellcode", exits 0. Then point Aletheia
at the file to see the analyzer catch the RWX + import-elision pattern.

## Pack it

```powershell
cd test-corpus
# Requires: upx on PATH, or $env:LETHE_BIN pointing at your Lethe launcher.
.\pack.ps1
# -> canary\target\release\aletheia_canary_upx.exe (if upx installed)
# -> canary\target\release\aletheia_canary_lethe.exe (if lethe available)
```

## Not-corpus, do NOT add here

Real malware samples, ransomware, credential stealers, C2 stagers -- any
of that goes to a purpose-built lab environment behind an isolated network,
not into a public repo. This corpus is *positive test data* only: benign
binaries whose behaviors we WANT the analyzer to detect.
