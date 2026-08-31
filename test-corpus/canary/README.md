# aletheia_canary

Tiny benign write-then-execute test binary.

## What it does

1. `VirtualAlloc` a 4 KiB page with `PAGE_EXECUTE_READWRITE` (the W^X flag)
2. `memcpy` a 4-byte shellcode into it (`xor rax, rax ; ret`)
3. Jump into the buffer via a function pointer
4. `VirtualFree` + exit 0

Prints the banner `[ALETHEIA_TEST_CANARY] ...` at every step. That marker
string is embedded in the read-only data section so the analyzer can find
it via strings.

## Why

It is the smallest binary that exercises the exact behaviors Aletheia s
dynamic detectors key on: `PAGE_EXECUTE_READWRITE`, memcpy-then-execute,
no imports besides the two VirtualAlloc / VirtualFree symbols. Point the
analyzer at it and every detector should fire.

## Build

```powershell
cargo build --release
# target\release\aletheia_canary.exe (~200 KB)
```

## Safety

The shellcode is `xor rax, rax ; ret`. It zeros rax and returns. That is
it. Run it once from a terminal; you will see the banner + exit 0.
