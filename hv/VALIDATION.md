# Aletheia HV validation

The `hv` tree is experimental, source-only research code. It is not part of the Aletheia desktop installers and has not been signed, loaded, or runtime-validated.

## Non-negotiable boundary

Build, sign, load, and test the driver only inside a disposable, snapshotted VM with nested virtualization enabled. Keep a kernel debugger and a rollback path available. Never load it on a development workstation or production endpoint.

## Static checks

The normal repository release pass may:

- parse `build.ps1` for PowerShell syntax;
- inspect the control-device ACL, IOCTL access bits, and privilege checks;
- review WDK compiler/linker hardening flags; and
- inventory unresolved `TODO(hv)` markers.

These checks do not establish runtime correctness.

## VM build

Install Visual Studio C++ Build Tools and a matching Windows Driver Kit in the VM, then run from `hv`:

```powershell
./build.ps1 -VmOnlyAcknowledged
```

The script enables warnings-as-errors, buffer/security checks, Spectre mitigation, Control Flow Guard, ASLR, NX compatibility, integrity checks, and SHA-256 debug information. It links `wdmsec.lib` because the control device is created with `IoCreateDeviceSecure`.

Test-signing is an explicit, separate VM-only choice:

```powershell
./build.ps1 -VmOnlyAcknowledged -Sign
```

## Before any load

1. Revert to a clean snapshot and disconnect or isolate networking as appropriate.
2. Confirm the generated file is an x64 native driver and inspect its imports and mitigations.
3. Confirm the test certificate and SHA-256 signature are the ones created inside the VM.
4. Attach a kernel debugger and configure Driver Verifier only for the Aletheia driver.
5. Follow `BRINGUP.md` one checkpoint at a time. Revert the snapshot after a hang, bugcheck, or failed teardown.

## Release status

Open `TODO(hv)` markers identify unverified architectural decisions and incomplete edge handling. Until VM build and live gates are completed, the only supportable public claim is that the source and build path are available for review. Do not publish a `.sys`, enable automatic driver installation, or describe the hypervisor as production-ready.
