# Aletheia HV — bring-up guide (throwaway VM only)

The `hv/` tree is a clean-room defensive VMI hypervisor built against the Intel
SDM (VT-x/EPT) and AMD APM Vol 2 (SVM/NPT). **It has never been compiled or
run.** This document is the checklist for taking it from "spec-correct on
paper" to "actually loads and traps a page." Do this on a snapshotted VM you
do not care about. **BSODs are expected during bring-up.**

Everything below assumes a Windows 11 x64 guest with test-signing available and
the Windows Driver Kit (WDK 10) installed. On VMware Workstation Pro, tick
*"Virtualize Intel VT-x/EPT or AMD-V/RVI"* in the VM's Processors settings so
the guest sees the vendor extension we need to VMXON/VMRUN against.

---

## Phase 0 — one-time VM prep

```powershell
# In an elevated PowerShell inside the guest:
bcdedit /set testsigning on
bcdedit /set nointegritychecks on           # optional; helps early bring-up
bcdedit /debug on                            # kernel-debug transport (kdcom); windbg over the VM
Restart-Computer
```

Take a clean snapshot after the reboot named `hv-clean`. Every failed load
below should revert to it.

## Phase 1 — compile

```powershell
cd C:\path\to\Aletheia\hv
.\build.ps1
```

Expect: **30–80 errors on the first try.** The C was written without a
compiler in the loop; every real bring-up finds intrinsic-signature drift,
missing includes, MASM directive casing, and struct-layout hiccups.

**Iteration loop:**
1. Copy the failing `cl.exe` line and the error text.
2. Paste it into the analysis session.
3. Patch the source; re-run `.\build.ps1`.
4. Repeat until it links.

Realistic: 2–4 sessions to compile clean.

## Phase 2 — sign + install

```powershell
.\build.ps1 -Sign                            # generates a self-signed cert on first run
# copy the resulting build\aletheia_hv.sys into %SystemRoot%\System32\drivers\ (build script does this already)

# Register the service without starting it:
sc.exe create AletheiaHV type= kernel binPath= "%SystemRoot%\System32\drivers\aletheia_hv.sys" start= demand
```

## Phase 3 — vendor probe (safest first load)

Before we VMXON/VMRUN anything, wire a `HV_VMCALL_PING` from a tiny usermode
tool that just opens the driver's device, sends an IOCTL that asks the driver
to run `hv_detect_vendor` + `vmx_check_support` / `svm_check_support`, and
returns the capability struct. **The first `sc start AletheiaHV`** should do
nothing but populate `g_hv.vendor / .caps / .svm_caps` and return.

Success = load-without-BSOD. Read `HV_STATE` back via IOCTL, confirm the
vendor bit + capability flags match `Get-WmiObject Win32_Processor`.

Snapshot again: `hv-probe-clean`.

## Phase 4 — VMXON / EFER.SVME only

Extend the IOCTL to call `hv_virtualize_all_processors` but hard-stop after
`vmx_enable_on_cpu` / `svm_enable_on_cpu` (comment out the launch). We want
to see:

- Intel: `CR4.VMXE` set + `IA32_FEATURE_CONTROL` locked with the "enable
  VMX outside SMX" bit; VMXON did not raise `#UD` or `#GP`.
- AMD: `EFER.SVME` set + `MSR_VM_HSAVE_PA` reads back the address we wrote.

Then `sc stop AletheiaHV` and the mirror `svm_disable_on_cpu` /
`vmx_disable_on_cpu` must run cleanly. Load / unload 10× to prove no leak.

## Phase 5 — VMLAUNCH / VMRUN

This is where every real HV project bleeds. Add the setup back (`vmcs_setup_*`
/ `vmcb_setup_*` + `ept_build_identity` / `npt_build_identity`), and try one
launch on CPU 0 only.

If VMLAUNCH fails: read `VMCS_RO_VM_INSTRUCTION_ERROR` (Intel SDM Vol 3C
Table 31-1 gives the codes; 7 = invalid control field, 8 = invalid host-state
field are the most common). Log it via `DbgPrintEx`, revert snapshot, patch.

If VMRUN fails: read `VMCB.control.exit_code`; `SVM_EXIT_INVALID` (-1) means
entry state was rejected — dump the whole `VMCB_STATE_SAVE_AREA` for
diagnosis.

Realistic: 2–5 sessions of "launch → BSOD → windbg log → decode → patch."

## Phase 6 — one page trap

Once launch is stable, wire an IOCTL that calls `ept_watch_page` /
`npt_watch_page` on a specific GPA and returns whether the write/exec trap
fired. Verify with a tiny usermode program that just writes then reads a
mapped page.

Success = the debug ring shows `HV_EVENT_EPT_WRITE` followed by
`HV_EVENT_EPT_EXEC` when the writer + reader hit the watched page.

That's the whole point of the HV.

---

## Failure recovery

If the VM hangs or BSODs and doesn't come back:

```powershell
# From the HOST (not the guest), via vmrun:
"C:\Program Files\VMware\VMware Workstation\vmrun.exe" -T ws revertToSnapshot "C:\path\to\vm.vmx" "hv-clean"
"C:\Program Files\VMware\VMware Workstation\vmrun.exe" -T ws start "C:\path\to\vm.vmx"
```

## Ground rules

- Never turn on `bcdedit /set testsigning on` on your daily machine.
- Every load starts from a snapshot revert.
- Every source edit is small and targeted; do not rebase load-bearing changes
  across a bring-up.
- Log liberally via `DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, ...)`.
  On the host, run DebugView.exe with "Capture Kernel" ticked to see it.
