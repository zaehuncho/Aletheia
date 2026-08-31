# Aletheia HV — Build, Load, and Hardware Bring-Up Validation

> **This tree has never been compiled, loaded, or run.** It is clean-room C + MASM
> written against the Intel SDM (Vol 3B/3C/3D) for the Aletheia blue-team VMI toolkit.
> Everything below is a *procedure to follow on a dedicated test machine*, not a record
> of anything that has executed. **Assume the first VMLAUNCH will hang or bugcheck a real
> box.** Do bring-up only on a machine you can power-cycle and do not care about — ideally
> a nested-virtualization guest (see §3.0).

---

## 1. How to build (WDK + Visual Studio + ml64)

### 1.1 Toolchain prerequisites

| Component | Version / note |
|-----------|----------------|
| Visual Studio 2022 | with **Desktop C++** and **Spectre-mitigated libs** |
| Windows Driver Kit (WDK) | matching the installed SDK build number |
| Windows SDK | provides `ntddk.h`, `wdm.h` |
| MASM (`ml64.exe`) | ships with VS C++ tools; assembles `asm_x64.asm` |
| A test/target machine | Intel VT-x + EPT; **not** the build box |

Confirm the assembler and compiler resolve from a **x64 Native Tools Command Prompt**:

```
where ml64      REM ...\bin\Hostx64\x64\ml64.exe
where cl        REM same toolset
```

### 1.2 No build system is committed yet — this is the first remaining TODO

`README.md` and the source headers flag this explicitly:

```
# TODO(hv): add the WDK .vcxproj / build.ps1 that compiles the .c + asm_x64.asm into a .sys
```

Two supported ways to produce the `.sys`:

**A. KMDF/WDM `.vcxproj` (recommended).** Create an *Empty WDM Driver* project, then:

- Add `src\*.c` and `src\asm_x64.asm` to the project. For the `.asm`, enable
  **Build Customizations → masm**, and set the item type to **Microsoft Macro Assembler**.
- Add `include\` to **C/C++ → General → Additional Include Directories**.
- **C/C++ → Code Generation:** `/kernel`, disable C++ exceptions, **buffer security check
  `/GS`** on, **Spectre mitigation** on. Warnings-as-errors (`/WX`) is desirable but expect
  to fix real warnings first.
- **Target:** x64 / Release. Driver runs at `DISPATCH_LEVEL` and in VMX root — **do not**
  let the optimizer assume a normal environment; keep `/O2` but verify no CRT calls slip in.
- Output: `AletheiaHv.sys`.

**B. Command-line sketch** (illustrative flags — a real build needs the WDK's generated
include/lib paths; use the IDE or `msbuild` to get them right):

```
ml64 /c /Fo obj\asm_x64.obj src\asm_x64.asm
cl /c /kernel /GS /O2 /I include ^
   /D_AMD64_ /DNDEBUG src\*.c /Fo obj\
link /DRIVER /SUBSYSTEM:NATIVE /ENTRY:GsDriverEntry /MACHINE:X64 ^
     obj\*.obj ntoskrnl.lib hal.lib /OUT:AletheiaHv.sys
```

### 1.3 Compile-time invariants that must hold before you sign anything

The headers already pin the on-silicon layouts with `C_ASSERT` (MSVC's compile-time
`static_assert`). A build that trips one of these is telling you a bitfield or a packing
decision is wrong — **fix it, never suppress it**:

- `ept_defs.h`: every `EPT_PML4E / PDPTE(_1GB) / PDE(_2MB) / PTE / EPT_ENTRY / EPTP == 8`,
  under `#pragma pack(push,1)`.
- `vmx_defs.h`: `INVEPT_DESCRIPTOR == 16`, `INVVPID_DESCRIPTOR == 16`.
- `hv.h`: `GUEST_REGISTERS == 16*8`, `HV_LAUNCH_CONTEXT == 18*8`.

**Suggested additional `static_assert` / `C_ASSERT` coverage** (see §6.1) — the paging
entries are asserted but the *runtime* structs the ASM and VMCS code index into are not.

---

## 2. Test-sign, enable test-signing, and load

All of this is on the **target** machine, from an elevated prompt. It reduces the box's
security posture — do it only on an isolated bring-up machine.

### 2.1 Make a test certificate and sign the driver

```
REM one-time: create a self-signed test cert in the local store
makecert -r -pe -ss PrivateCertStore -n "CN=AletheiaHvTest" AletheiaHvTest.cer

REM sign the built driver with it
signtool sign /v /s PrivateCertStore /n "AletheiaHvTest" /fd sha256 AletheiaHv.sys

REM (optional) trust the cert on the target so the loader accepts it
certmgr /add AletheiaHvTest.cer /s /r localMachine root
certmgr /add AletheiaHvTest.cer /s /r localMachine trustedpublisher
```

### 2.2 Enable test-signing + kernel debugging, then reboot

```
bcdedit /set testsigning on
bcdedit /set nointegritychecks on           REM belt-and-suspenders on a lab box
bcdedit /debug on                            REM see §4 — attach a kernel debugger
bcdedit /dbgsettings net hostip:w.x.y.z port:50000 key:a.b.c.d
shutdown /r /t 0
```

After reboot the desktop shows a **"Test Mode"** watermark — confirmation test-signing is live.

### 2.3 Create the service and load it — but do NOT auto-virtualize

`DriverEntry` deliberately does **not** start virtualization; it only creates the control
device `\Device\AletheiaHv` (symlink `\DosDevices\AletheiaHv`) and wires the IOCTL dispatch.
Virtualization is driven explicitly by `IOCTL_ALETHEIA_START`. This is the safety property
that makes staged bring-up possible — **loading the driver is inert; the danger is the START
IOCTL.**

```
sc create AletheiaHv type= kernel binPath= C:\lab\AletheiaHv.sys
sc start  AletheiaHv                 REM loads driver, runs DriverEntry only

REM later, to trigger virtualization (the risky step), a usermode client sends:
REM   IOCTL_ALETHEIA_START  (CTL_CODE 0x800)  -> hv_virtualize_all_processors
REM   IOCTL_ALETHEIA_QUERY  (0x802)           -> ALETHEIA_STATUS_OUT
REM   IOCTL_ALETHEIA_DRAIN  (0x804)           -> pull HV_EVENT records
REM   IOCTL_ALETHEIA_STOP   (0x801)           -> devirtualize all CPUs

sc stop   AletheiaHv                 REM devirtualize + unload
sc delete AletheiaHv
```

---

## 3. Hardware bring-up checklist (least → most dangerous)

Do these **in order**. Do not advance a step until the previous one is clean. Each step
past 3.2 can hang the box; §4 tells you what to watch and how to recover.

### 3.0 Step 0 — Use a nested VT-x guest first, not bare metal

Run the whole ladder first inside a hypervisor that exposes nested VT-x (VMware Workstation
with *Virtualize Intel VT-x/EPT* checked, or Hyper-V nested virtualization). A hang there is
a guest reset, not a physical power-cycle. Move to bare metal only after the nested pass is
clean — some Intel EPT/MTRR corner cases differ, so bare metal is still a required final run.

### 3.1 Step 1 — Verify VT-x is present and usable (cannot hang)

Gate on, in `vmx.c` order:

1. `CPUID.1:ECX.VMX[bit 5] == 1`.
2. `IA32_FEATURE_CONTROL` (MSR 0x3A): **LOCK** bit set **and** VMXON-outside-SMX bit set.
   If LOCK is set with VMXON cleared, the BIOS disabled VT-x — you cannot proceed
   (`HV_ERR_VMX_LOCKED_OFF`). If LOCK is clear, the driver may set both then lock.
3. EPT + the INVEPT type you rely on are present in `IA32_VMX_EPT_VPID_CAP`
   (`ept.c` gate; see the TODO at `ept.c:606`).
4. `CR0`/`CR4` satisfy the FIXED0/FIXED1 MSRs (`vmx_adjust_cr0` / `vmx_adjust_cr4`).

**Check:** `IOCTL_ALETHEIA_QUERY` returns `vt_supported == 1`, `ept_supported == 1`. This
step reads MSRs/CPUID only — it is safe.

### 3.2 Step 2 — VMXON on a single CPU (first point of no-return risk)

Restrict to **one** logical CPU (`KeSetSystemAffinityThreadEx` to CPU 0) for bring-up.
Allocate the 4KB VMXON region, stamp the revision id from `IA32_VMX_BASIC[30:0]` into its
first dword, set `CR4.VMXE`, execute `VMXON` with the region's physical address.

**Check:** `VMXON` clears CF **and** ZF. On failure, CF/ZF are set and there is no
instruction-error field yet (VMXON failure predates an active VMCS). Then `VMXOFF`
immediately and clear `CR4.VMXE`. If this is clean, the CPU is in VMX root but no guest
exists — still recoverable with `VMXOFF`.

### 3.3 Step 3 — VMLAUNCH resuming the host-as-guest, trivial CPUID exit (**will hang if wrong**)

This is the hyperjack: `vmcs.c` programs guest state = the *current* host context (captured
by `asm_capture_context`), host state = `asm_vmexit_entry`, minimal pin/proc/entry/exit
controls, **CPUID forced to exit** (CPUID unconditionally exits in VMX non-root — no control
bit needed), **EPT off for this step**. `VMLAUNCH` then "returns" as the running guest.

**Check, in this exact order:**

1. Execution continues past the launch point as the guest (the setup-pass returns 0, the
   guest re-entry returns 1 — the convention flagged at `hv.h:330` / `vmcs.c:445`).
2. A deliberate `CPUID` in the guest causes a VM-exit with
   `VMCS_RO_EXIT_REASON == EXIT_REASON_CPUID`.
3. `hv_vmexit_dispatch` runs on the host stack, the handler advances guest RIP by the
   instruction length (`VMCS_RO_VMEXIT_INSTR_LEN`), and `VMRESUME` returns to the guest.
4. The system stays alive and responsive.

If `VMLAUNCH` **fails cleanly** (CF/ZF set), read `VMCS_RO_VM_INSTRUCTION_ERROR` — this is
the single most valuable number in the whole project (SDM Vol 3C Table 31-1). Common values:
- **7 VM entry with invalid control field(s)** — a pin/proc/proc2 bit is not permitted by the
  capability MSR; recompose against `IA32_VMX_TRUE_*` (`vmx.c:80`).
- **8 VM entry with invalid host-state field(s)** — host RIP/RSP/selectors/CR0/CR4 wrong.
- **12 VM entry with invalid guest state** — guest segment/RFLAGS/CR constraints violated
  (the `vmcs.c` "unusable segment" logic at `vmcs.c:101`).

A **hang or triple-fault reboot** (no error code) means host state or the exit trampoline is
wrong — the CPU took an exit and could not find a valid host RIP/RSP. See §4.

### 3.4 Step 4 — EPT identity map (still single-CPU)

Build the identity 1:1 GPA==HPA EPT (`ept.c`), memory types from the MTRRs, program the EPTP
into the VMCS, enable EPT in the secondary proc-based controls, `INVEPT`, then relaunch.

**Check:** the guest still runs with EPT active (every access now walks EPT). A wrong memory
type or a missing mapping shows up as an unexpected `EXIT_REASON_EPT_VIOLATION` /
`EPT_MISCONFIG` with a GPA in the exit qualification (`ept_defs.h` `EPT_VIOLATION_INFO`), or a
hang. Confirm normal memory (RAM) maps **WB** and MMIO ranges map **UC** — a WB-over-MMIO
mistake corrupts devices silently.

### 3.5 Step 5 — W^X page watch (the actual product)

Mark one test page R+W-not-X, write to it (expect `HV_EVENT_EPT_WRITE`, re-arm R+X-not-W),
fetch from it (expect `HV_EVENT_EPT_EXEC`), each followed by `INVEPT`. Drain the ring via
`IOCTL_ALETHEIA_DRAIN`.

**Check:** exactly one write event then one exec event for the page, RIPs sane, and the guest
makes forward progress (no violation storm from failing to flip the bits or forgetting
`INVEPT` — a storm is the classic livelock here).

### 3.6 Step 6 — Multi-CPU

Remove the single-CPU affinity clamp; `hv_virtualize_all_processors` broadcasts bring-up to
every logical CPU (per-CPU VMXON region, VMCS, host stack, EPT can be shared or per-CPU).

**Check:** `vcpus_virtualized == vcpu_count`; every CPU handles its own exits; no cross-CPU
EPT races on the shared tables (the multi-VCPU producer race is flagged at `hv.h:192`). Then
exercise devirtualize on all CPUs and confirm a clean `VMXOFF` everywhere.

---

## 4. What to check at each step + recovering a hang

**Instrument before you launch.** Attach a kernel debugger (WinDbg over the net link from
§2.2) **before** the START IOCTL. The debugger is often the only way to see a launch-error
code before the box dies.

Per-step evidence to capture:

| Step | Primary evidence | Failure signature |
|------|------------------|-------------------|
| 1 | `QUERY` flags | `vt_supported==0` → BIOS/locked (safe, no hang) |
| 2 | VMXON CF/ZF | set → VMXON failed; `VMXOFF` recovers |
| 3 | `VMCS_RO_VM_INSTRUCTION_ERROR` | 7/8/12 → control/host/guest field; hang → host state |
| 4 | unexpected EPT_VIOLATION/MISCONFIG GPA | hang or device corruption → memory-type/map error |
| 5 | ordered WRITE→EXEC events | violation storm → bit-flip/INVEPT missing |
| 6 | `vcpus_virtualized == vcpu_count` | one CPU wedges → per-CPU state aliasing |

**Recovering a hang — it WILL happen early:**

- **Design in a kill switch first.** The driver only virtualizes on `IOCTL_ALETHEIA_START`,
  so if a *load* wedges, the fault is in `DriverEntry`, not VMX — rare.
- A wedged **VMLAUNCH/exit** typically gives no prompt and no debugger response (the CPU is
  spinning in root mode or triple-faulting). Recovery is a **hard power-cycle**. This is why
  §3.0 says do it nested first — a nested guest resets in seconds.
- If the debugger *is* responsive at the exit, dump `VMCS_RO_VM_INSTRUCTION_ERROR`,
  `VMCS_RO_EXIT_REASON`, `VMCS_RO_EXIT_QUALIFICATION`, and the guest RIP/RSP before doing
  anything else. Then `!vtop`, `.trap`, and the guest-state VMCS fields.
- **Boot recovery** if the box won't come back clean: boot to the recovery/other OS and
  `bcdedit /set testsigning off` + `sc delete AletheiaHv` from an offline hive, or roll back
  via a pre-bring-up restore point / disk image. **Image the test box before Step 3.**
- A failed `VMXOFF` leaves the CPU in root mode with no guest — the ASM path is supposed to
  bugcheck rather than limp on (`asm_x64.asm:455`, `vmx.c:354`). A bugcheck here is *correct*
  behavior, not a regression.

---

## 5. Honest known limitations + remaining TODO(hv) inventory

**64 actionable `// TODO(hv):` markers** remain across the tree (72 total occurrences, of
which 8 are the boilerplate "every decision is marked TODO(hv)" header banners). None of this
has run. The load-bearing gaps, by file:

### 5.1 The two things with no implementation at all

- **`vmi.c` does not exist.** The whole write-then-execute policy engine, the event-ring
  producer, and guest-memory reads are referenced by `vmexit.c`/`driver.c` but unwritten. The
  product's actual value lives here.
- **No build system.** No `.vcxproj` / `build.ps1` (`README.md:134`). §1.2 is the spec for it.

### 5.2 asm_x64.asm (7)

- `asm_x64.asm:290` — confirm the exit-trampoline discriminator model vs. a dedicated guest stub.
- `asm_x64.asm:291` — **XMM / segment / CR state are NOT captured** on the launch snapshot; the
  guest inherits live host values. A guest that touches XMM before the host reloads them is
  unproven.
- `asm_x64.asm:293` — **no `.pdata`/`.xdata` unwind info** is emitted for the ASM functions;
  add function tables before a real build or the linker/verifier may reject them.
- `asm_x64.asm:173` — INVEPT/INVVPID mnemonics assume a modern `ml64`; older assemblers need
  hand-encoded `db` bytes.
- `asm_x64.asm:109`, `:19`, `:455` — intrinsic-vs-wrapper choice, header banner, VMXOFF-fail
  bugcheck.

### 5.3 vmexit.c (20 — the largest cluster of unfinished handlers)

- `vmexit.c:121` / `:461` — **`#PF` injection does not load `VMCS_GUEST_CR2`**; injecting a
  page fault as-is gives the guest a wrong fault address.
- `vmexit.c:442` — **NMIs are not held/handled by the host**; an NMI during root mode is
  mishandled.
- `vmexit.c:225` — EPT-misconfig path: "the machine cannot safely continue" — no clean handling.
- `vmexit.c:248` / `:262` — CR0/CR4 writes don't re-apply FIXED0/FIXED1; `CR4.VMXE` must stay set.
- `vmexit.c:269` / `:287` — CR8/TPR is a placeholder returning 0 (no virtual-APIC/TPR shadow).
- `vmexit.c:345` / `:350` — MSR path does **not** spoof `IA32_FEATURE_CONTROL` to hide the HV,
  and a guest `RDMSR` of a reserved index can `#GP` the **host**.
- `vmexit.c:386` — EFER.LME/`IA32E_MODE_GUEST` retoggle not recomputed on mode switch.
- `vmexit.c:391` — PAT / SYSENTER_CS/ESP/EIP / FS_BASE / GS_BASE MSRs not routed to VMCS fields.
- `vmexit.c:646` — TRIPLE_FAULT / entry-failure MCE fatal; INIT/SIPI need real handling.
- Plus `:30, :121, :207, :274, :417, :512, :553, :568` — per-VCPU-vs-global state, retry==0
  unwatched-page path, event-log copy-out destination, NULL-vcpu host-stack back-pointer.

### 5.4 vmcs.c (8), vmx.c (5), driver.c (9), ept.c (8), headers (13)

- `vmcs.c:72/:101` — LDT (TI==1) selectors unresolved; "unusable" segment decision uses a
  heuristic, not LAR's ZF.
- `vmcs.c:445` / `hv.h:330` — the **setup-pass-returns-0 / guest-returns-1 convention is not
  pinned** across `driver.c` ↔ `asm_capture_context` ↔ `vmcs_setup_guest`. This is the
  convention Step 3 depends on; get it wrong and VMLAUNCH resumes at the wrong RIP.
- `vmx.c:80` — controls composed from a single CPU; asymmetric systems need per-CPU composition.
- `ept.c:292` — conflicting MTRR overlap resolved to UC (safe but not exact).
- `ept.c:326/:723` — **>512GB GPAs / MAXPHYADDR>39 / LA57 (5-level) unsupported** — one PML4
  entry only.
- `ept.c:606` — if `IA32_VMX_EPT_VPID_CAP` reports neither INVEPT type, EPT cannot be used.
- `driver.c:102` — phys-addr highest clamp not sized to `CPUID.80000008`.
- `driver.c:200` / `hv.h:241` — launch-context blob layout not pinned to `asm_capture_context`.
- `hv.h:35/:87/:349` — the hypercall ABI (which GPRs carry args/results) is **not locked**.
- `hv.h:449` — guest-memory read needs a guest-CR3 GVA→GPA page walk (not written).
- `arch.h:258` — pick/document a CPUID leaf in the `0x40000000` hypervisor range.
- `hv.h:228` / `ept_defs.h:260` — `watches[64]` and the identity-map span are guessed sizes.

---

## 6. Suggested compile-time `static_assert` coverage

The paging entries are asserted; the runtime structs the ASM and VMCS code *index by fixed
offset* are not. Add these (MSVC `C_ASSERT`, or C11 `static_assert`) so a layout drift fails
the build instead of the box:

### 6.1 Struct-size / offset asserts to add

```c
/* hv.h — the ASM exit stub and vmcs_setup_host index these by hand. Pin every field the
 * assembly touches, not just the aggregate size. */
C_ASSERT(FIELD_OFFSET(VCPU, host_rsp)  == /* value MASM assumes */);
C_ASSERT(FIELD_OFFSET(VCPU, gpr)       == /* value asm_vmexit_entry assumes */);
C_ASSERT(FIELD_OFFSET(VCPU, hv)        == /* back-pointer offset the stub recovers */);
C_ASSERT(sizeof(EPT_STATE)  == /* pinned */);
C_ASSERT(sizeof(EPT_WATCH)  == /* pinned */);
C_ASSERT(sizeof(HV_EVENT)   == /* pinned — ring producer/consumer must agree */);
C_ASSERT(sizeof(HV_EVENT_LOG) <= /* one allocation unit; it's ExAllocatePool'd whole */);
C_ASSERT((sizeof(VCPU) ) /* fits the NonPagedPoolNx allocation in driver.c:172 */);

/* ept_defs.h — already good; add the aggregate table is exactly a page. */
C_ASSERT(sizeof(EPT_PML4E) * 512 == PAGE_SIZE_4K);   /* 4096 */
C_ASSERT(sizeof(EPT_PTE)   * 512 == PAGE_SIZE_4K);

/* vmx_defs.h — VMCS/VMXON regions are revision-stamped 4KB pages; assert the wrapper. */
C_ASSERT(sizeof(VMCS_REGION_HEADER) <= PAGE_SIZE_4K);

/* hv.h — the launch snapshot the ASM writes and vmcs_setup_guest reads. */
C_ASSERT(sizeof(HV_LAUNCH_CONTEXT) == 18 * sizeof(u64));   /* already present */
C_ASSERT(sizeof(GUEST_REGISTERS)   == 16 * sizeof(u64));   /* already present */
```

The two most valuable additions are the **`FIELD_OFFSET(VCPU, …)` asserts** — the C struct
and the MASM `.asm` are two independent transcriptions of the same layout, and nothing today
forces them to agree. A single mismatched offset there is exactly the class of bug that causes
the silent VMLAUNCH hang in Step 3.

---

## Final summary

**Files created under `hv/` by this pass:** `VALIDATION.md` (this file) — the build /
test-sign / load / bring-up / limitations guide. No source was modified.

**Component status (all UNBUILT, UNRUN — clean-room against the SDM):**

| Component | State |
|-----------|-------|
| `include/*.h` (arch, vmx_defs, ept_defs, hv) | interface complete; paging structs `C_ASSERT`-pinned |
| `vmx.c` | VMX lifecycle drafted; per-CPU control composition TODO |
| `vmcs.c` | guest/host/control population drafted; setup/guest-return convention unpinned |
| `ept.c` | identity map + split + watch drafted; >512GB / LA57 / INVEPT-cap gaps |
| `vmexit.c` | dispatcher + handlers drafted; **20 TODOs**, several correctness-critical (CR2 on #PF, NMI, MSR #GP) |
| `driver.c` | WDM entry + IOCTL + per-CPU orchestration drafted; virtualize gated behind START IOCTL |
| `asm_x64.asm` | VMX wrappers + exit trampoline drafted; no XMM capture, no unwind info |
| `vmi.c` | **does not exist** — the unpacker policy + event ring is unwritten |
| build system | **does not exist** — no `.vcxproj`/`build.ps1` |

**Total `// TODO(hv):` count:** **72 occurrences**, of which **8 are header-banner boilerplate**
and **64 are actionable** (largest clusters: `vmexit.c` 20, `hv.h` 11, `driver.c` 9, `ept.c`/
`vmcs.c` 8 each, `asm_x64.asm` 7).

**Single most important correctness risk to verify first on real hardware:**
the **guest re-entry convention and the VCPU-layout agreement between `vmcs.c`/`driver.c` and
`asm_x64.asm`** — i.e. that after `VMLAUNCH` the CPU resumes at the instruction *after* the
launch call with the intended RIP/RSP/RFLAGS from the launch snapshot, and that the VM-exit
trampoline recovers the correct `VCPU*` and GPR block by offset. This is unpinned
(`vmcs.c:445`, `hv.h:330`, `hv.h:241`, `driver.c:200`) and is the exact failure that produces a
**silent hang with no error code** in bring-up Step 3. Add the `FIELD_OFFSET(VCPU, …)`
`static_assert`s from §6.1, attach a kernel debugger, force the trivial CPUID exit, and read
`VMCS_RO_VM_INSTRUCTION_ERROR` before trusting anything downstream.
