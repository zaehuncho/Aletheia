# Aletheia HV — clean-room Intel VT-x/EPT **and AMD-V/NPT** introspection hypervisor

A minimal, defensive **virtual-machine-introspection (VMI)** hypervisor for the
[Aletheia](../README.md) blue-team reverse-engineering toolkit. It thin-slices itself
underneath an already-running Windows x64 host, installs an identity nested-paging map
(**EPT** on Intel silicon, **NPT** on AMD), and uses page-permission traps to watch a
detection-aware sample perform **write-then-execute unpacking** — all from ring -1,
invisible to the guest.

This is the same category of tool as the public, open-source
**DRAKVUF, LibVMI, hvpp, Bareflank, and SimpleVisor** projects, and matches their
cross-vendor design (DRAKVUF / LibVMI / Bareflank all support both Intel and AMD). It is
**not** anti-cheat evasion and **not** malware. Its only job is to *observe* a sample and
dump the code it writes to memory at its original entry point (OEP).

---

## Clean-room provenance

Every value and structure in this tree is written **clean-room** from **public references
only**:

- **Intel® 64 and IA-32 Architectures Software Developer's Manual (SDM), Volumes 3B, 3C, 3D,
  and 4** — the normative source for VMX operation, VMCS field encodings, EPT paging-structure
  formats, VM-exit reasons, and the capability MSRs. Specific sections are cited inline in the
  headers (e.g. VMCS encodings → Vol 3C Appendix B; EPT formats → Vol 3C §29.3.3; capability
  MSRs → Vol 3D Appendix A).
- **AMD64 Architecture Programmer's Manual (APM), Volume 2 — "System Programming"** — the
  normative source for SVM operation, the VMCB layout, VM-exit codes, intercept fields, VMCB
  clean bits, NPT paging, and the SVM MSRs. Cited inline in `svm_defs.h` / `npt_defs.h`
  (e.g. VMCB layout → §15.5 Tables 15-1/15-2; intercepts → §15.7; VMCB clean bits → §15.15
  Table 15-8; VMEXIT codes → §15.9 Table 15-9; nested paging → §15.25; EFER.SVME → §15.4).
- **Public open-source VMMs** — hvpp, SimpleVisor, Bareflank (both Intel and AMD backends),
  DRAKVUF, LibVMI, KVM-svm — consulted only for architecture and for cross-checking the
  public SDM/APM tables they themselves transcribe.

No proprietary code was copied, and **no private or anti-cheat hypervisor was referenced.**
All code is original, written against the public specification.

---

## Architecture

The runtime is a straight line through four layers. Each is one translation unit implementing
the contract in [`include/hv.h`](include/hv.h).

```
                 DriverEntry (driver.c)
                        │
        hv_virtualize_all_processors  ── broadcast to every logical CPU
                        │
        ┌───────────────┴───────────────┐  per-CPU bring-up
        ▼                               ▼
   VMX lifecycle (vmx.c)          VMCS setup (vmcs.c)
   • CPUID + IA32_FEATURE_CONTROL  • alloc/revision-stamp VMXON+VMCS
   • CR0/CR4 FIXED0/1 adjust       • guest state  = current host context
   • VMXON                         • host state   = asm_vmexit_entry
                                    • controls: pin/proc/proc2/entry/exit
                                    • EPTP + MSR bitmap
        │                               │
        └───────────────┬───────────────┘
                        ▼
                  EPT (ept.c)
        • identity 1:1 GPA==HPA map, MTRR-correct memory types
        • split 2MB → 4KB on demand
        • write-then-execute page watches (R/W/X flips)
                        │
                        ▼  VMLAUNCH → guest (the live Windows host) runs
                        │
                  ┌─────┴─────┐  a trapped event faults out
                  ▼           ▼
        asm_vmexit_entry → hv_vmexit_dispatch (vmexit.c)
        • saves GUEST_REGISTERS            • routes on VM-exit reason
        • EPT violation / CPUID / CR / MSR / VMCALL / #exc
                        │
                        ▼
                  VMI policy (vmi.c)
        • write-then-execute state machine (catch write, then catch exec)
        • emit HV_EVENT records into the shared ring
        • guest memory reads for introspection
                        │
                        ▼  VMRESUME → guest continues, none the wiser
```

### The write-then-execute unpacking trap

Packers decrypt or decompress their payload into a memory buffer and then jump to it. The EPT
lets us see exactly that transition without touching guest page tables:

1. Mark candidate pages **R + W, not X** (or **R + X, not W**) in the EPT PTE.
2. When the packer **writes** decrypted code, a write-EPT-violation fires. We log
   `HV_EVENT_EPT_WRITE`, then re-arm the page as **R + X, not W**.
3. When control **fetches** an instruction from that freshly written page, an exec-EPT-violation
   fires. That RIP is a strong OEP candidate — we log `HV_EVENT_EPT_EXEC` and can dump the page.

All of this is driven by `vmi_on_ept_violation()` flipping the `read_access` / `write_access` /
`execute_access` bits in [`ept_defs.h`](include/ept_defs.h)'s `EPT_PTE`, followed by an
`INVEPT`.

---

## Vendor support

Aletheia HV is **vendor-neutral by design**. Bring-up detects the CPU vendor from
CPUID.0 and dispatches to either the Intel or the AMD backend. The observation contract
above the split — the write-then-execute state machine, the `HV_EVENT` ring, the VMI
policy — is identical on both; only the paging-structure and instruction-level details
differ.

| Layer | Intel (VT-x + EPT) | AMD (SVM + NPT) |
|---|---|---|
| Vendor enable | `CR4.VMXE` + `IA32_FEATURE_CONTROL` + `VMXON` | `EFER.SVME` + `MSR_VM_HSAVE_PA` |
| Guest control block | VMCS, accessed via `VMREAD`/`VMWRITE` | VMCB (4 KiB memory struct) |
| Run / exit | `VMLAUNCH` / `VMRESUME` | `VMRUN` (single instruction, VMCB PA in RAX) |
| Nested paging | EPT (permission-only paging entries) | NPT (standard IA-32e paging + NX) |
| Hypercall | `VMCALL` | `VMMCALL` |
| TLB maintenance | `INVEPT`, `INVVPID` | `INVLPGA`, TLB_CONTROL selector |
| Guarded section | *(none)* | `CLGI` / `STGI` (GIF gate) |
| Save / restore | implicit in VMCS | `VMSAVE` / `VMLOAD` |
| Spec source | Intel SDM Vol 3B–3D | AMD APM Vol 2 |

The write-then-execute unpacking trap works identically on both — flip the writable /
executable bits in an EPT PTE *or* an NPT PTE, take the fault, log the OEP candidate.
On Intel these are three independent EPT permission bits; on AMD they are the standard
`R/W` and `NX` bits in an IA-32e paging entry (`R + W - X = RW=1, NX=1`;
`R + X - W = RW=0, NX=0`; documented in `npt_defs.h`).

## Component map

| File | Role | Backend |
|------|------|---------|
| `include/arch.h` | MSR indices, CR0/CR4 bits, CPUID leaves, RFLAGS, MTRR/memory-type constants, segment/descriptor helpers. | shared |
| `include/hv.h` | Runtime structs (`VCPU`, `HV_STATE`, `HV_EVENT`, `HV_VENDOR`), all component prototypes + the `asm_x64` exports. The vendor-neutral seam. | shared |
| `include/vmx_defs.h` | VMCS field encodings (16/32/64/natural), VM-exit reason codes, pin/proc/proc2/entry/exit control masks, VM-instruction error numbers, INVEPT/INVVPID descriptors. | Intel |
| `include/ept_defs.h` | EPT PML4E/PDPTE/PDE/PTE bitfields, EPTP layout, EPT memory types, EPT-violation exit-qualification layout. | Intel |
| `include/svm_defs.h` | VMCB layout (control + state-save areas, `C_ASSERT`-pinned offsets), intercept fields (`SVM_ICPT_*`), VMEXIT codes (`SVM_EXIT_*`), VMCB clean bits, EFER/VM_CR/VM_HSAVE_PA MSRs, capability struct. | AMD |
| `include/npt_defs.h` | Nested-paging entries (union over standard IA-32e paging bits with NX at bit 63), identity-map + watch state (`NPT_WATCH_STATE_NORMAL / W_TRAP / X_TRAP`). | AMD |
| `src/vmx.c` | VMX lifecycle: support detection, VMXON/VMXOFF, CR adjustment. | Intel |
| `src/vmcs.c` | VMCS allocation and full guest/host/control population. | Intel |
| `src/ept.c` | Identity EPT construction, large-page splitting, watch primitives. | Intel |
| `src/svm.c` *(to build)* | SVM lifecycle: `svm_check_support`, `svm_enable_on_cpu` (EFER.SVME + HSAVE), `svm_launch`. | AMD |
| `src/vmcb.c` *(to build)* | VMCB allocation and full guest/control/IOPM/MSRPM population. | AMD |
| `src/npt.c` *(to build)* | Identity NPT construction, 2 MiB→4 KiB split, watch primitives (`npt_set_page_perms`). | AMD |
| `src/vmexit.c` | VM-exit dispatcher and per-reason handlers. AMD-side dispatcher (`hv_svm_vmexit_dispatch`) and per-reason handlers (`svm_handle_*`) live alongside the Intel ones. | shared / +AMD *(to build)* |
| `src/vmi.c` *(to build)* | Vendor-neutral introspection / unpacker policy. EPT violations and NPT faults both call `vmi_on_page_fault(gpa, kind)`. | shared |
| `src/driver.c` | WDM entry points; `hv_detect_vendor` at bring-up dispatches Intel or AMD lifecycle. | shared |
| `src/asm_x64.asm` | MASM wrappers. Intel: `asm_vmxon/vmread/vmwrite/vmlaunch/invept/…` + the VM-exit trampoline. AMD *(to build)*: `asm_svm_run` (CLGI/VMSAVE/VMRUN/STGI/VMLOAD loop), `asm_vmsave`, `asm_vmload`, `asm_clgi`, `asm_stgi`, `asm_invlpga`, `asm_vmmcall`, `asm_svm_vmexit_entry`. | shared |

The four headers in this commit are the interface; the `.c`/`.asm` translation units are
implemented against them.

---

## Honest status — cannot be built or run here

**This code cannot be compiled, loaded, or executed in this environment, and has not been.**
It targets Windows x64 kernel mode (a `.sys` built with the WDK/MSVC) and requires real
virtualization-capable silicon (Intel VT-x + EPT, or AMD-V + NPT) plus a kernel that will
load an unsigned/test-signed driver.

- Every unresolved decision or unverified assumption is marked with an explicit `// TODO(hv):`
  comment in the source. Nothing here is claimed to be complete.
- Correctness is judged **only** against the Intel SDM (VT-x/EPT paths) and the AMD APM Vol 2
  (SVM/NPT paths). Struct sizes are pinned with `C_ASSERT`; field encodings are transcribed
  from the public tables and cited inline.
- Actual validation must happen **on real hardware** — bring-up on a test machine (or a nested
  virtualization-capable hypervisor). On Intel: watch `VMCS_RO_VM_INSTRUCTION_ERROR` after a
  failed VMLAUNCH and confirm EPT violations fire as designed. On AMD: check the VMCB's
  `exit_code` (== `SVM_EXIT_INVALID` means VMRUN entry state was rejected — inspect the
  VMCB's CR/EFER/segment state), read back `EFER.SVME` and `VM_CR` after the enable path,
  and confirm NPT `SVM_EXIT_NPF` faults fire on watched pages. Until then, treat all of it
  as unverified.

### Building (on a real WDK toolchain, not here)

```
# Conceptual only — no build system is committed yet.
# TODO(hv): add the WDK .vcxproj / build.ps1 that compiles the .c + asm_x64.asm into a .sys,
# test-sign it, and load with `sc create` on an isolated test box with test-signing enabled.
```

Do not load this on a machine you care about. It is a research instrument for a controlled
malware-analysis lab.
