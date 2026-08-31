/*
 * vmexit.c -- VM-exit dispatcher and per-reason handlers for the Aletheia clean-room
 * VT-x/EPT VMI hypervisor.
 *
 * CLEAN-ROOM PROVENANCE: Every VMCS field, control bit, exit reason, and exit-qualification
 * layout referenced here traces to a symbolic definition in arch.h / vmx_defs.h / ept_defs.h,
 * which were themselves transcribed from the public Intel SDM (Vol 3C VM-exit reasons Ch.27 /
 * App. C; VMCS encodings App. B; CR/EPT exit-qualification tables 28-3 and 29-7; event
 * injection 25.8.3). No magic numbers, no proprietary or anti-cheat source. Original code
 * written against the public specification.
 *
 * ROLE: asm_vmexit_entry (asm_x64.asm) saves the guest GPRs into a GUEST_REGISTERS frame and
 * calls hv_vmexit_dispatch() with a pointer to it. This file routes on the basic exit reason,
 * services each event, and returns nonzero to request VMRESUME or zero to request an orderly
 * per-VCPU teardown (guest-requested unload).
 *
 * CANNOT BE BUILT OR RUN IN THIS ENVIRONMENT. Every unresolved decision is marked TODO(hv).
 * A wrong VMCS field or a mis-advanced RIP hangs the physical machine; correctness against the
 * SDM is the whole game.
 */

#include "hv.h"

/* -------------------------------------------------------------------------------------- */
/*  File-local teardown latch                                                              */
/*                                                                                          */
/*  Set by the HV_VMCALL_UNLOAD service; consulted by the dispatcher to return 0 (teardown) */
/*  instead of 1 (resume). A file-static latch keeps vmexit.c from having to add a field to */
/*  the shared VCPU struct (owned by hv.h / driver.c).                                      */
/*  TODO(hv): this is process-global, not per-VCPU. driver.c orchestrates devirtualization  */
/*  across every logical processor, so an orderly unload should broadcast; wire this latch   */
/*  to that broadcast (or move it to per-VCPU state) before relying on it for correctness.   */
/* -------------------------------------------------------------------------------------- */
static volatile long g_vmexit_unload_requested = 0;

/* -------------------------------------------------------------------------------------- */
/*  GPR file access                                                                        */
/*                                                                                          */
/*  GUEST_REGISTERS is laid out in architectural GPR order (enum GPR_INDEX: RAX=0..R15=15), */
/*  pinned by the C_ASSERT in hv.h. Index 4 (GPR_RSP) is the rsp_dummy placeholder -- the   */
/*  live guest RSP lives in the VMCS, so it is read/written there instead. This lets the    */
/*  CR-access and MOV-DR qualification decoders address any GPR uniformly.                  */
/* -------------------------------------------------------------------------------------- */
static u64 vmexit_read_gpr(GUEST_REGISTERS *regs, u32 idx)
{
    if (idx == GPR_RSP) {
        return vmcs_read(VMCS_GUEST_RSP);
    }
    return ((u64 *)regs)[idx & 0xF];
}

static void vmexit_write_gpr(GUEST_REGISTERS *regs, u32 idx, u64 value)
{
    if (idx == GPR_RSP) {
        (void)vmcs_write(VMCS_GUEST_RSP, value);
        return;
    }
    ((u64 *)regs)[idx & 0xF] = value;
}

/* -------------------------------------------------------------------------------------- */
/*  Shared: advance guest RIP past a consumed instruction (SDM Vol 3C 27.2.4)               */
/*                                                                                          */
/*  Handlers that fully emulate the faulting instruction (CPUID, RDMSR/WRMSR, MOV CR, ...)  */
/*  MUST advance RIP by the VM-exit instruction length. Handlers that inject a fault, or    */
/*  that arrange for the instruction to re-execute (EPT violations), MUST NOT.               */
/*                                                                                          */
/*  Advancing also clears the STI / MOV-SS interrupt shadow: once the blocking instruction  */
/*  is retired, a pending event must no longer be held (SDM Vol 3C 25.4.2, Table 25-3).     */
/* -------------------------------------------------------------------------------------- */
void vmexit_advance_rip(VCPU *vcpu)
{
    u64 rip = vmcs_read(VMCS_GUEST_RIP);
    u64 len = vmcs_read(VMCS_RO_EXIT_INSTR_LEN);
    u64 interruptibility;

    rip += len;
    (void)vmcs_write(VMCS_GUEST_RIP, rip);

    interruptibility = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY_STATE);
    interruptibility &= ~(u64)(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS);
    (void)vmcs_write(VMCS_GUEST_INTERRUPTIBILITY_STATE, interruptibility);

    vcpu->guest_rip = rip;
}

/* -------------------------------------------------------------------------------------- */
/*  Shared: inject an event on the next VM-entry (SDM Vol 3C 25.8.3)                         */
/*                                                                                          */
/*  Builds the VM-entry interruption-information field: vector, the interruption type, the   */
/*  deliver-error-code bit when requested, and the valid bit. For the software-delivered     */
/*  types -- software interrupt (4, INT n), privileged software exception (5, INT1/ICEBP),   */
/*  and software exception (6, INT3/INTO) -- 25.8.3 REQUIRES the VM-entry instruction-length  */
/*  field so the CPU pushes the correct trap return RIP; hardware exceptions (3) and NMI (2)  */
/*  ignore it. Faults/traps are reported relative to the offending instruction, so callers    */
/*  must NOT also advance RIP.                                                                */
/* -------------------------------------------------------------------------------------- */
void vmexit_inject_interruption(VCPU *vcpu, u8 vector, u32 intr_type,
                                int has_errcode, u32 errcode)
{
    u32 intr_info = (u32)vector
                  | ((intr_type & 0x7u) << VMENTRY_INTR_INFO_TYPE_SHIFT)
                  | (u32)VMENTRY_INTR_INFO_VALID;

    if (has_errcode) {
        intr_info |= (u32)VMENTRY_INTR_INFO_DELIVER_ERRCODE;
        (void)vmcs_write(VMCS_CTRL_VMENTRY_EXCEPTION_ERRCODE, errcode);
    }

    /* Software-delivered vectors carry an instruction length; source it from this exit's
     * VM-exit instruction-length field, which the CPU populates for INT n / INT3 / INTO /
     * INT1 exits (SDM Vol 3C 27.2.4). Without it VM-entry pushes a wrong RIP or fails. */
    if (intr_type == VMENTRY_INTR_TYPE_SW_INTERRUPT ||
        intr_type == VMENTRY_INTR_TYPE_PRIV_SW_EXCEPT ||
        intr_type == VMENTRY_INTR_TYPE_SW_EXCEPTION) {
        (void)vmcs_write(VMCS_CTRL_VMENTRY_INSTR_LEN, vmcs_read(VMCS_RO_EXIT_INSTR_LEN));
    }

    (void)vmcs_write(VMCS_CTRL_VMENTRY_INTR_INFO, intr_info);

    /* TODO(hv): if #PF (vector 14) is ever injected, VMCS_GUEST_CR2 must also be loaded with
     * the faulting linear address before entry. */
    (void)vcpu;
}

/* Convenience wrapper for the common case: a hardware exception (#UD/#GP/#PF...) synthesized
 * by the HV itself (VMCALL #UD, guarded-MSR #GP). Hardware exceptions use interruption type 3
 * and take no instruction length. */
void vmexit_inject_exception(VCPU *vcpu, u8 vector, int has_errcode, u32 errcode)
{
    vmexit_inject_interruption(vcpu, vector, VMENTRY_INTR_TYPE_HW_EXCEPTION,
                               has_errcode, errcode);
}

/* -------------------------------------------------------------------------------------- */
/*  CPUID (SDM Vol 2A) -- pass through, but hide the hypervisor-present bit and answer the   */
/*  synthetic hypervisor vendor leaf.                                                       */
/* -------------------------------------------------------------------------------------- */
void vmexit_handle_cpuid(VCPU *vcpu, GUEST_REGISTERS *regs)
{
    int   cpu_info[4];
    u32   leaf    = (u32)regs->rax;
    u32   subleaf = (u32)regs->rcx;
    u32   eax, ebx, ecx, edx;

    __cpuidex(cpu_info, (int)leaf, (int)subleaf);
    eax = (u32)cpu_info[0];
    ebx = (u32)cpu_info[1];
    ecx = (u32)cpu_info[2];
    edx = (u32)cpu_info[3];

    if (leaf == CPUID_LEAF_FEATURES) {
        /* Bit 31 of ECX is the software "a hypervisor is present" convention; strip it so a
         * detection-aware sample sees a bare-metal-looking CPU. Hardware leaves it 0, so this
         * is defensive against a nesting parent that set it. */
        ecx &= ~(u32)CPUID_1_ECX_HYPERVISOR;
    } else if (leaf == CPUID_LEAF_ALETHEIA_PRESENT &&
               (u32)regs->rdx == CPUID_ALETHEIA_MAGIC_EDX) {
        /* Our own control-plane leaf, gated behind an out-of-band knock (EDX == magic).
         * A hostile guest is by definition NOT well-behaved: a detection-aware sample
         * probes CPUID.0x40000000 unconditionally, so we must NOT reveal the "AletheiaHV"
         * vendor id on a blind probe -- that would defeat the transparency stripping
         * CPUID.1:ECX[31] is meant to provide. Only our agent, which loads EDX with the
         * magic first, sees the synthetic response; every other caller falls through to
         * the passthrough result below and reads bare-metal. */
        eax = CPUID_HV_VENDOR_MAX_LEAF;
        ebx = CPUID_HV_VENDOR_EBX;
        ecx = CPUID_HV_VENDOR_ECX;
        edx = CPUID_HV_VENDOR_EDX;
    }

    /* CPUID in 64-bit mode writes 32-bit results and zero-extends into the full RAX/RBX/RCX/
     * RDX (SDM Vol 2A CPUID). Assigning u32 -> u64 zero-extends, matching that. */
    regs->rax = eax;
    regs->rbx = ebx;
    regs->rcx = ecx;
    regs->rdx = edx;

    vmi_log_event(vcpu, HV_EVENT_CPUID, 0, 0, leaf, subleaf);
    vmexit_advance_rip(vcpu);
}

/* -------------------------------------------------------------------------------------- */
/*  EPT violation (SDM Vol 3C 29.3.3.2, exit qualification Table 29-7)                       */
/*                                                                                          */
/*  Decode the faulting access, hand it to the vmi.c write-then-execute state machine (which */
/*  remaps the page's R/W/X permissions), flush the EPT TLB, and resume WITHOUT advancing    */
/*  RIP so the faulting instruction re-executes against the new permissions.                 */
/* -------------------------------------------------------------------------------------- */
void vmexit_handle_ept_violation(VCPU *vcpu, GUEST_REGISTERS *regs)
{
    EPT_VIOLATION_INFO info;
    int retry;

    vmi_decode_ept_violation(vcpu, &info);

    /* vmi_on_ept_violation flips EPT_PTE R/W/X to catch the complementary access and emits the
     * HV_EVENT_EPT_WRITE / HV_EVENT_EPT_EXEC records. It performs the page REMAP; we own the
     * INVEPT so the CPU's cached EPT translations pick up the new permissions. */
    retry = vmi_on_ept_violation(vcpu, &info);
    ept_invalidate(vcpu);

    /* No RIP advance: an EPT violation faults BEFORE the access completes, so re-running the
     * same instruction is exactly the retry we want. */
    (void)regs;
    (void)retry;
    /* TODO(hv): retry==0 signals a violation on a page vmi.c does not consider watched (should
     * not happen on a complete identity map). Resuming re-faults into an infinite loop. Decide
     * the policy: rebuild/relax the offending PTE to EPT_ACCESS_RWX and log, or bugcheck. */
}

/* -------------------------------------------------------------------------------------- */
/*  EPT misconfiguration (SDM Vol 3C 29.3.3.1)                                               */
/*                                                                                          */
/*  A malformed EPT paging-structure entry (bad memory type, reserved bit set, X-without-R   */
/*  where exec-only is unsupported, ...). This is a hypervisor bug, not a guest event.       */
/* -------------------------------------------------------------------------------------- */
void vmexit_handle_ept_misconfig(VCPU *vcpu, GUEST_REGISTERS *regs)
{
    u64 gpa = vmcs_read(VMCS_RO_GUEST_PHYSICAL_ADDR);

    vmi_log_event(vcpu, HV_EVENT_NONE, gpa, 0, EXIT_REASON_EPT_MISCONFIG, 0);
    (void)regs;

    /* TODO(hv): the machine cannot safely continue -- the EPT tables built in ept.c are wrong.
     * A production build must KeBugCheckEx here (or devirtualize this CPU) rather than resume,
     * which would immediately re-fault. Left as a logged no-op so a lab bring-up can inspect
     * VMCS_RO_GUEST_PHYSICAL_ADDR. */
}

/* -------------------------------------------------------------------------------------- */
/*  CR access (SDM Vol 3C exit qualification Table 28-3)                                     */
/* -------------------------------------------------------------------------------------- */
void vmexit_handle_cr_access(VCPU *vcpu, GUEST_REGISTERS *regs)
{
    u64 qual = vmcs_read(VMCS_RO_EXIT_QUALIFICATION);
    u32 cr    = (u32)(qual & CR_ACCESS_CR_NUMBER_MASK);
    u32 type  = (u32)((qual & CR_ACCESS_TYPE_MASK) >> CR_ACCESS_TYPE_SHIFT);
    u32 gpr   = (u32)((qual & CR_ACCESS_GPR_MASK) >> CR_ACCESS_GPR_SHIFT);

    switch (type) {
    case CR_ACCESS_TYPE_MOV_TO_CR: {
        u64 value = vmexit_read_gpr(regs, gpr);
        switch (cr) {
        case 0:
            /* Emulate: store into the guest CR0 and keep the read shadow in sync so a later
             * MOV-from-CR0 (or the guest's own view) reflects what it wrote.
             * TODO(hv): re-apply the CR0 FIXED0/FIXED1 constraints (vmx_adjust_cr0) so we never
             * install a CR0 that violates VMX operation and triggers VM-entry failure. */
            (void)vmcs_write(VMCS_GUEST_CR0, value);
            (void)vmcs_write(VMCS_CTRL_CR0_READ_SHADOW, value);
            vmi_log_event(vcpu, HV_EVENT_CR_WRITE, 0, 0, 0, value);
            break;
        case 3:
            /* A MOV to CR3 is the classic address-space-switch signal the VMI layer wants.
             * Bit 63 (when CR4.PCIDE) means "do not flush"; it is not part of the stored CR3,
             * so mask it out of the value we install. */
            (void)vmcs_write(VMCS_GUEST_CR3, value & ~BIT(63));
            vmi_log_event(vcpu, HV_EVENT_CR_WRITE, 0, 0, 3, value);
            break;
        case 4:
            /* TODO(hv): re-apply CR4 FIXED0/FIXED1 (vmx_adjust_cr4); CR4.VMXE must remain set
             * for VMX operation regardless of what the guest writes. */
            (void)vmcs_write(VMCS_GUEST_CR4, value);
            (void)vmcs_write(VMCS_CTRL_CR4_READ_SHADOW, value);
            vmi_log_event(vcpu, HV_EVENT_CR_WRITE, 0, 0, 4, value);
            break;
        case 8:
            /* CR8 == APIC TPR. TODO(hv): mirror into the virtual-APIC page / TPR shadow; a
             * bare guest CR8 write has no VMCS field. Logged and ignored for now. */
            vmi_log_event(vcpu, HV_EVENT_CR_WRITE, 0, 0, 8, value);
            break;
        default:
            /* TODO(hv): unexpected CR index -- the guest/host masks should only route CR0/3/4/8
             * here. Ignore. */
            break;
        }
        break;
    }
    case CR_ACCESS_TYPE_MOV_FROM_CR: {
        u64 value = 0;
        switch (cr) {
        case 0: value = vmcs_read(VMCS_GUEST_CR0); break;
        case 3: value = vmcs_read(VMCS_GUEST_CR3); break;
        case 4: value = vmcs_read(VMCS_GUEST_CR4); break;
        case 8:
            /* TODO(hv): read the virtualized TPR. Returning 0 is a placeholder. */
            value = 0;
            break;
        default: break;
        }
        vmexit_write_gpr(regs, gpr, value);
        break;
    }
    case CR_ACCESS_TYPE_CLTS: {
        /* CLTS clears CR0.TS only. */
        u64 cr0 = vmcs_read(VMCS_GUEST_CR0) & ~(u64)CR0_TS;
        (void)vmcs_write(VMCS_GUEST_CR0, cr0);
        (void)vmcs_write(VMCS_CTRL_CR0_READ_SHADOW, cr0);
        break;
    }
    case CR_ACCESS_TYPE_LMSW: {
        /* LMSW writes CR0 bits 3:0 (PE,MP,EM,TS) from the source operand's low 4 bits but can
         * never CLEAR CR0.PE (SDM Vol 2B LMSW). The 16-bit source is in the qualification. */
        u64 src  = (qual >> CR_ACCESS_LMSW_SOURCE_SHIFT) & 0xFFFFu;
        u64 cr0  = vmcs_read(VMCS_GUEST_CR0);
        u64 low  = src & 0xFu;
        if (cr0 & CR0_PE) {
            low |= CR0_PE;   /* protected mode cannot be left via LMSW. */
        }
        cr0 = (cr0 & ~0xFull) | low;
        (void)vmcs_write(VMCS_GUEST_CR0, cr0);
        (void)vmcs_write(VMCS_CTRL_CR0_READ_SHADOW, cr0);
        break;
    }
    default:
        break;
    }

    vmexit_advance_rip(vcpu);
}

/* -------------------------------------------------------------------------------------- */
/*  Helper: is this a read-only architectural VMX MSR (WRMSR must #GP)?                      */
/*  Covers IA32_VMX_BASIC (0x480) .. IA32_VMX_PROCBASED_CTLS3 (0x492), the block defined in  */
/*  arch.h from SDM Vol 3D Appendix A.                                                       */
/* -------------------------------------------------------------------------------------- */
static int vmexit_is_vmx_capability_msr(u32 index)
{
    return (index >= IA32_VMX_BASIC) && (index <= IA32_VMX_PROCBASED_CTLS3);
}

/* -------------------------------------------------------------------------------------- */
/*  RDMSR (SDM Vol 2B)                                                                       */
/*                                                                                          */
/*  Only entered for MSRs the MSR bitmap traps (vmcs.c). Reads are allowed to succeed -- an  */
/*  analyst legitimately probes the VMX/feature MSRs -- but flow through this single choke    */
/*  point so a future stealth policy can spoof them.                                         */
/* -------------------------------------------------------------------------------------- */
void vmexit_handle_msr_read(VCPU *vcpu, GUEST_REGISTERS *regs)
{
    u32 index = (u32)regs->rcx;
    u64 value;

    /* TODO(hv): to hide the hypervisor, spoof IA32_FEATURE_CONTROL (report LOCK set, VMXON
     * disabled) and optionally zero the VMX capability MSRs here. Currently a transparent
     * pass-through. */
    value = __readmsr(index);

    /* TODO(hv): a hostile guest can RDMSR a reserved index to #GP the HOST. Because this path
     * only runs for MSRs we chose to trap in the bitmap, the exposure is bounded, but a robust
     * build should validate `index` (or wrap __readmsr) and inject #GP into the guest instead
     * of faulting root operation. */

    /* RDMSR returns the 64-bit value in EDX:EAX, zero-extended into RDX:RAX (SDM Vol 2B). */
    regs->rax = (u32)value;
    regs->rdx = (u32)(value >> 32);

    vmexit_advance_rip(vcpu);
}

/* -------------------------------------------------------------------------------------- */
/*  WRMSR (SDM Vol 2B)                                                                       */
/*                                                                                          */
/*  Guards IA32_FEATURE_CONTROL and the read-only VMX capability MSRs (a real WRMSR to these  */
/*  #GPs). Mirrors context-switched MSRs into their VMCS guest fields instead of writing the  */
/*  physical MSR (which would corrupt host state after VMRESUME).                            */
/* -------------------------------------------------------------------------------------- */
void vmexit_handle_msr_write(VCPU *vcpu, GUEST_REGISTERS *regs)
{
    u32 index = (u32)regs->rcx;
    u64 value = ((u64)(u32)regs->rdx << 32) | (u64)(u32)regs->rax;

    /* IA32_FEATURE_CONTROL is locked once VMXON is enabled; the VMX capability MSRs are
     * architecturally read-only. A WRMSR to any of them raises #GP(0) on real hardware --
     * reflect that to the guest and swallow the write (no RIP advance). */
    if (index == IA32_FEATURE_CONTROL || vmexit_is_vmx_capability_msr(index)) {
        vmexit_inject_exception(vcpu, VECTOR_GP, 1, 0);
        return;
    }

    switch (index) {
    case IA32_EFER:
        /* EFER is reloaded from VMCS_GUEST_EFER on VM-entry (entry ctrl LOAD_EFER). Writing the
         * physical MSR here would clobber HOST EFER, so mirror into the guest field only.
         * TODO(hv): recompute the ENTRY_CTL_IA32E_MODE_GUEST bit if the guest toggles EFER.LME,
         * and keep VMCS_GUEST_CR0.PG / IA32e-mode consistency. */
        (void)vmcs_write(VMCS_GUEST_EFER, value);
        break;

    /* TODO(hv): IA32_PAT, IA32_SYSENTER_CS/ESP/EIP, IA32_FS_BASE, IA32_GS_BASE all have VMCS
     * guest fields. If their MSR-bitmap bits are ever set to trap, mirror them into the VMCS
     * guest field here instead of __writemsr, for the same host-corruption reason as EFER. */

    default:
        /* Not a context-switched or guarded MSR: apply to hardware. Only reached for MSRs we
         * explicitly chose to trap. */
        __writemsr(index, value);
        break;
    }

    vmi_log_event(vcpu, HV_EVENT_MSR_WRITE, 0, 0, index, value);
    vmexit_advance_rip(vcpu);
}

/* -------------------------------------------------------------------------------------- */
/*  XSETBV (SDM Vol 2C)                                                                      */
/*                                                                                          */
/*  XSETBV always causes a VM exit in non-root. Emulate by executing it in root with the      */
/*  guest-supplied ECX/EDX:EAX, then advance.                                                */
/* -------------------------------------------------------------------------------------- */
void vmexit_handle_xsetbv(VCPU *vcpu, GUEST_REGISTERS *regs)
{
    u32 index = (u32)regs->rcx;
    u64 value = ((u64)(u32)regs->rdx << 32) | (u64)(u32)regs->rax;

    /* TODO(hv): a bad XCR0 (ECX!=0, bit0 clear, reserved/unsupported bits set, illegal
     * AVX/AVX-512 combos) #GPs. Executing it unvalidated faults the HOST. Validate against
     * CPUID.(EAX=0Dh) and CR4.OSXSAVE, and inject #GP into the guest on any violation instead
     * of performing it. Also confirm CR4.OSXSAVE is set in the guest before allowing it. */
    _xsetbv(index, value);

    vmexit_advance_rip(vcpu);
}

/* -------------------------------------------------------------------------------------- */
/*  Exception / NMI (SDM Vol 3C 27.2.2, exit interruption info)                              */
/*                                                                                          */
/*  Reached only for vectors set in the exception bitmap, or for NMI when pin-based           */
/*  NMI-exiting is enabled. Default policy: log for instrumentation and re-inject guest        */
/*  hardware exceptions so the guest's own handlers still run.                                */
/* -------------------------------------------------------------------------------------- */
void vmexit_handle_exception_nmi(VCPU *vcpu, GUEST_REGISTERS *regs)
{
    u64 intr_info = vmcs_read(VMCS_RO_EXIT_INTR_INFO);
    u32 vector = (u32)(intr_info & VMEXIT_INTR_INFO_VECTOR_MASK);
    u32 type   = (u32)((intr_info & VMEXIT_INTR_INFO_TYPE_MASK) >> VMEXIT_INTR_INFO_TYPE_SHIFT);

    (void)regs;
    vmi_log_event(vcpu, HV_EVENT_EXCEPTION, 0, 0, vector, intr_info);

    /* TODO(hv): NMIs (type == VMENTRY_INTR_TYPE_NMI) must be HELD/handled by the host, not
     * reflected -- if pin-based NMI-exiting or virtual-NMIs are enabled, service the NMI and
     * manage NMI-blocking state (VMCS_GUEST_INTERRUPTIBILITY_STATE bit 3) rather than injecting.
     * External interrupts (type 0) are likewise not reflected here. */
    if (intr_info & VMEXIT_INTR_INFO_VALID) {
        /* Reflect the whole exception class so the guest's own handlers still run, preserving
         * the SAME interruption type as the exit (SDM Vol 3C Table 27-1 / 25.8.3):
         *   - hardware exception (3): #UD/#GP/#PF and, when the exception bitmap arms it for
         *     instrumentation, a #BP delivered as a fault-class event;
         *   - software exception (6): INT3 (#BP) and INTO (#OF);
         *   - privileged software exception (5): INT1 / ICEBP (#DB).
         * Types 5/6 REQUIRE the VM-entry instruction length, which vmexit_inject_interruption
         * sets from VMCS_RO_EXIT_INSTR_LEN -- without which the guest would resume ON the INT3
         * and re-execute it forever. */
        if (type == VMENTRY_INTR_TYPE_HW_EXCEPTION ||
            type == VMENTRY_INTR_TYPE_SW_EXCEPTION ||
            type == VMENTRY_INTR_TYPE_PRIV_SW_EXCEPT) {
            int has_err = (intr_info & VMEXIT_INTR_INFO_ERRCODE_VALID) ? 1 : 0;
            u32 err = has_err ? (u32)vmcs_read(VMCS_RO_EXIT_INTR_ERRCODE) : 0;
            /* TODO(hv): a #PF (vector 14) also needs VMCS_GUEST_CR2 loaded with the faulting
             * linear address (from the exit qualification) before re-injection. */
            vmexit_inject_interruption(vcpu, (u8)vector, type, has_err, err);
        }
    }
    /* No RIP advance: the injected event is reported relative to the offending instruction, and
     * for software exceptions the pushed RIP is derived from the VM-entry instruction length. */
}

/* -------------------------------------------------------------------------------------- */
/*  VMCALL (SDM Vol 3C) -- Aletheia hypercall control plane                                  */
/*                                                                                          */
/*  ABI (DRAFT -- see hv.h TODO): RAX = HV_VMCALL_MAGIC, RCX = service number, RDX = arg0,   */
/*  result returned in RAX. Any VMCALL whose RAX is not our magic is not ours: report it as   */
/*  an unsupported instruction with #UD, exactly as a bare CPU would for VMCALL outside VMX.  */
/* -------------------------------------------------------------------------------------- */
void vmexit_handle_vmcall(VCPU *vcpu, GUEST_REGISTERS *regs)
{
    u64 magic   = regs->rax;
    u64 service = regs->rcx;
    u64 arg0    = regs->rdx;

    if (magic != HV_VMCALL_MAGIC) {
        /* Not our hypercall -- behave like a non-root VMCALL on bare metal: #UD, no advance. */
        vmexit_inject_exception(vcpu, VECTOR_UD, 0, 0);
        return;
    }

    vmi_log_event(vcpu, HV_EVENT_VMCALL, 0, 0, service, arg0);

    switch (service) {
    case HV_VMCALL_PING:
        regs->rax = (u64)HV_OK;
        break;

    case HV_VMCALL_UNLOAD:
        /* Latch the orderly-teardown request; the dispatcher returns 0 so the asm trampoline
         * takes the unload path for this VCPU. */
        _InterlockedExchange(&g_vmexit_unload_requested, 1);
        regs->rax = (u64)HV_OK;
        break;

    case HV_VMCALL_WATCH_GPA:
        regs->rax = (u64)ept_watch_page(vcpu, arg0);
        break;

    case HV_VMCALL_UNWATCH_GPA:
        regs->rax = (u64)ept_unwatch_page(vcpu, arg0);
        break;

    case HV_VMCALL_DRAIN_EVENTS:
        /* TODO(hv): copy event-log records into a guest buffer. Needs the guest destination
         * pointer/length (RDX/R8?) and a GVA->GPA walk via vmi_read/write_guest_virtual, plus a
         * locked ABI. Report unsupported for now. */
        regs->rax = (u64)HV_ERR_INVALID_ARG;
        break;

    default:
        regs->rax = (u64)HV_ERR_INVALID_ARG;
        break;
    }

    vmexit_advance_rip(vcpu);
}

/* -------------------------------------------------------------------------------------- */
/*  VMX instructions from the guest (SDM Vol 3C) -- we do not support nested virtualization. */
/*                                                                                          */
/*  VMCLEAR/VMLAUNCH/VMPTRLD/VMPTRST/VMREAD/VMRESUME/VMWRITE/VMXOFF/VMXON/INVEPT/INVVPID/    */
/*  VMFUNC. Report unsupported by injecting #UD -- CR4.VMXE is (deliberately) forced on for   */
/*  the guest, so it would not otherwise #UD on its own; #UD is the clean "not available"     */
/*  signal that also hides that a hypervisor is what refused it.                             */
/* -------------------------------------------------------------------------------------- */
void vmexit_handle_vmx_instruction(VCPU *vcpu, GUEST_REGISTERS *regs)
{
    (void)regs;
    vmexit_inject_exception(vcpu, VECTOR_UD, 0, 0);
    /* No RIP advance: #UD is reported at the faulting instruction. */
}

/* -------------------------------------------------------------------------------------- */
/*  The dispatcher                                                                          */
/*                                                                                          */
/*  Called by asm_vmexit_entry with the saved guest GPR frame. Returns nonzero to VMRESUME,  */
/*  zero to request an orderly per-VCPU teardown (guest asked to unload).                     */
/* -------------------------------------------------------------------------------------- */
int hv_vmexit_dispatch(GUEST_REGISTERS *regs)
{
    VCPU *vcpu = hv_current_vcpu();
    u64   exit_reason_full;
    u32   reason;

    /* TODO(hv): if vcpu is NULL the host-stack back-pointer set up in vmcs_setup_host is wrong;
     * there is no safe recovery inside a VM exit. A checked build should bugcheck. */

    exit_reason_full = vmcs_read(VMCS_RO_EXIT_REASON);
    reason = (u32)(exit_reason_full & EXIT_REASON_BASIC_MASK);

    /* Cache the guest register-file-adjacent state every handler may want. GPRs are in `regs`;
     * RSP/RIP/RFLAGS live in the VMCS. */
    vcpu->guest_rip    = vmcs_read(VMCS_GUEST_RIP);
    vcpu->guest_rsp    = vmcs_read(VMCS_GUEST_RSP);
    vcpu->guest_rflags = vmcs_read(VMCS_GUEST_RFLAGS);

    /* Bit 31 set => this "exit" is actually a VM-ENTRY failure (SDM Vol 3C Table 25-19). The
     * basic reason then names the failure class (invalid guest state / MSR load / MCE). */
    if (exit_reason_full & EXIT_REASON_FLAG_VMENTRY_FAIL) {
        /* TODO(hv): fatal. Capture VMCS_RO_VM_INSTRUCTION_ERROR + guest-state fields for the
         * bring-up log and devirtualize; resuming just re-fails the entry. */
        vmi_log_event(vcpu, HV_EVENT_NONE, 0, 0, reason, exit_reason_full);
        return 1;
    }

    switch (reason) {
    case EXIT_REASON_CPUID:
        vmexit_handle_cpuid(vcpu, regs);
        break;

    case EXIT_REASON_EPT_VIOLATION:
        vmexit_handle_ept_violation(vcpu, regs);
        break;

    case EXIT_REASON_EPT_MISCONFIG:
        vmexit_handle_ept_misconfig(vcpu, regs);
        break;

    case EXIT_REASON_CR_ACCESS:
        vmexit_handle_cr_access(vcpu, regs);
        break;

    case EXIT_REASON_RDMSR:
        vmexit_handle_msr_read(vcpu, regs);
        break;

    case EXIT_REASON_WRMSR:
        vmexit_handle_msr_write(vcpu, regs);
        break;

    case EXIT_REASON_XSETBV:
        vmexit_handle_xsetbv(vcpu, regs);
        break;

    case EXIT_REASON_INVD:
        /* INVD invalidates caches WITHOUT writeback -- it can silently drop dirty lines and
         * corrupt memory. Emulate with WBINVD (writeback + invalidate), the standard safe
         * substitution. INVD always exits in non-root, so we always land here. */
        __wbinvd();
        vmexit_advance_rip(vcpu);
        break;

    case EXIT_REASON_WBINVD:
        /* Only reached if PROC2_CTL_WBINVD_EXITING was enabled. Perform it and advance. */
        __wbinvd();
        vmexit_advance_rip(vcpu);
        break;

    case EXIT_REASON_VMCALL:
        vmexit_handle_vmcall(vcpu, regs);
        break;

    case EXIT_REASON_EXCEPTION_NMI:
        vmexit_handle_exception_nmi(vcpu, regs);
        break;

    /* Guest attempted a VMX instruction -- we expose no nested virtualization. */
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
    case EXIT_REASON_INVEPT:
    case EXIT_REASON_INVVPID:
    case EXIT_REASON_VMFUNC:
        vmexit_handle_vmx_instruction(vcpu, regs);
        break;

    default:
        /* We enable only the controls that produce the exits handled above, plus the always-
         * exiting instructions (CPUID, INVD, XSETBV, VMCALL, VMX-family). Anything else means a
         * control bit we set without a handler, or an unconditional exit (e.g. TRIPLE_FAULT,
         * INIT, SIPI) we have not wired.
         * TODO(hv): TRIPLE_FAULT and a VM-entry-failure MCE are fatal; INIT/SIPI need real
         * handling for AP bring-up. Logging and resuming without advancing RIP is a stopgap and
         * can loop for a fault-class exit. */
        vmi_log_event(vcpu, HV_EVENT_NONE, 0, 0, reason, exit_reason_full);
        break;
    }

    if (_InterlockedCompareExchange(&g_vmexit_unload_requested, 0, 0) != 0) {
        return 0;   /* orderly teardown requested via HV_VMCALL_UNLOAD. */
    }
    return 1;       /* resume the guest. */
}

/* ======================================================================================== */
/*                                                                                          */
/*  AMD SVM VM-exit dispatcher + per-reason handlers                                        */
/*                                                                                          */
/*  Peer of the Intel dispatcher above. Vendor-neutral policy (VMI, unpacker) lives one     */
/*  layer higher: both EPT violations and NPT faults call vmi_on_page_fault(gpa, kind).     */
/*                                                                                          */
/*  Provenance: written from AMD APM Vol 2 -- VMEXIT codes §15.9 Table 15-9; NPF/MSR/IOIO   */
/*  EXITINFO decoders §15.10; NRIP save §15.14.6. No proprietary source consulted.          */
/*                                                                                          */
/* ======================================================================================== */

void svm_decode_exit(VCPU *vcpu, SVM_EXIT_INFO *out)
{
    VMCB_CONTROL_AREA *c;
    if (vcpu == NULL || vcpu->vmcb == NULL || out == NULL) return;
    c = &vcpu->vmcb->control;
    out->exit_code = c->exit_code;
    out->info1     = c->exit_info_1;
    out->info2     = c->exit_info_2;
    out->intinfo   = c->exit_intinfo;
    out->nrip      = c->nrip;
    out->insn_len  = c->guest_insn_len;
    RtlCopyMemory(out->insn_bytes, c->guest_insn_bytes, sizeof(out->insn_bytes));
}

/* NPF exit-info decoders per APM §15.25.5: EXITINFO2 = faulting GPA, EXITINFO1 = flags. */
void svm_decode_npf(const SVM_EXIT_INFO *in, NPF_INFO *out)
{
    if (in == NULL || out == NULL) return;
    RtlZeroMemory(out, sizeof(*out));
    out->gpa      = in->info2;
    out->flags    = (u32)in->info1;
    out->is_write = (u8)((in->info1 & SVM_EXITINFO1_NPF_RW) != 0);
    out->is_exec  = (u8)((in->info1 & SVM_EXITINFO1_NPF_ID) != 0);
}

/*
 * APM §15.14.6: on parts with the NRIPS feature, VMCB.control.nrip is the next sequential
 * guest RIP -- authoritative. Fall back to guest_insn_len (Decode Assist). Last resort left
 * as a TODO(hv); every AMD part built this decade carries NRIPS.
 */
void svm_advance_rip(VCPU *vcpu)
{
    VMCB_STATE_SAVE_AREA *g;
    VMCB_CONTROL_AREA    *c;
    if (vcpu == NULL || vcpu->vmcb == NULL) return;
    g = &vcpu->vmcb->state_save;
    c = &vcpu->vmcb->control;

    if (g_hv.svm_caps.nrips && c->nrip != 0)
        g->rip = c->nrip;
    else if (c->guest_insn_len != 0)
        g->rip += c->guest_insn_len;
    /* else TODO(hv): last-resort length disassembler. */
}

/*
 * CPUID -- forward the guest's request, then mask off CPUID.80000001h:ECX[2] so a guest's
 * capability probe does not report our AMD-V presence back to it.
 */
void svm_handle_cpuid(VCPU *vcpu, GUEST_REGISTERS *regs)
{
    int r[4];
    u32 leaf, sub;
    if (vcpu == NULL || regs == NULL) return;

    leaf = (u32)vcpu->vmcb->state_save.rax;
    sub  = (u32)regs->rcx;
    __cpuidex(r, (int)leaf, (int)sub);

    if (leaf == CPUID_FN_EXT_FEATURES)
        r[2] &= ~CPUID_EXT_FEATURES_ECX_SVM;

    vcpu->vmcb->state_save.rax = (u32)r[0];
    regs->rbx                  = (u32)r[1];
    regs->rcx                  = (u32)r[2];
    regs->rdx                  = (u32)r[3];

    svm_advance_rip(vcpu);
    vmi_log_event(vcpu, HV_EVENT_CPUID, 0, 0, leaf, sub);
}

/*
 * Nested-page fault -- the whole reason the AMD backend exists. Hand the faulting GPA and
 * access kind (0=read, 1=write, 2=exec) to the vendor-neutral vmi_on_page_fault seam. Do NOT
 * advance RIP: retrying re-executes the faulting instruction under the new permission triple.
 */
void svm_handle_npf(VCPU *vcpu, GUEST_REGISTERS *regs)
{
    SVM_EXIT_INFO ei;
    NPF_INFO npf;
    u32 kind;
    int allow_retry;

    UNREFERENCED_PARAMETER(regs);

    svm_decode_exit(vcpu, &ei);
    svm_decode_npf(&ei, &npf);

    kind = npf.is_exec ? 2u : (npf.is_write ? 1u : 0u);
    allow_retry = vmi_on_page_fault(vcpu, npf.gpa, kind);

    if (!allow_retry) {
        /* TODO(hv): pass through as a real guest #PF (populate CR2 + error code from the
         * NPF flags before injecting). For now, log the diagnostic and resume. */
        vmi_log_event(vcpu, HV_EVENT_EPT_READ, npf.gpa, 0, ei.info1, 0);
    }
}

/* MSR read/write. Direction is EXITINFO1 bit 0; MSR index in ECX; value in EDX:EAX. */
static void svm_msr_common(VCPU *vcpu, GUEST_REGISTERS *regs, int write)
{
    u32 msr = (u32)regs->rcx;
    if (write) {
        u64 v = ((u64)(u32)regs->rdx << 32) | (u32)vcpu->vmcb->state_save.rax;
        if (msr == MSR_EFER) {
            v |= EFER_SVME;                   /* Refuse a guest attempt to clear SVME. */
            __writemsr(msr, v);
            vcpu->vmcb->state_save.efer = v;
        } else {
            __writemsr(msr, v);
        }
        vmi_log_event(vcpu, HV_EVENT_MSR_WRITE, 0, 0, msr, v);
    } else {
        u64 v = __readmsr(msr);
        vcpu->vmcb->state_save.rax = (u32)v;
        regs->rdx                  = (u32)(v >> 32);
        vmi_log_event(vcpu, HV_EVENT_MSR_WRITE, 0, 0, msr, v);   /* dir in aux */
    }
    svm_advance_rip(vcpu);
}

void svm_handle_msr_read (VCPU *vcpu, GUEST_REGISTERS *regs) { svm_msr_common(vcpu, regs, 0); }
void svm_handle_msr_write(VCPU *vcpu, GUEST_REGISTERS *regs) { svm_msr_common(vcpu, regs, 1); }

/*
 * VMMCALL -- Aletheia's guest-side hypercall (peer of Intel's VMCALL). ABI: RAX high 32b =
 * HV_VMCALL_MAGIC, low 32b = service; RCX/RDX/R8 = args; RAX = result. Anything else -> #UD.
 */
void svm_handle_vmmcall(VCPU *vcpu, GUEST_REGISTERS *regs)
{
    u64 rax = vcpu->vmcb->state_save.rax;
    u32 service;

    if ((rax >> 32) != (HV_VMCALL_MAGIC >> 32)) {
        vmexit_inject_exception(vcpu, 6 /* #UD */, 0, 0);
        return;
    }
    service = (u32)rax;

    switch (service) {
    case HV_VMCALL_PING:
        vcpu->vmcb->state_save.rax = HV_OK; break;
    case HV_VMCALL_UNLOAD:
        _InterlockedExchange(&g_vmexit_unload_requested, 1);
        vcpu->vmcb->state_save.rax = HV_OK; break;
    case HV_VMCALL_WATCH_GPA:
        vcpu->vmcb->state_save.rax = (u64)npt_watch_page(vcpu, regs->rcx); break;
    case HV_VMCALL_UNWATCH_GPA:
        vcpu->vmcb->state_save.rax = (u64)npt_unwatch_page(vcpu, regs->rcx); break;
    case HV_VMCALL_DRAIN_EVENTS:
        vcpu->vmcb->state_save.rax =
            (u64)vmi_drain_events((HV_EVENT *)regs->rcx, (u32)regs->rdx);
        break;
    default:
        vcpu->vmcb->state_save.rax = (u64)HV_ERR_INVALID_ARG; break;
    }
    vmi_log_event(vcpu, HV_EVENT_VMCALL, 0, 0, service, 0);
    svm_advance_rip(vcpu);
}

/* Intercepted exceptions (only fire when a bit in intercept_exceptions is set). */
void svm_handle_exception(VCPU *vcpu, GUEST_REGISTERS *regs)
{
    SVM_EXIT_INFO ei;
    UNREFERENCED_PARAMETER(regs);
    svm_decode_exit(vcpu, &ei);
    vmi_log_event(vcpu, HV_EVENT_EXCEPTION, 0, 0,
                  (u32)(ei.exit_code - SVM_EXIT_EXCP_BASE), ei.info1);
    vmexit_inject_exception(vcpu, (u8)(ei.exit_code - SVM_EXIT_EXCP_BASE), 0, 0);
}

/*
 * The AMD dispatcher. Called by asm_svm_vmexit_entry after saving GUEST_REGISTERS. Same
 * return contract as hv_vmexit_dispatch: nonzero = VMRUN again, zero = orderly unload.
 */
int hv_svm_vmexit_dispatch(GUEST_REGISTERS *regs)
{
    VCPU *vcpu = hv_current_vcpu();
    u64 code;

    if (vcpu == NULL || vcpu->vmcb == NULL)
        return 0;

    code = vcpu->vmcb->control.exit_code;

    if (code >= SVM_EXIT_EXCP_BASE && code <= (SVM_EXIT_EXCP_BASE + 31)) {
        svm_handle_exception(vcpu, regs);
        goto epilogue;
    }

    switch (code) {
    case SVM_EXIT_CPUID:      svm_handle_cpuid(vcpu, regs);   break;
    case SVM_EXIT_NPF:        svm_handle_npf(vcpu, regs);     break;
    case SVM_EXIT_MSR:
        if (vcpu->vmcb->control.exit_info_1 & SVM_EXITINFO1_MSR_WRITE)
            svm_handle_msr_write(vcpu, regs);
        else
            svm_handle_msr_read (vcpu, regs);
        break;
    case SVM_EXIT_VMMCALL:    svm_handle_vmmcall(vcpu, regs); break;

    /* Nested-SVM lockout -- refuse to let a guest run its own HV under us. */
    case SVM_EXIT_VMRUN:
    case SVM_EXIT_VMLOAD:
    case SVM_EXIT_VMSAVE:
    case SVM_EXIT_STGI:
    case SVM_EXIT_CLGI:
    case SVM_EXIT_SKINIT:
        vmexit_inject_exception(vcpu, 6 /* #UD */, 0, 0);
        break;

    /* EFER write trap -- keep SVME set even if the guest tries to clear it. */
    case SVM_EXIT_EFER_WRITE_TRAP: {
        u64 desired = vcpu->vmcb->state_save.efer | EFER_SVME;
        vcpu->vmcb->state_save.efer = desired;
        __writemsr(MSR_EFER, desired);
        vcpu->vmcb->control.vmcb_clean &= ~VMCB_CLEAN_CRX;
        break;
    }

    default:
        /* Intercepted without a handler, or an unconditional exit we have not wired.
         * Diagnostic-only path -- a fault-class exit here can loop. TODO(hv): expand. */
        vmi_log_event(vcpu, HV_EVENT_NONE, 0, 0, code, 0);
        break;
    }

epilogue:
    if (_InterlockedCompareExchange(&g_vmexit_unload_requested, 0, 0) != 0)
        return 0;
    return 1;
}
