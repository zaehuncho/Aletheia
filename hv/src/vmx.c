/*
 * vmx.c -- VMX lifecycle for the Aletheia clean-room VT-x/EPT VMI hypervisor.
 *
 * RESPONSIBILITY (per hv.h): detect VT-x, read/cache the VMX capability MSRs, adjust CR0/CR4
 * to the FIXED0/FIXED1 constraints, enable VMX (CR4.VMXE + IA32_FEATURE_CONTROL) and execute
 * VMXON/VMXOFF, plus the control-word and VMX-status/error reporting helpers everything else
 * in the tree consumes.
 *
 * CLEAN-ROOM PROVENANCE: written from the public Intel(R) SDM Vol 3C (Ch. 24 "Introduction to
 * Virtual Machine Extensions", Ch. 25 VMCS/controls, 31.2 conventions & error reporting) and
 * Vol 3D Appendix A (VMX capability-reporting MSRs). Cross-checked only against the public
 * open-source VMMs named in the headers (hvpp/SimpleVisor/Bareflank), which transcribe the same
 * public tables. No proprietary or anti-cheat source was consulted. Every SDM-derived constant
 * resolves through arch.h / vmx_defs.h -- there are no magic numbers below.
 *
 * CANNOT BE BUILT OR RUN IN THIS ENVIRONMENT. Unfinished/uncertain spots are marked
 * "// TODO(hv):". Correctness against the SDM is the whole game -- a wrong control bit hangs
 * the machine.
 */

#include "hv.h"

/* -------------------------------------------------------------------------------------- */
/*  Local logging. DbgPrintEx is safe at the IRQL levels this file runs at (bring-up runs   */
/*  via KeIpiGenericCall at IPI_LEVEL, where DbgPrintEx is still callable). Keep it terse.   */
/* -------------------------------------------------------------------------------------- */
#if DBG
#define HV_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[aletheia-vmx] " fmt "\n", __VA_ARGS__)
#else
#define HV_LOG(fmt, ...) ((void)0)
#endif

/* Split a 64-bit VMX capability MSR into its allowed-0 / allowed-1 halves (SDM Vol 3D A.3). */
#define VMX_MSR_ALLOWED0(v)     ((u32)((v) & 0xFFFFFFFFull))   /* low dword  : allowed-0 set. */
#define VMX_MSR_ALLOWED1(v)     ((u32)((v) >> 32))             /* high dword : allowed-1 set. */

/* ====================================================================================== */
/*  VMX-instruction status / error reporting                                               */
/* ====================================================================================== */

/* Human-readable tag for a VMX_RESULT (the three SDM outcomes of a VMX instruction:
 * VMsucceed, VMfailValid=ZF, VMfailInvalid=CF -- SDM Vol 3C 31.2). Used only for logging. */
static const char *vmx_result_str(VMX_RESULT r)
{
    switch (r) {
    case VMX_SUCCEED:      return "VMsucceed";
    case VMX_FAIL_VALID:   return "VMfailValid(ZF)";
    case VMX_FAIL_INVALID: return "VMfailInvalid(CF)";
    default:               return "VMX?";
    }
}

/*
 * Read the VM-instruction error number from the *currently loaded* VMCS
 * (VMCS_RO_VM_INSTRUCTION_ERROR, SDM Vol 3C Table 31-1). This is meaningful ONLY on a
 * VMfailValid (ZF=1) outcome AND only when a VMCS is active (VMPTRLD'd). VMXON/VMXOFF failures
 * are VMfailInvalid (CF=1) with no VMCS context, so callers must not consult this for them.
 *
 * Returns the error number, or 0 if there is no current VMCS / the VMREAD itself fails.
 * TODO(hv): the map of numbers -> text lives in vmx_defs.h (VMX_ERROR_*); a full decoder
 * belongs in vmcs.c where a VMCS is guaranteed loaded.
 */
u32 vmx_last_instruction_error(void)
{
    u64 err = 0;
    if (asm_vmread(VMCS_RO_VM_INSTRUCTION_ERROR, &err) != VMX_SUCCEED)
        return 0;   /* No current VMCS, or VMREAD unsupported -- nothing to report. */
    return (u32)err;
}

/* ====================================================================================== */
/*  Capability MSR reads                                                                    */
/* ====================================================================================== */

/*
 * Cache every VMX capability-reporting MSR this hypervisor consults (SDM Vol 3D Appendix A).
 * These values are architecturally identical across logical processors of the same package;
 * we still read them on the CPU that will run VMXON so a heterogeneous system can't surprise us.
 * TODO(hv): on a truly asymmetric system, compose controls per-CPU rather than trusting a
 * single cached snapshot.
 */
HV_STATUS vmx_read_capabilities(VMX_CAPABILITIES *caps_out)
{
    if (caps_out == NULL)
        return HV_ERR_INVALID_ARG;

    RtlZeroMemory(caps_out, sizeof(*caps_out));

    caps_out->basic       = __readmsr(IA32_VMX_BASIC);
    caps_out->pinbased    = __readmsr(IA32_VMX_PINBASED_CTLS);
    caps_out->procbased   = __readmsr(IA32_VMX_PROCBASED_CTLS);
    caps_out->exit_ctls   = __readmsr(IA32_VMX_EXIT_CTLS);
    caps_out->entry_ctls  = __readmsr(IA32_VMX_ENTRY_CTLS);
    caps_out->misc        = __readmsr(IA32_VMX_MISC);

    caps_out->cr0_fixed0  = __readmsr(IA32_VMX_CR0_FIXED0);
    caps_out->cr0_fixed1  = __readmsr(IA32_VMX_CR0_FIXED1);
    caps_out->cr4_fixed0  = __readmsr(IA32_VMX_CR4_FIXED0);
    caps_out->cr4_fixed1  = __readmsr(IA32_VMX_CR4_FIXED1);

    /* VMCS revision id = IA32_VMX_BASIC[30:0]. Bit 31 of the region's first dword must be 0,
     * so masking to the 31-bit revision guarantees a valid VMXON/VMCS stamp (SDM 25.11.5). */
    caps_out->vmcs_revision_id = (u32)(caps_out->basic & IA32_VMX_BASIC_REVISION_MASK);

    /* IA32_VMX_BASIC bit 55 => the "TRUE" capability MSRs exist and must be used to compute
     * controls (they report the genuinely-flexible bits; the non-TRUE MSRs can force default1
     * bits that a modern VMM wants to clear). SDM Vol 3D A.2 / A.3.1. */
    caps_out->has_true_ctls = (caps_out->basic & IA32_VMX_BASIC_TRUE_CTLS) ? 1 : 0;
    if (caps_out->has_true_ctls) {
        caps_out->true_pinbased  = __readmsr(IA32_VMX_TRUE_PINBASED_CTLS);
        caps_out->true_procbased = __readmsr(IA32_VMX_TRUE_PROCBASED_CTLS);
        caps_out->true_exit_ctls = __readmsr(IA32_VMX_TRUE_EXIT_CTLS);
        caps_out->true_entry_ctls= __readmsr(IA32_VMX_TRUE_ENTRY_CTLS);
    } else {
        /* Fall back to the non-TRUE MSRs so downstream code always has a usable value. */
        caps_out->true_pinbased  = caps_out->pinbased;
        caps_out->true_procbased = caps_out->procbased;
        caps_out->true_exit_ctls = caps_out->exit_ctls;
        caps_out->true_entry_ctls= caps_out->entry_ctls;
    }

    /* Secondary proc-based controls exist iff the primary controls allow bit 31
     * (PROC_CTL_ACTIVATE_SECONDARY) to be 1 -- i.e. that bit is set in the allowed-1 half of
     * IA32_VMX_PROCBASED_CTLS (SDM Vol 3D A.3.2). Only then is IA32_VMX_PROCBASED_CTLS2
     * architecturally defined; reading it otherwise is undefined, so we gate the read. */
    if (VMX_MSR_ALLOWED1(caps_out->procbased) & PROC_CTL_ACTIVATE_SECONDARY) {
        caps_out->procbased2 = __readmsr(IA32_VMX_PROCBASED_CTLS2);
        /* IA32_VMX_EPT_VPID_CAP is defined iff EPT or VPID can be enabled via the secondary
         * controls (SDM Vol 3D A.10). Gate on either allowed-1 secondary bit. */
        if (VMX_MSR_ALLOWED1(caps_out->procbased2) &
            (PROC2_CTL_ENABLE_EPT | PROC2_CTL_ENABLE_VPID)) {
            caps_out->ept_vpid_cap = __readmsr(IA32_VMX_EPT_VPID_CAP);
        }
    }

    return HV_OK;
}

/* ====================================================================================== */
/*  Feature detection                                                                       */
/* ====================================================================================== */

/* True iff CPUID.0 reports the Intel vendor string. VMX (VT-x) is an Intel feature; AMD reports
 * SVM instead and never sets CPUID.1:ECX.VMX, but we check the vendor explicitly so the failure
 * mode is a clean HV_ERR_NO_VT rather than a mis-decoded capability MSR. */
static int vmx_is_intel(void)
{
    int regs[4];
    __cpuid(regs, CPUID_LEAF_VENDOR);   /* regs = {EAX, EBX, ECX, EDX}. */
    return ((u32)regs[1] == CPUID_VENDOR_INTEL_EBX) &&   /* EBX "Genu" */
           ((u32)regs[3] == CPUID_VENDOR_INTEL_EDX) &&   /* EDX "ineI" */
           ((u32)regs[2] == CPUID_VENDOR_INTEL_ECX);     /* ECX "ntel" */
}

/*
 * Gate: is VMX usable on this logical processor, and if so cache its capabilities?
 *
 *   1. CPUID.0 vendor == GenuineIntel.
 *   2. CPUID.1:ECX.VMX (bit 5) set -- the CPU implements VMX.
 *   3. IA32_FEATURE_CONTROL: if the lock bit is set, VMXON-outside-SMX must also be enabled,
 *      otherwise the BIOS has locked VMX off and no software can enable it (SDM Vol 3C 24.7).
 *      If the lock bit is clear we do NOT write here (read-only probe) -- vmx_enable_on_cpu
 *      performs the lock+enable write on the CPU that will actually run VMXON.
 *   4. Read the capability MSRs into caps_out.
 *
 * Does not touch g_hv; the caller (driver.c) records vt_supported / ept_supported.
 */
HV_STATUS vmx_check_support(VMX_CAPABILITIES *caps_out)
{
    int regs[4];
    u64 feature_control;

    if (caps_out == NULL)
        return HV_ERR_INVALID_ARG;

    if (!vmx_is_intel()) {
        HV_LOG("CPUID vendor is not GenuineIntel -- no VT-x");
        return HV_ERR_NO_VT;
    }

    __cpuid(regs, CPUID_LEAF_FEATURES);     /* ECX bit 5 = VMX. */
    if (((u32)regs[2] & CPUID_1_ECX_VMX) == 0) {
        HV_LOG("CPUID.1:ECX.VMX clear -- CPU does not implement VMX");
        return HV_ERR_NO_VT;
    }

    /* IA32_FEATURE_CONTROL semantics (SDM Vol 3C 24.7):
     *   - Lock bit (0) clear  : MSR is writable; VMXON would #GP until we lock+enable it. That
     *                           write happens in vmx_enable_on_cpu.
     *   - Lock bit set + outside-SMX enable (2) set : VMX is available. Good.
     *   - Lock bit set + outside-SMX enable clear   : BIOS locked VMX off. Unrecoverable. */
    feature_control = __readmsr(IA32_FEATURE_CONTROL);
    if (feature_control & IA32_FEATURE_CONTROL_LOCK_BIT) {
        if ((feature_control & IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX) == 0) {
            HV_LOG("IA32_FEATURE_CONTROL locked with VMXON-outside-SMX disabled (BIOS locked off)");
            return HV_ERR_VMX_LOCKED_OFF;
        }
    }

    return vmx_read_capabilities(caps_out);
}

/* ====================================================================================== */
/*  Control-word and CR0/CR4 adjustment                                                     */
/* ====================================================================================== */

/*
 * Adjust a 32-bit VM-execution/exit/entry control word to the allowed settings of its
 * capability MSR (SDM Vol 3D A.3). Encoding:
 *   allowed-0 = low dword  : a bit set here MUST be 1  (0 is not allowed) -> force it on.
 *   allowed-1 = high dword : a bit clear here MUST be 0 (1 is not allowed) -> force it off.
 * A required-1 bit is by construction also allowed-1, so the OR-then-AND order is safe.
 *
 * `capability_msr` is the *value* of the MSR (already read into VMX_CAPABILITIES), not its
 * index -- pass caps->true_procbased etc. per the SDM's "use the TRUE MSR when BASIC[55]" rule.
 */
u32 vmx_adjust_controls(u32 desired, u64 capability_msr)
{
    u32 v = desired;
    v |= VMX_MSR_ALLOWED0(capability_msr);   /* set every required-1 bit. */
    v &= VMX_MSR_ALLOWED1(capability_msr);   /* clear every not-allowed-1 bit. */
    return v;
}

/*
 * Force CR0 to a value legal for VMX operation (SDM Vol 3C 24.8 / Appendix A.7):
 *   a bit set   in IA32_VMX_CR0_FIXED0 must be 1 in CR0 (required-1),
 *   a bit clear in IA32_VMX_CR0_FIXED1 must be 0 in CR0 (required-0).
 * So: OR in FIXED0 (turn on the required-1 bits), AND with FIXED1 (turn off the required-0
 * bits). Applied to the host's own CR0 at VMXON time -- PE and PG are already 1 on a running
 * 64-bit kernel, so the well-known unrestricted-guest relaxation of CR0.PE/PG does not apply
 * here (that relaxation is for *guest* CR0, handled in vmcs.c).
 */
u64 vmx_adjust_cr0(u64 cr0, const VMX_CAPABILITIES *caps)
{
    cr0 |= caps->cr0_fixed0;
    cr0 &= caps->cr0_fixed1;
    return cr0;
}

/*
 * Force CR4 to a value legal for VMX operation (same FIXED0/FIXED1 rule as CR0). CR4.VMXE
 * (bit 13) is required-1 for VMX operation and is therefore already set in IA32_VMX_CR4_FIXED0;
 * we still OR it in explicitly so the intent is visible and correct even if a caller passes a
 * CR4 snapshot taken before VMXE was set.
 */
u64 vmx_adjust_cr4(u64 cr4, const VMX_CAPABILITIES *caps)
{
    cr4 |= CR4_VMXE;
    cr4 |= caps->cr4_fixed0;
    cr4 &= caps->cr4_fixed1;
    return cr4;
}

/* ====================================================================================== */
/*  VMXON / VMXOFF                                                                          */
/* ====================================================================================== */

/*
 * Enable VMX operation on the current logical processor and enter VMX root (execute VMXON).
 * Runs on the target CPU (driver.c dispatches this per-processor).
 *
 * Preconditions: vcpu->vmxon_region / vcpu->vmxon_pa are a 4KB, page-aligned, physically
 * contiguous, non-paged allocation (vmcs_alloc's job). We stamp the VMCS revision id into its
 * first dword here defensively (idempotent) because VMXON #GPs on a wrong/zero revision.
 *
 * Steps (SDM Vol 3C 24.7 / 24.11.5 / 31.5 VMXON):
 *   1. lock+enable IA32_FEATURE_CONTROL if the BIOS left it unlocked;
 *   2. adjust CR0, set CR4.VMXE and adjust CR4 to the FIXED constraints;
 *   3. stamp the revision id into the VMXON region;
 *   4. VMXON with the region's physical address.
 */
HV_STATUS vmx_enable_on_cpu(VCPU *vcpu)
{
    const VMX_CAPABILITIES *caps;
    u64 feature_control;
    u64 cr0, cr4;
    VMX_RESULT r;

    if (vcpu == NULL || vcpu->vmxon_region == NULL || vcpu->vmxon_pa == 0)
        return HV_ERR_INVALID_ARG;

    if (vcpu->in_vmx_root)
        return HV_OK;   /* Idempotent: already in VMX root on this CPU. */

    /* Prefer the per-VCPU back-pointer's cached caps; fall back to the global snapshot. */
    caps = (vcpu->hv != NULL) ? &vcpu->hv->caps : &g_hv.caps;

    /* --- 1. IA32_FEATURE_CONTROL: lock + enable VMXON-outside-SMX if still writable. --- */
    feature_control = __readmsr(IA32_FEATURE_CONTROL);
    if ((feature_control & IA32_FEATURE_CONTROL_LOCK_BIT) == 0) {
        /* Unlocked: enable VMXON outside SMX and set the lock bit in one write. Once the lock
         * bit is set the MSR is read-only until the next reset. */
        feature_control |= IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX |
                           IA32_FEATURE_CONTROL_LOCK_BIT;
        __writemsr(IA32_FEATURE_CONTROL, feature_control);
        /* TODO(hv): a hostile/older BIOS could conceivably re-lock; re-read to confirm. */
        feature_control = __readmsr(IA32_FEATURE_CONTROL);
    }
    if ((feature_control & IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX) == 0) {
        HV_LOG("VMXON-outside-SMX not enabled after feature-control write (locked off)");
        return HV_ERR_VMX_LOCKED_OFF;
    }

    /* --- 2. CR0/CR4 to the FIXED0/FIXED1 constraints; CR4.VMXE on. --- */
    cr0 = __readcr0();
    cr0 = vmx_adjust_cr0(cr0, caps);
    __writecr0(cr0);

    cr4 = __readcr4();
    cr4 = vmx_adjust_cr4(cr4, caps);   /* sets CR4.VMXE and applies FIXED bits. */
    __writecr4(cr4);

    /* --- 3. Stamp the VMCS revision id into the VMXON region's first 32 bits (bit 31 = 0). --- */
    *(volatile u32 *)vcpu->vmxon_region = caps->vmcs_revision_id;

    /* --- 4. VMXON. Failure here is VMfailInvalid (CF): there is no VMCS, so the instruction-
     * error field is NOT consultable -- only CF/ZF distinguish the outcome. --- */
    r = asm_vmxon(vcpu->vmxon_pa);
    if (r != VMX_SUCCEED) {
        HV_LOG("VMXON failed: %s (cpu %u, vmxon_pa=%p)",
               vmx_result_str(r), vcpu->index, (void *)vcpu->vmxon_pa);
        /* Undo CR4.VMXE so the CPU is left in a clean, non-VMX state. */
        __writecr4(__readcr4() & ~(u64)CR4_VMXE);
        return HV_ERR_VMXON;
    }

    vcpu->in_vmx_root = 1;
    HV_LOG("VMXON ok on cpu %u", vcpu->index);
    return HV_OK;
}

/*
 * Leave VMX operation on the current logical processor (VMXOFF) and clear CR4.VMXE.
 *
 * The caller is responsible for having already VMCLEAR'd the active VMCS (vmcs.c / driver.c
 * teardown ordering); VMXOFF itself simply exits VMX root. VMXOFF failure is VMfailInvalid
 * (CF) -- e.g. called when not in VMX root -- with no VMCS context to read an error from.
 */
HV_STATUS vmx_disable_on_cpu(VCPU *vcpu)
{
    VMX_RESULT r;

    if (vcpu == NULL)
        return HV_ERR_INVALID_ARG;

    if (!vcpu->in_vmx_root)
        return HV_OK;   /* Nothing to do; not in VMX root on this CPU. */

    r = asm_vmxoff();
    if (r != VMX_SUCCEED) {
        HV_LOG("VMXOFF failed: %s (cpu %u)", vmx_result_str(r), vcpu->index);
        /* TODO(hv): a failed VMXOFF leaves the CPU in VMX root -- the safest recovery is to
         * leave CR4.VMXE set and surface the error so the driver aborts devirtualization on
         * this CPU rather than clearing VMXE underneath an active VMX-root state. */
        return HV_ERR_NOT_VIRTUALIZED;
    }

    vcpu->in_vmx_root = 0;

    /* Clear CR4.VMXE now that we are out of VMX operation. */
    __writecr4(__readcr4() & ~(u64)CR4_VMXE);

    HV_LOG("VMXOFF ok on cpu %u", vcpu->index);
    return HV_OK;
}
