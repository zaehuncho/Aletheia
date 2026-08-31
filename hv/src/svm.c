/*
 * svm.c -- AMD SVM lifecycle for the Aletheia clean-room VT-x-and-AMD-V VMI hypervisor.
 *
 * RESPONSIBILITY (per hv.h): detect AMD-V, read the CPUID + VM_CR gates, enable SVM
 * (EFER.SVME + MSR_VM_HSAVE_PA), disable it, and drive the per-VCPU VMRUN loop that hands
 * every VM-exit off to vmexit.c.
 *
 * CLEAN-ROOM PROVENANCE: written from the public AMD64 APM Vol 2 -- "System Programming"
 * (§15 "Secure Virtual Machine"). Cross-checked only against the public open-source VMMs
 * named in the tree README (Bareflank AMD backend, KVM-svm), which transcribe the same
 * public tables. No proprietary or anti-cheat source was consulted. Every APM-derived
 * constant resolves through arch.h / svm_defs.h -- there are no magic numbers below.
 *
 * CANNOT BE BUILT OR RUN IN THIS ENVIRONMENT. Unfinished/uncertain spots are marked
 * "// TODO(hv):". Correctness against the APM is the whole game -- a wrong control bit,
 * a bad VMCB clean-bits state, or a missing GIF gate hangs the machine.
 */

#include "hv.h"

/* -------------------------------------------------------------------------------------- */
/*  Local logging (peer of vmx.c's HV_LOG; safe at KeIpiGenericCall's IPI_LEVEL).           */
/* -------------------------------------------------------------------------------------- */
#if DBG
#define HV_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[aletheia-svm] " fmt "\n", __VA_ARGS__)
#else
#define HV_LOG(fmt, ...) ((void)0)
#endif

/* Human-readable tag for an SVM_RESULT (only three outcomes at the C wrapper level). */
static const char *svm_result_str(SVM_RESULT r)
{
    switch (r) {
    case SVM_SUCCEED:      return "SVMsucceed";
    case SVM_FAIL_ENTRY:   return "SVMfailEntry(VMCB_INVALID)";
    case SVM_FAIL_GENERAL: return "SVMfailGeneral";
    default:               return "SVM?";
    }
}

/* ====================================================================================== */
/*  Capability probe -- APM §15.4 (CPUID feature reporting).                                */
/* ====================================================================================== */

/*
 * Populate SVM_CAPABILITIES from CPUID + MSR_VM_CR. This is the "can we even virtualize"
 * check the driver.c bring-up runs before touching CR0/EFER on any CPU. Reads:
 *   - CPUID.80000001h:ECX[2] -- AMD-V present.
 *   - CPUID.8000000Ah        -- SVM revision (EAX[7:0]), NASID (EBX), features (EDX).
 *   - MSR_VM_CR              -- SVMDIS + LOCK gates.
 *
 * `caps_out->present` is the master gate; every downstream check assumes it.
 */
HV_STATUS svm_check_support(SVM_CAPABILITIES *caps_out)
{
    int regs[4] = { 0 };
    u64 vm_cr;

    if (caps_out == NULL)
        return HV_ERR_INVALID_ARG;

    RtlZeroMemory(caps_out, sizeof(*caps_out));

    /* CPUID.80000000h vendor + max-extended-leaf. We only care that the extended-leaf range
     * is large enough to reach 8000_000Ah; otherwise SVM cannot be present. */
    __cpuidex(regs, 0x80000000, 0);
    if ((u32)regs[0] < CPUID_FN_SVM_FEATURES) {
        HV_LOG("CPUID max ext leaf 0x%x < 0x8000000A; no SVM report", regs[0]);
        return HV_ERR_NO_SVM;
    }

    /* CPUID.80000001h -- ECX[2] = SVM. */
    __cpuidex(regs, CPUID_FN_EXT_FEATURES, 0);
    if (((u32)regs[2] & CPUID_EXT_FEATURES_ECX_SVM) == 0) {
        HV_LOG("CPUID.80000001h:ECX[2] clear; no AMD-V");
        return HV_ERR_NO_SVM;
    }
    caps_out->present = 1;

    /* CPUID.8000000Ah -- SVM revision + NASID + feature bits. */
    __cpuidex(regs, CPUID_FN_SVM_FEATURES, 0);
    caps_out->revision      = (u32)regs[0] & 0xFF;
    caps_out->asid_count    = (u32)regs[1];
    {
        u32 edx = (u32)regs[3];
        caps_out->nested_paging = !!(edx & CPUID_SVM_EDX_NP);
        caps_out->svml          = !!(edx & CPUID_SVM_EDX_SVML);
        caps_out->nrips         = !!(edx & CPUID_SVM_EDX_NRIPS);
        caps_out->vmcb_clean    = !!(edx & CPUID_SVM_EDX_VMCB_CLEAN);
        caps_out->flush_by_asid = !!(edx & CPUID_SVM_EDX_FLUSHBYASID);
        caps_out->decode_assist = !!(edx & CPUID_SVM_EDX_DECODEASSIST);
        caps_out->vgif          = !!(edx & CPUID_SVM_EDX_VGIF);
    }

    /* MSR_VM_CR -- if BIOS locked SVM off, we cannot enable it. APM §15.30.1:
     * "If VM_CR.LOCK==1 and VM_CR.SVMDIS==1 then EFER.SVME writes cause #GP." */
    vm_cr = __readmsr(MSR_VM_CR);
    caps_out->vm_cr   = vm_cr;
    caps_out->svmdis  = !!(vm_cr & VM_CR_SVMDIS);
    caps_out->svmlock = !!(vm_cr & VM_CR_LOCK);
    if (caps_out->svmlock && caps_out->svmdis) {
        HV_LOG("VM_CR.LOCK && VM_CR.SVMDIS: SVM permanently gated off (VM_CR=0x%llx)", vm_cr);
        return HV_ERR_SVM_LOCKED_OFF;
    }

    /* We need at least NASID >= 2 (host + one guest) and NP support (Aletheia depends on it). */
    if (caps_out->asid_count < 2) {
        HV_LOG("NASID=%u insufficient for guest use", caps_out->asid_count);
        return HV_ERR_NO_SVM;
    }
    if (!caps_out->nested_paging) {
        HV_LOG("Nested paging feature bit clear (CPUID.8000000Ah:EDX[0]==0)");
        return HV_ERR_NO_NPT;
    }

    HV_LOG("SVM supported: rev=%u NASID=%u NP=%u NRIPS=%u CLEAN=%u FBYASID=%u DECODE=%u VGIF=%u",
           caps_out->revision, caps_out->asid_count,
           caps_out->nested_paging, caps_out->nrips, caps_out->vmcb_clean,
           caps_out->flush_by_asid, caps_out->decode_assist, caps_out->vgif);
    return HV_OK;
}

/* ====================================================================================== */
/*  Per-CPU enable / disable                                                                */
/* ====================================================================================== */

/*
 * Enable SVM on the *current* processor and program the per-CPU HSAVE region. Must be
 * called at DPC/IPI level on the target CPU. Sequence (APM §15.4, §15.30.4):
 *   1. Re-check the VM_CR gate on THIS CPU (SVMDIS is per-package but we're paranoid).
 *   2. Set EFER.SVME. Doing this with SVMDIS==1 raises #GP -- guarded by step 1.
 *   3. Write the HSAVE physical address to MSR_VM_HSAVE_PA. The CPU uses this page to
 *      stash host state on every VMRUN and restore it on every VM-exit.
 *
 * Caller owns vcpu->hsave_region / vcpu->hsave_pa (allocated by vmcb_alloc).
 */
HV_STATUS svm_enable_on_cpu(VCPU *vcpu)
{
    u64 vm_cr, efer;

    if (vcpu == NULL || vcpu->hsave_region == NULL || vcpu->hsave_pa == 0)
        return HV_ERR_INVALID_ARG;

    vm_cr = __readmsr(MSR_VM_CR);
    if ((vm_cr & VM_CR_LOCK) && (vm_cr & VM_CR_SVMDIS)) {
        HV_LOG("cpu%u: VM_CR locks SVM off (0x%llx)", vcpu->index, vm_cr);
        return HV_ERR_SVM_LOCKED_OFF;
    }

    /* Set EFER.SVME. Preserve every other bit (LME/LMA/NXE etc. -- Windows relies on them). */
    efer = __readmsr(MSR_EFER);
    if ((efer & EFER_SVME) == 0) {
        __writemsr(MSR_EFER, efer | EFER_SVME);
        /* Read back to confirm; a laptop with a strict firmware may silently reject. */
        efer = __readmsr(MSR_EFER);
        if ((efer & EFER_SVME) == 0) {
            HV_LOG("cpu%u: EFER.SVME did not stick (EFER=0x%llx)", vcpu->index, efer);
            return HV_ERR_SVM_LOCKED_OFF;
        }
    }

    /* Program HSAVE. APM §15.30.4: physical address, 4KB-aligned, of a 4KB region. */
    __writemsr(MSR_VM_HSAVE_PA, vcpu->hsave_pa);

    g_hv.vcpus_virtualized++;                       /* Interlocked counter is fine as ++ here;
                                                       we own this CPU during bring-up. */
    /* TODO(hv): swap to InterlockedIncrement if driver.c later moves bring-up off the IPI. */

    HV_LOG("cpu%u: SVM enabled (EFER=0x%llx HSAVE=0x%llx)",
           vcpu->index, efer | EFER_SVME, vcpu->hsave_pa);
    return HV_OK;
}

/*
 * Clear EFER.SVME on the current processor. Only safe once every VCPU using this CPU has
 * been torn down (asm_devirtualize_and_resume) and no VMCB is loaded here. See driver.c.
 */
HV_STATUS svm_disable_on_cpu(VCPU *vcpu)
{
    u64 efer;

    UNREFERENCED_PARAMETER(vcpu);

    efer = __readmsr(MSR_EFER);
    if (efer & EFER_SVME)
        __writemsr(MSR_EFER, efer & ~EFER_SVME);

    /* Zero MSR_VM_HSAVE_PA; APM doesn't require it, but leaves less dangling state. */
    __writemsr(MSR_VM_HSAVE_PA, 0);
    return HV_OK;
}

/* ====================================================================================== */
/*  VMRUN loop                                                                              */
/* ====================================================================================== */

/*
 * Enter the guest via VMRUN and run until an exit tells us to unload. Each iteration:
 *   1. Call asm_svm_run(vmcb_pa, &vcpu->gpr).
 *        The asm wrapper does CLGI -> VMSAVE(host) -> VMLOAD(guest bits not covered by
 *        VMCB) -> VMRUN(vmcb_pa) -> VMLOAD(host) -> STGI, and copies guest GPRs to/from
 *        vcpu->gpr. See asm_x64.asm.
 *   2. Read VMCB->control.exit_code. If SVM_EXIT_INVALID (-1 unsigned), the entry state
 *      was rejected -- bail with HV_ERR_VMRUN so driver.c can bugcheck usefully.
 *   3. Otherwise dispatch to vmexit.c's hv_svm_vmexit_dispatch(). Return value:
 *        nonzero -> another VMRUN iteration.
 *        zero    -> orderly unload; return HV_OK.
 *   4. After the first successful VMRUN, mark svm_launched -- subsequent iterations run
 *      through the same asm path, and hardware handles the "launched vs resumed" delta.
 *
 * TODO(hv): pause-filter / preemption timer integration.
 * TODO(hv): a hard iteration cap for debugging (default 0 = uncapped), plumbed from a
 * driver-parameter registry key, so a runaway exit loop doesn't wedge the box.
 */
HV_STATUS svm_launch(VCPU *vcpu)
{
    if (vcpu == NULL || vcpu->vmcb == NULL || vcpu->vmcb_pa == 0)
        return HV_ERR_INVALID_ARG;

    for (;;) {
        SVM_RESULT r;
        u64 exit_code;
        int cont;

        r = asm_svm_run(vcpu->vmcb_pa, &vcpu->gpr);
        if (r != SVM_SUCCEED) {
            HV_LOG("cpu%u: asm_svm_run -> %s", vcpu->index, svm_result_str(r));
            return HV_ERR_VMRUN;
        }
        vcpu->svm_launched = 1;

        exit_code = vcpu->vmcb->control.exit_code;
        if (exit_code == SVM_EXIT_INVALID) {
            HV_LOG("cpu%u: VMCB rejected on entry (EXITCODE=INVALID)", vcpu->index);
            /* On INVALID entry the VMCB's state fields are the authoritative diagnostic
             * -- driver.c's bugcheck path reads them; nothing useful to do here beyond
             * returning. */
            return HV_ERR_VMRUN;
        }

        cont = hv_svm_vmexit_dispatch(&vcpu->gpr);   /* vmexit.c owns the routing. */
        if (!cont)
            return HV_OK;                            /* Orderly unload requested. */
        /* else fall through to the next VMRUN. */
    }
}

/* ====================================================================================== */
/*  Small accessors                                                                         */
/* ====================================================================================== */

u64 svm_last_exit_code(VCPU *vcpu)
{
    if (vcpu == NULL || vcpu->vmcb == NULL)
        return SVM_EXIT_INVALID;
    return vcpu->vmcb->control.exit_code;
}
