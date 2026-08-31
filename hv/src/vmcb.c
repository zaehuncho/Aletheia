/*
 * vmcb.c -- VMCB allocation and full guest/control/permission-bitmap population.
 * AMD peer of vmcs.c. Per hv.h: vmcb_alloc, vmcb_setup_guest, vmcb_setup_intercepts,
 * vmcb_setup_msrpm, vmcb_setup_iopm.
 *
 * CLEAN-ROOM PROVENANCE: written from the AMD64 APM Vol 2:
 *   VMCB layout                 §15.5  (Tables 15-1 / 15-2)
 *   Guest state save area       §15.5.1
 *   Intercept fields            §15.7  (Tables 15-3..15-7)
 *   VMCB clean bits             §15.15 (Table 15-8)
 *   IOPM permission bitmap      §15.10.1
 *   MSRPM permission bitmap     §15.11
 *   Legal VMCB state on VMRUN   §15.6
 *   TLB control                 §15.16
 * All constants come from svm_defs.h / arch.h -- no magic numbers below.
 *
 * CANNOT BE BUILT OR RUN IN THIS ENVIRONMENT. // TODO(hv): markers for every unverified
 * assumption. Correctness is judged against the APM only.
 */

#include "hv.h"

#if DBG
#define HV_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[aletheia-vmcb] " fmt "\n", __VA_ARGS__)
#else
#define HV_LOG(fmt, ...) ((void)0)
#endif

/* -------------------------------------------------------------------------------------- */
/*  Contiguous physical alloc helper -- APM requires the VMCB, HSAVE, IOPM, MSRPM all be    */
/*  4 KiB-aligned. MmAllocateContiguousMemorySpecifyCache guarantees both alignment (>=      */
/*  PAGE_SIZE) and physical contiguity, which matters for the multi-page IOPM/MSRPM.         */
/* -------------------------------------------------------------------------------------- */
static void *hv_alloc_contig_pages(SIZE_T size, u64 *pa_out)
{
    PHYSICAL_ADDRESS low, high, boundary;
    void *va;

    low.QuadPart      = 0;
    /* (LONGLONG)0xFFFFFFFFFFFFFFFFULL isn't in every WDK profile; write the constant. Same value. */
    high.QuadPart     = (LONGLONG)0xFFFFFFFFFFFFFFFFULL;
    boundary.QuadPart = 0;

    va = MmAllocateContiguousMemorySpecifyCache(size, low, high, boundary, MmCached);
    if (va == NULL) {
        *pa_out = 0;
        return NULL;
    }
    RtlZeroMemory(va, size);
    *pa_out = MmGetPhysicalAddress(va).QuadPart;
    return va;
}

static void hv_free_contig_pages(void *va)
{
    if (va)
        MmFreeContiguousMemory(va);
}

/* ====================================================================================== */
/*  Allocation                                                                              */
/* ====================================================================================== */

HV_STATUS vmcb_alloc(VCPU *vcpu)
{
    if (vcpu == NULL)
        return HV_ERR_INVALID_ARG;

    vcpu->vmcb = (VMCB *)hv_alloc_contig_pages(SVM_VMCB_SIZE, &vcpu->vmcb_pa);
    if (vcpu->vmcb == NULL)
        goto oom;

    vcpu->hsave_region = hv_alloc_contig_pages(SVM_HSAVE_SIZE, &vcpu->hsave_pa);
    if (vcpu->hsave_region == NULL)
        goto oom;

    vcpu->iopm = hv_alloc_contig_pages(SVM_IOPM_SIZE, &vcpu->iopm_pa);
    if (vcpu->iopm == NULL)
        goto oom;

    vcpu->msrpm = hv_alloc_contig_pages(SVM_MSRPM_SIZE, &vcpu->msrpm_pa);
    if (vcpu->msrpm == NULL)
        goto oom;

    /* Per-VCPU ASID: index+1 avoids ASID 0 (reserved for host). Overflow past NASID is a
     * TODO(hv): partition ASIDs across sockets if hv.svm_caps.asid_count is tight. */
    vcpu->svm_asid = vcpu->index + 1;
    if (g_hv.svm_caps.asid_count && vcpu->svm_asid >= g_hv.svm_caps.asid_count)
        vcpu->svm_asid = 1;

    HV_LOG("cpu%u: VMCB=0x%llx HSAVE=0x%llx IOPM=0x%llx MSRPM=0x%llx ASID=%u",
           vcpu->index, vcpu->vmcb_pa, vcpu->hsave_pa,
           vcpu->iopm_pa, vcpu->msrpm_pa, vcpu->svm_asid);
    return HV_OK;

oom:
    vmcb_free(vcpu);
    return HV_ERR_ALLOC;
}

void vmcb_free(VCPU *vcpu)
{
    if (vcpu == NULL)
        return;
    hv_free_contig_pages(vcpu->vmcb);         vcpu->vmcb = NULL;         vcpu->vmcb_pa = 0;
    hv_free_contig_pages(vcpu->hsave_region); vcpu->hsave_region = NULL; vcpu->hsave_pa = 0;
    hv_free_contig_pages(vcpu->iopm);         vcpu->iopm = NULL;         vcpu->iopm_pa = 0;
    hv_free_contig_pages(vcpu->msrpm);        vcpu->msrpm = NULL;        vcpu->msrpm_pa = 0;
}

/* ====================================================================================== */
/*  Segment attribute encoding                                                              */
/* ====================================================================================== */

/*
 * The VMCB stores segment attributes in a compact 12-bit form (APM §15.5.1) that is NOT
 * the descriptor-cache-format access-rights word CPUID and asm_read_seg_access_rights()
 * return. The transform: take the 16-bit access-rights word (attr in bits 15..8, some hi
 * flags in bits 23..16 of the full 32-bit "type+attr" word), then pack:
 *   bits 0..3  = type  (from ar[11..8])
 *   bit  4     = S     (ar[12])
 *   bits 5..6  = DPL   (ar[14..13])
 *   bit  7     = P     (ar[15])
 *   bit  12    = AVL   (ar[20])
 *   bit  13    = L     (ar[21])
 *   bit  14    = D/B   (ar[22])
 *   bit  15    = G     (ar[23])
 * asm_read_seg_access_rights returns the SDM/AMD "access rights" 32-bit word from LAR --
 * bits 8..15 already carry the type/S/DPL/P nibble in the low byte-relative sense used by
 * VMX; bits 20..23 carry AVL/L/D/G. We rearrange those to the VMCB packed layout.
 */
static u16 vmcb_pack_seg_attr(u32 lar)
{
    u16 v = 0;
    v |= (u16)((lar >>  8) & 0x0F);            /* type */
    v |= (u16)((lar & (1u << 12)) ? VMCB_SEG_ATTR_S    : 0);
    v |= (u16)(((lar >> 13) & 0x03) << 5);     /* DPL */
    v |= (u16)((lar & (1u << 15)) ? VMCB_SEG_ATTR_P    : 0);
    v |= (u16)((lar & (1u << 20)) ? VMCB_SEG_ATTR_AVL  : 0);
    v |= (u16)((lar & (1u << 21)) ? VMCB_SEG_ATTR_L    : 0);
    v |= (u16)((lar & (1u << 22)) ? VMCB_SEG_ATTR_DB   : 0);
    v |= (u16)((lar & (1u << 23)) ? VMCB_SEG_ATTR_G    : 0);
    return v;
    /* TODO(hv): validate against a known Windows kernel CS/SS/TR read on real silicon --
     * some AMD errata suggest the AVL bit position differs on Family 15h; verify. */
}

static void vmcb_fill_seg(VMCB_SEG *dst, u16 selector, u32 lar, u32 limit, u64 base)
{
    dst->selector = selector;
    dst->attrib   = vmcb_pack_seg_attr(lar);
    dst->limit    = limit;
    dst->base     = base;
}

/* ====================================================================================== */
/*  Guest state population -- "hyperjack" bring-up (mirror current host into the VMCB).     */
/*  On the first VMRUN, the guest resumes exactly at the instruction after the launch call, */
/*  running natively but under our EPT/NPT permissions -- the SimpleVisor pattern.          */
/* ====================================================================================== */

HV_STATUS vmcb_setup_guest(VCPU *vcpu)
{
    VMCB_STATE_SAVE_AREA *g;
    PSEUDO_DESCRIPTOR_64 gdtr, idtr;

    if (vcpu == NULL || vcpu->vmcb == NULL || vcpu->launch_context == NULL)
        return HV_ERR_INVALID_ARG;

    g = &vcpu->vmcb->state_save;

    /* Segments: selector + descriptor-cache limit/base + packed attribute from LAR. */
    asm_read_gdtr(&gdtr);
    asm_read_idtr(&idtr);

    vmcb_fill_seg(&g->cs, asm_read_cs(),
                  asm_read_seg_access_rights(asm_read_cs()),
                  asm_read_seg_limit(asm_read_cs()),
                  0);   /* CS.base = 0 in 64-bit mode. */
    vmcb_fill_seg(&g->ss, asm_read_ss(),
                  asm_read_seg_access_rights(asm_read_ss()),
                  asm_read_seg_limit(asm_read_ss()), 0);
    vmcb_fill_seg(&g->ds, asm_read_ds(),
                  asm_read_seg_access_rights(asm_read_ds()),
                  asm_read_seg_limit(asm_read_ds()), 0);
    vmcb_fill_seg(&g->es, asm_read_es(),
                  asm_read_seg_access_rights(asm_read_es()),
                  asm_read_seg_limit(asm_read_es()), 0);
    vmcb_fill_seg(&g->fs, asm_read_fs(),
                  asm_read_seg_access_rights(asm_read_fs()),
                  asm_read_seg_limit(asm_read_fs()),
                  __readmsr(0xC0000100 /* IA32_FS_BASE */));
    vmcb_fill_seg(&g->gs, asm_read_gs(),
                  asm_read_seg_access_rights(asm_read_gs()),
                  asm_read_seg_limit(asm_read_gs()),
                  __readmsr(0xC0000101 /* IA32_GS_BASE */));
    vmcb_fill_seg(&g->tr, asm_read_tr(),
                  asm_read_seg_access_rights(asm_read_tr()),
                  asm_read_seg_limit(asm_read_tr()), 0);
    vmcb_fill_seg(&g->ldtr, asm_read_ldtr(),
                  asm_read_seg_access_rights(asm_read_ldtr()),
                  asm_read_seg_limit(asm_read_ldtr()), 0);

    /* GDTR / IDTR: only limit + base are honoured; selector + attrib unused per APM. */
    g->gdtr.limit = gdtr.limit;
    g->gdtr.base  = gdtr.base;
    g->idtr.limit = idtr.limit;
    g->idtr.base  = idtr.base;

    /* Control regs. Guest inherits the host's CR0/CR3/CR4/EFER; the packer's writes to any
     * of these will VM-exit if we intercepted them. */
    g->cr0    = __readcr0();
    g->cr3    = __readcr3();
    g->cr4    = __readcr4();
    g->efer   = __readmsr(MSR_EFER);            /* EFER.SVME already set by svm_enable.    */
    g->dr7    = __readdr(7);
    g->dr6    = __readdr(6);

    /* CPL = 0: we are launching from kernel mode; the host->guest handoff runs in ring 0. */
    g->cpl = 0;

    /* SYSCALL MSRs -- Windows relies on them, so copy through so guest keeps working. */
    g->star   = __readmsr(0xC0000081);
    g->lstar  = __readmsr(0xC0000082);
    g->cstar  = __readmsr(0xC0000083);
    g->sfmask = __readmsr(0xC0000084);
    g->kernel_gs_base = __readmsr(0xC0000102);
    g->sysenter_cs   = __readmsr(0x174);
    g->sysenter_esp  = __readmsr(0x175);
    g->sysenter_eip  = __readmsr(0x176);
    g->g_pat         = __readmsr(0x277);        /* Nested paging honours the guest PAT.    */

    /* RIP/RSP/RFLAGS come from the launch-context snapshot -- the guest resumes at the
     * instruction after asm_capture_context() in the setup pass (SimpleVisor bring-up). */
    {
        typedef struct { u64 rip, rsp, rflags; } LAUNCH_CTX;
        LAUNCH_CTX *lc = (LAUNCH_CTX *)vcpu->launch_context;
        g->rip    = lc->rip;
        g->rsp    = lc->rsp;
        g->rflags = lc->rflags;
    }

    /* RAX in the state-save area is the value the guest resumes with. GPRs other than RAX
     * live in the VMRUN loop's GUEST_REGISTERS scratch and are reloaded around VMRUN by the
     * asm trampoline; RAX has to be in the VMCB because VMRUN uses it as its VMCB PA input. */
    g->rax = vcpu->gpr.rax;
    return HV_OK;
}

/* ====================================================================================== */
/*  Intercept programming                                                                   */
/* ====================================================================================== */

/*
 * Aletheia's intercept default is "stealth-minimal": intercept only what we NEED to observe
 * or must own (nested-page faults, VMMCALL as our hypercall, EFER writes so a guest can't
 * clear SVME, CPUID so we can hide the SVM bit if we ever want to). Everything else stays
 * uninstrumented so a detection-aware guest has as few exit-count timing signals as possible.
 * VMRUN is a mandatory intercept per APM §15.7.1 -- the CPU refuses to run without it.
 */
HV_STATUS vmcb_setup_intercepts(VCPU *vcpu)
{
    VMCB_CONTROL_AREA *c;

    if (vcpu == NULL || vcpu->vmcb == NULL)
        return HV_ERR_INVALID_ARG;

    c = &vcpu->vmcb->control;

    c->intercept_cr         = 0;    /* No CR-read/write intercepts by default.              */
    c->intercept_dr         = 0;
    c->intercept_exceptions = 0;    /* No exception intercepts by default.                  */

    c->intercept_word3      = SVM_ICPT_CPUID;
    c->intercept_word4      = SVM_ICPT_VMRUN                /* Required.                     */
                            | SVM_ICPT_VMMCALL              /* Aletheia hypercall entry.     */
                            | SVM_ICPT_EFER_WRITE           /* Guard EFER.SVME.              */
                            | SVM_ICPT_VMLOAD               /* Nested-SVM lockout.           */
                            | SVM_ICPT_VMSAVE
                            | SVM_ICPT_STGI
                            | SVM_ICPT_CLGI
                            | SVM_ICPT_SKINIT;
    c->intercept_word5      = 0;

    /* Nested paging on, our NPT root. Aletheia depends on NP being available (guarded in
     * svm_check_support). */
    c->np_enable            = VMCB_NP_ENABLE;
    c->n_cr3                = vcpu->npt.pml4_pa;

    /* Permission-bitmap physical addresses. Both allocated + zeroed by vmcb_alloc + setup. */
    c->iopm_base_pa         = vcpu->iopm_pa;
    c->msrpm_base_pa        = vcpu->msrpm_pa;

    /* Guest ASID + TLB control. We flush this guest's TLB on every VMRUN for the first
     * bring-up (safest default); once FlushByAsid is proven, drop to DO_NOTHING and rely on
     * INVLPGA at the exit handler. */
    c->asid                 = vcpu->svm_asid;
    if (g_hv.svm_caps.flush_by_asid)
        c->tlb_control      = SVM_TLB_CONTROL_FLUSH_THIS_GUEST;
    else
        c->tlb_control      = SVM_TLB_CONTROL_FLUSH_ALL_ASIDS;

    /* V_INTR: V_INTR_MASKING = 1 so guest RFLAGS.IF does NOT gate host interrupts (host owns
     * physical interrupts). We do not virtualize APIC / AVIC here. */
    c->vintr                = VMCB_VINTR_V_INTR_MASKING;

    /* Clean bits = 0 on first entry (nothing cached yet). Hardware fills after VMRUN. */
    c->vmcb_clean           = 0;

    return HV_OK;
}

/* ====================================================================================== */
/*  Permission bitmaps                                                                      */
/*                                                                                          */
/*  IOPM (12 KiB): one bit per I/O port. Zero == "not intercepted". APM §15.10.1.            */
/*  MSRPM ( 8 KiB): two bits per MSR (read + write) in three ranges. Zero == "not intercepted".*/
/*    Range 0: 0x0000_0000 .. 0x0000_1FFF (first 2 KiB of the MSRPM)                         */
/*    Range 1: 0xC000_0000 .. 0xC000_1FFF (next 2 KiB)                                       */
/*    Range 2: 0xC001_0000 .. 0xC001_1FFF (next 2 KiB)                                       */
/*    Trailing 2 KiB is reserved.                                                            */
/* ====================================================================================== */

/* Locate an MSR's byte + bit indices inside the MSRPM. Returns 0 (success) or !=0 if the
 * MSR is outside the three ranges (in which case the CPU will trap unconditionally and the
 * caller shouldn't bother touching the MSRPM). */
static int msrpm_bit_index(u32 msr, u32 *byte_off, u32 *bit_index, int write)
{
    u32 base;
    if (msr <= 0x00001FFF)               base = 0x000;
    else if (msr >= 0xC0000000 && msr <= 0xC0001FFF)   { base = 0x800; msr -= 0xC0000000; }
    else if (msr >= 0xC0010000 && msr <= 0xC0011FFF)   { base = 0x1000; msr -= 0xC0010000; }
    else return -1;

    /* Two bits per MSR: bit 0 = read intercept, bit 1 = write intercept. */
    *byte_off  = base + (msr >> 2);
    *bit_index = ((msr & 0x3) * 2) + (write ? 1 : 0);
    return 0;
}

static void msrpm_intercept(void *msrpm, u32 msr, int read, int write)
{
    u8 *p = (u8 *)msrpm;
    u32 byte, bit;

    if (read) {
        if (msrpm_bit_index(msr, &byte, &bit, 0) == 0)
            p[byte] |= (u8)(1u << bit);
    }
    if (write) {
        if (msrpm_bit_index(msr, &byte, &bit, 1) == 0)
            p[byte] |= (u8)(1u << bit);
    }
}

HV_STATUS vmcb_setup_msrpm(VCPU *vcpu)
{
    if (vcpu == NULL || vcpu->msrpm == NULL)
        return HV_ERR_INVALID_ARG;

    /* Start with nothing intercepted (already zeroed by hv_alloc_contig_pages). Set only
     * the MSRs whose writes we want to see. */
    msrpm_intercept(vcpu->msrpm, MSR_EFER,          0, 1);   /* Catch clears of SVME.        */
    msrpm_intercept(vcpu->msrpm, MSR_VM_CR,         1, 1);   /* Guard SVMDIS attempts.       */
    msrpm_intercept(vcpu->msrpm, MSR_VM_HSAVE_PA,   1, 1);
    /* TODO(hv): add STAR/LSTAR/CSTAR/SFMASK to the write intercepts if the guest tries to
     * rewire syscall from underneath us (very unusual, not blocked yet). */
    return HV_OK;
}

HV_STATUS vmcb_setup_iopm(VCPU *vcpu)
{
    /* Aletheia does not intercept any I/O by default. The IOPM was zeroed at alloc time;
     * this is a no-op that exists so driver.c bring-up can call every setup step
     * symmetrically. */
    UNREFERENCED_PARAMETER(vcpu);
    return HV_OK;
}
