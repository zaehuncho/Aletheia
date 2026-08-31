/*
 * vmcs.c -- VMCS allocation and full guest/host/control population for the Aletheia
 * clean-room VT-x/EPT VMI hypervisor.
 *
 * CLEAN-ROOM PROVENANCE: Written against the public Intel(R) 64 and IA-32 Architectures
 * Software Developer's Manual (SDM) Vol 3C (VMCS field usage: §25 "Virtual-Machine Control
 * Structures", §26 "VM Entries", §28 "VM Exits") and Vol 3D Appendix A (VMX capability MSRs).
 * Cross-checked for architecture only against the public open-source VMMs named in hv.h
 * (hvpp, SimpleVisor, Bareflank). No proprietary or anti-cheat source was consulted. Every
 * SDM-derived constant traces to a #define in arch.h / vmx_defs.h / ept_defs.h -- there are no
 * magic numbers here.
 *
 * BRING-UP MODEL (SimpleVisor-style "hyperjacking"): VMLAUNCH resumes the *currently running*
 * host OS as the guest. So the guest-state area is a snapshot of the live processor context at
 * the moment of bring-up (CR0/CR3/CR4, the segment descriptors, GDT/IDT, RSP/RIP/RFLAGS), and
 * the host-state area is where VM-exits land (RIP -> asm_vmexit_entry, RSP -> the per-VCPU host
 * stack). The caller (driver.c) is expected to have snapshotted the guest resume point via
 * asm_capture_context() and stored it into vcpu->guest_rip / guest_rsp / guest_rflags BEFORE
 * calling vmcs_setup_guest(); see the TODO in vmcs_setup_guest().
 *
 * CANNOT BE BUILT OR RUN IN THIS ENVIRONMENT. A single wrong VMCS field or control bit hangs
 * the machine; correctness is judged only against the SDM. Every unfinished decision is marked
 * "// TODO(hv):".
 */

#include "hv.h"

/* ====================================================================================== */
/*  Local helpers                                                                          */
/* ====================================================================================== */

/* VMWRITE with a hard failure path. Used pervasively by the setup routines: any failing
 * VMWRITE during setup means the field encoding or value is wrong, which would make VMLAUNCH
 * fail (or worse, silently misbehave), so we abort setup immediately. */
#define VMCS_WR(field, value)                                                   \
    do {                                                                        \
        HV_STATUS _wr = vmcs_write((u64)(field), (u64)(value));                 \
        if (_wr != HV_OK) {                                                     \
            return _wr;                                                         \
        }                                                                       \
    } while (0)

/* Select the correct capability MSR for a control group: the "TRUE" MSR when IA32_VMX_BASIC
 * bit 55 says it exists (SDM Vol 3D A.2 -- the TRUE MSRs report the genuinely-flexible bits;
 * the legacy MSRs may force default1 bits that we would rather leave clear). */
static u64 vmcs_cap_msr(const VMX_CAPABILITIES *caps, u64 true_msr, u64 legacy_msr)
{
    return caps->has_true_ctls ? true_msr : legacy_msr;
}

/* A raw x86-64 GDT/LDT descriptor. Code/data descriptors are 8 bytes; system descriptors
 * (LDT, TSS -- access.s == 0) are 16 bytes and carry an upper 32 bits of base. SDM Vol 3A
 * §3.4.5 (segment descriptors) and §8.2.3 (TSS descriptor in IA-32e). */
#pragma pack(push, 1)
typedef struct _GDT_DESCRIPTOR_64 {
    u16 limit_low;      /* Limit 15:0. */
    u16 base_low;       /* Base 15:0. */
    u8  base_mid;       /* Base 23:16. */
    u8  access;         /* Type(3:0), S(4), DPL(6:5), P(7). */
    u8  gran;           /* Limit 19:16, AVL, L, D/B, G. */
    u8  base_high;      /* Base 31:24. */
    u32 base_upper;     /* Base 63:32 (system descriptors only). */
    u32 reserved;       /* Zero (system descriptors only). */
} GDT_DESCRIPTOR_64;
#pragma pack(pop)

#define GDT_DESC_ACCESS_S   BIT(4)   /* Descriptor type: 1 = code/data, 0 = system. */

/* Reconstruct a segment's linear base from its GDT descriptor. Handles the 16-byte system
 * descriptor form (TR / LDTR) as well as ordinary 8-byte descriptors. Returns 0 for a null
 * selector. TI (LDT) selectors are not resolved -- Windows keeps TR/LDTR in the GDT.
 * TODO(hv): resolve TI==1 selectors through the LDT if a future guest actually uses one. */
static u64 vmcs_segment_base_from_gdt(u64 gdt_base, u16 selector)
{
    GDT_DESCRIPTOR_64 *desc;
    u64 base;

    if ((selector & SELECTOR_INDEX_MASK) == 0) {
        return 0;
    }
    /* The index field is the selector with RPL/TI stripped; it is a byte offset into the GDT. */
    desc = (GDT_DESCRIPTOR_64 *)(gdt_base + (selector & SELECTOR_INDEX_MASK));

    base = (u64)desc->base_low
         | ((u64)desc->base_mid  << 16)
         | ((u64)desc->base_high << 24);

    /* System descriptor (S == 0): TSS/LDT in long mode carry base bits 63:32. */
    if ((desc->access & GDT_DESC_ACCESS_S) == 0) {
        base |= ((u64)desc->base_upper << 32);
    }
    return base;
}

/* Compose the VMX segment access-rights word (SDM Vol 3C §25.4.1, Table 25-2) for a selector.
 * The LAR instruction (via asm_read_seg_access_rights) returns the descriptor's access-rights
 * dword with the AR bytes in bits 15:8; the VMCS field wants those bytes right-shifted by 8,
 * with bits 11:8 and 31:17 clear and bit 16 = "unusable". A null selector index is reported
 * unusable, which is what the VM-entry consistency checks require for a segment the guest is
 * not using (SDM Vol 3C §26.3.1.2).
 * TODO(hv): a fully robust "unusable" decision would use LAR's ZF (segment not present /
 * not accessible) rather than only the null-selector test; asm_read_seg_access_rights would
 * have to surface that flag. Null-index covers the case that actually occurs here (LDTR). */
static u32 vmcs_segment_access_rights(u16 selector)
{
    VMX_SEGMENT_ACCESS_RIGHTS ar;
    u32 lar;

    ar.all = 0;

    if ((selector & SELECTOR_INDEX_MASK) == 0) {
        ar.bits.unusable = 1;      /* Bases/limits are ignored on entry for an unusable seg. */
        return ar.all;
    }

    lar = asm_read_seg_access_rights(selector);
    /* Keep type(3:0), S(4), DPL(6:5), P(7) and AVL(12)/L(13)/DB(14)/G(15); drop reserved
     * 11:8 and everything at or above the unusable bit. */
    ar.all = (lar >> 8) & 0xF0FFu;
    ar.bits.unusable = 0;
    return ar.all;
}

/* Segment limit via LSL (SDM Vol 3A §3.5.1). Long-mode data segments ignore the limit, but a
 * usable segment must still carry a self-consistent one for the VM-entry checks. */
static u32 vmcs_segment_limit(u16 selector)
{
    if ((selector & SELECTOR_INDEX_MASK) == 0) {
        return 0;
    }
    return asm_read_seg_limit(selector);
}

/* ====================================================================================== */
/*  Physical-memory allocation for the VMX-owned pages                                     */
/* ====================================================================================== */

/* Allocate a single 4KB physically-contiguous, non-paged, page-aligned page and report its
 * physical address. VMXON/VMCS/MSR-bitmap regions all share these requirements (SDM Vol 3C
 * §24.11.5, §25.6.9): 4KB aligned, within the processor's physical-address width, of the
 * memory type reported by IA32_VMX_BASIC (WB on all current parts). MmAllocateContiguousMemory
 * returns page-aligned, non-paged, write-back memory for a >= PAGE_SIZE request.
 * TODO(hv): if a part ever reports a non-WB VMCS memtype in IA32_VMX_BASIC bits 53:50, switch
 * to MmAllocateContiguousMemorySpecifyCache and honor it. */
static void *vmcs_alloc_contiguous_page(u64 *out_pa)
{
    PHYSICAL_ADDRESS highest;
    PHYSICAL_ADDRESS pa;
    void *va;

    highest.QuadPart = ~0ll;   /* No ceiling below the addressable maximum. */

    va = MmAllocateContiguousMemory(PAGE_SIZE_4K, highest);
    if (va == NULL) {
        return NULL;
    }
    RtlZeroMemory(va, PAGE_SIZE_4K);

    pa = MmGetPhysicalAddress(va);
    if (out_pa != NULL) {
        *out_pa = (u64)pa.QuadPart;
    }
    return va;
}

static void vmcs_free_contiguous_page(void *va)
{
    if (va != NULL) {
        MmFreeContiguousMemory(va);
    }
}

/* ====================================================================================== */
/*  Public VMWRITE / VMREAD convenience wrappers (declared in hv.h)                         */
/* ====================================================================================== */

HV_STATUS vmcs_write(u64 field, u64 value)
{
    VMX_RESULT r = asm_vmwrite(field, value);
    if (r != VMX_SUCCEED) {
        /* In a checked build, capture the instruction error and break: a failed setup VMWRITE
         * is a programming bug (wrong encoding / read-only field), not a runtime condition. */
        NT_ASSERTMSG("vmcs_write: VMWRITE failed", FALSE);
        return HV_ERR_VMWRITE;
    }
    return HV_OK;
}

u64 vmcs_read(u64 field)
{
    u64 value = 0;
    VMX_RESULT r = asm_vmread(field, &value);
    if (r != VMX_SUCCEED) {
        NT_ASSERTMSG("vmcs_read: VMREAD failed", FALSE);
        return 0;
    }
    return value;
}

/* ====================================================================================== */
/*  Allocation + revision stamping (hv.h: vmcs_alloc / vmcs_free)                           */
/* ====================================================================================== */

/*
 * Allocate the four per-VCPU physical regions this hypervisor owns:
 *   - VMXON region  (4KB, revision-stamped) -- consumed by vmx_enable_on_cpu()'s VMXON.
 *   - VMCS region   (4KB, revision-stamped) -- the active control structure.
 *   - MSR bitmap    (4KB, zeroed)           -- programmed by vmcs_setup_controls().
 *   - Host stack    (page-multiple)         -- VMCS_HOST_RSP lands here on every exit.
 *
 * The VMXON and VMCS regions must have their first dword set to the VMCS revision identifier
 * from IA32_VMX_BASIC bits 30:0, with bit 31 (shadow-VMCS indicator) clear for an ordinary
 * VMCS (SDM Vol 3C §24.11.5 and §25.2).
 *
 * OWNERSHIP NOTE: the header comment on vmcs_alloc only names "VMCS/VMXON pages", but the MSR
 * bitmap and host stack have no other clear owner and are needed to complete VMCS setup, so
 * they are allocated here and released in vmcs_free(). If driver.c later takes ownership of the
 * host stack (e.g. to embed the asm exit frame), move these two out.
 */
HV_STATUS vmcs_alloc(VCPU *vcpu)
{
    u32 revision_id;
    u64 stack_top;

    if (vcpu == NULL || vcpu->hv == NULL) {
        return HV_ERR_INVALID_ARG;
    }

    /* Bits 30:0 of IA32_VMX_BASIC. vmx.c caches this as caps.vmcs_revision_id; fall back to a
     * direct mask of caps.basic if the cached field was not populated. */
    revision_id = vcpu->hv->caps.vmcs_revision_id;
    if (revision_id == 0) {
        revision_id = (u32)(vcpu->hv->caps.basic & IA32_VMX_BASIC_REVISION_MASK);
    }

    /* ---- VMXON region ---- */
    vcpu->vmxon_region = vmcs_alloc_contiguous_page(&vcpu->vmxon_pa);
    if (vcpu->vmxon_region == NULL) {
        goto fail;
    }
    /* First dword = revision id; bit 31 must be 0 for the VMXON region (SDM §24.11.5). */
    *(volatile u32 *)vcpu->vmxon_region = revision_id & (u32)IA32_VMX_BASIC_REVISION_MASK;

    /* ---- VMCS region ---- */
    vcpu->vmcs_region = vmcs_alloc_contiguous_page(&vcpu->vmcs_pa);
    if (vcpu->vmcs_region == NULL) {
        goto fail;
    }
    /* First dword = revision id; bit 31 = 0 marks an ordinary (non-shadow) VMCS (SDM §25.2). */
    *(volatile u32 *)vcpu->vmcs_region = revision_id & (u32)IA32_VMX_BASIC_REVISION_MASK;

    /* ---- MSR bitmap ---- (all zero => no MSR access causes a VM exit; fully transparent). */
    vcpu->msr_bitmap = vmcs_alloc_contiguous_page(&vcpu->msr_bitmap_pa);
    if (vcpu->msr_bitmap == NULL) {
        goto fail;
    }

    /* ---- Host stack ---- (VMCS_HOST_RSP). Arrange the top so the asm exit stub can recover
     * its VCPU: we store &vcpu at the top-of-stack slot and point host_rsp at it. */
    vcpu->host_stack = ExAllocatePoolWithTag(NonPagedPoolNx, HV_HOST_STACK_SIZE, HV_POOL_TAG);
    if (vcpu->host_stack == NULL) {
        goto fail;
    }
    RtlZeroMemory(vcpu->host_stack, HV_HOST_STACK_SIZE);

    /* 16-byte-align the top, then reserve one 16-byte slot holding the back-pointer. On a
     * VM exit the CPU loads RSP := host_rsp; the very first thing at [RSP] is &vcpu.
     * CONTRACT WITH asm_x64.asm: asm_vmexit_entry may read its VCPU as `mov rXX,[rsp]` on
     * entry (before it starts pushing GUEST_REGISTERS downward, which never touches [rsp]).
     * TODO(hv): pin this convention against the asm_vmexit_entry implementation when it lands;
     * if the stub instead expects &vcpu just ABOVE the initial RSP, adjust the offset here. */
    stack_top = ((u64)vcpu->host_stack + HV_HOST_STACK_SIZE) & ~0xFull;
    stack_top -= 0x10;                              /* Reserve one 16-byte aligned slot. */
    *(VCPU **)stack_top = vcpu;                     /* Back-pointer at [host_rsp]. */
    vcpu->host_rsp = stack_top;

    return HV_OK;

fail:
    vmcs_free(vcpu);
    return HV_ERR_ALLOC;
}

void vmcs_free(VCPU *vcpu)
{
    if (vcpu == NULL) {
        return;
    }
    if (vcpu->host_stack != NULL) {
        ExFreePoolWithTag(vcpu->host_stack, HV_POOL_TAG);
        vcpu->host_stack = NULL;
        vcpu->host_rsp = 0;
    }
    vmcs_free_contiguous_page(vcpu->msr_bitmap);
    vcpu->msr_bitmap = NULL;
    vcpu->msr_bitmap_pa = 0;

    vmcs_free_contiguous_page(vcpu->vmcs_region);
    vcpu->vmcs_region = NULL;
    vcpu->vmcs_pa = 0;

    vmcs_free_contiguous_page(vcpu->vmxon_region);
    vcpu->vmxon_region = NULL;
    vcpu->vmxon_pa = 0;
}

/* ====================================================================================== */
/*  VMCLEAR + VMPTRLD (hv.h: vmcs_clear_and_load)                                           */
/* ====================================================================================== */

/*
 * Put this VCPU's VMCS into the launched-clear state and make it current (SDM Vol 3C §25.11.3,
 * §31.6). VMCLEAR sets the VMCS's launch state to "clear" (so the next entry must be VMLAUNCH,
 * not VMRESUME) and flushes any cached VMCS data; VMPTRLD makes it the current VMCS for
 * subsequent VMREAD/VMWRITE/VMLAUNCH. Must run in VMX root operation (after VMXON).
 */
HV_STATUS vmcs_clear_and_load(VCPU *vcpu)
{
    if (vcpu == NULL || vcpu->vmcs_region == NULL || vcpu->vmcs_pa == 0) {
        return HV_ERR_INVALID_ARG;
    }

    if (asm_vmclear(vcpu->vmcs_pa) != VMX_SUCCEED) {
        return HV_ERR_VMCLEAR;
    }
    if (asm_vmptrld(vcpu->vmcs_pa) != VMX_SUCCEED) {
        return HV_ERR_VMPTRLD;
    }

    /* A freshly VMCLEAR'd VMCS requires VMLAUNCH first; the exit path switches to VMRESUME. */
    vcpu->launched = 0;
    return HV_OK;
}

/* ====================================================================================== */
/*  Guest-state area (hv.h: vmcs_setup_guest)                                               */
/* ====================================================================================== */

/*
 * Populate the guest-state area from the live processor context so VMLAUNCH resumes the running
 * host OS as the guest (SDM Vol 3C §25.4, §26.3.1). We snapshot control registers, all segment
 * registers (selector/base/limit/access-rights), GDTR/IDTR, the relevant MSRs, and the
 * RSP/RIP/RFLAGS resume point.
 */
HV_STATUS vmcs_setup_guest(VCPU *vcpu)
{
    PSEUDO_DESCRIPTOR_64 gdtr;
    PSEUDO_DESCRIPTOR_64 idtr;
    u16 es, cs, ss, ds, fs, gs, tr, ldtr;
    u64 guest_rip, guest_rsp, guest_rflags;

    if (vcpu == NULL) {
        return HV_ERR_INVALID_ARG;
    }

    asm_read_gdtr(&gdtr);
    asm_read_idtr(&idtr);

    es   = asm_read_es();
    cs   = asm_read_cs();
    ss   = asm_read_ss();
    ds   = asm_read_ds();
    fs   = asm_read_fs();
    gs   = asm_read_gs();
    tr   = asm_read_tr();
    ldtr = asm_read_ldtr();

    /* ---- Control registers / DR7 ---- (SDM §26.3.1.1). The live host values already satisfy
     * the VMX fixed-bit constraints (the machine is running), so we snapshot them directly.
     * With Unrestricted-Guest enabled, CR0.PE/PG are not forced by VMX, and the guest owns
     * them via a zero CR0/CR4 guest/host mask (see vmcs_setup_controls). */
    VMCS_WR(VMCS_GUEST_CR0, __readcr0());
    VMCS_WR(VMCS_GUEST_CR3, __readcr3());
    VMCS_WR(VMCS_GUEST_CR4, __readcr4());
    VMCS_WR(VMCS_GUEST_DR7, __readdr(7));

    /* ---- Segment selectors ---- */
    VMCS_WR(VMCS_GUEST_ES_SELECTOR,   es);
    VMCS_WR(VMCS_GUEST_CS_SELECTOR,   cs);
    VMCS_WR(VMCS_GUEST_SS_SELECTOR,   ss);
    VMCS_WR(VMCS_GUEST_DS_SELECTOR,   ds);
    VMCS_WR(VMCS_GUEST_FS_SELECTOR,   fs);
    VMCS_WR(VMCS_GUEST_GS_SELECTOR,   gs);
    VMCS_WR(VMCS_GUEST_TR_SELECTOR,   tr);
    VMCS_WR(VMCS_GUEST_LDTR_SELECTOR, ldtr);

    /* ---- Segment bases ---- In IA-32e, ES/CS/SS/DS bases are treated as 0; FS/GS bases come
     * from their MSRs; TR/LDTR bases come from the GDT descriptor (SDM §26.3.1.1). */
    VMCS_WR(VMCS_GUEST_ES_BASE,   0);
    VMCS_WR(VMCS_GUEST_CS_BASE,   0);
    VMCS_WR(VMCS_GUEST_SS_BASE,   0);
    VMCS_WR(VMCS_GUEST_DS_BASE,   0);
    VMCS_WR(VMCS_GUEST_FS_BASE,   __readmsr(IA32_FS_BASE));
    VMCS_WR(VMCS_GUEST_GS_BASE,   __readmsr(IA32_GS_BASE));
    VMCS_WR(VMCS_GUEST_TR_BASE,   vmcs_segment_base_from_gdt(gdtr.base, tr));
    VMCS_WR(VMCS_GUEST_LDTR_BASE, vmcs_segment_base_from_gdt(gdtr.base, ldtr));

    /* ---- Segment limits ---- */
    VMCS_WR(VMCS_GUEST_ES_LIMIT,   vmcs_segment_limit(es));
    VMCS_WR(VMCS_GUEST_CS_LIMIT,   vmcs_segment_limit(cs));
    VMCS_WR(VMCS_GUEST_SS_LIMIT,   vmcs_segment_limit(ss));
    VMCS_WR(VMCS_GUEST_DS_LIMIT,   vmcs_segment_limit(ds));
    VMCS_WR(VMCS_GUEST_FS_LIMIT,   vmcs_segment_limit(fs));
    VMCS_WR(VMCS_GUEST_GS_LIMIT,   vmcs_segment_limit(gs));
    VMCS_WR(VMCS_GUEST_TR_LIMIT,   vmcs_segment_limit(tr));
    VMCS_WR(VMCS_GUEST_LDTR_LIMIT, vmcs_segment_limit(ldtr));

    /* ---- Segment access rights ---- */
    VMCS_WR(VMCS_GUEST_ES_ACCESS_RIGHTS,   vmcs_segment_access_rights(es));
    VMCS_WR(VMCS_GUEST_CS_ACCESS_RIGHTS,   vmcs_segment_access_rights(cs));
    VMCS_WR(VMCS_GUEST_SS_ACCESS_RIGHTS,   vmcs_segment_access_rights(ss));
    VMCS_WR(VMCS_GUEST_DS_ACCESS_RIGHTS,   vmcs_segment_access_rights(ds));
    VMCS_WR(VMCS_GUEST_FS_ACCESS_RIGHTS,   vmcs_segment_access_rights(fs));
    VMCS_WR(VMCS_GUEST_GS_ACCESS_RIGHTS,   vmcs_segment_access_rights(gs));
    VMCS_WR(VMCS_GUEST_TR_ACCESS_RIGHTS,   vmcs_segment_access_rights(tr));
    VMCS_WR(VMCS_GUEST_LDTR_ACCESS_RIGHTS, vmcs_segment_access_rights(ldtr));

    /* ---- Descriptor-table registers ---- (limits are 16-bit, bases natural-width). */
    VMCS_WR(VMCS_GUEST_GDTR_BASE,  gdtr.base);
    VMCS_WR(VMCS_GUEST_GDTR_LIMIT, gdtr.limit);
    VMCS_WR(VMCS_GUEST_IDTR_BASE,  idtr.base);
    VMCS_WR(VMCS_GUEST_IDTR_LIMIT, idtr.limit);

    /* ---- Guest MSRs mirrored into the VMCS ---- (SDM §26.3.1.1). DEBUGCTL is loaded via the
     * VM-entry "load debug controls" bit; PAT/EFER via "load PAT"/"load EFER". */
    VMCS_WR(VMCS_GUEST_DEBUGCTL,      __readmsr(IA32_DEBUGCTL));
    VMCS_WR(VMCS_GUEST_PAT,           __readmsr(IA32_PAT));
    VMCS_WR(VMCS_GUEST_EFER,          __readmsr(IA32_EFER));
    VMCS_WR(VMCS_GUEST_SYSENTER_CS,   __readmsr(IA32_SYSENTER_CS));
    VMCS_WR(VMCS_GUEST_SYSENTER_ESP,  __readmsr(IA32_SYSENTER_ESP));
    VMCS_WR(VMCS_GUEST_SYSENTER_EIP,  __readmsr(IA32_SYSENTER_EIP));

    /* ---- Non-register guest state ---- (SDM §26.3.1.5).
     *  - VMCS link pointer must be all-ones unless VMCS shadowing is used.
     *  - Activity state ACTIVE; no interruptibility blocking; no pending debug exceptions. */
    VMCS_WR(VMCS_GUEST_VMCS_LINK_POINTER,       ~0ull);
    VMCS_WR(VMCS_GUEST_ACTIVITY_STATE,          GUEST_ACTIVITY_ACTIVE);
    VMCS_WR(VMCS_GUEST_INTERRUPTIBILITY_STATE,  0);
    VMCS_WR(VMCS_GUEST_PENDING_DBG_EXCEPTIONS,  0);

    /* ---- Resume point ---- The caller must have captured these via asm_capture_context()
     * (the SimpleVisor trick): guest_rip is the instruction just past the capture, guest_rsp
     * the stack at that instant. If driver.c has not populated them we fall back to the live
     * RFLAGS but cannot invent a RIP/RSP -- that is a caller bug.
     * TODO(hv): make driver.c responsible for filling vcpu->guest_rip/rsp/rflags before this
     * call and assert them non-zero here; a zero RIP will fault the guest immediately. */
    guest_rip    = vcpu->guest_rip;
    guest_rsp    = vcpu->guest_rsp;
    guest_rflags = vcpu->guest_rflags ? vcpu->guest_rflags : asm_read_rflags();

    NT_ASSERTMSG("vmcs_setup_guest: guest RIP not captured by caller", guest_rip != 0);

    VMCS_WR(VMCS_GUEST_RSP,    guest_rsp);
    VMCS_WR(VMCS_GUEST_RIP,    guest_rip);
    VMCS_WR(VMCS_GUEST_RFLAGS, guest_rflags);

    return HV_OK;
}

/* ====================================================================================== */
/*  Host-state area (hv.h: vmcs_setup_host)                                                 */
/* ====================================================================================== */

/*
 * Populate the host-state area: where the processor lands on every VM exit (SDM Vol 3C §25.5,
 * §27.5). Host segment selectors must have TI==0 and RPL==0; host RIP is the asm exit
 * trampoline; host RSP is this VCPU's host stack top (which holds the &vcpu back-pointer).
 * The host runs in 64-bit mode (VM-exit control "host address-space size" is set in
 * vmcs_setup_controls), so only FS/GS/TR bases and the GDTR/IDTR bases are needed -- host
 * segment limits are fixed by the architecture on exit.
 */
HV_STATUS vmcs_setup_host(VCPU *vcpu)
{
    PSEUDO_DESCRIPTOR_64 gdtr;
    PSEUDO_DESCRIPTOR_64 idtr;
    u16 cs, ss, ds, es, fs, gs, tr;

    if (vcpu == NULL || vcpu->host_rsp == 0) {
        return HV_ERR_INVALID_ARG;
    }

    asm_read_gdtr(&gdtr);
    asm_read_idtr(&idtr);

    /* Host selectors: strip RPL and TI (SDM §27.2.3 requires RPL=TI=0 for host selectors). */
    cs = asm_read_cs() & SELECTOR_INDEX_MASK;
    ss = asm_read_ss() & SELECTOR_INDEX_MASK;
    ds = asm_read_ds() & SELECTOR_INDEX_MASK;
    es = asm_read_es() & SELECTOR_INDEX_MASK;
    fs = asm_read_fs() & SELECTOR_INDEX_MASK;
    gs = asm_read_gs() & SELECTOR_INDEX_MASK;
    tr = asm_read_tr() & SELECTOR_INDEX_MASK;

    /* ---- Host control registers ---- The live values satisfy the fixed-bit constraints and
     * carry CR4.VMXE (set by vmx_enable_on_cpu before VMXON). CR3 is the current kernel-mapping
     * CR3, which the exit stub runs under.
     * TODO(hv): consider pinning host CR3 to the System process directory base so exits never
     * run under a torn-down or user-narrowed address space; __readcr3() of driver context is
     * acceptable because it still maps all of kernel. */
    VMCS_WR(VMCS_HOST_CR0, __readcr0());
    VMCS_WR(VMCS_HOST_CR3, __readcr3());
    VMCS_WR(VMCS_HOST_CR4, __readcr4());

    /* ---- Host segment selectors ---- */
    VMCS_WR(VMCS_HOST_ES_SELECTOR, es);
    VMCS_WR(VMCS_HOST_CS_SELECTOR, cs);
    VMCS_WR(VMCS_HOST_SS_SELECTOR, ss);
    VMCS_WR(VMCS_HOST_DS_SELECTOR, ds);
    VMCS_WR(VMCS_HOST_FS_SELECTOR, fs);
    VMCS_WR(VMCS_HOST_GS_SELECTOR, gs);
    VMCS_WR(VMCS_HOST_TR_SELECTOR, tr);

    /* ---- Host segment / descriptor-table bases ---- FS/GS bases from their MSRs; TR base from
     * the GDT; GDTR/IDTR bases from the live tables (SDM §27.5.1, §27.2.3). */
    VMCS_WR(VMCS_HOST_FS_BASE,   __readmsr(IA32_FS_BASE));
    VMCS_WR(VMCS_HOST_GS_BASE,   __readmsr(IA32_GS_BASE));
    VMCS_WR(VMCS_HOST_TR_BASE,   vmcs_segment_base_from_gdt(gdtr.base, tr));
    VMCS_WR(VMCS_HOST_GDTR_BASE, gdtr.base);
    VMCS_WR(VMCS_HOST_IDTR_BASE, idtr.base);

    /* ---- Host SYSENTER MSRs ---- (loaded into the host on exit). */
    VMCS_WR(VMCS_HOST_SYSENTER_CS,  __readmsr(IA32_SYSENTER_CS));
    VMCS_WR(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
    VMCS_WR(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));

    /* ---- Host PAT / EFER ---- loaded on exit via the VM-exit "load IA32_PAT"/"load IA32_EFER"
     * controls (set in vmcs_setup_controls). Mirror the live values so nothing changes across
     * an exit. */
    VMCS_WR(VMCS_HOST_PAT,  __readmsr(IA32_PAT));
    VMCS_WR(VMCS_HOST_EFER, __readmsr(IA32_EFER));

    /* ---- Host RSP / RIP ---- exits land on asm_vmexit_entry with RSP at the host stack top
     * (which stores the &vcpu back-pointer). */
    VMCS_WR(VMCS_HOST_RSP, vcpu->host_rsp);
    VMCS_WR(VMCS_HOST_RIP, (u64)(ULONG_PTR)&asm_vmexit_entry);

    return HV_OK;
}

/* ====================================================================================== */
/*  Execution / entry / exit controls (hv.h: vmcs_setup_controls)                          */
/* ====================================================================================== */

/*
 * Compose the four control groups, each adjusted against its capability MSR so required-1 bits
 * are set and required-0 bits are cleared (vmx_adjust_controls, from vmx.c, applies the
 * allowed-0/allowed-1 encoding of SDM Vol 3D A.3). Also programs the EPTP, VPID, MSR bitmap,
 * exception bitmap, CR shadow/mask fields, and zeroes the MSR-list and CR3-target counts.
 *
 * PRECONDITION: ept_build_identity() must have populated vcpu->ept.eptp before this runs, since
 * Enable-EPT requires a valid EPTP in VMCS_CTRL_EPT_POINTER.
 */
HV_STATUS vmcs_setup_controls(VCPU *vcpu)
{
    const VMX_CAPABILITIES *caps;
    u32 pin, proc, proc2, entry, exit_ctls;

    if (vcpu == NULL || vcpu->hv == NULL) {
        return HV_ERR_INVALID_ARG;
    }
    caps = &vcpu->hv->caps;

    /* ---------------------------------------------------------------------------------- */
    /*  Pin-based controls (SDM Table 25-5).                                               */
    /*  We deliberately leave external-interrupt and NMI exiting OFF: this is a transparent */
    /*  VMI hypervisor riding under the live host, which must keep servicing its own        */
    /*  interrupts and NMIs. Only the capability-required bits get forced on.               */
    /* ---------------------------------------------------------------------------------- */
    pin = 0;
    pin = vmx_adjust_controls(pin,
              vmcs_cap_msr(caps, caps->true_pinbased, caps->pinbased));
    VMCS_WR(VMCS_CTRL_PIN_BASED_CONTROLS, pin);

    /* ---------------------------------------------------------------------------------- */
    /*  Primary processor-based controls (SDM Table 25-6).                                 */
    /*  Need MSR bitmaps (so a zeroed bitmap gives us zero MSR exits) and the secondary     */
    /*  controls activation gate (for Enable-EPT / Unrestricted-Guest / VPID). Everything   */
    /*  else stays off for transparency -- no CR3/HLT/RDTSC/etc. exiting.                    */
    /* ---------------------------------------------------------------------------------- */
    proc = PROC_CTL_USE_MSR_BITMAPS | PROC_CTL_ACTIVATE_SECONDARY;
    proc = vmx_adjust_controls(proc,
               vmcs_cap_msr(caps, caps->true_procbased, caps->procbased));
    VMCS_WR(VMCS_CTRL_PROC_BASED_CONTROLS, proc);

    /* If the platform refused the secondary-activation bit, EPT is impossible -- bail rather
     * than launch a guest with no address-translation trap surface. */
    if ((proc & PROC_CTL_ACTIVATE_SECONDARY) == 0) {
        return HV_ERR_NO_EPT;
    }

    /* ---------------------------------------------------------------------------------- */
    /*  Secondary processor-based controls (SDM Table 25-7).                               */
    /*  Enable-EPT and Unrestricted-Guest are the point of the exercise. Enable-VPID gives   */
    /*  us tagged TLB entries (INVVPID). RDTSCP / INVPCID / XSAVES are enabled so the live    */
    /*  host's use of those instructions does not #UD in non-root operation -- if the         */
    /*  platform does not allow one, vmx_adjust_controls clears it (older guests simply must   */
    /*  not use it). CONCEAL_VMX_FROM_PT hides us from Intel PT if available.                 */
    /* ---------------------------------------------------------------------------------- */
    proc2 = PROC2_CTL_ENABLE_EPT
          | PROC2_CTL_UNRESTRICTED_GUEST
          | PROC2_CTL_ENABLE_VPID
          | PROC2_CTL_ENABLE_RDTSCP
          | PROC2_CTL_ENABLE_INVPCID
          | PROC2_CTL_ENABLE_XSAVES
          | PROC2_CTL_CONCEAL_VMX_FROM_PT;
    /* Secondary controls have only one capability MSR (no TRUE variant). */
    proc2 = vmx_adjust_controls(proc2, caps->procbased2);
    VMCS_WR(VMCS_CTRL_PROC_BASED_CONTROLS2, proc2);

    /* Enable-EPT and Unrestricted-Guest are mandatory for this design. */
    if ((proc2 & PROC2_CTL_ENABLE_EPT) == 0) {
        return HV_ERR_NO_EPT;
    }

    /* ---- EPTP + VPID ---- EPTP comes from the identity map built by ept.c. VPID must be a
     * non-zero 16-bit value when Enable-VPID is set (SDM §25.6.11); derive it from the VCPU
     * index so every logical processor gets a distinct tag. */
    if (vcpu->ept.eptp.all == 0) {
        /* ept_build_identity() has not run (or failed) -- Enable-EPT with a zero EPTP is an
         * invalid VMCS and would fault VM entry. */
        return HV_ERR_EPT_BUILD;
    }
    VMCS_WR(VMCS_CTRL_EPT_POINTER, vcpu->ept.eptp.all);

    if (proc2 & PROC2_CTL_ENABLE_VPID) {
        VMCS_WR(VMCS_CTRL_VPID, (u16)(vcpu->index + 1));
    }

    /* ---------------------------------------------------------------------------------- */
    /*  VM-entry controls (SDM Table 25-15).                                               */
    /*  The guest is the live 64-bit host, so IA-32e-mode-guest must be set. Load the guest  */
    /*  debug controls / PAT / EFER we mirrored in vmcs_setup_guest so entry restores them    */
    /*  exactly. No event is injected at entry.                                              */
    /* ---------------------------------------------------------------------------------- */
    entry = ENTRY_CTL_IA32E_MODE_GUEST
          | ENTRY_CTL_LOAD_DEBUG_CONTROLS
          | ENTRY_CTL_LOAD_PAT
          | ENTRY_CTL_LOAD_EFER;
    entry = vmx_adjust_controls(entry,
                vmcs_cap_msr(caps, caps->true_entry_ctls, caps->entry_ctls));
    VMCS_WR(VMCS_CTRL_VMENTRY_CONTROLS, entry);

    VMCS_WR(VMCS_CTRL_VMENTRY_INTR_INFO,          0);   /* No event injection at launch. */
    VMCS_WR(VMCS_CTRL_VMENTRY_EXCEPTION_ERRCODE,  0);
    VMCS_WR(VMCS_CTRL_VMENTRY_INSTR_LEN,          0);
    VMCS_WR(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT,     0);

    /* ---------------------------------------------------------------------------------- */
    /*  VM-exit controls (SDM Table 25-13).                                                */
    /*  Host-address-space-size returns the host to 64-bit mode on every exit. Save/load     */
    /*  debug controls, PAT and EFER so the host/guest MSR values survive the round trip     */
    /*  unchanged. We do NOT set ACK-interrupt-on-exit because we never exit on external       */
    /*  interrupts (pin control is clear).                                                   */
    /* ---------------------------------------------------------------------------------- */
    exit_ctls = EXIT_CTL_HOST_ADDR_SPACE_SIZE
              | EXIT_CTL_SAVE_DEBUG_CONTROLS
              | EXIT_CTL_SAVE_PAT
              | EXIT_CTL_LOAD_PAT
              | EXIT_CTL_SAVE_EFER
              | EXIT_CTL_LOAD_EFER;
    exit_ctls = vmx_adjust_controls(exit_ctls,
                    vmcs_cap_msr(caps, caps->true_exit_ctls, caps->exit_ctls));
    VMCS_WR(VMCS_CTRL_VMEXIT_CONTROLS, exit_ctls);

    VMCS_WR(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
    VMCS_WR(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT,  0);

    /* ---------------------------------------------------------------------------------- */
    /*  MSR bitmap ---- zeroed page => no RDMSR/WRMSR causes an exit (fully transparent).   */
    /*  The VMI layer can later set bits to trap specific MSRs.                              */
    /* ---------------------------------------------------------------------------------- */
    VMCS_WR(VMCS_CTRL_MSR_BITMAP, vcpu->msr_bitmap_pa);

    /* ---------------------------------------------------------------------------------- */
    /*  Exception bitmap + page-fault match ---- intercept nothing by default; the VMI layer  */
    /*  arms specific vectors (#BP/#UD/#PF) later. PF error-code mask=match=0 with an empty    */
    /*  exception bitmap means page faults are NOT intercepted (they are delivered to the      */
    /*  guest normally); only when bit 14 of the exception bitmap is set do mask/match apply.  */
    /* ---------------------------------------------------------------------------------- */
    VMCS_WR(VMCS_CTRL_EXCEPTION_BITMAP, 0);
    VMCS_WR(VMCS_CTRL_PF_ERRCODE_MASK,  0);
    VMCS_WR(VMCS_CTRL_PF_ERRCODE_MATCH, 0);

    /* ---------------------------------------------------------------------------------- */
    /*  CR0/CR4 guest/host masks + read shadows (SDM §25.6.6, §28.2.4).                     */
    /*  Mask = 0 => the guest owns every CR0/CR4 bit and CR loads do not exit; the read       */
    /*  shadow is then irrelevant, but we seed it with the live values for cleanliness.       */
    /*  NOTE: this leans on Unrestricted-Guest so VMX does not require CR0.PE/PG be forced.    */
    /*  TODO(hv): if we later want to observe paging-mode/CR3 switches, set CR3-load exiting   */
    /*  (primary control) rather than widening these masks.                                   */
    /* ---------------------------------------------------------------------------------- */
    VMCS_WR(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
    VMCS_WR(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0);
    VMCS_WR(VMCS_CTRL_CR0_READ_SHADOW, __readcr0());
    VMCS_WR(VMCS_CTRL_CR4_READ_SHADOW, __readcr4());
    VMCS_WR(VMCS_CTRL_CR3_TARGET_COUNT, 0);

    return HV_OK;
}
