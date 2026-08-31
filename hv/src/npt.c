/*
 * npt.c -- Identity NPT construction and the write-then-execute watch primitive.
 * AMD peer of ept.c. Per hv.h: npt_build_identity, npt_split_2mb, npt_set_page_perms,
 * npt_watch_page/unwatch/find, npt_invalidate.
 *
 * CLEAN-ROOM PROVENANCE: written from the AMD64 APM Vol 2:
 *   Nested paging                    §15.25
 *   Standard IA-32e paging entries   §5.3.4  (P/RW/US/PWT/PCD/A/D/PS/G/PAT/NX)
 *   NPT effective memory type        §15.25.8
 * All constants come from npt_defs.h / arch.h -- no magic numbers below.
 *
 * DESIGN. NPT reuses the standard IA-32e paging format: 4 levels, 512 8-byte entries per
 * level, PS-bit on a PDE or PDPTE denotes a large page. Identity map means "for every valid
 * host physical range, GPA == HPA". We start with 1-GiB pages at the PDPTE level (one page
 * covers 1 GiB, so 512 entries in one PDPT cover the entire canonical 512-GiB PML4 slot at
 * the low end -- more than enough for any physical RAM this HV would actually see). When
 * the analyst arms a watch on a specific 4 KiB GPA, we walk the tree splitting on demand:
 * 1 GiB -> 512 2 MiB PDEs (allocate one PD), 2 MiB -> 512 4 KiB PTEs (allocate one PT), then
 * flip the target PTE's permissions.
 *
 * MEMORY TYPES. First cut hard-codes write-back (WB) for every mapped page. That is
 * correct for ordinary RAM and wrong for MMIO regions -- so the current NPT should not be
 * pointed at a device MMIO range. Aletheia's targets are userland processes, so this is a
 * legitimate first-cut simplification. TODO(hv): a proper MTRR-derived memory type per
 * region (mirror ept.c's ept_memtype_for_gpa walk against MSR_MTRRphys*_BASE/MASK etc).
 *
 * CANNOT BE BUILT OR RUN IN THIS ENVIRONMENT. // TODO(hv): markers on unverified spots.
 */

#include "hv.h"

#if DBG
#define HV_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[aletheia-npt] " fmt "\n", __VA_ARGS__)
#else
#define HV_LOG(fmt, ...) ((void)0)
#endif

/* -------------------------------------------------------------------------------------- */
/*  Local page allocator                                                                    */
/* -------------------------------------------------------------------------------------- */
static void *npt_alloc_page(u64 *pa_out)
{
    PHYSICAL_ADDRESS low, high, boundary;
    void *va;
    low.QuadPart = 0;
    high.QuadPart = (LONGLONG)0xFFFFFFFFFFFFFFFFULL;
    boundary.QuadPart = 0;
    va = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE_4K, low, high, boundary, MmCached);
    if (va == NULL) {
        *pa_out = 0;
        return NULL;
    }
    RtlZeroMemory(va, PAGE_SIZE_4K);
    *pa_out = MmGetPhysicalAddress(va).QuadPart;
    return va;
}

static void npt_free_page(void *va)
{
    if (va)
        MmFreeContiguousMemory(va);
}

/* -------------------------------------------------------------------------------------- */
/*  Entry helpers                                                                            */
/* -------------------------------------------------------------------------------------- */
static NPT_ENTRY npt_make_leaf_4k(u64 hpa)
{
    NPT_ENTRY e;
    e.flags = 0;
    e.bits.p   = 1;
    e.bits.rw  = 1;
    e.bits.us  = 1;                            /* NPT ignores US for guest-mode enforcement.    */
    e.bits.pfn = (hpa >> NPT_PT_SHIFT) & ((1ull << 40) - 1);
    /* nx=0: executable by default. */
    return e;
}

static NPT_ENTRY npt_make_large_2mb(u64 hpa)
{
    NPT_ENTRY e;
    e.flags = 0;
    e.bits.p         = 1;
    e.bits.rw        = 1;
    e.bits.us        = 1;
    e.bits.ps_or_pat = 1;                       /* PS = 1 in a PDE -> 2 MiB page.                */
    e.bits.pfn       = (hpa >> NPT_PT_SHIFT) & ((1ull << 40) - 1);
    return e;
}

static NPT_ENTRY npt_make_large_1gb(u64 hpa)
{
    NPT_ENTRY e;
    e.flags = 0;
    e.bits.p         = 1;
    e.bits.rw        = 1;
    e.bits.us        = 1;
    e.bits.ps_or_pat = 1;                       /* PS = 1 in a PDPTE -> 1 GiB page.              */
    e.bits.pfn       = (hpa >> NPT_PT_SHIFT) & ((1ull << 40) - 1);
    return e;
}

static NPT_ENTRY npt_make_table(u64 child_pa)
{
    NPT_ENTRY e;
    e.flags = 0;
    e.bits.p   = 1;
    e.bits.rw  = 1;
    e.bits.us  = 1;
    e.bits.pfn = (child_pa >> NPT_PT_SHIFT) & ((1ull << 40) - 1);
    return e;
}

/* Physical address of the next-level table an entry points at. */
static u64 npt_entry_child_pa(NPT_ENTRY e)
{
    return ((u64)e.bits.pfn) << NPT_PT_SHIFT;
}

/* MmGetVirtualForPhysical: turn the PA back into our VA so we can index the next level. Every
 * table we allocated is mapped in the kernel virtual space by the contiguous allocator. */
static void *npt_child_va(u64 child_pa)
{
    PHYSICAL_ADDRESS p;
    p.QuadPart = child_pa;
    return MmGetVirtualForPhysical(p);
}

/* ====================================================================================== */
/*  Build the identity map                                                                  */
/* ====================================================================================== */

/*
 * Populate the top of the address space with 1-GiB identity PDPTEs. One PML4E covers 512
 * GiB; one PDPT it points at covers the whole thing. In practice a Windows box has orders
 * of magnitude less physical RAM than that, so a single low PML4E is enough. Future work
 * (TODO(hv)) is to extend to whatever RAM ranges the memory manager reports rather than
 * blanket-mapping the low 512 GiB.
 */
HV_STATUS npt_build_identity(VCPU *vcpu)
{
    NPT_PML4 *pml4;
    NPT_PDPT *pdpt;
    u64 pdpt_pa;
    int i;

    if (vcpu == NULL)
        return HV_ERR_INVALID_ARG;

    pml4 = (NPT_PML4 *)npt_alloc_page(&vcpu->npt.pml4_pa);
    if (pml4 == NULL) return HV_ERR_ALLOC;
    vcpu->npt.pml4 = pml4;

    pdpt = (NPT_PDPT *)npt_alloc_page(&pdpt_pa);
    if (pdpt == NULL) { npt_free_page(pml4); vcpu->npt.pml4 = NULL; return HV_ERR_ALLOC; }

    /* PML4[0] -> PDPT. Every other PML4 slot stays not-present. */
    (*pml4)[0] = npt_make_table(pdpt_pa);

    /* PDPT[i] -> 1 GiB identity page at HPA i*1GiB. */
    for (i = 0; i < NPT_ENTRIES_PER_TABLE; i++) {
        u64 hpa = ((u64)i) << NPT_PDPT_SHIFT;
        (*pdpt)[i] = npt_make_large_1gb(hpa);
    }

    HV_LOG("cpu%u: identity NPT built (PML4 PA=0x%llx, 512x1GiB via one PDPT)",
           vcpu->index, vcpu->npt.pml4_pa);
    return HV_OK;
}

/* Free every table reachable from PML4. First cut only touches PML4[0] since that is the
 * only slot npt_build_identity populates; on-demand splits allocated further tables that
 * we walk here. */
static void npt_free_subtree(NPT_ENTRY *table, int level)
{
    int i;
    if (table == NULL) return;
    /* level: 4 = PML4, 3 = PDPT, 2 = PD, 1 = PT. */
    if (level > 1) {
        for (i = 0; i < NPT_ENTRIES_PER_TABLE; i++) {
            NPT_ENTRY e = table[i];
            if (!e.bits.p) continue;
            if (level >= 2 && e.bits.ps_or_pat)
                continue;                                     /* Leaf large page; nothing to free. */
            {
                u64 pa = npt_entry_child_pa(e);
                void *child = npt_child_va(pa);
                npt_free_subtree((NPT_ENTRY *)child, level - 1);
            }
        }
    }
    /* Level-1 tables are leaves: their entries point at final host pages, not sub-tables. */
    npt_free_page(table);
}

void npt_destroy(VCPU *vcpu)
{
    if (vcpu == NULL || vcpu->npt.pml4 == NULL) return;
    npt_free_subtree((NPT_ENTRY *)vcpu->npt.pml4, 4);
    vcpu->npt.pml4 = NULL;
    vcpu->npt.pml4_pa = 0;
}

/* ====================================================================================== */
/*  On-demand split                                                                         */
/* ====================================================================================== */

/*
 * Split the 1-GiB PDPTE covering `gpa` into 512 2-MiB PDEs. Returns HV_OK on success or
 * if the covering entry is already split. Idempotent.
 */
static HV_STATUS npt_split_1gb(VCPU *vcpu, u64 gpa)
{
    NPT_PDPT *pdpt;
    NPT_PD   *pd;                  /* pointer to the 512-entry array, not a single entry */
    u64 pd_pa, base;
    int pdpt_i, i;

    if (vcpu == NULL || vcpu->npt.pml4 == NULL) return HV_ERR_INVALID_ARG;

    {
        NPT_PML4E e = (*vcpu->npt.pml4)[NPT_PML4_INDEX(gpa)];
        if (!e.bits.p) return HV_ERR_INVALID_ARG;
        pdpt = (NPT_PDPT *)npt_child_va(npt_entry_child_pa(e));
    }

    pdpt_i = (int)NPT_PDPT_INDEX(gpa);
    {
        NPT_PDPTE e = (*pdpt)[pdpt_i];
        if (!e.bits.p) return HV_ERR_INVALID_ARG;
        if (!e.bits.ps_or_pat) return HV_OK;                  /* Already split. */
    }

    pd = (NPT_PD *)npt_alloc_page(&pd_pa);
    if (pd == NULL) return HV_ERR_ALLOC;

    base = ((u64)pdpt_i) << NPT_PDPT_SHIFT;
    for (i = 0; i < NPT_ENTRIES_PER_TABLE; i++) {
        u64 hpa = base + (((u64)i) << NPT_PD_SHIFT);
        (*pd)[i] = npt_make_large_2mb(hpa);
    }

    (*pdpt)[pdpt_i] = npt_make_table(pd_pa);
    vcpu->npt.pages_split_1gb++;
    return HV_OK;
}

/*
 * Split the 2-MiB PDE covering `gpa` into 512 4-KiB PTEs. Auto-splits the enclosing 1-GiB
 * region first if necessary. Idempotent.
 */
HV_STATUS npt_split_2mb(VCPU *vcpu, u64 gpa)
{
    NPT_PDPT *pdpt;
    NPT_PD   *pd;
    NPT_PT   *pt;
    u64 pt_pa, base;
    int pd_i, i;
    HV_STATUS st;

    if (vcpu == NULL || vcpu->npt.pml4 == NULL) return HV_ERR_INVALID_ARG;

    st = npt_split_1gb(vcpu, gpa);
    if (st != HV_OK) return st;

    {
        NPT_PML4E e = (*vcpu->npt.pml4)[NPT_PML4_INDEX(gpa)];
        pdpt = (NPT_PDPT *)npt_child_va(npt_entry_child_pa(e));
    }
    {
        NPT_PDPTE e = (*pdpt)[NPT_PDPT_INDEX(gpa)];
        pd = (NPT_PD *)npt_child_va(npt_entry_child_pa(e));
    }

    pd_i = (int)NPT_PD_INDEX(gpa);
    {
        NPT_PDE e = (*pd)[pd_i];
        if (!e.bits.p) return HV_ERR_INVALID_ARG;
        if (!e.bits.ps_or_pat) return HV_OK;                  /* Already split. */
    }

    pt = (NPT_PT *)npt_alloc_page(&pt_pa);
    if (pt == NULL) return HV_ERR_ALLOC;

    base = (gpa & ~(NPT_2MB_SIZE - 1));
    for (i = 0; i < NPT_ENTRIES_PER_TABLE; i++) {
        u64 hpa = base + (((u64)i) << NPT_PT_SHIFT);
        (*pt)[i] = npt_make_leaf_4k(hpa);
    }

    (*pd)[pd_i] = npt_make_table(pt_pa);
    vcpu->npt.pages_split_2mb++;
    return HV_OK;
}

/* ====================================================================================== */
/*  Locate a 4 KiB PTE for a GPA (splitting on demand)                                     */
/* ====================================================================================== */

NPT_PTE *npt_get_pte(VCPU *vcpu, u64 gpa, int allocate_split)
{
    NPT_PDPT *pdpt;
    NPT_PD   *pd;
    NPT_PT   *pt;
    HV_STATUS st;

    if (vcpu == NULL || vcpu->npt.pml4 == NULL) return NULL;

    if (allocate_split) {
        st = npt_split_2mb(vcpu, gpa);
        if (st != HV_OK) return NULL;
    }

    {
        NPT_PML4E e = (*vcpu->npt.pml4)[NPT_PML4_INDEX(gpa)];
        if (!e.bits.p) return NULL;
        pdpt = (NPT_PDPT *)npt_child_va(npt_entry_child_pa(e));
    }
    {
        NPT_PDPTE e = (*pdpt)[NPT_PDPT_INDEX(gpa)];
        if (!e.bits.p || e.bits.ps_or_pat) return NULL;       /* Still a 1 GiB leaf.       */
        pd = (NPT_PD *)npt_child_va(npt_entry_child_pa(e));
    }
    {
        NPT_PDE e = (*pd)[NPT_PD_INDEX(gpa)];
        if (!e.bits.p || e.bits.ps_or_pat) return NULL;       /* Still a 2 MiB leaf.       */
        pt = (NPT_PT *)npt_child_va(npt_entry_child_pa(e));
    }
    return &(*pt)[NPT_PT_INDEX(gpa)];
}

/* ====================================================================================== */
/*  W^X permission flip                                                                     */
/* ====================================================================================== */

HV_STATUS npt_set_page_perms(VCPU *vcpu, u64 gpa, u8 state)
{
    NPT_PTE *pte = npt_get_pte(vcpu, gpa, 1);
    NPT_ENTRY e;
    if (pte == NULL) return HV_ERR_INVALID_ARG;

    e = *pte;
    if (!e.bits.p) return HV_ERR_INVALID_ARG;

    switch (state) {
    case NPT_WATCH_STATE_NORMAL:  e.bits.rw = 1; e.bits.nx = 0; break;
    case NPT_WATCH_STATE_W_TRAP:  e.bits.rw = 1; e.bits.nx = 1; break;
    case NPT_WATCH_STATE_X_TRAP:  e.bits.rw = 0; e.bits.nx = 0; break;
    default: return HV_ERR_INVALID_ARG;
    }
    *pte = e;
    npt_invalidate(vcpu);
    return HV_OK;
}

/* ====================================================================================== */
/*  Watch table                                                                             */
/* ====================================================================================== */

static NPT_WATCH *npt_alloc_watch_slot(VCPU *vcpu)
{
    u32 i;
    for (i = 0; i < RTL_NUMBER_OF(vcpu->npt_watches); i++) {
        if (!vcpu->npt_watches[i].armed) {
            RtlZeroMemory(&vcpu->npt_watches[i], sizeof(vcpu->npt_watches[i]));
            vcpu->npt_watches[i].armed = 1;
            vcpu->npt_watch_count++;
            return &vcpu->npt_watches[i];
        }
    }
    return NULL;
}

NPT_WATCH *npt_find_watch(VCPU *vcpu, u64 gpa)
{
    u32 i;
    u64 page = gpa & ~(u64)(PAGE_SIZE_4K - 1);
    for (i = 0; i < RTL_NUMBER_OF(vcpu->npt_watches); i++) {
        if (vcpu->npt_watches[i].armed && vcpu->npt_watches[i].gpa == page)
            return &vcpu->npt_watches[i];
    }
    return NULL;
}

HV_STATUS npt_watch_page(VCPU *vcpu, u64 gpa)
{
    NPT_WATCH *w;
    NPT_PTE *pte;
    u64 page;
    HV_STATUS st;

    if (vcpu == NULL) return HV_ERR_INVALID_ARG;
    page = gpa & ~(u64)(PAGE_SIZE_4K - 1);

    if (npt_find_watch(vcpu, page)) return HV_OK;             /* Already watched.           */

    w = npt_alloc_watch_slot(vcpu);
    if (w == NULL) return HV_ERR_ALLOC;

    pte = npt_get_pte(vcpu, page, 1);
    if (pte == NULL) { w->armed = 0; vcpu->npt_watch_count--; return HV_ERR_INVALID_ARG; }

    w->gpa = page;
    w->pte = pte;
    w->pfn = ((u64)pte->bits.pfn) << NPT_PT_SHIFT;
    w->current = NPT_WATCH_STATE_W_TRAP;                      /* Start by catching execs.   */

    st = npt_set_page_perms(vcpu, page, NPT_WATCH_STATE_W_TRAP);
    if (st != HV_OK) { w->armed = 0; vcpu->npt_watch_count--; }
    return st;
}

HV_STATUS npt_unwatch_page(VCPU *vcpu, u64 gpa)
{
    NPT_WATCH *w = npt_find_watch(vcpu, gpa);
    if (w == NULL) return HV_ERR_INVALID_ARG;

    (void)npt_set_page_perms(vcpu, w->gpa, NPT_WATCH_STATE_NORMAL);
    w->armed = 0;
    vcpu->npt_watch_count--;
    return HV_OK;
}

/* ====================================================================================== */
/*  TLB maintenance                                                                         */
/*                                                                                          */
/*  APM §15.16 / §15.30: on a page-perm change we must invalidate the guest ASID's TLB, or   */
/*  the CPU may keep using cached translations with the old (stale) permissions.             */
/*  First-cut: request FLUSH_THIS_GUEST on the next VMRUN via TLB_CONTROL. That's coarse    */
/*  but always correct. TODO(hv): switch to per-page INVLPGA once we're confident.           */
/* ====================================================================================== */

void npt_invalidate(VCPU *vcpu)
{
    if (vcpu == NULL || vcpu->vmcb == NULL) return;
    if (g_hv.svm_caps.flush_by_asid)
        vcpu->vmcb->control.tlb_control = SVM_TLB_CONTROL_FLUSH_THIS_GUEST;
    else
        vcpu->vmcb->control.tlb_control = SVM_TLB_CONTROL_FLUSH_ALL_ASIDS;
    /* Also clear the NP clean bit so hardware honours the change on the next VMRUN. */
    vcpu->vmcb->control.vmcb_clean &= ~VMCB_CLEAN_NP;
}
