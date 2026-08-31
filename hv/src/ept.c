/*
 * ept.c -- Extended Page Table (EPT) construction and the write-then-execute watch
 * primitives for the Aletheia clean-room VT-x/EPT VMI hypervisor.
 *
 * CLEAN-ROOM PROVENANCE: Every EPT paging-structure bit, EPTP field, INVEPT descriptor,
 * and MTRR rule used here is transcribed from the public Intel(R) SDM:
 *   - EPT paging-structure formats + EPTP  : Vol 3C Chapter 29 (29.3.2, 29.3.3, Table 25-9)
 *   - EPT memory-type selection / MTRR     : Vol 3A Chapter 11 (11.11, 11.12), Vol 3C 29.3.7
 *   - INVEPT                               : Vol 3C 29.4.3 / 31.4.1
 *   - IA32_VMX_EPT_VPID_CAP                 : Vol 3D Appendix A.10
 *   - MAXPHYADDR from CPUID.80000008       : Vol 2A CPUID
 * Cross-checked only against the public tables that hvpp/DRAKVUF transcribe from the same
 * SDM. No proprietary or anti-cheat source consulted. All code original.
 *
 * CANNOT BE BUILT OR RUN IN THIS ENVIRONMENT. Correctness is judged only against the SDM.
 * Unresolved decisions are marked "// TODO(hv):".
 *
 * IRQL: ept_build_identity()/ept_destroy() allocate contiguous memory and MUST run at
 * PASSIVE_LEVEL (before the VMXON/VMLAUNCH IPI broadcast). The runtime primitives
 * (ept_get_pte/ept_split_2mb/ept_set_access/ept_watch_page/ept_invalidate) touch only
 * already-allocated memory and issue INVEPT, so they are safe from a VM-exit handler in
 * VMX root operation.
 */

#include "hv.h"

/* -------------------------------------------------------------------------------------- */
/*  File-local tunables                                                                    */
/* -------------------------------------------------------------------------------------- */
/* Pre-allocated pool of 4KB EPT page tables used to demote 2MB large pages to 4KB. Each
 * split consumes one page (512 PTEs). Budget: one per possible watch (VCPU.watches[64])
 * plus headroom for the handful of 2MB regions that straddle an MTRR memory-type boundary
 * in the identity map (typically the low-1MB page and a few MMIO edges).
 * TODO(hv): size this against a real memory map; a machine with many misaligned MMIO
 * memory-type boundaries could in principle need more. On exhaustion the build falls back
 * to a conservative UC large page and the watch path returns HV_ERR_EPT_BUILD. */
#define EPT_SPLIT_POOL_PAGES        128u

/* Initial trapping permissions installed when a page is first watched: readable and
 * executable but NOT writable, so the packer's first decrypting store to the page faults
 * out (HV_EVENT_EPT_WRITE). vmi_on_ept_violation() owns every subsequent R/W/X flip; ept.c
 * only installs the initial trap and registers the watch. */
#define EPT_WATCH_INITIAL_ACCESS    EPT_ACCESS_RX

/* First 1MB is described by the fixed-range MTRRs (SDM Vol 3A 11.11.2.2). */
#define MTRR_FIXED_TOP              0x100000ull

/* -------------------------------------------------------------------------------------- */
/*  Cached MTRR state (read once, consulted per-frame while composing EPT memory types)     */
/*                                                                                          */
/*  Kept file-static rather than in EPT_STATE: it is a property of the physical platform,   */
/*  identical for every VCPU, and needs no teardown. This avoids widening the shared struct. */
/* -------------------------------------------------------------------------------------- */
typedef struct _MTRR_VAR_RANGE {
    u64 base_addr;   /* PHYSBASE address bits (bits 12..MAXPHYADDR-1), low bits zeroed. */
    u64 mask_addr;   /* PHYSMASK address bits (bits 12..MAXPHYADDR-1). */
    u8  type;        /* MEMTYPE_*. */
    u8  valid;       /* PHYSMASK.V. */
} MTRR_VAR_RANGE;

static struct {
    u8  initialized;
    u8  mtrr_enabled;     /* IA32_MTRR_DEF_TYPE.E. */
    u8  fixed_enabled;    /* IA32_MTRR_DEF_TYPE.FE && IA32_MTRRCAP.FIX. */
    u8  default_type;     /* IA32_MTRR_DEF_TYPE[7:0]. */
    u8  var_count;        /* IA32_MTRRCAP.VCNT, clamped to array size. */
    u64 phys_mask;        /* (1<<MAXPHYADDR)-1. */
    u64 max_addr;         /* Highest address any MTRR range describes; above it => default. */
    u64 fixed[11];        /* Raw values: [0]=FIX64K_00000, [1]=FIX16K_80000,
                           *             [2]=FIX16K_A0000, [3..10]=FIX4K_C0000..F8000. */
    MTRR_VAR_RANGE var[64];
} g_mtrr;

/* -------------------------------------------------------------------------------------- */
/*  Small memory helpers                                                                   */
/* -------------------------------------------------------------------------------------- */

/* Allocate zeroed, page-aligned, physically contiguous, write-back memory for EPT paging
 * structures. MmAllocateContiguousMemory returns cache-aligned memory that is page-aligned
 * for allocations >= PAGE_SIZE and is cached (WB) -- exactly what EPT tables require.
 * PASSIVE_LEVEL only. */
static void *ept_alloc_pages(SIZE_T bytes, u64 *pa_out)
{
    PHYSICAL_ADDRESS highest;
    void *va;

    /* Constrain to the platform physical-address width so every allocated table PA fits the
     * 40-bit EPT PFN fields (bits 51:12). Real RAM is always well within this. */
    highest.QuadPart = (LONGLONG)(g_mtrr.phys_mask ? g_mtrr.phys_mask : ~0ull);

    va = MmAllocateContiguousMemory(bytes, highest);
    if (va == NULL) {
        return NULL;
    }
    RtlZeroMemory(va, bytes);
    if (pa_out != NULL) {
        *pa_out = (u64)MmGetPhysicalAddress(va).QuadPart;
    }
    return va;
}

static void ept_free_pages(void *va)
{
    if (va != NULL) {
        MmFreeContiguousMemory(va);
    }
}

/* Program the low R/W/X permission bits of any EPT entry from an EPT_ACCESS_* mask. The
 * three permission bits share bit positions 0/1/2 across every EPT paging-structure entry
 * (SDM Vol 3C 29.3.3), so a single helper serves PML4E/PDPTE/PDE/PTE alike. */
static void ept_entry_set_access(EPT_ENTRY *e, u8 access)
{
    e->bits.read_access    = (access & EPT_ACCESS_R) ? 1 : 0;
    e->bits.write_access   = (access & EPT_ACCESS_W) ? 1 : 0;
    e->bits.execute_access = (access & EPT_ACCESS_X) ? 1 : 0;
}

/* -------------------------------------------------------------------------------------- */
/*  MTRR read + memory-type composition (SDM Vol 3A 11.11)                                  */
/* -------------------------------------------------------------------------------------- */

static u32 ept_maxphyaddr(void)
{
    int regs[4];
    u32 max_ext;

    __cpuid(regs, (int)CPUID_LEAF_EXT_MAX);
    max_ext = (u32)regs[0];
    if (max_ext >= CPUID_LEAF_ADDR_WIDTH) {
        __cpuid(regs, (int)CPUID_LEAF_ADDR_WIDTH);
        return (u32)(regs[0] & 0xFF);   /* EAX[7:0] = physical-address bits. */
    }
    /* TODO(hv): pre-Nehalem parts without leaf 0x80000008; 36 bits is the safe legacy floor. */
    return 36u;
}

/* Populate g_mtrr from the MTRR MSRs. Idempotent. */
static void ept_mtrr_init(void)
{
    u64 def_type;
    u64 mtrrcap;
    u32 maxphyaddr;
    u32 i;

    if (g_mtrr.initialized) {
        return;
    }
    RtlZeroMemory(&g_mtrr, sizeof(g_mtrr));

    maxphyaddr = ept_maxphyaddr();
    g_mtrr.phys_mask = (maxphyaddr >= 64u) ? ~0ull : ((1ull << maxphyaddr) - 1ull);

    def_type = __readmsr(IA32_MTRR_DEF_TYPE);
    mtrrcap  = __readmsr(IA32_MTRRCAP);

    g_mtrr.mtrr_enabled  = (def_type & IA32_MTRR_DEF_TYPE_E) ? 1 : 0;
    g_mtrr.default_type  = (u8)(def_type & IA32_MTRR_DEF_TYPE_TYPE_MASK);
    g_mtrr.fixed_enabled = ((def_type & IA32_MTRR_DEF_TYPE_FE) &&
                            (mtrrcap & IA32_MTRRCAP_FIX)) ? 1 : 0;

    /* Fixed-range MTRRs cover the first 1MB. */
    g_mtrr.fixed[0]  = __readmsr(IA32_MTRR_FIX64K_00000);
    g_mtrr.fixed[1]  = __readmsr(IA32_MTRR_FIX16K_80000);
    g_mtrr.fixed[2]  = __readmsr(IA32_MTRR_FIX16K_A0000);
    for (i = 0; i < 8; i++) {
        g_mtrr.fixed[3 + i] = __readmsr(IA32_MTRR_FIX4K_C0000 + i);
    }

    /* Variable-range MTRRs. */
    g_mtrr.var_count = (u8)(mtrrcap & IA32_MTRRCAP_VCNT_MASK);
    if (g_mtrr.var_count > RTL_NUMBER_OF(g_mtrr.var)) {
        g_mtrr.var_count = (u8)RTL_NUMBER_OF(g_mtrr.var);
    }

    g_mtrr.max_addr = MTRR_FIXED_TOP;   /* Fixed MTRRs always describe up to 1MB. */

    for (i = 0; i < g_mtrr.var_count; i++) {
        u64 base_raw = __readmsr(IA32_MTRR_PHYSBASE(i));
        u64 mask_raw = __readmsr(IA32_MTRR_PHYSMASK(i));
        u64 mask_addr = mask_raw & g_mtrr.phys_mask & PAGE_MASK_4K;
        u64 base_addr = base_raw & g_mtrr.phys_mask & PAGE_MASK_4K;

        g_mtrr.var[i].valid     = (mask_raw & IA32_MTRR_PHYSMASK_VALID) ? 1 : 0;
        g_mtrr.var[i].type      = (u8)(base_raw & IA32_MTRR_PHYSBASE_TYPE_MASK);
        g_mtrr.var[i].base_addr = base_addr;
        g_mtrr.var[i].mask_addr = mask_addr;

        if (g_mtrr.var[i].valid) {
            /* For a contiguous mask the range size is (~mask & physmask)+1 and its top is
             * base + size (SDM Vol 3A 11.11.3). Track the highest described address so the
             * identity build can skip the per-4KB uniformity scan above it. */
            u64 size = ((~mask_addr) & g_mtrr.phys_mask) + 1ull;
            u64 top  = base_addr + size;
            if (top > g_mtrr.max_addr) {
                g_mtrr.max_addr = top;
            }
        }
    }

    g_mtrr.initialized = 1;
}

/* Look up the fixed-range MTRR memory type for an address < 1MB. */
static u8 ept_mtrr_fixed_type(u64 addr)
{
    u32 msr_idx;
    u32 byte_idx;
    u64 raw;

    if (addr < 0x80000ull) {                 /* 8 x 64KB in FIX64K_00000. */
        msr_idx  = 0;
        byte_idx = (u32)(addr >> 16) & 7u;
    } else if (addr < 0xA0000ull) {          /* 8 x 16KB in FIX16K_80000. */
        msr_idx  = 1;
        byte_idx = (u32)((addr - 0x80000ull) >> 14) & 7u;
    } else if (addr < 0xC0000ull) {          /* 8 x 16KB in FIX16K_A0000. */
        msr_idx  = 2;
        byte_idx = (u32)((addr - 0xA0000ull) >> 14) & 7u;
    } else {                                 /* 8 MSRs x 8 x 4KB, 0xC0000..0xFFFFF. */
        u64 off  = addr - 0xC0000ull;
        msr_idx  = 3u + (u32)(off >> 15);    /* Each MSR spans 8 x 4KB = 32KB. */
        byte_idx = (u32)(off >> 12) & 7u;
    }
    raw = g_mtrr.fixed[msr_idx];
    return (u8)((raw >> (byte_idx * 8u)) & 0xFFu);
}

/* Compose the effective MTRR memory type of the 4KB frame containing gpa (SDM Vol 3A
 * 11.11.4.1 precedence rules). vcpu is accepted for interface symmetry / future per-VCPU
 * memory-type overrides but the MTRR state is platform-global. */
u8 ept_memtype_for_gpa(VCPU *vcpu, u64 gpa)
{
    u32 i;
    int matched = 0;
    int saw_uc = 0, saw_wt = 0, saw_wb = 0, saw_other = 0;
    u8  other_type = MEMTYPE_UC;

    UNREFERENCED_PARAMETER(vcpu);

    if (!g_mtrr.initialized) {
        ept_mtrr_init();
    }

    /* MTRRs globally disabled => the entire physical space is UC (SDM 11.11.2.1). */
    if (!g_mtrr.mtrr_enabled) {
        return MEMTYPE_UC;
    }

    /* Fixed ranges take precedence for the first 1MB. */
    if (gpa < MTRR_FIXED_TOP && g_mtrr.fixed_enabled) {
        return ept_mtrr_fixed_type(gpa);
    }

    /* Variable ranges: collect every match, then apply the overlap precedence. */
    for (i = 0; i < g_mtrr.var_count; i++) {
        const MTRR_VAR_RANGE *r = &g_mtrr.var[i];
        if (!r->valid) {
            continue;
        }
        if ((gpa & r->mask_addr) == (r->base_addr & r->mask_addr)) {
            matched = 1;
            switch (r->type) {
            case MEMTYPE_UC: saw_uc = 1; break;
            case MEMTYPE_WT: saw_wt = 1; break;
            case MEMTYPE_WB: saw_wb = 1; break;
            default:         saw_other = 1; other_type = r->type; break;
            }
        }
    }

    if (!matched) {
        return g_mtrr.default_type;         /* No range describes it => default type. */
    }
    /* SDM 11.11.4.1 overlap rules: UC always wins; WT+WB resolves to WT; any other mix is
     * architecturally undefined, so fall back to UC (the safe, coherency-preserving type). */
    if (saw_uc) {
        return MEMTYPE_UC;
    }
    if (saw_wt && saw_wb) {
        return MEMTYPE_WT;
    }
    if (saw_wt && !saw_wb && !saw_other) {
        return MEMTYPE_WT;
    }
    if (saw_wb && !saw_wt && !saw_other) {
        return MEMTYPE_WB;
    }
    if (saw_other && !saw_uc && !saw_wt && !saw_wb) {
        return other_type;                  /* Single consistent non-UC/WT/WB type (e.g. WC). */
    }
    /* TODO(hv): a conflicting overlap (e.g. WC vs WB) is undefined; UC is the safe choice. */
    return MEMTYPE_UC;
}

/* True iff every 4KB frame in the 2MB page at base2mb shares one memory type; returns that
 * type in *out_type. A 2MB EPT large page carries a single memory type, so a non-uniform
 * span must be demoted to 4KB. */
static u8 ept_2mb_uniform(VCPU *vcpu, u64 base2mb, u8 *out_type)
{
    u8  t0 = ept_memtype_for_gpa(vcpu, base2mb);
    u64 off;

    for (off = PAGE_SIZE_4K; off < PAGE_SIZE_2M; off += PAGE_SIZE_4K) {
        if (ept_memtype_for_gpa(vcpu, base2mb + off) != t0) {
            return 0;
        }
    }
    *out_type = t0;
    return 1;
}

/* -------------------------------------------------------------------------------------- */
/*  Table navigation                                                                       */
/* -------------------------------------------------------------------------------------- */

/* Locate the 2MB PDE that maps gpa in the identity map. Returns NULL if gpa lies outside
 * the single-PML4 512GB span this build installs. */
static EPT_PDE_2MB *ept_locate_pde(VCPU *vcpu, u64 gpa)
{
    u64 pdpt_i = EPT_PDPT_INDEX(gpa);       /* bits 38:30 -> which PD table. */
    u64 pd_i   = EPT_PD_INDEX(gpa);         /* bits 29:21 -> which PDE within it. */
    EPT_PDE_2MB *pd;

    if (EPT_PML4_INDEX(gpa) != 0) {
        /* TODO(hv): >512GB GPAs need additional PML4 entries / PDPTs; unsupported here. */
        return NULL;
    }
    if (vcpu->ept.pd_pages == NULL) {
        return NULL;
    }
    pd = (EPT_PDE_2MB *)((u8 *)vcpu->ept.pd_pages + (SIZE_T)pdpt_i * PAGE_SIZE_4K);
    return &pd[pd_i];
}

/* Recover the kernel VA of the 4KB EPT page table referenced by a (non-large) PDE. Every
 * split PT is carved from the physically contiguous split pool, so PA->VA is a fixed offset
 * from the pool base -- no MmGetVirtualForPhysical needed. */
static EPT_PTE *ept_pt_va_from_pde(VCPU *vcpu, const EPT_PDE *pde)
{
    u64 pt_pa = (u64)pde->bits.pfn << PAGE_SHIFT_4K;
    u64 pool_pa;

    if (vcpu->ept.split_pt_pool == NULL) {
        return NULL;
    }
    pool_pa = (u64)MmGetPhysicalAddress(vcpu->ept.split_pt_pool).QuadPart;
    return (EPT_PTE *)((u8 *)vcpu->ept.split_pt_pool + (SIZE_T)(pt_pa - pool_pa));
}

/* Hand out the next unused 4KB PT from the split pool, or NULL if exhausted. */
static EPT_PTE *ept_split_pool_take(VCPU *vcpu, u64 *pt_pa_out)
{
    EPT_PTE *pt;
    u8 *base;

    if (vcpu->ept.split_pt_pool == NULL ||
        vcpu->ept.split_pt_used >= vcpu->ept.split_pt_capacity) {
        return NULL;
    }
    base = (u8 *)vcpu->ept.split_pt_pool;
    pt = (EPT_PTE *)(base + (SIZE_T)vcpu->ept.split_pt_used * PAGE_SIZE_4K);
    vcpu->ept.split_pt_used++;
    if (pt_pa_out != NULL) {
        *pt_pa_out = (u64)MmGetPhysicalAddress(pt).QuadPart;
    }
    return pt;
}

/* -------------------------------------------------------------------------------------- */
/*  ept_split_2mb -- demote a 2MB large PDE into 512 4KB PTEs                                */
/*                                                                                          */
/*  Pure structural operation: it does NOT INVEPT. The caller is responsible for TLB        */
/*  invalidation once it has finished mutating the freshly created PTEs (ept_set_access /    */
/*  ept_watch_page do so; the identity-build path defers to the single post-build INVEPT     */
/*  that happens when the guest first runs, so it skips invalidation entirely).              */
/* -------------------------------------------------------------------------------------- */
HV_STATUS ept_split_2mb(VCPU *vcpu, u64 gpa)
{
    EPT_PDE_2MB *pde2mb;
    EPT_PDE      new_pde;
    EPT_PTE     *pt;
    u64          pt_pa = 0;
    u64          base2mb;
    u64          base_pfn4k;
    u32          j;

    if (vcpu == NULL) {
        return HV_ERR_INVALID_ARG;
    }
    pde2mb = ept_locate_pde(vcpu, gpa);
    if (pde2mb == NULL) {
        return HV_ERR_INVALID_ARG;
    }
    /* Already a table reference (bit 7 == 0) -- nothing to split, idempotent success. */
    if (pde2mb->bits.large_page == 0) {
        return HV_OK;
    }

    pt = ept_split_pool_take(vcpu, &pt_pa);
    if (pt == NULL) {
        return HV_ERR_EPT_BUILD;            /* Split pool exhausted. */
    }

    base2mb    = gpa & ~(PAGE_SIZE_2M - 1);
    base_pfn4k = base2mb >> PAGE_SHIFT_4K;

    /* Populate the 512 leaf PTEs, preserving the identity mapping (GPA==HPA) and giving each
     * 4KB frame its own MTRR-correct memory type. Default access is full R/W/X; watch/set
     * callers strip bits afterward. */
    for (j = 0; j < EPT_ENTRIES_PER_TABLE; j++) {
        EPT_PTE *pte = &pt[j];
        u64 frame_gpa = base2mb + ((u64)j << PAGE_SHIFT_4K);
        pte->all = 0;
        pte->bits.read_access    = 1;
        pte->bits.write_access   = 1;
        pte->bits.execute_access = 1;
        pte->bits.memory_type    = ept_memtype_for_gpa(vcpu, frame_gpa);
        pte->bits.pfn            = base_pfn4k + j;
    }

    /* Rewrite the PDE to reference the new PT (clears bit 7). Grant R/W/X at the PDE level;
     * effective access is the AND of every level, so per-page restriction stays in the PTE. */
    new_pde.all = 0;
    new_pde.bits.read_access    = 1;
    new_pde.bits.write_access   = 1;
    new_pde.bits.execute_access = 1;
    new_pde.bits.pfn            = pt_pa >> PAGE_SHIFT_4K;
    /* Publish atomically: the entry is a naturally aligned 8-byte value. */
    pde2mb->all = new_pde.all;

    return HV_OK;
}

/* -------------------------------------------------------------------------------------- */
/*  ept_get_pte -- walk to the 4KB PTE for gpa, optionally splitting a covering 2MB page     */
/* -------------------------------------------------------------------------------------- */
EPT_PTE *ept_get_pte(VCPU *vcpu, u64 gpa, int allocate_split)
{
    EPT_PDE_2MB *pde2mb;
    EPT_PDE     *pde;
    EPT_PTE     *pt;

    if (vcpu == NULL) {
        return NULL;
    }
    pde2mb = ept_locate_pde(vcpu, gpa);
    if (pde2mb == NULL) {
        return NULL;
    }
    if (pde2mb->bits.large_page) {
        if (!allocate_split) {
            return NULL;                    /* Caller wants a 4KB PTE but none exists yet. */
        }
        if (ept_split_2mb(vcpu, gpa) != HV_OK) {
            return NULL;
        }
    }
    /* PDE now references a PT (bit 7 == 0). */
    pde = (EPT_PDE *)pde2mb;
    pt = ept_pt_va_from_pde(vcpu, pde);
    if (pt == NULL) {
        return NULL;
    }
    return &pt[EPT_PT_INDEX(gpa)];
}

/* -------------------------------------------------------------------------------------- */
/*  ept_set_access -- install EPT_ACCESS_* on the 4KB page mapping gpa, then INVEPT          */
/* -------------------------------------------------------------------------------------- */
HV_STATUS ept_set_access(VCPU *vcpu, u64 gpa, u8 access)
{
    EPT_PTE *pte;

    if (vcpu == NULL) {
        return HV_ERR_INVALID_ARG;
    }
    pte = ept_get_pte(vcpu, gpa, 1 /* split if needed */);
    if (pte == NULL) {
        return HV_ERR_EPT_BUILD;
    }
    ept_entry_set_access((EPT_ENTRY *)pte, access);
    ept_invalidate(vcpu);
    return HV_OK;
}

/* -------------------------------------------------------------------------------------- */
/*  Watch bookkeeping (the write-then-execute primitive's registration side)                */
/* -------------------------------------------------------------------------------------- */
EPT_WATCH *ept_find_watch(VCPU *vcpu, u64 gpa)
{
    u32 i;
    u64 page = gpa & PAGE_MASK_4K;

    if (vcpu == NULL) {
        return NULL;
    }
    for (i = 0; i < RTL_NUMBER_OF(vcpu->watches); i++) {
        if (vcpu->watches[i].armed && vcpu->watches[i].gpa == page) {
            return &vcpu->watches[i];
        }
    }
    return NULL;
}

HV_STATUS ept_watch_page(VCPU *vcpu, u64 gpa)
{
    u64        page;
    EPT_WATCH *w;
    EPT_PTE   *pte;
    u32        i;

    if (vcpu == NULL) {
        return HV_ERR_INVALID_ARG;
    }
    page = gpa & PAGE_MASK_4K;

    if (ept_find_watch(vcpu, page) != NULL) {
        return HV_OK;                       /* Already watched. */
    }

    pte = ept_get_pte(vcpu, page, 1 /* split so we can restrict a single 4KB page */);
    if (pte == NULL) {
        return HV_ERR_EPT_BUILD;
    }

    /* Find a free watch slot. */
    w = NULL;
    for (i = 0; i < RTL_NUMBER_OF(vcpu->watches); i++) {
        if (!vcpu->watches[i].armed) {
            w = &vcpu->watches[i];
            break;
        }
    }
    if (w == NULL) {
        return HV_ERR_ALLOC;                /* Watch table full. */
    }

    /* Install the initial trap (R+X, not W) and register the watch. */
    ept_entry_set_access((EPT_ENTRY *)pte, EPT_WATCH_INITIAL_ACCESS);

    w->gpa            = page;
    w->pte            = pte;
    w->armed          = 1;
    w->current_access = EPT_WATCH_INITIAL_ACCESS;
    w->saw_write      = 0;
    w->saw_exec       = 0;
    w->write_count    = 0;
    w->exec_count     = 0;
    vcpu->watch_count++;

    ept_invalidate(vcpu);
    return HV_OK;
}

HV_STATUS ept_unwatch_page(VCPU *vcpu, u64 gpa)
{
    EPT_WATCH *w;

    if (vcpu == NULL) {
        return HV_ERR_INVALID_ARG;
    }
    w = ept_find_watch(vcpu, gpa & PAGE_MASK_4K);
    if (w == NULL) {
        return HV_OK;                       /* Nothing armed here. */
    }
    /* Restore full R/W/X so the page stops trapping. The split PTE stays in place (the split
     * pool is not reclaimed piecemeal; it is freed wholesale in ept_destroy). */
    if (w->pte != NULL) {
        ept_entry_set_access((EPT_ENTRY *)w->pte, EPT_ACCESS_RWX);
    }
    w->armed = 0;
    w->pte = NULL;
    if (vcpu->watch_count > 0) {
        vcpu->watch_count--;
    }
    ept_invalidate(vcpu);
    return HV_OK;
}

/* -------------------------------------------------------------------------------------- */
/*  ept_invalidate -- INVEPT after a permission change (SDM Vol 3C 29.4.3)                   */
/* -------------------------------------------------------------------------------------- */
void ept_invalidate(VCPU *vcpu)
{
    INVEPT_DESCRIPTOR desc;
    u64 cap;

    if (vcpu == NULL) {
        return;
    }
    cap = (vcpu->hv != NULL) ? vcpu->hv->caps.ept_vpid_cap : 0;

    desc.eptp     = vcpu->ept.eptp.all;
    desc.reserved = 0;

    /* Prefer single-context (flush just this EPTP's mappings) when supported; otherwise fall
     * back to all-context. INVEPT is only valid in VMX operation, so this is a no-op-if-not
     * concern for the caller, never invoked during PASSIVE-level identity build. */
    if (cap & VMX_EPT_CAP_INVEPT_SINGLE) {
        (void)asm_invept(INVEPT_TYPE_SINGLE_CONTEXT, &desc);
    } else {
        /* All-context ignores desc.eptp but a valid descriptor is still passed. */
        (void)asm_invept(INVEPT_TYPE_ALL_CONTEXT, &desc);
    }
    /* TODO(hv): if IA32_VMX_EPT_VPID_CAP reports neither INVEPT type, EPT cannot be used
     * safely; ept_build_identity already gates on INVEPT support. */
}

/* -------------------------------------------------------------------------------------- */
/*  ept_build_identity -- construct the 1:1 GPA==HPA EPT and the EPTP                        */
/* -------------------------------------------------------------------------------------- */
HV_STATUS ept_build_identity(VCPU *vcpu)
{
    EPT_STATE *ept;
    u64 cap;
    u64 pml4_pa = 0, pdpt_pa = 0, pd_pa = 0, split_pa = 0;
    EPT_PML4E *pml4;
    EPT_PDPTE *pdpt;
    u32 pdpt_i, pd_j;

    if (vcpu == NULL) {
        return HV_ERR_INVALID_ARG;
    }
    ept = &vcpu->ept;

    /* MTRR state feeds both the memory-type composition and the phys-addr mask used to bound
     * the contiguous allocations, so read it first. */
    ept_mtrr_init();

    /* Gate on the EPT features we actually rely on (SDM Vol 3D A.10). */
    cap = (vcpu->hv != NULL) ? vcpu->hv->caps.ept_vpid_cap : 0;
    if (!(cap & VMX_EPT_CAP_PAGE_WALK_4) ||
        !(cap & VMX_EPT_CAP_MEMTYPE_WB) ||
        !(cap & VMX_EPT_CAP_2MB_PAGE) ||
        !(cap & VMX_EPT_CAP_INVEPT)) {
        return HV_ERR_NO_EPT;
    }

    /* Allocate the paging structures:
     *   PML4 : 1 page  (only entry 0 used -> covers the low 512GB).
     *   PDPT : 1 page  (512 entries, one per 1GB, each -> a PD).
     *   PDs  : EPT_IDENTITY_PD_COUNT contiguous pages (512 * 512 * 2MB == 512GB).
     *   split: EPT_SPLIT_POOL_PAGES contiguous pages for on-demand 2MB->4KB demotion. */
    pml4 = (EPT_PML4E *)ept_alloc_pages(PAGE_SIZE_4K, &pml4_pa);
    pdpt = (EPT_PDPTE *)ept_alloc_pages(PAGE_SIZE_4K, &pdpt_pa);
    ept->pml4        = pml4;
    ept->pdpt        = pdpt;
    ept->pd_pages    = ept_alloc_pages((SIZE_T)EPT_IDENTITY_PD_COUNT * PAGE_SIZE_4K, &pd_pa);
    ept->split_pt_pool = ept_alloc_pages((SIZE_T)EPT_SPLIT_POOL_PAGES * PAGE_SIZE_4K, &split_pa);

    if (pml4 == NULL || pdpt == NULL || ept->pd_pages == NULL || ept->split_pt_pool == NULL) {
        ept_destroy(vcpu);
        return HV_ERR_ALLOC;
    }
    ept->split_pt_used     = 0;
    ept->split_pt_capacity = EPT_SPLIT_POOL_PAGES;

    /* PML4[0] -> PDPT (R/W/X; effective access is AND'd down the walk). */
    pml4[0].all = 0;
    pml4[0].bits.read_access    = 1;
    pml4[0].bits.write_access   = 1;
    pml4[0].bits.execute_access = 1;
    pml4[0].bits.pfn            = pdpt_pa >> PAGE_SHIFT_4K;

    /* Fill the PDPT and every PD with identity 2MB large pages. */
    for (pdpt_i = 0; pdpt_i < EPT_IDENTITY_PD_COUNT; pdpt_i++) {
        u64 this_pd_pa = pd_pa + (u64)pdpt_i * PAGE_SIZE_4K;
        EPT_PDE_2MB *pd = (EPT_PDE_2MB *)((u8 *)ept->pd_pages + (SIZE_T)pdpt_i * PAGE_SIZE_4K);

        pdpt[pdpt_i].all = 0;
        pdpt[pdpt_i].bits.read_access    = 1;
        pdpt[pdpt_i].bits.write_access   = 1;
        pdpt[pdpt_i].bits.execute_access = 1;
        pdpt[pdpt_i].bits.pfn            = this_pd_pa >> PAGE_SHIFT_4K;

        for (pd_j = 0; pd_j < EPT_IDENTITY_PDE_PER_PD; pd_j++) {
            u64 gpa = ((u64)pdpt_i << PAGE_SHIFT_1G) | ((u64)pd_j << PAGE_SHIFT_2M);
            u8  mt;
            u8  uniform;

            if (!g_mtrr.mtrr_enabled) {
                mt = MEMTYPE_UC;             /* MTRRs off => whole space UC. */
                uniform = 1;
            } else if (gpa >= g_mtrr.max_addr) {
                mt = g_mtrr.default_type;    /* Above every MTRR range => default, uniform. */
                uniform = 1;
            } else {
                uniform = ept_2mb_uniform(vcpu, gpa, &mt);
            }

            /* Install a 2MB identity large page (bit 7 == 1). */
            pd[pd_j].all = 0;
            pd[pd_j].bits.read_access    = 1;
            pd[pd_j].bits.write_access   = 1;
            pd[pd_j].bits.execute_access = 1;
            pd[pd_j].bits.large_page     = 1;
            pd[pd_j].bits.memory_type    = uniform ? mt : MEMTYPE_UC;
            pd[pd_j].bits.pfn            = gpa >> PAGE_SHIFT_2M;

            /* A 2MB span with mixed memory types cannot be a single large page. Demote it to
             * 512 4KB PTEs, each carrying its own MTRR-correct type. On pool exhaustion the
             * conservative UC large page installed just above stays in place. */
            if (!uniform) {
                (void)ept_split_2mb(vcpu, gpa);
                /* No INVEPT here: nothing is running on this EPTP yet. */
            }
        }
    }

    /* Build the EPTP loaded into VMCS_CTRL_EPT_POINTER (SDM Vol 3C Table 25-9). */
    ept->eptp.all = 0;
    ept->eptp.bits.memory_type = EPT_MEMTYPE_WB;          /* Paging-structure accesses WB. */
    ept->eptp.bits.walk_length = EPT_PAGE_WALK_LENGTH_4;  /* 4-level walk encodes as 3. */
    ept->eptp.bits.enable_ad   = 0;                       /* A/D disabled; not needed for VMI.
                                                           * TODO(hv): optionally enable when
                                                           * VMX_EPT_CAP_AD_BITS to cheapen
                                                           * dirty tracking. */
    ept->eptp.bits.pml4_pfn    = pml4_pa >> PAGE_SHIFT_4K;

    /* Highest GPA the single-PML4 map can translate. */
    ept->highest_gpa = ((u64)EPT_IDENTITY_PD_COUNT << PAGE_SHIFT_1G) - 1ull;
    /* TODO(hv): systems with MAXPHYADDR > 39 bits or 5-level (LA57) guests need more than one
     * PDPT; extend to multiple PML4 entries before claiming full coverage. */

    return HV_OK;
}

/* -------------------------------------------------------------------------------------- */
/*  ept_destroy -- release all EPT paging structures                                        */
/* -------------------------------------------------------------------------------------- */
void ept_destroy(VCPU *vcpu)
{
    EPT_STATE *ept;

    if (vcpu == NULL) {
        return;
    }
    ept = &vcpu->ept;

    ept_free_pages(ept->pml4);
    ept_free_pages(ept->pdpt);
    ept_free_pages(ept->pd_pages);
    ept_free_pages(ept->split_pt_pool);

    ept->pml4          = NULL;
    ept->pdpt          = NULL;
    ept->pd_pages      = NULL;
    ept->split_pt_pool = NULL;
    ept->split_pt_used     = 0;
    ept->split_pt_capacity = 0;
    ept->highest_gpa   = 0;
    ept->eptp.all      = 0;

    /* Watch table lives inline in the VCPU; clear it so a re-virtualize starts clean. */
    RtlZeroMemory(vcpu->watches, sizeof(vcpu->watches));
    vcpu->watch_count = 0;
}
