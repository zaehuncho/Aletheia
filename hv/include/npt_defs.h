/*
 * npt_defs.h -- AMD NPT (Nested Page Tables) paging-structure definitions for the Aletheia
 * clean-room VMI hypervisor. Peer of ept_defs.h.
 *
 * CLEAN-ROOM PROVENANCE: written from the AMD64 Architecture Programmer's Manual (APM),
 * Volume 2 -- "System Programming":
 *
 *   Nested paging (NPT) .............. §15.25
 *   Standard IA-32e paging structures  §5.3.4 (PML4E, PDPTE, PDE, PTE, encrypted-memory bit)
 *
 * KEY DIFFERENCE FROM INTEL EPT: NPT is NOT a permission-only paging scheme (Intel's EPT
 * encodes read/write/execute as three independent permission bits with its own paging-entry
 * layout). AMD NPT REUSES the standard IA-32e long-mode paging entry format -- the same
 * bits the guest CPU already understands (P, R/W, U/S, PWT, PCD, A, D, PS, G, PAT, NX,
 * physical-address field). The CPU walks NPT with the same rules as a regular page walk;
 * only the ROOT is different (nCR3 in the VMCB rather than CR3 in the guest).
 *
 * This has one direct consequence for the unpacker's W^X trap:
 *   - "readable, writable, not-executable" in NPT == P=1, R/W=1, NX=1
 *   - "readable, executable, not-writable" in NPT == P=1, R/W=0, NX=0
 *   - "not-present"                       in NPT == P=0  (fault delivers as EXITINFO1.P=0)
 * A page's execute permission is controlled by the NX bit (bit 63), which requires
 * EFER.NXE = 1 in the guest, which Windows and Linux always set.
 *
 * CANNOT BE BUILT OR RUN IN THIS ENVIRONMENT. Every unresolved decision is marked
 * "// TODO(hv):".
 */
#ifndef ALETHEIA_HV_NPT_DEFS_H
#define ALETHEIA_HV_NPT_DEFS_H

#include "arch.h"

/* ====================================================================================== */
/*  Paging-entry bit layout (IA-32e long-mode; APM Vol 2 §5.3.4).                          */
/* ====================================================================================== */
#define NPT_P                   BIT(0)          /* Present.                                    */
#define NPT_RW                  BIT(1)          /* 0 = read-only, 1 = writable.                */
#define NPT_US                  BIT(2)          /* 0 = supervisor, 1 = user.                   */
#define NPT_PWT                 BIT(3)          /* Page-level write-through.                   */
#define NPT_PCD                 BIT(4)          /* Page-level cache disable.                   */
#define NPT_A                   BIT(5)          /* Accessed (hw-set on any access).            */
#define NPT_D                   BIT(6)          /* Dirty (hw-set on write to a page frame).    */
#define NPT_PS                  BIT(7)          /* Page size: 1 in PDE = 2 MiB, in PDPTE = 1 GiB. */
#define NPT_G                   BIT(8)          /* Global (ignored in NPT walks).              */
#define NPT_PAT_4K              BIT(7)          /* PAT bit for 4 KiB pages (same bit as PS in a
                                                   PTE). Determines memory-type bit 2.         */
#define NPT_PAT_LARGE           BIT(12)         /* PAT bit for 2 MiB / 1 GiB pages.            */
#define NPT_NX                  (1ull << 63)    /* No-execute (requires EFER.NXE).             */

/* Physical-address field (bits 51..12 for 4 KiB; the ES.SME reduces the top when SME live). */
#define NPT_ADDR_MASK           0x000FFFFFFFFFF000ULL   /* Bits 51..12 (52-bit PA space).      */
#define NPT_ADDR_MASK_2MB       0x000FFFFFFFE00000ULL   /* Bits 51..21 for 2 MiB entries.      */
#define NPT_ADDR_MASK_1GB       0x000FFFFFC0000000ULL   /* Bits 51..30 for 1 GiB entries.      */

/* Shift constants (matching arch.h page shifts). */
#define NPT_PT_SHIFT            12              /* 4 KiB page.                                 */
#define NPT_PD_SHIFT            21              /* 2 MiB region -> one PDE.                    */
#define NPT_PDPT_SHIFT          30              /* 1 GiB region -> one PDPTE.                  */
#define NPT_PML4_SHIFT          39              /* 512 GiB region -> one PML4E.                */

/* Index-into-level extractors: 9 bits per level, up to bit 47 in canonical x86-64. */
#define NPT_INDEX_MASK          0x1FFu
#define NPT_PT_INDEX(gpa)       (((gpa) >> NPT_PT_SHIFT)   & NPT_INDEX_MASK)
#define NPT_PD_INDEX(gpa)       (((gpa) >> NPT_PD_SHIFT)   & NPT_INDEX_MASK)
#define NPT_PDPT_INDEX(gpa)     (((gpa) >> NPT_PDPT_SHIFT) & NPT_INDEX_MASK)
#define NPT_PML4_INDEX(gpa)     (((gpa) >> NPT_PML4_SHIFT) & NPT_INDEX_MASK)

/* Region sizes. */
#define NPT_2MB_SIZE            (1ull << NPT_PD_SHIFT)
#define NPT_1GB_SIZE            (1ull << NPT_PDPT_SHIFT)

/* Number of entries per paging level (always 512 in long-mode IA-32e). */
#define NPT_ENTRIES_PER_TABLE   512

/* ====================================================================================== */
/*  Paging-entry types. In long-mode IA-32e all four levels use identical 64-bit entries    */
/*  differing only in which bits are meaningful (PS is meaningful in PDPTE/PDE, PAT bit     */
/*  moves for large pages). Modeling them all as a single union keeps the walker simple.    */
/* ====================================================================================== */
#pragma pack(push, 1)


/* --- line-unique C_ASSERT replacement (cl.exe strict mode chokes on the
   WDK's shared __C_ASSERT__ typedef when multiple asserts appear in the
   same TU). Same semantics: fail the build if the expression is false. */
#ifdef C_ASSERT
#undef C_ASSERT
#endif
#define _AL_HV_CAT2(a,b) a##b
#define _AL_HV_CAT(a,b) _AL_HV_CAT2(a,b)
#define C_ASSERT(e) typedef char _AL_HV_CAT(__C_ASSERT_LN_, __LINE__)[(e) ? 1 : -1]

typedef union _NPT_ENTRY {
    u64 flags;
    struct {
        u64 p               : 1;    /* Present.                                                */
        u64 rw              : 1;    /* Read/write.                                             */
        u64 us              : 1;    /* User/supervisor.                                        */
        u64 pwt             : 1;
        u64 pcd             : 1;
        u64 a               : 1;
        u64 d               : 1;
        u64 ps_or_pat       : 1;    /* PS in PDE/PDPTE; PAT in PTE.                            */
        u64 g               : 1;
        u64 avl_low         : 3;    /* Available to software.                                  */
        u64 pfn             : 40;   /* Bits 51..12: physical frame number of next-level or page.
                                       For 2 MiB / 1 GiB entries the low bits inside the PFN
                                       must be zero (natural alignment). */
        u64 avl_high        : 11;   /* Available (52..62).                                     */
        u64 nx              : 1;    /* No-execute.                                             */
    } bits;
} NPT_ENTRY;
C_ASSERT(sizeof(NPT_ENTRY) == 8);

/* Level tables are just 512 entries each; declaring separate typedefs keeps the walker's
 * intent readable. */
typedef NPT_ENTRY NPT_PML4E;
typedef NPT_ENTRY NPT_PDPTE;
typedef NPT_ENTRY NPT_PDE;
typedef NPT_ENTRY NPT_PTE;

typedef NPT_PML4E NPT_PML4[NPT_ENTRIES_PER_TABLE];
typedef NPT_PDPTE NPT_PDPT[NPT_ENTRIES_PER_TABLE];
typedef NPT_PDE   NPT_PD  [NPT_ENTRIES_PER_TABLE];
typedef NPT_PTE   NPT_PT  [NPT_ENTRIES_PER_TABLE];

C_ASSERT(sizeof(NPT_PML4) == PAGE_SIZE_4K);
C_ASSERT(sizeof(NPT_PDPT) == PAGE_SIZE_4K);
C_ASSERT(sizeof(NPT_PD)   == PAGE_SIZE_4K);
C_ASSERT(sizeof(NPT_PT)   == PAGE_SIZE_4K);

#pragma pack(pop)

/* ====================================================================================== */
/*  Permission triples used by the write-then-execute unpacker.                            */
/*                                                                                          */
/*  We use "canonical" defensive permissions -- present, supervisor, accessed left as       */
/*  hardware-tracked. The three states cycle:                                               */
/*                                                                                          */
/*    NORMAL   (R + W + X) : P=1, RW=1, NX=0                                                */
/*    W_TRAP   (R + W - X) : P=1, RW=1, NX=1  -- writes allowed, execute faults (NPF, ID=1) */
/*    X_TRAP   (R + X - W) : P=1, RW=0, NX=0  -- reads/exec allowed, write faults (NPF, RW=1)*/
/*                                                                                          */
/*  On boot every mapped page starts NORMAL. On a watch arm we downgrade to W_TRAP -- the   */
/*  packer will decrypt/decompress into the page (fault -> log write, flip to X_TRAP), then */
/*  jump to it (fault -> log candidate OEP, dump, flip back to NORMAL if the analyst wants  */
/*  to let the payload run).                                                                */
/* ====================================================================================== */
#define NPT_PERMS_NORMAL(pfn)   (NPT_P | NPT_RW |                (pfn) & NPT_ADDR_MASK)
#define NPT_PERMS_W_TRAP(pfn)   (NPT_P | NPT_RW | NPT_NX |       (pfn) & NPT_ADDR_MASK)
#define NPT_PERMS_X_TRAP(pfn)   (NPT_P |                          (pfn) & NPT_ADDR_MASK)
/* (NX=0, RW=0 -> read+exec allowed, write faults.)                                          */

/* Convenience derived from an existing entry's flags: strip R/W and NX to reprogram in place. */
#define NPT_MASK_PERMS_CLEAR    (NPT_RW | NPT_NX)

/* ====================================================================================== */
/*  Runtime state -- mirrors EPT_STATE on the Intel side.                                  */
/*  The identity-mapped PML4 is built once; on-demand splits demote 2 MiB PDEs to 4 KiB     */
/*  PTEs so a single watched page can trap without disturbing its 511 neighbours.           */
/* ====================================================================================== */
typedef struct _NPT_STATE {
    NPT_PML4    *pml4;                  /* 4 KiB, allocated contiguously.                     */
    u64          pml4_pa;               /* Written into VMCB.control.n_cr3.                   */
    u64          pages_split_2mb;       /* Diagnostic counter.                                */
    u64          pages_split_1gb;
    /* TODO(hv): reserve a small pre-allocated pool of empty PDs/PTs for on-fault splits so
     * the NPF handler never needs to call the allocator at fault time. */
    void        *split_pool;
    u32          split_pool_free;
    u32          split_pool_capacity;
} NPT_STATE;

/* A single watched guest-physical page in the write-then-execute unpacker -- peer of
 * EPT_WATCH. `current` records the currently installed permission triple so the exit
 * handler can advance the state machine without losing the page's real PFN. */
typedef struct _NPT_WATCH {
    u64        gpa;                     /* Watched guest-physical page (4 KiB-aligned).       */
    NPT_PTE   *pte;                     /* Live PTE mapping this page (after any split).      */
    u64        pfn;                     /* Preserved host-physical PFN (identity == gpa PFN). */
    u8         armed;
    u8         current;                 /* NPT_WATCH_STATE_*.                                 */
    u8         saw_write;
    u8         saw_exec;
    u64        write_count;
    u64        exec_count;
} NPT_WATCH;

#define NPT_WATCH_STATE_NORMAL          0   /* R + W + X.                                     */
#define NPT_WATCH_STATE_W_TRAP          1   /* R + W - X (catch exec of newly-written code).   */
#define NPT_WATCH_STATE_X_TRAP          2   /* R + X - W (catch subsequent overwrites).        */

#endif /* ALETHEIA_HV_NPT_DEFS_H */
