/*
 * ept_defs.h -- Extended Page Table (EPT) paging-structure bitfields, EPTP layout, EPT
 * memory types, and the EPT-violation exit-qualification layout for the Aletheia clean-room
 * VT-x/EPT VMI hypervisor.
 *
 * CLEAN-ROOM PROVENANCE: Bit layouts are transcribed from the public Intel SDM Vol 3C,
 * Chapter 29 "VMX Support for Address Translation" -- specifically the EPT PML4E / EPT PDPTE /
 * EPT PDE / EPT PTE format tables (29.3.3), the EPTP format (Table 25-9 / 29.3.2), and the
 * EPT-violation exit-qualification table (Table 29-7). Cross-checked against open-source
 * hvpp/DRAKVUF, which transcribe the same public tables. No proprietary source consulted.
 *
 * A guest-physical address is translated by a 4-level EPT walk (PML4 -> PDPT -> PD -> PT),
 * mirroring IA-32e paging: 9 index bits per level, a 12-bit page offset. Large pages (1GB at
 * the PDPTE, 2MB at the PDE) collapse the walk early. The write-then-execute VMI trick this
 * project relies on lives in the R/W/X permission bits below.
 */
#ifndef ALETHEIA_HV_EPT_DEFS_H
#define ALETHEIA_HV_EPT_DEFS_H

#include "arch.h"

/* EPT memory types carried in the paging-structure "memtype" field and in the EPTP
 * (SDM Vol 3C 29.3.7 / Table 25-9). Same numeric encoding as the MTRR/PAT memory types. */
#define EPT_MEMTYPE_UC      MEMTYPE_UC   /* 0 */
#define EPT_MEMTYPE_WC      MEMTYPE_WC   /* 1 */
#define EPT_MEMTYPE_WT      MEMTYPE_WT   /* 4 */
#define EPT_MEMTYPE_WP      MEMTYPE_WP   /* 5 */
#define EPT_MEMTYPE_WB      MEMTYPE_WB   /* 6 */

/* Walk-length encoded in the EPTP is (levels - 1); a 4-level walk stores 3. */
#define EPT_PAGE_WALK_LENGTH_4      3u

/* Index-extraction helpers for a guest-physical address (9 bits per level). */
#define EPT_PML4_INDEX(gpa)     (((u64)(gpa) >> 39) & 0x1FF)
#define EPT_PDPT_INDEX(gpa)     (((u64)(gpa) >> 30) & 0x1FF)
#define EPT_PD_INDEX(gpa)       (((u64)(gpa) >> 21) & 0x1FF)
#define EPT_PT_INDEX(gpa)       (((u64)(gpa) >> 12) & 0x1FF)
#define EPT_ENTRIES_PER_TABLE   512

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

/* -------------------------------------------------------------------------------------- */
/*  EPT PML4 entry -- references an EPT page-directory-pointer table (SDM Vol 3C 29.3.3)    */
/* -------------------------------------------------------------------------------------- */
typedef union _EPT_PML4E {
    u64 all;
    struct {
        u64 read_access     : 1;   /* bit 0  : readable. */
        u64 write_access    : 1;   /* bit 1  : writable. */
        u64 execute_access  : 1;   /* bit 2  : executable (supervisor, or both w/o MBEC). */
        u64 reserved0       : 5;   /* bits 7:3 : must be 0. */
        u64 accessed        : 1;   /* bit 8  : accessed (if EPT A/D enabled). */
        u64 ignored0        : 1;   /* bit 9. */
        u64 user_execute    : 1;   /* bit 10 : user-mode executable (if MBEC enabled). */
        u64 ignored1        : 1;   /* bit 11. */
        u64 pfn             : 40;  /* bits 51:12 : physical page number of next table. */
        u64 ignored2        : 12;  /* bits 63:52. */
    } bits;
} EPT_PML4E;
C_ASSERT(sizeof(EPT_PML4E) == 8);

/* -------------------------------------------------------------------------------------- */
/*  EPT PDPTE -- 1GB page mapping (bit 7 = 1)                                               */
/* -------------------------------------------------------------------------------------- */
typedef union _EPT_PDPTE_1GB {
    u64 all;
    struct {
        u64 read_access     : 1;   /* bit 0. */
        u64 write_access    : 1;   /* bit 1. */
        u64 execute_access  : 1;   /* bit 2. */
        u64 memory_type     : 3;   /* bits 5:3 : EPT memory type. */
        u64 ignore_pat      : 1;   /* bit 6  : ignore guest PAT. */
        u64 large_page      : 1;   /* bit 7  : must be 1 for a 1GB page. */
        u64 accessed        : 1;   /* bit 8. */
        u64 dirty           : 1;   /* bit 9. */
        u64 user_execute    : 1;   /* bit 10. */
        u64 ignored0        : 1;   /* bit 11. */
        u64 reserved0       : 18;  /* bits 29:12 : must be 0 (1GB alignment). */
        u64 pfn             : 22;  /* bits 51:30 : physical page number of the 1GB frame. */
        u64 ignored1        : 11;  /* bits 62:52. */
        u64 suppress_ve     : 1;   /* bit 63 : suppress #VE (if EPT-violation #VE enabled). */
    } bits;
} EPT_PDPTE_1GB;
C_ASSERT(sizeof(EPT_PDPTE_1GB) == 8);

/* EPT PDPTE -- references an EPT page directory (bit 7 = 0). */
typedef union _EPT_PDPTE {
    u64 all;
    struct {
        u64 read_access     : 1;
        u64 write_access    : 1;
        u64 execute_access  : 1;
        u64 reserved0       : 4;   /* bits 6:3 : must be 0. */
        u64 large_page      : 1;   /* bit 7  : must be 0 to reference a PD. */
        u64 accessed        : 1;
        u64 ignored0        : 1;
        u64 user_execute    : 1;
        u64 ignored1        : 1;
        u64 pfn             : 40;  /* bits 51:12 : PFN of the next table (PD). */
        u64 ignored2        : 12;
    } bits;
} EPT_PDPTE;
C_ASSERT(sizeof(EPT_PDPTE) == 8);

/* -------------------------------------------------------------------------------------- */
/*  EPT PDE -- 2MB page mapping (bit 7 = 1)                                                 */
/* -------------------------------------------------------------------------------------- */
typedef union _EPT_PDE_2MB {
    u64 all;
    struct {
        u64 read_access     : 1;
        u64 write_access    : 1;
        u64 execute_access  : 1;
        u64 memory_type     : 3;   /* bits 5:3. */
        u64 ignore_pat      : 1;   /* bit 6. */
        u64 large_page      : 1;   /* bit 7  : must be 1 for a 2MB page. */
        u64 accessed        : 1;
        u64 dirty           : 1;
        u64 user_execute    : 1;
        u64 ignored0        : 1;
        u64 reserved0       : 9;   /* bits 20:12 : must be 0 (2MB alignment). */
        u64 pfn             : 31;  /* bits 51:21 : physical page number of the 2MB frame. */
        u64 ignored1        : 11;
        u64 suppress_ve     : 1;   /* bit 63. */
    } bits;
} EPT_PDE_2MB;
C_ASSERT(sizeof(EPT_PDE_2MB) == 8);

/* EPT PDE -- references an EPT page table (bit 7 = 0). */
typedef union _EPT_PDE {
    u64 all;
    struct {
        u64 read_access     : 1;
        u64 write_access    : 1;
        u64 execute_access  : 1;
        u64 reserved0       : 4;   /* bits 6:3 : must be 0. */
        u64 large_page      : 1;   /* bit 7  : must be 0 to reference a PT. */
        u64 accessed        : 1;
        u64 ignored0        : 1;
        u64 user_execute    : 1;
        u64 ignored1        : 1;
        u64 pfn             : 40;  /* bits 51:12 : PFN of the next table (PT). */
        u64 ignored2        : 12;
    } bits;
} EPT_PDE;
C_ASSERT(sizeof(EPT_PDE) == 8);

/* -------------------------------------------------------------------------------------- */
/*  EPT PTE -- maps a single 4KB guest-physical page (SDM Vol 3C 29.3.3)                    */
/*                                                                                          */
/*  This is the entry the VMI unpacker toggles: strip write_access to trap the packer's     */
/*  self-modifying store, then on the write-EPT-violation restore W and strip                */
/*  execute_access so the first fetch from the freshly written page re-exits -- the          */
/*  classic write-then-execute OEP capture.                                                  */
/* -------------------------------------------------------------------------------------- */
typedef union _EPT_PTE {
    u64 all;
    struct {
        u64 read_access     : 1;   /* bit 0. */
        u64 write_access    : 1;   /* bit 1. */
        u64 execute_access  : 1;   /* bit 2. */
        u64 memory_type     : 3;   /* bits 5:3 : EPT memory type. */
        u64 ignore_pat      : 1;   /* bit 6. */
        u64 ignored0        : 1;   /* bit 7. */
        u64 accessed        : 1;   /* bit 8. */
        u64 dirty           : 1;   /* bit 9. */
        u64 user_execute    : 1;   /* bit 10 : user-mode executable (MBEC). */
        u64 ignored1        : 1;   /* bit 11. */
        u64 pfn             : 40;  /* bits 51:12 : physical page number of the mapped frame. */
        u64 ignored2        : 11;  /* bits 62:52. */
        u64 suppress_ve     : 1;   /* bit 63. */
    } bits;
} EPT_PTE;
C_ASSERT(sizeof(EPT_PTE) == 8);

/* Generic EPT entry view -- the low permission bits and PFN are common across all levels,
 * so table-walk code can treat any entry uniformly for R/W/X and next-PFN. */
typedef union _EPT_ENTRY {
    u64 all;
    struct {
        u64 read_access     : 1;
        u64 write_access    : 1;
        u64 execute_access  : 1;
        u64 bits_3_6        : 4;
        u64 large_page      : 1;   /* bit 7. */
        u64 bits_8_11       : 4;
        u64 pfn             : 40;
        u64 bits_52_63      : 12;
    } bits;
} EPT_ENTRY;
C_ASSERT(sizeof(EPT_ENTRY) == 8);

/* -------------------------------------------------------------------------------------- */
/*  EPT pointer (EPTP) -- loaded into VMCS_CTRL_EPT_POINTER (SDM Vol 3C Table 25-9)         */
/* -------------------------------------------------------------------------------------- */
typedef union _EPTP {
    u64 all;
    struct {
        u64 memory_type     : 3;   /* bits 2:0 : EPT paging-structure memory type (UC or WB). */
        u64 walk_length     : 3;   /* bits 5:3 : page-walk length minus 1 (== 3 for 4 levels). */
        u64 enable_ad       : 1;   /* bit 6  : enable accessed/dirty flags for EPT. */
        u64 enable_sss      : 1;   /* bit 7  : enable supervisor shadow-stack access control. */
        u64 reserved0       : 4;   /* bits 11:8 : must be 0. */
        u64 pml4_pfn        : 40;  /* bits 51:12 : PFN of the top-level EPT PML4 table. */
        u64 reserved1       : 12;  /* bits 63:52 : must be 0. */
    } bits;
} EPTP;
C_ASSERT(sizeof(EPTP) == 8);

#pragma pack(pop)

/* -------------------------------------------------------------------------------------- */
/*  Permission helpers for the write-then-execute VMI strategy                              */
/* -------------------------------------------------------------------------------------- */
#define EPT_ACCESS_NONE     0u
#define EPT_ACCESS_R        BIT(0)
#define EPT_ACCESS_W        BIT(1)
#define EPT_ACCESS_X        BIT(2)
#define EPT_ACCESS_RW       (EPT_ACCESS_R | EPT_ACCESS_W)
#define EPT_ACCESS_RX       (EPT_ACCESS_R | EPT_ACCESS_X)
#define EPT_ACCESS_RWX      (EPT_ACCESS_R | EPT_ACCESS_W | EPT_ACCESS_X)

/* -------------------------------------------------------------------------------------- */
/*  EPT-violation exit qualification (SDM Vol 3C Table 29-7)                                */
/*                                                                                          */
/*  Read from VMCS_RO_EXIT_QUALIFICATION on an EXIT_REASON_EPT_VIOLATION. Bits 2:0 report    */
/*  the access that faulted; bits 5:3 report the EPT permissions in effect at fault time.    */
/* -------------------------------------------------------------------------------------- */
#define EPT_VIOLATION_READ              BIT(0)   /* Access was a data read. */
#define EPT_VIOLATION_WRITE            BIT(1)   /* Access was a data write. */
#define EPT_VIOLATION_INSTR_FETCH       BIT(2)   /* Access was an instruction fetch. */
#define EPT_VIOLATION_EPT_READABLE      BIT(3)   /* Entry allowed read. */
#define EPT_VIOLATION_EPT_WRITABLE      BIT(4)   /* Entry allowed write. */
#define EPT_VIOLATION_EPT_EXECUTABLE    BIT(5)   /* Entry allowed (supervisor) execute. */
#define EPT_VIOLATION_EPT_USER_EXEC     BIT(6)   /* Entry allowed user-mode execute (MBEC). */
#define EPT_VIOLATION_GLA_VALID         BIT(7)   /* Guest-linear-address field is valid. */
#define EPT_VIOLATION_GLA_TO_PAGE       BIT(8)   /* 0 = paging-structure access, 1 = translation. */
#define EPT_VIOLATION_USER_MODE_ADDR    BIT(9)   /* Guest linear addr was user-mode accessible. */
#define EPT_VIOLATION_RW_PAGE           BIT(10)  /* Guest translation was writable. */
#define EPT_VIOLATION_EXEC_DISABLED     BIT(11)  /* Guest translation had XD/NX set. */
#define EPT_VIOLATION_NMI_UNBLOCK_IRET  BIT(12)  /* NMI unblocking due to IRET. */
#define EPT_VIOLATION_SHADOW_STACK      BIT(13)  /* Access was a shadow-stack access. */

/* Decoded, human-readable form of an EPT-violation qualification the VMI layer passes
 * around in place of the raw 64-bit word. */
typedef struct _EPT_VIOLATION_INFO {
    u64 guest_physical_address;   /* From VMCS_RO_GUEST_PHYSICAL_ADDR. */
    u64 guest_linear_address;     /* From VMCS_RO_GUEST_LINEAR_ADDR (valid iff gla_valid). */
    u32 qualification;            /* Raw exit qualification bits above. */
    u8  is_read;
    u8  is_write;
    u8  is_execute;
    u8  gla_valid;
} EPT_VIOLATION_INFO;

/* -------------------------------------------------------------------------------------- */
/*  Identity-map geometry (for the initial 1:1 GPA==HPA EPT the driver builds)              */
/* -------------------------------------------------------------------------------------- */
/* One PML4 -> one PDPT covers 512GB with 512 PD tables, each PD holding 512 2MB entries.
 * TODO(hv): the real span must be sized from the top of physical RAM reported by the memory
 * map / CPUID.80000008 rather than assuming a fixed 512GB. */
#define EPT_IDENTITY_PDPT_COUNT     1
#define EPT_IDENTITY_PD_COUNT       512
#define EPT_IDENTITY_PDE_PER_PD     512

#endif /* ALETHEIA_HV_EPT_DEFS_H */
