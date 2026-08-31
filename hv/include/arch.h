/*
 * arch.h -- Architectural definitions for the Aletheia clean-room VT-x/EPT VMI hypervisor.
 *
 * CLEAN-ROOM PROVENANCE: Every constant here is transcribed from the public Intel(R) 64
 * and IA-32 Architectures Software Developer's Manual (SDM), Volume 3B/3C/4 (December 2023
 * revision family) and public open-source references (hvpp, SimpleVisor, Bareflank, DRAKVUF,
 * LibVMI). No proprietary or anti-cheat source was consulted. Values are the ones the CPU
 * defines; they are the same in any correct implementation.
 *
 * Scope: MSR indices, CR0/CR4 bit definitions, CPUID leaves, RFLAGS bits, and the segment/
 * descriptor helpers every translation unit needs. VMCS encodings live in vmx_defs.h; EPT
 * paging structures live in ept_defs.h.
 *
 * Target: Windows x64 (AMD64), MSVC/WDK. This file is pure declarations -- safe to include
 * from C and from asm-adjacent C shims.
 */
#ifndef ALETHEIA_HV_ARCH_H
#define ALETHEIA_HV_ARCH_H

#include <ntddk.h>   /* UINT8/16/32/64, ULONG_PTR, etc. via WDK. */

#if defined(_MSC_VER)
#include <intrin.h>
#endif

/* -------------------------------------------------------------------------------------- */
/*  Fixed-width helpers                                                                    */
/* -------------------------------------------------------------------------------------- */
typedef unsigned __int8  u8;
typedef unsigned __int16 u16;
typedef unsigned __int32 u32;
typedef unsigned __int64 u64;

#ifndef BIT
#define BIT(n)      (1ull << (n))
#endif
#ifndef BITMASK
/* Inclusive mask for bits [hi:lo]. hi<64. */
#define BITMASK(hi, lo) (((0xFFFFFFFFFFFFFFFFull) >> (63 - (hi))) & ~((1ull << (lo)) - 1))
#endif

/* Page geometry. */
#define PAGE_SIZE_4K        0x1000ull
#define PAGE_SHIFT_4K       12
#define PAGE_SIZE_2M        0x200000ull
#define PAGE_SHIFT_2M       21
#define PAGE_SIZE_1G        0x40000000ull
#define PAGE_SHIFT_1G       30
#define PAGE_MASK_4K        (~(PAGE_SIZE_4K - 1))
#define PFN_4K(pa)          ((u64)(pa) >> PAGE_SHIFT_4K)

/* -------------------------------------------------------------------------------------- */
/*  Model-Specific Registers (SDM Vol 4, Table 2-2 and the VMX capability appendix)        */
/* -------------------------------------------------------------------------------------- */

/* VMX enable / lock. SDM Vol 3C 24.7, Vol 4. */
#define IA32_FEATURE_CONTROL            0x0000003A
#define   IA32_FEATURE_CONTROL_LOCK_BIT             BIT(0)  /* Lock bit. */
#define   IA32_FEATURE_CONTROL_VMXON_SMX_BIT        BIT(1)  /* Enable VMXON inside SMX. */
#define   IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX    BIT(2)  /* Enable VMXON outside SMX. */

/* VMX capability-reporting MSRs. SDM Vol 3D Appendix A. */
#define IA32_VMX_BASIC                  0x00000480
#define IA32_VMX_PINBASED_CTLS          0x00000481
#define IA32_VMX_PROCBASED_CTLS         0x00000482
#define IA32_VMX_EXIT_CTLS              0x00000483
#define IA32_VMX_ENTRY_CTLS             0x00000484
#define IA32_VMX_MISC                   0x00000485
#define IA32_VMX_CR0_FIXED0             0x00000486
#define IA32_VMX_CR0_FIXED1             0x00000487
#define IA32_VMX_CR4_FIXED0             0x00000488
#define IA32_VMX_CR4_FIXED1             0x00000489
#define IA32_VMX_VMCS_ENUM              0x0000048A
#define IA32_VMX_PROCBASED_CTLS2        0x0000048B
#define IA32_VMX_EPT_VPID_CAP           0x0000048C
/* "TRUE" capability MSRs -- valid only when IA32_VMX_BASIC bit 55 == 1. */
#define IA32_VMX_TRUE_PINBASED_CTLS     0x0000048D
#define IA32_VMX_TRUE_PROCBASED_CTLS    0x0000048E
#define IA32_VMX_TRUE_EXIT_CTLS         0x0000048F
#define IA32_VMX_TRUE_ENTRY_CTLS        0x00000490
#define IA32_VMX_VMFUNC                 0x00000491
#define IA32_VMX_PROCBASED_CTLS3        0x00000492   /* 64-bit; tertiary proc-based (public). */

/* IA32_VMX_BASIC field layout (SDM Vol 3D A.1). */
#define IA32_VMX_BASIC_REVISION_MASK        BITMASK(30, 0)  /* Bits 30:0 VMCS revision id. */
#define IA32_VMX_BASIC_VMCS_SIZE_SHIFT      32              /* Bits 44:32 region size. */
#define IA32_VMX_BASIC_VMCS_SIZE_MASK       BITMASK(44, 32)
#define IA32_VMX_BASIC_MEMTYPE_SHIFT        50              /* Bits 53:50 VMCS memory type. */
#define IA32_VMX_BASIC_MEMTYPE_MASK         BITMASK(53, 50)
#define IA32_VMX_BASIC_INS_OUTS             BIT(54)         /* VM-exit reports INS/OUTS info. */
#define IA32_VMX_BASIC_TRUE_CTLS            BIT(55)         /* TRUE capability MSRs present. */

/* IA32_VMX_MISC selected fields (SDM Vol 3D A.6). */
#define IA32_VMX_MISC_PREEMPT_TSC_RATE_MASK BITMASK(4, 0)   /* VMX-preemption timer TSC ratio. */
#define IA32_VMX_MISC_ACT_HLT               BIT(6)
#define IA32_VMX_MISC_ACT_SHUTDOWN          BIT(7)
#define IA32_VMX_MISC_ACT_WAIT_SIPI         BIT(8)
#define IA32_VMX_MISC_CR3_TARGETS_SHIFT     16
#define IA32_VMX_MISC_MSR_LIST_MAX_SHIFT    25

/* Extended feature enable register. SDM Vol 4 Table 2-2. */
#define IA32_EFER                       0xC0000080
#define   IA32_EFER_SCE                 BIT(0)   /* SYSCALL enable. */
#define   IA32_EFER_LME                 BIT(8)   /* Long-mode enable. */
#define   IA32_EFER_LMA                 BIT(10)  /* Long-mode active. */
#define   IA32_EFER_NXE                 BIT(11)  /* No-execute enable. */

/* SYSCALL/SYSENTER plumbing needed for host/guest state save (SDM Vol 4). */
#define IA32_SYSENTER_CS                0x00000174
#define IA32_SYSENTER_ESP               0x00000175
#define IA32_SYSENTER_EIP               0x00000176
#define IA32_STAR                       0xC0000081
#define IA32_LSTAR                      0xC0000082
#define IA32_CSTAR                      0xC0000083
#define IA32_FMASK                      0xC0000084
#define IA32_FS_BASE                    0xC0000100
#define IA32_GS_BASE                    0xC0000101
#define IA32_KERNEL_GS_BASE             0xC0000102
#define IA32_TSC                        0x00000010
#define IA32_TSC_AUX                    0xC0000103
#define IA32_DEBUGCTL                   0x000001D9
#define IA32_PAT                        0x00000277
#define IA32_BIOS_SIGN_ID               0x0000008B

/* MTRR MSRs (SDM Vol 3A 12.11, Vol 4). Consulted when composing the EPT memory-type map. */
#define IA32_MTRRCAP                    0x000000FE
#define   IA32_MTRRCAP_VCNT_MASK        BITMASK(7, 0)   /* Number of variable-range regs. */
#define   IA32_MTRRCAP_FIX              BIT(8)          /* Fixed-range MTRRs supported. */
#define   IA32_MTRRCAP_WC               BIT(10)         /* Write-combining supported. */
#define   IA32_MTRRCAP_SMRR             BIT(11)         /* SMRR supported. */
#define IA32_MTRR_DEF_TYPE              0x000002FF
#define   IA32_MTRR_DEF_TYPE_TYPE_MASK  BITMASK(7, 0)   /* Default memory type. */
#define   IA32_MTRR_DEF_TYPE_FE         BIT(10)         /* Fixed-range enable. */
#define   IA32_MTRR_DEF_TYPE_E          BIT(11)         /* MTRR enable. */
/* Fixed-range MTRRs. */
#define IA32_MTRR_FIX64K_00000          0x00000250
#define IA32_MTRR_FIX16K_80000          0x00000258
#define IA32_MTRR_FIX16K_A0000          0x00000259
#define IA32_MTRR_FIX4K_C0000           0x00000268  /* ...C0000..F8000 run to 0x0000026F. */
#define IA32_MTRR_FIX4K_C8000           0x00000269
#define IA32_MTRR_FIX4K_D0000           0x0000026A
#define IA32_MTRR_FIX4K_D8000           0x0000026B
#define IA32_MTRR_FIX4K_E0000           0x0000026C
#define IA32_MTRR_FIX4K_E8000           0x0000026D
#define IA32_MTRR_FIX4K_F0000           0x0000026E
#define IA32_MTRR_FIX4K_F8000           0x0000026F
/* Variable-range MTRRs: PHYSBASE at 0x200+2n, PHYSMASK at 0x201+2n. */
#define IA32_MTRR_PHYSBASE0             0x00000200
#define IA32_MTRR_PHYSMASK0             0x00000201
#define IA32_MTRR_PHYSBASE(n)           (IA32_MTRR_PHYSBASE0 + 2u * (n))
#define IA32_MTRR_PHYSMASK(n)           (IA32_MTRR_PHYSMASK0 + 2u * (n))
#define   IA32_MTRR_PHYSMASK_VALID      BIT(11)
#define   IA32_MTRR_PHYSBASE_TYPE_MASK  BITMASK(7, 0)

/* Memory types (shared by MTRR, PAT, and EPT; SDM Vol 3A Table 11-11). */
#define MEMTYPE_UC          0x00u   /* Uncacheable. */
#define MEMTYPE_WC          0x01u   /* Write-combining. */
#define MEMTYPE_WT          0x04u   /* Write-through. */
#define MEMTYPE_WP          0x05u   /* Write-protected. */
#define MEMTYPE_WB          0x06u   /* Write-back. */
#define MEMTYPE_UC_MINUS    0x07u   /* UC- (PAT only). */

/* -------------------------------------------------------------------------------------- */
/*  IA32_VMX_EPT_VPID_CAP field layout (SDM Vol 3D A.10)                                   */
/* -------------------------------------------------------------------------------------- */
#define VMX_EPT_CAP_EXEC_ONLY               BIT(0)   /* Execute-only translations supported. */
#define VMX_EPT_CAP_PAGE_WALK_4             BIT(6)   /* 4-level page walk. */
#define VMX_EPT_CAP_MEMTYPE_UC              BIT(8)   /* EPTP may specify UC. */
#define VMX_EPT_CAP_MEMTYPE_WB              BIT(14)  /* EPTP may specify WB. */
#define VMX_EPT_CAP_2MB_PAGE                BIT(16)  /* EPT 2MB pages. */
#define VMX_EPT_CAP_1GB_PAGE               BIT(17)  /* EPT 1GB pages. */
#define VMX_EPT_CAP_INVEPT                  BIT(20)  /* INVEPT supported. */
#define VMX_EPT_CAP_AD_BITS                 BIT(21)  /* Accessed/dirty flags for EPT. */
#define VMX_EPT_CAP_ADVANCED_VMEXIT_INFO    BIT(22)  /* Advanced EPT-violation exit info. */
#define VMX_EPT_CAP_INVEPT_SINGLE           BIT(25)  /* INVEPT single-context. */
#define VMX_EPT_CAP_INVEPT_ALL              BIT(26)  /* INVEPT all-context. */
#define VMX_EPT_CAP_INVVPID                 BIT(32)  /* INVVPID supported. */
#define VMX_EPT_CAP_INVVPID_INDIV_ADDR      BIT(40)  /* INVVPID individual-address. */
#define VMX_EPT_CAP_INVVPID_SINGLE          BIT(41)  /* INVVPID single-context. */
#define VMX_EPT_CAP_INVVPID_ALL             BIT(42)  /* INVVPID all-context. */
#define VMX_EPT_CAP_INVVPID_SINGLE_RETAIN   BIT(43)  /* Single-context retaining globals. */

/* -------------------------------------------------------------------------------------- */
/*  Control registers (SDM Vol 3A 2.5)                                                     */
/* -------------------------------------------------------------------------------------- */
#define CR0_PE      BIT(0)   /* Protection enable. */
#define CR0_MP      BIT(1)   /* Monitor coprocessor. */
#define CR0_EM      BIT(2)   /* Emulation. */
#define CR0_TS      BIT(3)   /* Task switched. */
#define CR0_ET      BIT(4)   /* Extension type. */
#define CR0_NE      BIT(5)   /* Numeric error. */
#define CR0_WP      BIT(16)  /* Write protect. */
#define CR0_AM      BIT(18)  /* Alignment mask. */
#define CR0_NW      BIT(29)  /* Not write-through. */
#define CR0_CD      BIT(30)  /* Cache disable. */
#define CR0_PG      BIT(31)  /* Paging. */

#define CR4_VME         BIT(0)   /* Virtual-8086 mode extensions. */
#define CR4_PVI         BIT(1)   /* Protected-mode virtual interrupts. */
#define CR4_TSD         BIT(2)   /* Time-stamp disable. */
#define CR4_DE          BIT(3)   /* Debugging extensions. */
#define CR4_PSE         BIT(4)   /* Page-size extensions. */
#define CR4_PAE         BIT(5)   /* Physical-address extension. */
#define CR4_MCE         BIT(6)   /* Machine-check enable. */
#define CR4_PGE         BIT(7)   /* Page global enable. */
#define CR4_PCE         BIT(8)   /* Performance-monitoring counter enable. */
#define CR4_OSFXSR      BIT(9)   /* OS support for FXSAVE/FXRSTOR. */
#define CR4_OSXMMEXCPT  BIT(10)  /* OS support for unmasked SIMD exceptions. */
#define CR4_UMIP        BIT(11)  /* User-mode instruction prevention. */
#define CR4_LA57        BIT(12)  /* 57-bit linear addresses (5-level paging). */
#define CR4_VMXE        BIT(13)  /* VMX enable. */
#define CR4_SMXE        BIT(14)  /* SMX enable. */
#define CR4_FSGSBASE    BIT(16)  /* Enable RD/WR FS/GS BASE. */
#define CR4_PCIDE       BIT(17)  /* PCID enable. */
#define CR4_OSXSAVE     BIT(18)  /* XSAVE and processor extended states. */
#define CR4_SMEP        BIT(20)  /* Supervisor-mode execution prevention. */
#define CR4_SMAP        BIT(21)  /* Supervisor-mode access prevention. */
#define CR4_PKE         BIT(22)  /* Protection-key enable. */
#define CR4_CET         BIT(23)  /* Control-flow enforcement technology. */

/* Bit positions inside the CR-access VM-exit qualification. Kept here with the CR defs. */
#define CR3_ADDR_MASK   0xFFFFFFFFFFFFF000ull

/* -------------------------------------------------------------------------------------- */
/*  RFLAGS (SDM Vol 1 3.4.3)                                                               */
/* -------------------------------------------------------------------------------------- */
#define RFLAGS_CF   BIT(0)   /* Carry -- set by VMfailInvalid. */
#define RFLAGS_PF   BIT(2)   /* Parity. */
#define RFLAGS_AF   BIT(4)   /* Auxiliary carry. */
#define RFLAGS_ZF   BIT(6)   /* Zero -- set by VMfailValid. */
#define RFLAGS_SF   BIT(7)   /* Sign. */
#define RFLAGS_TF   BIT(8)   /* Trap. */
#define RFLAGS_IF   BIT(9)   /* Interrupt enable. */
#define RFLAGS_DF   BIT(10)  /* Direction. */
#define RFLAGS_OF   BIT(11)  /* Overflow. */
#define RFLAGS_RESERVED_1  BIT(1)  /* Always 1. */

/* -------------------------------------------------------------------------------------- */
/*  CPUID leaves used by feature detection (SDM Vol 2A CPUID)                              */
/* -------------------------------------------------------------------------------------- */
#define CPUID_LEAF_VENDOR               0x00000000  /* EBX/EDX/ECX = "GenuineIntel". */
#define CPUID_LEAF_FEATURES             0x00000001  /* ECX bit 5 = VMX. */
#define   CPUID_1_ECX_VMX               BIT(5)
#define   CPUID_1_ECX_HYPERVISOR        BIT(31)     /* Set by a present hypervisor. */
#define CPUID_LEAF_EXT_FEATURES         0x00000007  /* Structured extended features. */
#define CPUID_LEAF_EXT_MAX              0x80000000
#define CPUID_LEAF_EXT_FEATURES_2       0x80000001  /* EDX bit 20 = NX, bit 29 = LM. */
#define   CPUID_EXT1_EDX_NX             BIT(20)
#define   CPUID_EXT1_EDX_LM             BIT(29)
#define CPUID_LEAF_ADDR_WIDTH           0x80000008  /* EAX[7:0] = physical-address bits. */

/* Intel "GenuineIntel" vendor signature (EBX, EDX, ECX order from CPUID.0). */
#define CPUID_VENDOR_INTEL_EBX          0x756E6547  /* "Genu" */
#define CPUID_VENDOR_INTEL_EDX          0x49656E69  /* "ineI" */
#define CPUID_VENDOR_INTEL_ECX          0x6C65746E  /* "ntel" */

/* Synthetic CPUID leaf the VMI layer answers to prove presence during bring-up.
 * TODO(hv): pick a leaf in the 0x40000000-0x400000FF hypervisor range and document it. */
#define CPUID_LEAF_ALETHEIA_PRESENT     0x40000000

/* Answer returned in EAX:EBX:ECX:EDX for the hypervisor vendor leaf above (the standard
 * 0x40000000 hypervisor-CPUID convention). EAX = highest hypervisor leaf implemented; the
 * EBX/ECX/EDX dwords spell the 12-byte vendor id "AletheiaHV\0\0" in CPUID string order.
 * ADDED by vmexit.c author: arch.h defined only the leaf, not the response. */
#define CPUID_HV_VENDOR_MAX_LEAF        0x40000000
#define CPUID_HV_VENDOR_EBX             0x74656C41  /* "Alet" */
#define CPUID_HV_VENDOR_ECX             0x61696568  /* "heia" */
#define CPUID_HV_VENDOR_EDX             0x00005648  /* "HV\0\0" */

/* Out-of-band knock that gates the synthetic vendor leaf above. The standard
 * 0x40000000 leaf is probed unconditionally by detection-aware guests (the exact
 * adversary this HV observes), so answering it on a blind probe would leak the
 * hypervisor's name and defeat the transparency the stripped CPUID.1:ECX[31]
 * buys. The Aletheia agent loads EDX with this magic before its CPUID; any other
 * caller (EDX != magic) falls through to bare-metal passthrough. EDX is not a
 * CPUID input register (leaf=EAX, subleaf=ECX), so it is free to carry a secret,
 * and a blind probe matching a full 32-bit magic is ~1-in-2^32. */
#define CPUID_ALETHEIA_MAGIC_EDX        0x6874656C  /* "leth" */

/* -------------------------------------------------------------------------------------- */
/*  Segment selector / descriptor helpers (SDM Vol 3A 3.4.5)                               */
/* -------------------------------------------------------------------------------------- */
#define SELECTOR_RPL_MASK   0x0003
#define SELECTOR_TI_MASK    0x0004
#define SELECTOR_INDEX_MASK 0xFFF8

/* Access-rights word as consumed by the guest/host segment VMCS fields (SDM 24.4.1). */
typedef union _VMX_SEGMENT_ACCESS_RIGHTS {
    u32 all;
    struct {
        u32 type       : 4;   /* Segment type. */
        u32 s          : 1;   /* Descriptor type (0 = system, 1 = code/data). */
        u32 dpl        : 2;   /* Descriptor privilege level. */
        u32 present    : 1;   /* Present. */
        u32 reserved0  : 4;
        u32 avl        : 1;   /* Available for use by system software. */
        u32 l          : 1;   /* 64-bit mode active (for CS). */
        u32 db         : 1;   /* Default operation size. */
        u32 g          : 1;   /* Granularity. */
        u32 unusable   : 1;   /* Segment unusable (bit 16). */
        u32 reserved1  : 15;
    } bits;
} VMX_SEGMENT_ACCESS_RIGHTS;


/* --- line-unique C_ASSERT replacement (cl.exe strict mode chokes on the
   WDK's shared __C_ASSERT__ typedef when multiple asserts appear in the
   same TU). Same semantics: fail the build if the expression is false. */
#ifdef C_ASSERT
#undef C_ASSERT
#endif
#define _AL_HV_CAT2(a,b) a##b
#define _AL_HV_CAT(a,b) _AL_HV_CAT2(a,b)
#define C_ASSERT(e) typedef char _AL_HV_CAT(__C_ASSERT_LN_, __LINE__)[(e) ? 1 : -1]

/* A raw GDT/IDT descriptor as loaded by SGDT/SIDT (10-byte pseudo-descriptor). */
#pragma pack(push, 1)
typedef struct _PSEUDO_DESCRIPTOR_64 {
    u16 limit;
    u64 base;
} PSEUDO_DESCRIPTOR_64;
#pragma pack(pop)
C_ASSERT(sizeof(PSEUDO_DESCRIPTOR_64) == 10);

/* -------------------------------------------------------------------------------------- */
/*  static_assert alias -- WDK ships C_ASSERT; keep a portable spelling too.               */
/* -------------------------------------------------------------------------------------- */
#ifndef HV_STATIC_ASSERT
#define HV_STATIC_ASSERT(cond) C_ASSERT(cond)
#endif

#endif /* ALETHEIA_HV_ARCH_H */
