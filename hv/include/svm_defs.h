/*
 * svm_defs.h -- AMD SVM (Secure Virtual Machine) interface types for the Aletheia
 * clean-room VMI hypervisor. Peer to vmx_defs.h; the vendor-neutral hv.h glues the two.
 *
 * CLEAN-ROOM PROVENANCE: every value, field offset, and bit layout in this header is
 * transcribed from the AMD64 Architecture Programmer's Manual (APM), Volume 2 -- "System
 * Programming". Cross-checked for architectural intent against public open-source VMMs
 * (Bareflank AMD backend, KVM-svm, hvbd) that themselves transcribe the same APM tables.
 * No proprietary source consulted. No private/anti-cheat HV was referenced.
 *
 * PRIMARY CITATIONS (AMD APM Vol 2, revision 24593; section numbers correct as of that rev):
 *   VMCB layout ................... §15.5,  Tables 15-1 (control area), 15-2 (state save)
 *   Intercept fields .............. §15.7,  Tables 15-3, 15-4, 15-5, 15-6, 15-7
 *   VMCB clean bits ............... §15.15, Table 15-8
 *   VMEXIT codes .................. §15.9,  Table 15-9 (SVM_EXIT_*)
 *   NPT (nested paging) ........... §15.25
 *   EFER.SVME ..................... §15.4,  MSR C000_0080h bit 12
 *   VM_CR / SVMDIS / SVMLOCK ...... §15.30, MSR C001_0114h
 *   VM_HSAVE_PA ................... §15.30, MSR C001_0117h
 *   IOPM (I/O permission bitmap) .. §15.10.1 (12 KiB + 1 bit, 4 KiB-aligned)
 *   MSRPM (MSR permission bitmap) . §15.11   (8 KiB, 4 KiB-aligned)
 *   TLB control ................... §15.16
 *   VMRUN / VMEXIT ................ §15.6
 *
 * Layout correctness is the whole game -- hardware loads/saves the VMCB directly by these
 * offsets. Every field group carries a C_ASSERT on its offset; the top-level VMCB carries
 * one on its total size (0x1000, one 4 KiB page).
 *
 * CANNOT BE BUILT OR RUN IN THIS ENVIRONMENT. Every unresolved decision is marked
 * "// TODO(hv):".
 */
#ifndef ALETHEIA_HV_SVM_DEFS_H
#define ALETHEIA_HV_SVM_DEFS_H

#include "arch.h"

/* ====================================================================================== */
/*  AMD-specific MSRs (APM Vol 2 §15.4, §15.30; also APM Vol 2 Appendix A "MSR Cross-Ref") */
/* ====================================================================================== */
#define MSR_EFER                        0xC0000080  /* Extended Feature Enable Register.       */
#define EFER_SCE                        BIT(0)      /* SYSCALL enable.                         */
#define EFER_LME                        BIT(8)      /* Long-mode enable.                       */
#define EFER_LMA                        BIT(10)     /* Long-mode active.                       */
#define EFER_NXE                        BIT(11)     /* No-execute enable.                      */
#define EFER_SVME                       BIT(12)     /* Secure Virtual Machine enable.          */
#define EFER_LMSLE                      BIT(13)     /* Long-mode segment-limit enable.         */
#define EFER_FFXSR                      BIT(14)     /* Fast FXSAVE/FXRSTOR.                    */
#define EFER_TCE                        BIT(15)     /* Translation cache extension.            */

#define MSR_VM_CR                       0xC0010114  /* SVM control MSR (§15.30.1).             */
#define VM_CR_DPD                       BIT(0)      /* Disable HDT (host debug port).          */
#define VM_CR_R_INIT                    BIT(1)      /* R_INIT: intercept INIT.                 */
#define VM_CR_DIS_A20M                  BIT(2)      /* Disable A20 masking.                    */
#define VM_CR_LOCK                      BIT(3)      /* LOCK: SVMDIS write-locked.              */
#define VM_CR_SVMDIS                    BIT(4)      /* SVMDIS: SVM disabled by BIOS.           */

#define MSR_VM_HSAVE_PA                 0xC0010117  /* Host state save area PA (§15.30.4).     */

#define MSR_TSC_AUX                     0xC0000103  /* RDTSCP auxiliary.                       */

/* CPUID leaves. APM Vol 3 CPUID reference. */
#define CPUID_FN_EXT_FEATURES           0x80000001  /* ECX bit 2 (SVM) is the AMD-V gate.      */
#define CPUID_EXT_FEATURES_ECX_SVM      BIT(2)      /* CPUID.80000001h:ECX[2].                 */

#define CPUID_FN_SVM_FEATURES           0x8000000A  /* SVM revision + feature bits.            */
/* CPUID.8000000Ah:EAX[7:0] = SVM revision.                                                    */
/* CPUID.8000000Ah:EBX[31:0] = NASID (number of address-space IDs supported).                  */
/* CPUID.8000000Ah:EDX[bit N] feature bits below.                                              */
#define CPUID_SVM_EDX_NP                BIT(0)      /* Nested paging present.                  */
#define CPUID_SVM_EDX_LBRV              BIT(1)      /* LBR virtualization.                     */
#define CPUID_SVM_EDX_SVML              BIT(2)      /* SVM lock present.                       */
#define CPUID_SVM_EDX_NRIPS             BIT(3)      /* NRIP save (next-sequential IP).         */
#define CPUID_SVM_EDX_TSC_RATE_MSR      BIT(4)      /* MSR-based TSC ratio.                    */
#define CPUID_SVM_EDX_VMCB_CLEAN        BIT(5)      /* VMCB clean bits.                        */
#define CPUID_SVM_EDX_FLUSHBYASID       BIT(6)      /* TLB flush by ASID.                      */
#define CPUID_SVM_EDX_DECODEASSIST      BIT(7)      /* Decode assists.                         */
#define CPUID_SVM_EDX_PAUSEFILTER       BIT(10)     /* Pause intercept filter.                 */
#define CPUID_SVM_EDX_PFTHRESHOLD       BIT(12)     /* PAUSE filter threshold.                 */
#define CPUID_SVM_EDX_AVIC              BIT(13)     /* Advanced Virtual Interrupt Controller.  */
#define CPUID_SVM_EDX_V_VMSAVE_VMLOAD   BIT(15)     /* Virtualized VMSAVE/VMLOAD.              */
#define CPUID_SVM_EDX_VGIF              BIT(16)     /* Virtualized GIF.                        */

/* Fixed VMCB region sizing (§15.5). Hardware requires a full page, 4 KiB-aligned. */
#define SVM_VMCB_SIZE                   PAGE_SIZE_4K
#define SVM_HSAVE_SIZE                  PAGE_SIZE_4K
#define SVM_IOPM_SIZE                   (3 * PAGE_SIZE_4K)  /* 12 KiB + 1 bit; alloc 12 KiB.  */
#define SVM_MSRPM_SIZE                  (2 * PAGE_SIZE_4K)  /* 8 KiB.                          */

/* IOPM must be strictly larger than 12 KiB by one bit for I/O port 65535 (§15.10.1). Most
 * VMMs simply allocate 3 pages == 12 KiB and treat the trailing bit as "in-range". A stricter
 * conformance would allocate 12 KiB + 1 byte and land it on a 4 KiB-aligned base; we take the
 * common 3-page allocation. TODO(hv): confirm the CPU tolerates a 3-page IOPM (KVM-svm does). */

/* ====================================================================================== */
/*  Guest ASID / TLB control (VMCB control area offset 0x058-0x05F; §15.16)                */
/* ====================================================================================== */
#define SVM_TLB_CONTROL_DO_NOTHING              0x00  /* Do not flush.                         */
#define SVM_TLB_CONTROL_FLUSH_ALL_ASIDS         0x01  /* Flush entire TLB.                     */
#define SVM_TLB_CONTROL_FLUSH_THIS_GUEST        0x03  /* Requires FlushByAsid feature.         */
#define SVM_TLB_CONTROL_FLUSH_THIS_NON_GLOBAL   0x07  /* Requires FlushByAsid feature.         */

/* ====================================================================================== */
/*  Intercept vectors (VMCB control area offsets 0x000-0x013). APM §15.7 / Tables 15-3..7. */
/* ====================================================================================== */
/* Intercept CR read/write (offset 0x000, u32): bits 0..15 = CR0..CR15 read, 16..31 = write. */
#define SVM_ICPT_CR_READ(n)     (1u << (n))                 /* 0 <= n <= 15                    */
#define SVM_ICPT_CR_WRITE(n)    (1u << (16 + (n)))          /* 0 <= n <= 15                    */

/* Intercept DR read/write (offset 0x004, u32): same layout as CR. */
#define SVM_ICPT_DR_READ(n)     (1u << (n))
#define SVM_ICPT_DR_WRITE(n)    (1u << (16 + (n)))

/* Intercept Exceptions (offset 0x008, u32): bit N = vector N (0..31). */
#define SVM_ICPT_EXCEPTION(v)   (1u << (v))                 /* v in 0..31                      */

/* Intercept Word 3 (offset 0x00C, u32). APM Table 15-4. */
#define SVM_ICPT_INTR                   BIT(0)
#define SVM_ICPT_NMI                    BIT(1)
#define SVM_ICPT_SMI                    BIT(2)
#define SVM_ICPT_INIT                   BIT(3)
#define SVM_ICPT_VINTR                  BIT(4)
#define SVM_ICPT_CR0_SEL_WRITE          BIT(5)
#define SVM_ICPT_IDTR_READ              BIT(6)
#define SVM_ICPT_GDTR_READ              BIT(7)
#define SVM_ICPT_LDTR_READ              BIT(8)
#define SVM_ICPT_TR_READ                BIT(9)
#define SVM_ICPT_IDTR_WRITE             BIT(10)
#define SVM_ICPT_GDTR_WRITE             BIT(11)
#define SVM_ICPT_LDTR_WRITE             BIT(12)
#define SVM_ICPT_TR_WRITE               BIT(13)
#define SVM_ICPT_RDTSC                  BIT(14)
#define SVM_ICPT_RDPMC                  BIT(15)
#define SVM_ICPT_PUSHF                  BIT(16)
#define SVM_ICPT_POPF                   BIT(17)
#define SVM_ICPT_CPUID                  BIT(18)
#define SVM_ICPT_RSM                    BIT(19)
#define SVM_ICPT_IRET                   BIT(20)
#define SVM_ICPT_INT_N                  BIT(21)     /* SWINT (INTn).                           */
#define SVM_ICPT_INVD                   BIT(22)
#define SVM_ICPT_PAUSE                  BIT(23)
#define SVM_ICPT_HLT                    BIT(24)
#define SVM_ICPT_INVLPG                 BIT(25)
#define SVM_ICPT_INVLPGA                BIT(26)
#define SVM_ICPT_IOIO_PROT              BIT(27)     /* Consult the IOPM.                       */
#define SVM_ICPT_MSR_PROT               BIT(28)     /* Consult the MSRPM.                      */
#define SVM_ICPT_TASK_SWITCH            BIT(29)
#define SVM_ICPT_FERR_FREEZE            BIT(30)
#define SVM_ICPT_SHUTDOWN               BIT(31)

/* Intercept Word 4 (offset 0x010, u32). APM Table 15-5. */
#define SVM_ICPT_VMRUN                  BIT(0)      /* MUST be set for a valid VMCB.           */
#define SVM_ICPT_VMMCALL                BIT(1)
#define SVM_ICPT_VMLOAD                 BIT(2)
#define SVM_ICPT_VMSAVE                 BIT(3)
#define SVM_ICPT_STGI                   BIT(4)
#define SVM_ICPT_CLGI                   BIT(5)
#define SVM_ICPT_SKINIT                 BIT(6)
#define SVM_ICPT_RDTSCP                 BIT(7)
#define SVM_ICPT_ICEBP                  BIT(8)
#define SVM_ICPT_WBINVD                 BIT(9)
#define SVM_ICPT_MONITOR                BIT(10)
#define SVM_ICPT_MWAIT                  BIT(11)
#define SVM_ICPT_MWAIT_ARMED            BIT(12)     /* Only if hw is in armed state.           */
#define SVM_ICPT_XSETBV                 BIT(13)
#define SVM_ICPT_RDPRU                  BIT(14)
#define SVM_ICPT_EFER_WRITE             BIT(15)     /* EFER write trap.                        */
/* Bits 16..31: intercept CR0-CR15 write AFTER-guest writes finish (post-write trap). */
#define SVM_ICPT_CR_WRITE_TRAP(n)       (1u << (16 + (n)))  /* 0 <= n <= 15                    */

/* Intercept Word 5 (offset 0x014, u32). APM Table 15-6 (newer feature block; reserved on
 * pre-INVLPGB parts). Fields defined only when the corresponding CPUID feature is present. */
#define SVM_ICPT_INVLPGB                BIT(0)
#define SVM_ICPT_INVLPGB_ILLEGAL        BIT(1)
#define SVM_ICPT_INVPCID                BIT(2)
#define SVM_ICPT_MCOMMIT                BIT(3)
#define SVM_ICPT_TLBSYNC                BIT(4)
#define SVM_ICPT_BUSLOCK                BIT(5)
#define SVM_ICPT_IDLE_HLT               BIT(6)

/* ====================================================================================== */
/*  VMEXIT codes (VMCB control area offset 0x070). APM §15.9, Table 15-9.                  */
/*  Full enumeration -- adding new ones is a one-line entry, so keep this exhaustive.       */
/* ====================================================================================== */
#define SVM_EXIT_READ_CR0               0x0000
#define SVM_EXIT_READ_CR3               0x0003
#define SVM_EXIT_READ_CR4               0x0004
#define SVM_EXIT_READ_CR8               0x0008
#define SVM_EXIT_WRITE_CR0              0x0010
#define SVM_EXIT_WRITE_CR3              0x0013
#define SVM_EXIT_WRITE_CR4              0x0014
#define SVM_EXIT_WRITE_CR8              0x0018
#define SVM_EXIT_READ_DR0               0x0020
#define SVM_EXIT_READ_DR7               0x0027
#define SVM_EXIT_WRITE_DR0              0x0030
#define SVM_EXIT_WRITE_DR7              0x0037
#define SVM_EXIT_EXCP_BASE              0x0040      /* Vector v -> SVM_EXIT_EXCP_BASE + v.     */
#define SVM_EXIT_EXCP_DE                0x0040
#define SVM_EXIT_EXCP_DB                0x0041
#define SVM_EXIT_EXCP_NMI               0x0042      /* Reserved in AMD APM; NMI has own code.  */
#define SVM_EXIT_EXCP_BP                0x0043
#define SVM_EXIT_EXCP_UD                0x0046
#define SVM_EXIT_EXCP_NM                0x0047
#define SVM_EXIT_EXCP_DF                0x0048
#define SVM_EXIT_EXCP_TS                0x004A
#define SVM_EXIT_EXCP_NP                0x004B
#define SVM_EXIT_EXCP_SS                0x004C
#define SVM_EXIT_EXCP_GP                0x004D
#define SVM_EXIT_EXCP_PF                0x004E
#define SVM_EXIT_EXCP_MF                0x0050
#define SVM_EXIT_EXCP_AC                0x0051
#define SVM_EXIT_EXCP_MC                0x0052
#define SVM_EXIT_EXCP_XM                0x0053
#define SVM_EXIT_EXCP_VE                0x0054      /* Reserved; kept as VE for completeness.  */
#define SVM_EXIT_EXCP_SX                0x005E

#define SVM_EXIT_INTR                   0x0060      /* External interrupt.                     */
#define SVM_EXIT_NMI                    0x0061
#define SVM_EXIT_SMI                    0x0062
#define SVM_EXIT_INIT                   0x0063
#define SVM_EXIT_VINTR                  0x0064      /* Virtual interrupt.                      */
#define SVM_EXIT_CR0_SEL_WRITE          0x0065
#define SVM_EXIT_IDTR_READ              0x0066
#define SVM_EXIT_GDTR_READ              0x0067
#define SVM_EXIT_LDTR_READ              0x0068
#define SVM_EXIT_TR_READ                0x0069
#define SVM_EXIT_IDTR_WRITE             0x006A
#define SVM_EXIT_GDTR_WRITE             0x006B
#define SVM_EXIT_LDTR_WRITE             0x006C
#define SVM_EXIT_TR_WRITE               0x006D
#define SVM_EXIT_RDTSC                  0x006E
#define SVM_EXIT_RDPMC                  0x006F
#define SVM_EXIT_PUSHF                  0x0070
#define SVM_EXIT_POPF                   0x0071
#define SVM_EXIT_CPUID                  0x0072
#define SVM_EXIT_RSM                    0x0073
#define SVM_EXIT_IRET                   0x0074
#define SVM_EXIT_SWINT                  0x0075
#define SVM_EXIT_INVD                   0x0076
#define SVM_EXIT_PAUSE                  0x0077
#define SVM_EXIT_HLT                    0x0078
#define SVM_EXIT_INVLPG                 0x0079
#define SVM_EXIT_INVLPGA                0x007A
#define SVM_EXIT_IOIO                   0x007B      /* EXITINFO1 carries direction/port/size.  */
#define SVM_EXIT_MSR                    0x007C      /* EXITINFO1 bit 0 = write, else read.     */
#define SVM_EXIT_TASK_SWITCH            0x007D
#define SVM_EXIT_FERR_FREEZE            0x007E
#define SVM_EXIT_SHUTDOWN               0x007F
#define SVM_EXIT_VMRUN                  0x0080
#define SVM_EXIT_VMMCALL                0x0081      /* Aletheia hypercall entry point.         */
#define SVM_EXIT_VMLOAD                 0x0082
#define SVM_EXIT_VMSAVE                 0x0083
#define SVM_EXIT_STGI                   0x0084
#define SVM_EXIT_CLGI                   0x0085
#define SVM_EXIT_SKINIT                 0x0086
#define SVM_EXIT_RDTSCP                 0x0087
#define SVM_EXIT_ICEBP                  0x0088
#define SVM_EXIT_WBINVD                 0x0089
#define SVM_EXIT_MONITOR                0x008A
#define SVM_EXIT_MWAIT                  0x008B
#define SVM_EXIT_MWAIT_ARMED            0x008C
#define SVM_EXIT_XSETBV                 0x008D
#define SVM_EXIT_RDPRU                  0x008E
#define SVM_EXIT_EFER_WRITE_TRAP        0x008F
#define SVM_EXIT_CR_WRITE_TRAP_BASE     0x0090      /* CRn write trap -> BASE + n.             */
#define SVM_EXIT_INVLPGB                0x00A0
#define SVM_EXIT_INVLPGB_ILLEGAL        0x00A1
#define SVM_EXIT_INVPCID                0x00A2
#define SVM_EXIT_MCOMMIT                0x00A3
#define SVM_EXIT_TLBSYNC                0x00A4
#define SVM_EXIT_BUSLOCK                0x00A5
#define SVM_EXIT_IDLE_HLT               0x00A6

#define SVM_EXIT_NPF                    0x0400      /* Nested page fault -- the unpacker trap. */
#define SVM_EXIT_AVIC_INCOMPLETE_IPI    0x0401
#define SVM_EXIT_AVIC_NOACCEL           0x0402
#define SVM_EXIT_VMGEXIT                0x0403      /* SEV-ES hypercall (unused by Aletheia).  */

/* Special: hardware detected invalid guest state on VMRUN entry (APM §15.6.1 / §15.9). Value
 * is sign-extended -1 when read as a u64; guard the switch/case explicitly. */
#define SVM_EXIT_INVALID                0xFFFFFFFFFFFFFFFFULL

/* ====================================================================================== */
/*  EXITINFO decoders                                                                      */
/* ====================================================================================== */
/* MSR (§15.10.2): EXITINFO1 bit 0 = direction (0 = RDMSR, 1 = WRMSR). MSR index in ECX. */
#define SVM_EXITINFO1_MSR_WRITE         BIT(0)

/* IOIO (§15.10.2 / §15.10.5): EXITINFO1 bit layout. */
#define SVM_EXITINFO1_IOIO_TYPE_IN      BIT(0)      /* 0 = OUT, 1 = IN.                        */
#define SVM_EXITINFO1_IOIO_STR          BIT(2)      /* String I/O (INS/OUTS).                  */
#define SVM_EXITINFO1_IOIO_REP          BIT(3)      /* REP prefix.                             */
#define SVM_EXITINFO1_IOIO_SZ8          BIT(4)      /* 8-bit operand.                          */
#define SVM_EXITINFO1_IOIO_SZ16         BIT(5)      /* 16-bit operand.                         */
#define SVM_EXITINFO1_IOIO_SZ32         BIT(6)      /* 32-bit operand.                         */
#define SVM_EXITINFO1_IOIO_A16          BIT(7)      /* 16-bit address.                         */
#define SVM_EXITINFO1_IOIO_A32          BIT(8)      /* 32-bit address.                         */
#define SVM_EXITINFO1_IOIO_A64          BIT(9)      /* 64-bit address.                         */
#define SVM_EXITINFO1_IOIO_SEG_SHIFT    10          /* 3-bit segment override (10..12).        */
#define SVM_EXITINFO1_IOIO_PORT_SHIFT   16          /* 16-bit port number (16..31).            */

/* NPF (§15.25.5): EXITINFO1 carries the fault flags, EXITINFO2 carries the guest-physical
 * address that faulted. */
#define SVM_EXITINFO1_NPF_P             BIT(0)      /* 1: fault caused by page protections.    */
#define SVM_EXITINFO1_NPF_RW            BIT(1)      /* 0 = read, 1 = write access.             */
#define SVM_EXITINFO1_NPF_US            BIT(2)      /* 0 = supervisor, 1 = user.               */
#define SVM_EXITINFO1_NPF_RSV           BIT(3)      /* Reserved bit set in a NPT paging entry. */
#define SVM_EXITINFO1_NPF_ID            BIT(4)      /* Instruction fetch fault.                */
#define SVM_EXITINFO1_NPF_SS            BIT(6)      /* Shadow-stack access.                    */
#define SVM_EXITINFO1_NPF_GUEST_PT      BIT(32)     /* Fault while walking a guest page table. */
#define SVM_EXITINFO1_NPF_GUEST_FINAL   BIT(33)     /* Fault on a final guest-visible access.  */

/* EVENTINJ / EXITINTINFO (§15.20): common encoding.
 * bits 0..7   : vector
 * bits 8..10  : type (0=INTR, 2=NMI, 3=EXCEPTION, 4=SOFTINT)
 * bit  11     : error-code valid
 * bit  31     : valid
 * bits 32..63 : error code (if valid)
 */
#define SVM_INTINFO_VECTOR_MASK         BITMASK(7, 0)
#define SVM_INTINFO_TYPE_SHIFT          8
#define SVM_INTINFO_TYPE_MASK           BITMASK(10, 8)
#define SVM_INTINFO_TYPE_INTR           (0u << 8)
#define SVM_INTINFO_TYPE_NMI            (2u << 8)
#define SVM_INTINFO_TYPE_EXCEPTION      (3u << 8)
#define SVM_INTINFO_TYPE_SOFTINT        (4u << 8)
#define SVM_INTINFO_ERR_VALID           BIT(11)
#define SVM_INTINFO_VALID               BIT(31)
#define SVM_INTINFO_ERRCODE_SHIFT       32

/* ====================================================================================== */
/*  VMCB Clean Bits (VMCB control area offset 0x0C0, u32). APM §15.15 Table 15-8.          */
/*  Setting a bit tells the CPU it may reuse cached state; clear a bit after modifying its  */
/*  region so the CPU reloads on the next VMRUN. On a first-run VMCB, clean = 0.            */
/* ====================================================================================== */
#define VMCB_CLEAN_I                    BIT(0)      /* Intercepts, TSC offset, pause filters.  */
#define VMCB_CLEAN_IOPM_MSRPM           BIT(1)      /* IOPM_BASE, MSRPM_BASE.                  */
#define VMCB_CLEAN_ASID                 BIT(2)
#define VMCB_CLEAN_TPR                  BIT(3)      /* V_TPR / V_IRQ / V_INTR_PRIO.            */
#define VMCB_CLEAN_NP                   BIT(4)      /* NP_ENABLE, NCR3, memory-type control.   */
#define VMCB_CLEAN_CRX                  BIT(5)      /* CR0, CR3, CR4, EFER.                    */
#define VMCB_CLEAN_DRX                  BIT(6)      /* DR6, DR7.                               */
#define VMCB_CLEAN_DT                   BIT(7)      /* GDT, IDT.                               */
#define VMCB_CLEAN_SEG                  BIT(8)      /* CS, DS, SS, ES + CPL.                   */
#define VMCB_CLEAN_CR2                  BIT(9)
#define VMCB_CLEAN_LBR                  BIT(10)     /* DEBUGCTL, LBR MSRs.                     */
#define VMCB_CLEAN_AVIC                 BIT(11)
#define VMCB_CLEAN_CET                  BIT(12)

/* ====================================================================================== */
/*  VMCB Control Area (VMCB offset 0x000..0x3FF). APM §15.5 Table 15-1.                    */
/* ====================================================================================== */
#pragma pack(push, 1)

typedef struct _VMCB_CONTROL_AREA {
    u32 intercept_cr;           /* +0x000: CR read/write intercepts (SVM_ICPT_CR_*).           */
    u32 intercept_dr;           /* +0x004: DR read/write intercepts.                           */
    u32 intercept_exceptions;   /* +0x008: exception vectors 0..31.                            */
    u32 intercept_word3;        /* +0x00C: INTR/NMI/... /SHUTDOWN.                             */
    u32 intercept_word4;        /* +0x010: VMRUN/VMMCALL/... /CR-write-trap.                   */
    u32 intercept_word5;        /* +0x014: INVLPGB/INVPCID/... (feature-gated).                */
    u32 reserved_018[9];        /* +0x018..0x03B: reserved, zero. 9 u32 = 0x24 bytes.          */
    u16 pause_filter_threshold; /* +0x03C: PAUSE-filter threshold cycles.  APM §15.14.4.       */
    u16 pause_filter_count;     /* +0x03E: PAUSE-filter counter.                               */
    u64 iopm_base_pa;           /* +0x040: physical addr of IOPM (4 KiB-aligned).              */
    u64 msrpm_base_pa;          /* +0x048: physical addr of MSRPM (4 KiB-aligned).             */
    u64 tsc_offset;             /* +0x050: added to guest RDTSC / RDTSCP.                      */
    u32 asid;                   /* +0x058: guest ASID (nonzero).                               */
    u8  tlb_control;            /* +0x05C: TLB flush selector (SVM_TLB_CONTROL_*).             */
    u8  reserved_05D[3];        /* +0x05D..0x05F: reserved.                                    */
    u64 vintr;                  /* +0x060: V_TPR/V_IRQ/V_INTR_PRIO/V_INTR_MASKING/V_GIF/vec.    */
    u64 int_shadow;             /* +0x068: bit 0 = interrupt shadow, bit 1 = guest IF.         */
    u64 exit_code;              /* +0x070: SVM_EXIT_*.                                         */
    u64 exit_info_1;            /* +0x078: exit-specific.                                      */
    u64 exit_info_2;            /* +0x080: exit-specific (NPF fault GPA lives here).           */
    u64 exit_intinfo;           /* +0x088: interruption that was being delivered on the exit.  */
    u64 np_enable;              /* +0x090: bit 0 = enable NP, bit 1 = SEV, bit 2 = SEV-ES, ... */
    u64 avic_apic_bar;          /* +0x098: AVIC APIC-backing-page BAR (unused).                */
    u64 ghcb_gpa;               /* +0x0A0: SEV-ES Guest-Hypervisor Communication Block GPA.    */
    u64 eventinj;               /* +0x0A8: event to inject at next VMRUN.                      */
    u64 n_cr3;                  /* +0x0B0: nested CR3 (physical addr of NPT PML4).             */
    u64 lbr_virt_control;       /* +0x0B8: LBR / virtualized VMSAVE-VMLOAD enable bits.        */
    u32 vmcb_clean;             /* +0x0C0: VMCB_CLEAN_* bits (set: reuse cached state).        */
    u32 reserved_0C4;           /* +0x0C4: reserved.                                           */
    u64 nrip;                   /* +0x0C8: next sequential guest RIP (NRIPS feature).          */
    u8  guest_insn_len;         /* +0x0D0: bytes fetched into guest_insn (0..15).              */
    u8  guest_insn_bytes[15];   /* +0x0D1..0x0DF: raw bytes of the faulting instruction.       */
    u64 avic_backing_page;      /* +0x0E0: (unused).                                           */
    u64 reserved_0E8;           /* +0x0E8.                                                     */
    u64 avic_logical_table;     /* +0x0F0.                                                     */
    u64 avic_physical_table;    /* +0x0F8.                                                     */
    u64 reserved_100;           /* +0x100.                                                     */
    u64 vmsa_pa;                /* +0x108: SEV-ES Save Area PA.                                */
    u8  reserved_110[0x2F0];    /* +0x110..0x3FF: reserved.                                    */
} VMCB_CONTROL_AREA;


/* --- line-unique C_ASSERT replacement (cl.exe strict mode chokes on the
   WDK's shared __C_ASSERT__ typedef when multiple asserts appear in the
   same TU). Same semantics: fail the build if the expression is false. */
#ifdef C_ASSERT
#undef C_ASSERT
#endif
#define _AL_HV_CAT2(a,b) a##b
#define _AL_HV_CAT(a,b) _AL_HV_CAT2(a,b)
#define C_ASSERT(e) typedef char _AL_HV_CAT(__C_ASSERT_LN_, __LINE__)[(e) ? 1 : -1]

C_ASSERT(sizeof(VMCB_CONTROL_AREA) == 0x400);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, iopm_base_pa)   == 0x040);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, msrpm_base_pa)  == 0x048);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, asid)           == 0x058);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, exit_code)      == 0x070);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, exit_info_2)    == 0x080);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, np_enable)      == 0x090);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, n_cr3)          == 0x0B0);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, vmcb_clean)     == 0x0C0);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, nrip)           == 0x0C8);

/* NP_ENABLE control-area bit layout (APM §15.5 / §15.25). */
#define VMCB_NP_ENABLE                  BIT(0)      /* Enable nested paging.                   */
#define VMCB_NP_SEV_ENABLE              BIT(1)
#define VMCB_NP_SEV_ES_ENABLE           BIT(2)
#define VMCB_NP_GMET                    BIT(3)      /* Guest-mode execute trap (feature-gated).*/
#define VMCB_NP_VTE                     BIT(6)      /* Virtual transparent encryption.         */
#define VMCB_NP_READ_ONLY_GUEST_PT      BIT(7)      /* GMET/RO-guest-PT feature.               */

/* V_INTR control-area bit layout (VMCB offset 0x060, u64). APM §15.21. */
#define VMCB_VINTR_V_TPR_MASK           BITMASK(7, 0)
#define VMCB_VINTR_V_IRQ                BIT(8)
#define VMCB_VINTR_VGIF_ENABLE          BIT(9)
#define VMCB_VINTR_V_INTR_PRIO_SHIFT    16
#define VMCB_VINTR_V_INTR_PRIO_MASK     BITMASK(19, 16)
#define VMCB_VINTR_V_IGN_TPR            BIT(20)
#define VMCB_VINTR_V_INTR_MASKING       BIT(24)
#define VMCB_VINTR_VGIF                 BIT(25)
#define VMCB_VINTR_AVIC_ENABLE          BIT(31)
#define VMCB_VINTR_V_INTR_VECTOR_SHIFT  32
#define VMCB_VINTR_V_INTR_VECTOR_MASK   BITMASK(39, 32)

/* ====================================================================================== */
/*  VMCB Segment attributes (state-save area, per-segment u16). APM §15.5.1.                */
/*  This is the 12-bit "packed attribute" form the CPU stores in the VMCB, NOT the 32-bit    */
/*  form that lives in the descriptor cache. Layout:                                         */
/*    bits 0..3   : type     bits 4     : s     bits 5..6 : dpl     bit 7 : present          */
/*    bits 8..11  : reserved bits 12   : avl   bit 13 : l         bit 14 : db  bit 15 : g   */
/* ====================================================================================== */
#define VMCB_SEG_ATTR_TYPE_MASK         BITMASK(3, 0)
#define VMCB_SEG_ATTR_S                 BIT(4)
#define VMCB_SEG_ATTR_DPL_SHIFT         5
#define VMCB_SEG_ATTR_DPL_MASK          BITMASK(6, 5)
#define VMCB_SEG_ATTR_P                 BIT(7)
#define VMCB_SEG_ATTR_AVL               BIT(12)
#define VMCB_SEG_ATTR_L                 BIT(13)
#define VMCB_SEG_ATTR_DB                BIT(14)
#define VMCB_SEG_ATTR_G                 BIT(15)

typedef struct _VMCB_SEG {
    u16 selector;
    u16 attrib;                 /* Packed 12-bit attribute; see VMCB_SEG_ATTR_* above.         */
    u32 limit;
    u64 base;
} VMCB_SEG;
C_ASSERT(sizeof(VMCB_SEG) == 16);

/* ====================================================================================== */
/*  VMCB State-Save Area (VMCB offset 0x400..). APM §15.5 Table 15-2.                       */
/* ====================================================================================== */
typedef struct _VMCB_STATE_SAVE_AREA {
    VMCB_SEG es;                /* +0x400 (relative to VMCB base; +0x000 within this struct).  */
    VMCB_SEG cs;                /* +0x410                                                       */
    VMCB_SEG ss;                /* +0x420                                                       */
    VMCB_SEG ds;                /* +0x430                                                       */
    VMCB_SEG fs;                /* +0x440                                                       */
    VMCB_SEG gs;                /* +0x450                                                       */
    VMCB_SEG gdtr;              /* +0x460 -- selector/attrib ignored; limit + base loaded.     */
    VMCB_SEG ldtr;              /* +0x470                                                       */
    VMCB_SEG idtr;              /* +0x480 -- selector/attrib ignored.                          */
    VMCB_SEG tr;                /* +0x490                                                       */
    u8  cpl;                    /* +0x4A0: Current Privilege Level.                            */
    u8  reserved_4A1[3];        /* +0x4A1..0x4A3                                                */
    u32 reserved_4A4;           /* +0x4A4                                                       */
    u64 efer;                   /* +0x4A8: EFER (EFER_SVME MUST be set for VMRUN).             */
    u8  reserved_4B0[112];      /* +0x4B0..0x51F                                                */
    u64 cr4;                    /* +0x520                                                       */
    u64 cr3;                    /* +0x528                                                       */
    u64 cr0;                    /* +0x530                                                       */
    u64 dr7;                    /* +0x538                                                       */
    u64 dr6;                    /* +0x540                                                       */
    u64 rflags;                 /* +0x548                                                       */
    u64 rip;                    /* +0x550                                                       */
    u8  reserved_558[88];       /* +0x558..0x5AF                                                */
    u64 rsp;                    /* +0x5B0                                                       */
    u64 s_cet;                  /* +0x5B8: shadow-stack S_CET (CET feature).                   */
    u64 ssp;                    /* +0x5C0: shadow-stack pointer.                               */
    u64 isst_addr;              /* +0x5C8: interrupt SSP table addr.                           */
    u64 rax;                    /* +0x5D0                                                       */
    u64 star;                   /* +0x5D8                                                       */
    u64 lstar;                  /* +0x5E0                                                       */
    u64 cstar;                  /* +0x5E8                                                       */
    u64 sfmask;                 /* +0x5F0                                                       */
    u64 kernel_gs_base;         /* +0x5F8                                                       */
    u64 sysenter_cs;            /* +0x600                                                       */
    u64 sysenter_esp;           /* +0x608                                                       */
    u64 sysenter_eip;           /* +0x610                                                       */
    u64 cr2;                    /* +0x618                                                       */
    u8  reserved_620[32];       /* +0x620..0x63F                                                */
    u64 g_pat;                  /* +0x640: guest PAT (only when nested paging enabled).        */
    u64 dbgctl;                 /* +0x648: DEBUGCTL.                                            */
    u64 br_from;                /* +0x650                                                       */
    u64 br_to;                  /* +0x658                                                       */
    u64 last_excp_from;         /* +0x660                                                       */
    u64 last_excp_to;           /* +0x668                                                       */
    /* Remaining offsets up to 0xBFF are reserved for future / SEV-ES fields; pad to make the
     * enclosing VMCB come out to a full 4 KiB below.
     * State-save area is VMCB[0x400..0xFFF] (0xC00 bytes). Fields above end at
     * struct-relative 0x270 (VMCB 0x670). Pad from there to struct 0xC00. */
    u8  reserved_670[0xC00 - 0x270];
} VMCB_STATE_SAVE_AREA;

C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, es)       == 0x000);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, cs)       == 0x010);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, gdtr)     == 0x060);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, cpl)      == 0x0A0);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, efer)     == 0x0A8);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, cr4)      == 0x120);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, cr3)      == 0x128);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, cr0)      == 0x130);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, rflags)   == 0x148);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, rip)      == 0x150);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, rsp)      == 0x1B0);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, rax)      == 0x1D0);

/* ====================================================================================== */
/*  Full 4 KiB VMCB = control area (0x000..0x3FF) + state save area (0x400..0xFFF).         */
/* ====================================================================================== */
typedef struct _VMCB {
    VMCB_CONTROL_AREA    control;
    VMCB_STATE_SAVE_AREA state_save;
} VMCB;

C_ASSERT(sizeof(VMCB) == SVM_VMCB_SIZE);
C_ASSERT(FIELD_OFFSET(VMCB, state_save) == 0x400);

#pragma pack(pop)

/* ====================================================================================== */
/*  Decoded exit convenience -- populated by svm.c on each VM-exit; peer of the Intel path. */
/* ====================================================================================== */
typedef struct _SVM_EXIT_INFO {
    u64 exit_code;              /* VMCB->control.exit_code.                                    */
    u64 info1;                  /* VMCB->control.exit_info_1.                                  */
    u64 info2;                  /* VMCB->control.exit_info_2.                                  */
    u64 intinfo;                /* VMCB->control.exit_intinfo.                                 */
    u64 nrip;                   /* VMCB->control.nrip (NRIPS feature; 0 if unavailable).       */
    u8  insn_len;               /* Bytes fetched (may be 0 if decode-assist absent).           */
    u8  insn_bytes[15];         /* Raw bytes.                                                  */
} SVM_EXIT_INFO;

/* NPF-specific decoded view. GPA is the second exit-info field per §15.25.5. */
typedef struct _NPF_INFO {
    u64 gpa;                    /* Faulting guest-physical address.                            */
    u32 flags;                  /* SVM_EXITINFO1_NPF_* bits.                                   */
    u8  is_write;               /* Convenience: RW bit.                                        */
    u8  is_exec;                /* Convenience: ID bit.                                        */
    u8  reserved[2];
} NPF_INFO;

/* ====================================================================================== */
/*  Vendor capability probe -- populated by svm.c hv_svm_supported().                       */
/*  Peer to VMX_CAPABILITIES; the vendor-neutral bring-up reads whichever applies.          */
/* ====================================================================================== */
typedef struct _SVM_CAPABILITIES {
    u8  present;                /* CPUID.80000001h:ECX[2].                                     */
    u8  nested_paging;          /* CPUID.8000000Ah:EDX[0].                                     */
    u8  nrips;                  /* CPUID.8000000Ah:EDX[3].                                     */
    u8  vmcb_clean;             /* CPUID.8000000Ah:EDX[5].                                     */
    u8  flush_by_asid;          /* CPUID.8000000Ah:EDX[6].                                     */
    u8  decode_assist;          /* CPUID.8000000Ah:EDX[7].                                     */
    u8  svml;                   /* CPUID.8000000Ah:EDX[2] (SVM lock feature).                  */
    u8  vgif;                   /* CPUID.8000000Ah:EDX[16].                                    */
    u32 asid_count;             /* CPUID.8000000Ah:EBX (NASID).                                */
    u32 revision;               /* CPUID.8000000Ah:EAX[7:0].                                   */
    u64 vm_cr;                  /* IA32-side snapshot of MSR_VM_CR at probe time.              */
    /* Convenience flags derived from vm_cr. */
    u8  svmdis;                 /* VM_CR.SVMDIS -- SVM disabled by BIOS/firmware.              */
    u8  svmlock;                /* VM_CR.LOCK   -- VM_CR write-locked.                         */
} SVM_CAPABILITIES;

#endif /* ALETHEIA_HV_SVM_DEFS_H */
