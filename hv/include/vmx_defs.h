/*
 * vmx_defs.h -- VMCS field encodings, VM-exit reasons, VMX control bit masks, and
 * instruction-error codes for the Aletheia clean-room VT-x/EPT VMI hypervisor.
 *
 * CLEAN-ROOM PROVENANCE: All encodings are from the public Intel SDM Vol 3C (VMCS field
 * encoding tables, Appendix B), Vol 3D (Appendix A capability MSRs), and Vol 3C Chapter 27
 * (VM-exit reasons). Cross-checked against open-source hvpp/SimpleVisor headers, which
 * transcribe the same public tables. No proprietary source consulted.
 *
 * VMCS field encoding structure (SDM Vol 3C, Table 25-21 "Structure of VMCS Component
 * Encoding"):
 *   bit 0        : Access type (0 = full, 1 = high 32 bits of a 64-bit field)
 *   bits 9:1     : Index
 *   bits 11:10   : Field type (0 = control, 1 = VM-exit info (read-only), 2 = guest, 3 = host)
 *   bits 14:13   : Field width (0 = 16-bit, 1 = 64-bit, 2 = 32-bit, 3 = natural-width)
 * The literal constants below already encode all of that; they are what VMREAD/VMWRITE take.
 */
#ifndef ALETHEIA_HV_VMX_DEFS_H
#define ALETHEIA_HV_VMX_DEFS_H

#include "arch.h"

/* ====================================================================================== */
/*  16-bit VMCS fields                                                                     */
/* ====================================================================================== */
/* Control fields. */
#define VMCS_CTRL_VPID                          0x00000000
#define VMCS_CTRL_POSTED_INTR_NOTIFY_VECTOR     0x00000002
#define VMCS_CTRL_EPTP_INDEX                    0x00000004
/* Guest-state fields. */
#define VMCS_GUEST_ES_SELECTOR                  0x00000800
#define VMCS_GUEST_CS_SELECTOR                  0x00000802
#define VMCS_GUEST_SS_SELECTOR                  0x00000804
#define VMCS_GUEST_DS_SELECTOR                  0x00000806
#define VMCS_GUEST_FS_SELECTOR                  0x00000808
#define VMCS_GUEST_GS_SELECTOR                  0x0000080A
#define VMCS_GUEST_LDTR_SELECTOR                0x0000080C
#define VMCS_GUEST_TR_SELECTOR                  0x0000080E
#define VMCS_GUEST_INTR_STATUS                  0x00000810
#define VMCS_GUEST_PML_INDEX                    0x00000812
/* Host-state fields. */
#define VMCS_HOST_ES_SELECTOR                   0x00000C00
#define VMCS_HOST_CS_SELECTOR                   0x00000C02
#define VMCS_HOST_SS_SELECTOR                   0x00000C04
#define VMCS_HOST_DS_SELECTOR                   0x00000C06
#define VMCS_HOST_FS_SELECTOR                   0x00000C08
#define VMCS_HOST_GS_SELECTOR                   0x00000C0A
#define VMCS_HOST_TR_SELECTOR                   0x00000C0C

/* ====================================================================================== */
/*  64-bit VMCS fields (full encoding; add +1 for the _HIGH half on 32-bit hosts)          */
/* ====================================================================================== */
/* Control fields. */
#define VMCS_CTRL_IO_BITMAP_A                   0x00002000
#define VMCS_CTRL_IO_BITMAP_B                   0x00002002
#define VMCS_CTRL_MSR_BITMAP                    0x00002004
#define VMCS_CTRL_VMEXIT_MSR_STORE_ADDR         0x00002006
#define VMCS_CTRL_VMEXIT_MSR_LOAD_ADDR          0x00002008
#define VMCS_CTRL_VMENTRY_MSR_LOAD_ADDR         0x0000200A
#define VMCS_CTRL_EXECUTIVE_VMCS_PTR            0x0000200C
#define VMCS_CTRL_PML_ADDR                      0x0000200E
#define VMCS_CTRL_TSC_OFFSET                    0x00002010
#define VMCS_CTRL_VIRTUAL_APIC_ADDR             0x00002012
#define VMCS_CTRL_APIC_ACCESS_ADDR              0x00002014
#define VMCS_CTRL_POSTED_INTR_DESC_ADDR         0x00002016
#define VMCS_CTRL_VMFUNC_CONTROLS               0x00002018
#define VMCS_CTRL_EPT_POINTER                   0x0000201A
#define VMCS_CTRL_EOI_EXIT_BITMAP_0             0x0000201C
#define VMCS_CTRL_EOI_EXIT_BITMAP_1             0x0000201E
#define VMCS_CTRL_EOI_EXIT_BITMAP_2             0x00002020
#define VMCS_CTRL_EOI_EXIT_BITMAP_3             0x00002022
#define VMCS_CTRL_EPTP_LIST_ADDR                0x00002024
#define VMCS_CTRL_VMREAD_BITMAP_ADDR            0x00002026
#define VMCS_CTRL_VMWRITE_BITMAP_ADDR           0x00002028
#define VMCS_CTRL_VIRT_EXCEPTION_INFO_ADDR      0x0000202A
#define VMCS_CTRL_XSS_EXITING_BITMAP            0x0000202C
#define VMCS_CTRL_ENCLS_EXITING_BITMAP          0x0000202E
#define VMCS_CTRL_TSC_MULTIPLIER                0x00002032
/* Read-only VM-exit info. */
#define VMCS_RO_GUEST_PHYSICAL_ADDR             0x00002400  /* GPA of an EPT violation. */
/* Guest-state 64-bit fields. */
#define VMCS_GUEST_VMCS_LINK_POINTER            0x00002800
#define VMCS_GUEST_DEBUGCTL                     0x00002802
#define VMCS_GUEST_PAT                          0x00002804
#define VMCS_GUEST_EFER                         0x00002806
#define VMCS_GUEST_PERF_GLOBAL_CTRL             0x00002808
#define VMCS_GUEST_PDPTE0                       0x0000280A
#define VMCS_GUEST_PDPTE1                       0x0000280C
#define VMCS_GUEST_PDPTE2                       0x0000280E
#define VMCS_GUEST_PDPTE3                       0x00002810
/* Host-state 64-bit fields. */
#define VMCS_HOST_PAT                           0x00002C00
#define VMCS_HOST_EFER                          0x00002C02
#define VMCS_HOST_PERF_GLOBAL_CTRL              0x00002C04

/* ====================================================================================== */
/*  32-bit VMCS fields                                                                     */
/* ====================================================================================== */
/* Control fields. */
#define VMCS_CTRL_PIN_BASED_CONTROLS            0x00004000
#define VMCS_CTRL_PROC_BASED_CONTROLS           0x00004002
#define VMCS_CTRL_EXCEPTION_BITMAP              0x00004004
#define VMCS_CTRL_PF_ERRCODE_MASK               0x00004006
#define VMCS_CTRL_PF_ERRCODE_MATCH              0x00004008
#define VMCS_CTRL_CR3_TARGET_COUNT              0x0000400A
#define VMCS_CTRL_VMEXIT_CONTROLS               0x0000400C
#define VMCS_CTRL_VMEXIT_MSR_STORE_COUNT        0x0000400E
#define VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT         0x00004010
#define VMCS_CTRL_VMENTRY_CONTROLS              0x00004012
#define VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT        0x00004014
#define VMCS_CTRL_VMENTRY_INTR_INFO             0x00004016
#define VMCS_CTRL_VMENTRY_EXCEPTION_ERRCODE     0x00004018
#define VMCS_CTRL_VMENTRY_INSTR_LEN             0x0000401A
#define VMCS_CTRL_TPR_THRESHOLD                 0x0000401C
#define VMCS_CTRL_PROC_BASED_CONTROLS2          0x0000401E
#define VMCS_CTRL_PLE_GAP                       0x00004020
#define VMCS_CTRL_PLE_WINDOW                    0x00004022
/* Read-only VM-exit info. */
#define VMCS_RO_VM_INSTRUCTION_ERROR            0x00004400
#define VMCS_RO_EXIT_REASON                     0x00004402
#define VMCS_RO_EXIT_INTR_INFO                  0x00004404
#define VMCS_RO_EXIT_INTR_ERRCODE               0x00004406
#define VMCS_RO_IDT_VECTORING_INFO              0x00004408
#define VMCS_RO_IDT_VECTORING_ERRCODE           0x0000440A
#define VMCS_RO_EXIT_INSTR_LEN                  0x0000440C
#define VMCS_RO_EXIT_INSTR_INFO                 0x0000440E
/* Guest-state 32-bit fields. */
#define VMCS_GUEST_ES_LIMIT                     0x00004800
#define VMCS_GUEST_CS_LIMIT                     0x00004802
#define VMCS_GUEST_SS_LIMIT                     0x00004804
#define VMCS_GUEST_DS_LIMIT                     0x00004806
#define VMCS_GUEST_FS_LIMIT                     0x00004808
#define VMCS_GUEST_GS_LIMIT                     0x0000480A
#define VMCS_GUEST_LDTR_LIMIT                   0x0000480C
#define VMCS_GUEST_TR_LIMIT                     0x0000480E
#define VMCS_GUEST_GDTR_LIMIT                   0x00004810
#define VMCS_GUEST_IDTR_LIMIT                   0x00004812
#define VMCS_GUEST_ES_ACCESS_RIGHTS             0x00004814
#define VMCS_GUEST_CS_ACCESS_RIGHTS             0x00004816
#define VMCS_GUEST_SS_ACCESS_RIGHTS             0x00004818
#define VMCS_GUEST_DS_ACCESS_RIGHTS             0x0000481A
#define VMCS_GUEST_FS_ACCESS_RIGHTS             0x0000481C
#define VMCS_GUEST_GS_ACCESS_RIGHTS             0x0000481E
#define VMCS_GUEST_LDTR_ACCESS_RIGHTS           0x00004820
#define VMCS_GUEST_TR_ACCESS_RIGHTS             0x00004822
#define VMCS_GUEST_INTERRUPTIBILITY_STATE       0x00004824
#define VMCS_GUEST_ACTIVITY_STATE               0x00004826
#define VMCS_GUEST_SMBASE                       0x00004828
#define VMCS_GUEST_SYSENTER_CS                  0x0000482A
#define VMCS_GUEST_PREEMPT_TIMER_VALUE          0x0000482E
/* Host-state 32-bit field. */
#define VMCS_HOST_SYSENTER_CS                   0x00004C00

/* ====================================================================================== */
/*  Natural-width VMCS fields                                                              */
/* ====================================================================================== */
/* Control fields. */
#define VMCS_CTRL_CR0_GUEST_HOST_MASK           0x00006000
#define VMCS_CTRL_CR4_GUEST_HOST_MASK           0x00006002
#define VMCS_CTRL_CR0_READ_SHADOW               0x00006004
#define VMCS_CTRL_CR4_READ_SHADOW               0x00006006
#define VMCS_CTRL_CR3_TARGET_VALUE_0            0x00006008
#define VMCS_CTRL_CR3_TARGET_VALUE_1            0x0000600A
#define VMCS_CTRL_CR3_TARGET_VALUE_2            0x0000600C
#define VMCS_CTRL_CR3_TARGET_VALUE_3            0x0000600E
/* Read-only VM-exit info. */
#define VMCS_RO_EXIT_QUALIFICATION              0x00006400
#define VMCS_RO_IO_RCX                          0x00006402
#define VMCS_RO_IO_RSI                          0x00006404
#define VMCS_RO_IO_RDI                          0x00006406
#define VMCS_RO_IO_RIP                          0x00006408
#define VMCS_RO_GUEST_LINEAR_ADDR               0x0000640A  /* GLA of an EPT violation. */
/* Guest-state natural-width fields. */
#define VMCS_GUEST_CR0                          0x00006800
#define VMCS_GUEST_CR3                          0x00006802
#define VMCS_GUEST_CR4                          0x00006804
#define VMCS_GUEST_ES_BASE                      0x00006806
#define VMCS_GUEST_CS_BASE                      0x00006808
#define VMCS_GUEST_SS_BASE                      0x0000680A
#define VMCS_GUEST_DS_BASE                      0x0000680C
#define VMCS_GUEST_FS_BASE                      0x0000680E
#define VMCS_GUEST_GS_BASE                      0x00006810
#define VMCS_GUEST_LDTR_BASE                    0x00006812
#define VMCS_GUEST_TR_BASE                      0x00006814
#define VMCS_GUEST_GDTR_BASE                    0x00006816
#define VMCS_GUEST_IDTR_BASE                    0x00006818
#define VMCS_GUEST_DR7                          0x0000681A
#define VMCS_GUEST_RSP                          0x0000681C
#define VMCS_GUEST_RIP                          0x0000681E
#define VMCS_GUEST_RFLAGS                       0x00006820
#define VMCS_GUEST_PENDING_DBG_EXCEPTIONS       0x00006822
#define VMCS_GUEST_SYSENTER_ESP                 0x00006824
#define VMCS_GUEST_SYSENTER_EIP                 0x00006826
/* Host-state natural-width fields. */
#define VMCS_HOST_CR0                           0x00006C00
#define VMCS_HOST_CR3                           0x00006C02
#define VMCS_HOST_CR4                           0x00006C04
#define VMCS_HOST_FS_BASE                       0x00006C06
#define VMCS_HOST_GS_BASE                       0x00006C08
#define VMCS_HOST_TR_BASE                       0x00006C0A
#define VMCS_HOST_GDTR_BASE                     0x00006C0C
#define VMCS_HOST_IDTR_BASE                     0x00006C0E
#define VMCS_HOST_SYSENTER_ESP                  0x00006C10
#define VMCS_HOST_SYSENTER_EIP                  0x00006C12
#define VMCS_HOST_RSP                           0x00006C14
#define VMCS_HOST_RIP                           0x00006C16

/* ====================================================================================== */
/*  Pin-based VM-execution controls (SDM Vol 3C Table 25-5)                                */
/* ====================================================================================== */
#define PIN_CTL_EXT_INTR_EXITING        BIT(0)
#define PIN_CTL_NMI_EXITING             BIT(3)
#define PIN_CTL_VIRTUAL_NMIS            BIT(5)
#define PIN_CTL_PREEMPT_TIMER           BIT(6)
#define PIN_CTL_POSTED_INTERRUPTS       BIT(7)

/* ====================================================================================== */
/*  Primary processor-based VM-execution controls (SDM Vol 3C Table 25-6)                  */
/* ====================================================================================== */
#define PROC_CTL_INTR_WINDOW_EXITING    BIT(2)
#define PROC_CTL_USE_TSC_OFFSETTING     BIT(3)
#define PROC_CTL_HLT_EXITING            BIT(7)
#define PROC_CTL_INVLPG_EXITING         BIT(9)
#define PROC_CTL_MWAIT_EXITING          BIT(10)
#define PROC_CTL_RDPMC_EXITING          BIT(11)
#define PROC_CTL_RDTSC_EXITING          BIT(12)
#define PROC_CTL_CR3_LOAD_EXITING       BIT(15)
#define PROC_CTL_CR3_STORE_EXITING      BIT(16)
#define PROC_CTL_ACTIVATE_TERTIARY      BIT(17)
#define PROC_CTL_CR8_LOAD_EXITING       BIT(19)
#define PROC_CTL_CR8_STORE_EXITING      BIT(20)
#define PROC_CTL_USE_TPR_SHADOW         BIT(21)
#define PROC_CTL_NMI_WINDOW_EXITING     BIT(22)
#define PROC_CTL_MOV_DR_EXITING         BIT(23)
#define PROC_CTL_UNCOND_IO_EXITING      BIT(24)
#define PROC_CTL_USE_IO_BITMAPS         BIT(25)
#define PROC_CTL_MONITOR_TRAP_FLAG      BIT(27)
#define PROC_CTL_USE_MSR_BITMAPS        BIT(28)
#define PROC_CTL_MONITOR_EXITING        BIT(29)
#define PROC_CTL_PAUSE_EXITING          BIT(30)
#define PROC_CTL_ACTIVATE_SECONDARY     BIT(31)

/* ====================================================================================== */
/*  Secondary processor-based VM-execution controls (SDM Vol 3C Table 25-7)                */
/* ====================================================================================== */
#define PROC2_CTL_VIRT_APIC_ACCESSES    BIT(0)
#define PROC2_CTL_ENABLE_EPT            BIT(1)
#define PROC2_CTL_DESC_TABLE_EXITING    BIT(2)
#define PROC2_CTL_ENABLE_RDTSCP         BIT(3)
#define PROC2_CTL_VIRT_X2APIC_MODE      BIT(4)
#define PROC2_CTL_ENABLE_VPID           BIT(5)
#define PROC2_CTL_WBINVD_EXITING        BIT(6)
#define PROC2_CTL_UNRESTRICTED_GUEST    BIT(7)
#define PROC2_CTL_APIC_REG_VIRT         BIT(8)
#define PROC2_CTL_VIRT_INTR_DELIVERY    BIT(9)
#define PROC2_CTL_PAUSE_LOOP_EXITING    BIT(10)
#define PROC2_CTL_RDRAND_EXITING        BIT(11)
#define PROC2_CTL_ENABLE_INVPCID        BIT(12)
#define PROC2_CTL_ENABLE_VMFUNC         BIT(13)
#define PROC2_CTL_VMCS_SHADOWING        BIT(14)
#define PROC2_CTL_ENABLE_ENCLS_EXITING  BIT(15)
#define PROC2_CTL_RDSEED_EXITING        BIT(16)
#define PROC2_CTL_ENABLE_PML            BIT(17)
#define PROC2_CTL_EPT_VIOLATION_VE      BIT(18)
#define PROC2_CTL_CONCEAL_VMX_FROM_PT   BIT(19)
#define PROC2_CTL_ENABLE_XSAVES         BIT(20)
#define PROC2_CTL_MODE_BASED_EXEC_EPT   BIT(22)
#define PROC2_CTL_SUB_PAGE_WRITE_EPT    BIT(23)
#define PROC2_CTL_PT_USE_GPA            BIT(24)
#define PROC2_CTL_USE_TSC_SCALING       BIT(25)
#define PROC2_CTL_ENABLE_USER_WAIT      BIT(26)
#define PROC2_CTL_ENABLE_ENCLV_EXITING  BIT(28)

/* ====================================================================================== */
/*  VM-exit controls (SDM Vol 3C Table 25-13)                                              */
/* ====================================================================================== */
#define EXIT_CTL_SAVE_DEBUG_CONTROLS    BIT(2)
#define EXIT_CTL_HOST_ADDR_SPACE_SIZE   BIT(9)   /* Return to 64-bit host. */
#define EXIT_CTL_LOAD_PERF_GLOBAL_CTRL  BIT(12)
#define EXIT_CTL_ACK_INTR_ON_EXIT       BIT(15)
#define EXIT_CTL_SAVE_PAT               BIT(18)
#define EXIT_CTL_LOAD_PAT               BIT(19)
#define EXIT_CTL_SAVE_EFER              BIT(20)
#define EXIT_CTL_LOAD_EFER              BIT(21)
#define EXIT_CTL_SAVE_PREEMPT_TIMER     BIT(22)
#define EXIT_CTL_CLEAR_BNDCFGS          BIT(23)
#define EXIT_CTL_CONCEAL_VMX_FROM_PT    BIT(24)

/* ====================================================================================== */
/*  VM-entry controls (SDM Vol 3C Table 25-15)                                             */
/* ====================================================================================== */
#define ENTRY_CTL_LOAD_DEBUG_CONTROLS   BIT(2)
#define ENTRY_CTL_IA32E_MODE_GUEST      BIT(9)   /* Guest enters 64-bit mode. */
#define ENTRY_CTL_ENTRY_TO_SMM          BIT(10)
#define ENTRY_CTL_DEACT_DUAL_MONITOR    BIT(11)
#define ENTRY_CTL_LOAD_PERF_GLOBAL_CTRL BIT(13)
#define ENTRY_CTL_LOAD_PAT              BIT(14)
#define ENTRY_CTL_LOAD_EFER             BIT(15)
#define ENTRY_CTL_LOAD_BNDCFGS          BIT(16)
#define ENTRY_CTL_CONCEAL_VMX_FROM_PT   BIT(17)

/* ====================================================================================== */
/*  VM-entry interruption-information field (SDM Vol 3C 25.8.3)                             */
/* ====================================================================================== */
#define VMENTRY_INTR_INFO_VECTOR_MASK       BITMASK(7, 0)
#define VMENTRY_INTR_INFO_TYPE_SHIFT        8
#define VMENTRY_INTR_INFO_TYPE_MASK         BITMASK(10, 8)
#define   VMENTRY_INTR_TYPE_EXTERNAL        0u
#define   VMENTRY_INTR_TYPE_NMI             2u
#define   VMENTRY_INTR_TYPE_HW_EXCEPTION    3u
#define   VMENTRY_INTR_TYPE_SW_INTERRUPT    4u
#define   VMENTRY_INTR_TYPE_PRIV_SW_EXCEPT  5u
#define   VMENTRY_INTR_TYPE_SW_EXCEPTION    6u
#define VMENTRY_INTR_INFO_DELIVER_ERRCODE   BIT(11)
#define VMENTRY_INTR_INFO_VALID             BIT(31)

/* Interruptibility-state bits (VMCS_GUEST_INTERRUPTIBILITY_STATE, SDM Vol 3C Table 25-3). */
#define GUEST_INTR_STATE_STI            BIT(0)
#define GUEST_INTR_STATE_MOV_SS         BIT(1)
#define GUEST_INTR_STATE_SMI            BIT(2)
#define GUEST_INTR_STATE_NMI            BIT(3)

/* Guest activity states (VMCS_GUEST_ACTIVITY_STATE, SDM Vol 3C Table 25-4). */
#define GUEST_ACTIVITY_ACTIVE           0u
#define GUEST_ACTIVITY_HLT              1u
#define GUEST_ACTIVITY_SHUTDOWN         2u
#define GUEST_ACTIVITY_WAIT_SIPI        3u

/* ====================================================================================== */
/*  Basic VM-exit reasons (SDM Vol 3C Appendix C / Table 27-1)                             */
/* ====================================================================================== */
#define EXIT_REASON_EXCEPTION_NMI           0
#define EXIT_REASON_EXTERNAL_INTERRUPT      1
#define EXIT_REASON_TRIPLE_FAULT            2
#define EXIT_REASON_INIT_SIGNAL             3
#define EXIT_REASON_SIPI                    4
#define EXIT_REASON_IO_SMI                  5
#define EXIT_REASON_OTHER_SMI               6
#define EXIT_REASON_INTERRUPT_WINDOW        7
#define EXIT_REASON_NMI_WINDOW              8
#define EXIT_REASON_TASK_SWITCH             9
#define EXIT_REASON_CPUID                   10
#define EXIT_REASON_GETSEC                  11
#define EXIT_REASON_HLT                     12
#define EXIT_REASON_INVD                    13
#define EXIT_REASON_INVLPG                  14
#define EXIT_REASON_RDPMC                   15
#define EXIT_REASON_RDTSC                   16
#define EXIT_REASON_RSM                     17
#define EXIT_REASON_VMCALL                  18
#define EXIT_REASON_VMCLEAR                 19
#define EXIT_REASON_VMLAUNCH                20
#define EXIT_REASON_VMPTRLD                 21
#define EXIT_REASON_VMPTRST                 22
#define EXIT_REASON_VMREAD                  23
#define EXIT_REASON_VMRESUME                24
#define EXIT_REASON_VMWRITE                 25
#define EXIT_REASON_VMXOFF                  26
#define EXIT_REASON_VMXON                   27
#define EXIT_REASON_CR_ACCESS               28
#define EXIT_REASON_MOV_DR                  29
#define EXIT_REASON_IO_INSTRUCTION          30
#define EXIT_REASON_RDMSR                   31
#define EXIT_REASON_WRMSR                   32
#define EXIT_REASON_VMENTRY_FAIL_GUEST      33
#define EXIT_REASON_VMENTRY_FAIL_MSR        34
#define EXIT_REASON_MWAIT                   36
#define EXIT_REASON_MONITOR_TRAP_FLAG       37
#define EXIT_REASON_MONITOR                 39
#define EXIT_REASON_PAUSE                   40
#define EXIT_REASON_VMENTRY_FAIL_MCE        41
#define EXIT_REASON_TPR_BELOW_THRESHOLD     43
#define EXIT_REASON_APIC_ACCESS             44
#define EXIT_REASON_VIRTUALIZED_EOI         45
#define EXIT_REASON_GDTR_IDTR_ACCESS        46
#define EXIT_REASON_LDTR_TR_ACCESS          47
#define EXIT_REASON_EPT_VIOLATION           48
#define EXIT_REASON_EPT_MISCONFIG           49
#define EXIT_REASON_INVEPT                  50
#define EXIT_REASON_RDTSCP                  51
#define EXIT_REASON_PREEMPT_TIMER_EXPIRED   52
#define EXIT_REASON_INVVPID                 53
#define EXIT_REASON_WBINVD                  54
#define EXIT_REASON_XSETBV                  55
#define EXIT_REASON_APIC_WRITE              56
#define EXIT_REASON_RDRAND                  57
#define EXIT_REASON_INVPCID                 58
#define EXIT_REASON_VMFUNC                  59
#define EXIT_REASON_ENCLS                   60
#define EXIT_REASON_RDSEED                  61
#define EXIT_REASON_PML_FULL                62
#define EXIT_REASON_XSAVES                  63
#define EXIT_REASON_XRSTORS                 64
#define EXIT_REASON_UMWAIT                  67
#define EXIT_REASON_TPAUSE                  68
#define EXIT_REASON_MAX                     69   /* One past the highest defined reason. */

/* Exit-reason word bit fields (SDM Vol 3C Table 25-19 / 27.2.1). The 16-bit basic reason is
 * in bits 15:0; the upper bits carry flags. */
#define EXIT_REASON_BASIC_MASK              BITMASK(15, 0)
#define EXIT_REASON_FLAG_MODUL              BIT(28)  /* Exit from SMM (modal). */
#define EXIT_REASON_FLAG_PENDING_MTF        BIT(28)
#define EXIT_REASON_FLAG_VMX_ROOT           BIT(29)  /* Exit occurred in VMX root operation. */
#define EXIT_REASON_FLAG_VMENTRY_FAIL       BIT(31)  /* VM-entry failure. */

/* ====================================================================================== */
/*  CR-access exit qualification (SDM Vol 3C Table 28-3)                                   */
/* ====================================================================================== */
#define CR_ACCESS_CR_NUMBER_MASK        BITMASK(3, 0)
#define CR_ACCESS_TYPE_SHIFT            4
#define CR_ACCESS_TYPE_MASK             BITMASK(5, 4)
#define   CR_ACCESS_TYPE_MOV_TO_CR      0u
#define   CR_ACCESS_TYPE_MOV_FROM_CR    1u
#define   CR_ACCESS_TYPE_CLTS           2u
#define   CR_ACCESS_TYPE_LMSW           3u
#define CR_ACCESS_LMSW_OPERAND          BIT(6)
#define CR_ACCESS_GPR_SHIFT             8
#define CR_ACCESS_GPR_MASK              BITMASK(11, 8)
#define CR_ACCESS_LMSW_SOURCE_SHIFT     16

/* ====================================================================================== */
/*  I/O-instruction exit qualification (SDM Vol 3C Table 28-5)                             */
/* ====================================================================================== */
#define IO_EXIT_SIZE_MASK               BITMASK(2, 0)  /* 0=1 byte, 1=2 bytes, 3=4 bytes. */
#define IO_EXIT_DIRECTION_IN            BIT(3)
#define IO_EXIT_STRING                  BIT(4)
#define IO_EXIT_REP                     BIT(5)
#define IO_EXIT_OPERAND_IMM             BIT(6)
#define IO_EXIT_PORT_SHIFT              16
#define IO_EXIT_PORT_MASK               BITMASK(31, 16)

/* ====================================================================================== */
/*  VM-instruction error numbers (SDM Vol 3C Table 31-1)                                   */
/* ====================================================================================== */
#define VMX_ERROR_VMCALL_IN_VMX_ROOT            1
#define VMX_ERROR_VMCLEAR_INVALID_ADDR          2
#define VMX_ERROR_VMCLEAR_VMXON_PTR             3
#define VMX_ERROR_VMLAUNCH_NONCLEAR_VMCS        4
#define VMX_ERROR_VMRESUME_NONLAUNCHED_VMCS     5
#define VMX_ERROR_VMRESUME_AFTER_VMXOFF         6
#define VMX_ERROR_VMENTRY_INVALID_CTRL          7
#define VMX_ERROR_VMENTRY_INVALID_HOST_STATE    8
#define VMX_ERROR_VMPTRLD_INVALID_ADDR          9
#define VMX_ERROR_VMPTRLD_VMXON_PTR             10
#define VMX_ERROR_VMPTRLD_BAD_REVISION          11
#define VMX_ERROR_VMREAD_VMWRITE_UNSUPPORTED    12
#define VMX_ERROR_VMWRITE_READONLY_FIELD        13
#define VMX_ERROR_VMXON_IN_VMX_ROOT             15
#define VMX_ERROR_VMENTRY_INVALID_EXEC_VMCS     16
#define VMX_ERROR_VMENTRY_NONLAUNCHED_EXEC      17
#define VMX_ERROR_VMENTRY_EXEC_VMCS_NO_VMXON    18
#define VMX_ERROR_VMCALL_NONCLEAR_VMCS          19
#define VMX_ERROR_VMCALL_INVALID_EXIT_CTRL      20
#define VMX_ERROR_VMCALL_BAD_MSEG_REVISION      22
#define VMX_ERROR_VMXOFF_DUAL_MONITOR           23
#define VMX_ERROR_VMCALL_BAD_SMM_MONITOR        24
#define VMX_ERROR_VMENTRY_INVALID_VM_EXEC_CTRL  25
#define VMX_ERROR_VMENTRY_EVENTS_BLOCKED_MOVSS  26
#define VMX_ERROR_INVALID_INVEPT_INVVPID        28

/* INVEPT / INVVPID descriptor types (SDM Vol 3C 31.4.1 / 31.4.2). */
#define INVEPT_TYPE_SINGLE_CONTEXT      1u
#define INVEPT_TYPE_ALL_CONTEXT         2u
#define INVVPID_TYPE_INDIV_ADDR         0u
#define INVVPID_TYPE_SINGLE_CONTEXT     1u
#define INVVPID_TYPE_ALL_CONTEXT        2u
#define INVVPID_TYPE_SINGLE_RETAIN_GLB  3u

#pragma pack(push, 1)
typedef struct _INVEPT_DESCRIPTOR {
    u64 eptp;
    u64 reserved;   /* Must be zero. */
} INVEPT_DESCRIPTOR;


/* --- line-unique C_ASSERT replacement (cl.exe strict mode chokes on the
   WDK's shared __C_ASSERT__ typedef when multiple asserts appear in the
   same TU). Same semantics: fail the build if the expression is false. */
#ifdef C_ASSERT
#undef C_ASSERT
#endif
#define _AL_HV_CAT2(a,b) a##b
#define _AL_HV_CAT(a,b) _AL_HV_CAT2(a,b)
#define C_ASSERT(e) typedef char _AL_HV_CAT(__C_ASSERT_LN_, __LINE__)[(e) ? 1 : -1]

typedef struct _INVVPID_DESCRIPTOR {
    u16 vpid;
    u16 reserved0;
    u32 reserved1;
    u64 linear_address;
} INVVPID_DESCRIPTOR;
#pragma pack(pop)
C_ASSERT(sizeof(INVEPT_DESCRIPTOR) == 16);
C_ASSERT(sizeof(INVVPID_DESCRIPTOR) == 16);

/* ====================================================================================== */
/*  Exit-reason / exit-interruption info decoders (SDM Vol 3C 25.9.2 / 27.2.2)             */
/* ====================================================================================== */
#define VMEXIT_INTR_INFO_VECTOR_MASK    BITMASK(7, 0)
#define VMEXIT_INTR_INFO_TYPE_SHIFT     8
#define VMEXIT_INTR_INFO_TYPE_MASK      BITMASK(10, 8)
#define VMEXIT_INTR_INFO_ERRCODE_VALID  BIT(11)
#define VMEXIT_INTR_INFO_NMI_UNBLOCK    BIT(12)
#define VMEXIT_INTR_INFO_VALID          BIT(31)

/* Exception vectors most relevant to VMI (SDM Vol 3A Table 6-1). */
#define VECTOR_DE   0    /* Divide error. */
#define VECTOR_DB   1    /* Debug. */
#define VECTOR_NMI  2
#define VECTOR_BP   3    /* Breakpoint (INT3). */
#define VECTOR_UD   6    /* Invalid opcode. */
#define VECTOR_GP   13   /* General protection. */
#define VECTOR_PF   14   /* Page fault. */
#define VECTOR_MC   18   /* Machine check. */

#endif /* ALETHEIA_HV_VMX_DEFS_H */
