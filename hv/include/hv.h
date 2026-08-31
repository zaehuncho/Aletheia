/*
 * hv.h -- Shared runtime contract for the Aletheia clean-room VT-x/EPT VMI hypervisor.
 *
 * CLEAN-ROOM PROVENANCE: The structures and prototypes here are original, written against
 * the public Intel SDM Vol 3B/3C/3D and the public open-source VMM references (hvpp,
 * SimpleVisor, Bareflank, DRAKVUF, LibVMI). No proprietary source consulted. This is the
 * single header every component (vmx.c, vmcs.c, ept.c, vmexit.c, vmi.c, driver.c, and the
 * asm_x64 exports) codes against.
 *
 * PURPOSE: defensive malware-analysis VMI. The hypervisor thin-slices itself under the
 * running Windows host (a "hyperjacking" bring-up of an already-booted OS, like SimpleVisor),
 * installs an identity EPT, and uses EPT permission traps to observe a detection-aware sample
 * doing write-then-execute unpacking -- all from ring -1, invisible to the guest.
 *
 * CANNOT BE BUILT OR RUN IN THIS ENVIRONMENT. Every unfinished decision is marked
 * "// TODO(hv):". Correctness against the SDM is the whole game.
 */
#ifndef ALETHEIA_HV_HV_H
#define ALETHEIA_HV_HV_H

#include "arch.h"
#include "vmx_defs.h"
#include "ept_defs.h"
#include "svm_defs.h"
#include "npt_defs.h"

/* ====================================================================================== */
/*  Vendor discriminator. Every HV_STATE and VCPU carries a vendor tag; the runtime picks   */
/*  the Intel (vmx/vmcs/ept) or AMD (svm/vmcb/npt) code paths off it at bring-up. The       */
/*  observation contract (HV_EVENT, the event log, vmi_*) is vendor-neutral -- an NPT fault */
/*  and an EPT violation both call the same vmi_on_page_fault() seam.                       */
/*  Peer design of DRAKVUF / LibVMI / Bareflank.                                            */
/* ====================================================================================== */
typedef enum _HV_VENDOR {
    HV_VENDOR_UNKNOWN = 0,
    HV_VENDOR_INTEL,        /* "GenuineIntel" CPUID.0h vendor string; use VMX + EPT.        */
    HV_VENDOR_AMD,          /* "AuthenticAMD" CPUID.0h vendor string; use SVM + NPT.        */
} HV_VENDOR;

/* ====================================================================================== */
/*  Tunables                                                                               */
/* ====================================================================================== */
#define HV_POOL_TAG             'ThvA'   /* "AhvT" reversed -- Aletheia HV tag. */
#define HV_HOST_STACK_SIZE      (KERNEL_STACK_SIZE)   /* Per-VCPU host stack; page-multiple. */
#define HV_MSR_BITMAP_SIZE      PAGE_SIZE_4K          /* 4KB MSR bitmap (SDM 25.6.9). */
#define HV_EVENT_LOG_CAPACITY   4096                  /* Ring-buffer slots for VMI events. */
#define HV_MAX_VCPU             256                   /* Upper bound on logical processors. */

/* VMCALL "hypercall" service numbers placed in RAX by guest-side agents (VMI control plane).
 * TODO(hv): lock the ABI (which GPRs carry args/results) before any guest agent ships. */
#define HV_VMCALL_MAGIC             0x416C657468ull /* "Aleth" -- identify our VMCALL. */
#define HV_VMCALL_PING              0x0001
#define HV_VMCALL_UNLOAD            0x0002           /* Request orderly per-VCPU vmxoff. */
#define HV_VMCALL_WATCH_GPA         0x0010           /* Arm a write/exec EPT trap on a GPA. */
#define HV_VMCALL_UNWATCH_GPA       0x0011
#define HV_VMCALL_DRAIN_EVENTS      0x0020           /* Copy event-log records to the guest. */


/* --- line-unique C_ASSERT replacement (cl.exe strict mode chokes on the
   WDK's shared __C_ASSERT__ typedef when multiple asserts appear in the
   same TU). Same semantics: fail the build if the expression is false. */
#ifdef C_ASSERT
#undef C_ASSERT
#endif
#define _AL_HV_CAT2(a,b) a##b
#define _AL_HV_CAT(a,b) _AL_HV_CAT2(a,b)
#define C_ASSERT(e) typedef char _AL_HV_CAT(__C_ASSERT_LN_, __LINE__)[(e) ? 1 : -1]

/* ====================================================================================== */
/*  General-purpose register file, saved by the asm VM-exit stub (SDM GPR order)           */
/* ====================================================================================== */
/* The asm entry stub pushes the guest GPRs in this exact layout, then passes a pointer to it
 * as the argument to hv_vmexit_dispatch(). RSP/RIP/RFLAGS are NOT here -- they live in the
 * VMCS and are read via VMREAD. Field order is load-bearing: asm_x64.asm must match it. */
typedef struct _GUEST_REGISTERS {
    u64 rax;
    u64 rcx;
    u64 rdx;
    u64 rbx;
    u64 rsp_dummy;   /* Placeholder to keep PUSHAQ-style symmetry; guest RSP comes from VMCS. */
    u64 rbp;
    u64 rsi;
    u64 rdi;
    u64 r8;
    u64 r9;
    u64 r10;
    u64 r11;
    u64 r12;
    u64 r13;
    u64 r14;
    u64 r15;
    /* SSE/XMM are not saved here; host runs with the guest's; TODO(hv): confirm XMM handling
     * for the VMI code path (we must not clobber guest XMM across an exit). */
} GUEST_REGISTERS;
C_ASSERT(sizeof(GUEST_REGISTERS) == 16 * sizeof(u64));

/* Index of each GPR for decoding CR-access / MOV-DR exit qualifications (SDM Vol 3C 28.2.1:
 * the "general-purpose register" field uses the architectural encoding RAX=0..R15=15). */
enum GPR_INDEX {
    GPR_RAX = 0, GPR_RCX, GPR_RDX, GPR_RBX, GPR_RSP, GPR_RBP, GPR_RSI, GPR_RDI,
    GPR_R8, GPR_R9, GPR_R10, GPR_R11, GPR_R12, GPR_R13, GPR_R14, GPR_R15
};

/* ====================================================================================== */
/*  Launch-context snapshot (SimpleVisor-style bring-up capture)                            */
/* ====================================================================================== */
/* asm_capture_context() fills this with the caller's register file, RFLAGS, and the exact
 * RSP/RIP of the instruction after the call. vmcs_setup_guest() then programs VMCS_GUEST_RSP/
 * RIP/RFLAGS from .rsp/.rip/.rflags so the freshly launched guest resumes as that caller.
 * asm_restore_context() reloads this and jumps to .rip (a non-VMX resume of the captured point).
 * HEADER ADDITION (owned by asm_x64.asm): field ORDER is load-bearing -- the .asm byte offsets
 * mirror this struct exactly (rax=0, rcx=8, ... r15=120, rflags=128, rip=136).
 * TODO(hv): reconcile with the "return 0 on the setup pass / 1 as the running guest" convention
 * in asm_capture_context's prototype; the re-entry EAX=1 is arranged by the launch glue
 * (driver.c) placing 1 into the guest RAX before VMLAUNCH, since VMCS does not carry RAX. */
typedef struct _HV_LAUNCH_CONTEXT {
    u64 rax;        /* offset 0   */
    u64 rcx;        /* offset 8   */
    u64 rdx;        /* offset 16  */
    u64 rbx;        /* offset 24  */
    u64 rsp;        /* offset 32  : caller RSP (with the call's return address already popped). */
    u64 rbp;        /* offset 40  */
    u64 rsi;        /* offset 48  */
    u64 rdi;        /* offset 56  */
    u64 r8;         /* offset 64  */
    u64 r9;         /* offset 72  */
    u64 r10;        /* offset 80  */
    u64 r11;        /* offset 88  */
    u64 r12;        /* offset 96  */
    u64 r13;        /* offset 104 */
    u64 r14;        /* offset 112 */
    u64 r15;        /* offset 120 */
    u64 rflags;     /* offset 128 */
    u64 rip;        /* offset 136 : return address == where the guest resumes. */
} HV_LAUNCH_CONTEXT;
C_ASSERT(sizeof(HV_LAUNCH_CONTEXT) == 18 * sizeof(u64));

/* ====================================================================================== */
/*  Cached VMX capability MSRs -- read once at bring-up, consulted when composing controls  */
/* ====================================================================================== */
typedef struct _VMX_CAPABILITIES {
    u64 basic;              /* IA32_VMX_BASIC. */
    u64 pinbased;           /* IA32_VMX_PINBASED_CTLS. */
    u64 procbased;          /* IA32_VMX_PROCBASED_CTLS. */
    u64 procbased2;         /* IA32_VMX_PROCBASED_CTLS2. */
    u64 exit_ctls;          /* IA32_VMX_EXIT_CTLS. */
    u64 entry_ctls;         /* IA32_VMX_ENTRY_CTLS. */
    u64 true_pinbased;      /* IA32_VMX_TRUE_PINBASED_CTLS (if basic bit 55). */
    u64 true_procbased;     /* IA32_VMX_TRUE_PROCBASED_CTLS. */
    u64 true_exit_ctls;     /* IA32_VMX_TRUE_EXIT_CTLS. */
    u64 true_entry_ctls;    /* IA32_VMX_TRUE_ENTRY_CTLS. */
    u64 misc;               /* IA32_VMX_MISC. */
    u64 ept_vpid_cap;       /* IA32_VMX_EPT_VPID_CAP. */
    u64 cr0_fixed0;         /* IA32_VMX_CR0_FIXED0. */
    u64 cr0_fixed1;         /* IA32_VMX_CR0_FIXED1. */
    u64 cr4_fixed0;         /* IA32_VMX_CR4_FIXED0. */
    u64 cr4_fixed1;         /* IA32_VMX_CR4_FIXED1. */
    u32 vmcs_revision_id;   /* Low 31 bits of IA32_VMX_BASIC. */
    u8  has_true_ctls;      /* IA32_VMX_BASIC bit 55. */
} VMX_CAPABILITIES;

/* ====================================================================================== */
/*  EPT bookkeeping per VCPU (identity map + the watched-page shadow list)                 */
/* ====================================================================================== */
typedef struct _EPT_STATE {
    EPTP        eptp;               /* Value programmed into VMCS_CTRL_EPT_POINTER. */
    EPT_PML4E  *pml4;               /* Virtual pointer to the single PML4 table (4KB). */
    void       *pdpt;               /* Virtual pointer to the PDPT page. */
    void       *pd_pages;           /* Virtual base of the contiguous PD tables. */
    void       *split_pt_pool;      /* Pre-allocated 4KB PTs used to split a 2MB page. */
    u32         split_pt_used;      /* How many split PTs have been handed out. */
    u32         split_pt_capacity;
    u64         highest_gpa;        /* Top of the identity-mapped guest-physical range. */
} EPT_STATE;

/* One watched guest-physical page in the write-then-execute unpacker. Each records the
 * "real" permissions vs. the currently installed (trapping) permissions so the exit handler
 * can single-step permissions without losing the page's intended mapping. */
typedef struct _EPT_WATCH {
    u64        gpa;                 /* Watched guest-physical page (4KB-aligned). */
    EPT_PTE   *pte;                 /* The live PTE controlling this page (after any split). */
    u8         armed;               /* Slot in use. */
    u8         current_access;      /* EPT_ACCESS_* currently installed. */
    u8         saw_write;           /* A write to this page has been observed. */
    u8         saw_exec;            /* An exec fetch from this page has been observed. */
    u64        write_count;
    u64        exec_count;
} EPT_WATCH;

/* ====================================================================================== */
/*  VMI event-log record -- the ring -1 observation stream Aletheia's analyzer consumes     */
/* ====================================================================================== */
typedef enum _HV_EVENT_TYPE {
    HV_EVENT_NONE = 0,
    HV_EVENT_EPT_WRITE,         /* Guest wrote a watched (would-be-code) page. */
    HV_EVENT_EPT_EXEC,          /* Guest executed a freshly-written page (candidate OEP). */
    HV_EVENT_EPT_READ,
    HV_EVENT_CR_WRITE,          /* CR0/CR3/CR4 write (paging changes, process switch). */
    HV_EVENT_MSR_WRITE,
    HV_EVENT_CPUID,
    HV_EVENT_EXCEPTION,         /* #BP / #UD / #PF intercepted for instrumentation. */
    HV_EVENT_VMCALL,
} HV_EVENT_TYPE;

typedef struct _HV_EVENT {
    u64 tsc;                    /* RDTSC at exit time. */
    u32 vcpu_index;
    u32 type;                   /* HV_EVENT_TYPE. */
    u64 guest_rip;              /* Faulting guest RIP. */
    u64 guest_cr3;              /* Address-space id (which process). */
    u64 gpa;                    /* Guest-physical address (EPT events). */
    u64 gla;                    /* Guest-linear address (if valid). */
    u64 aux0;                   /* Event-specific: exit qualification, MSR index, CPUID leaf. */
    u64 aux1;                   /* Event-specific: written value, CR value, etc. */
} HV_EVENT;

/* Lock-free-ish single-producer ring. The exit handler (producer, one VCPU at a time per
 * slot) advances head; the drain path advances tail. TODO(hv): the multi-VCPU producer case
 * needs an interlocked head reservation -- current draft assumes per-VCPU sharding. */
typedef struct _HV_EVENT_LOG {
    HV_EVENT  records[HV_EVENT_LOG_CAPACITY];
    volatile long head;         /* Next slot to write (mod capacity). */
    volatile long tail;         /* Next slot to read. */
    volatile long dropped;      /* Count of events lost to a full ring. */
} HV_EVENT_LOG;

/* ====================================================================================== */
/*  Per-VCPU state                                                                         */
/* ====================================================================================== */
typedef struct _VCPU {
    u32                 index;              /* Logical processor number. */
    u8                  launched;           /* VMLAUNCH has succeeded; use VMRESUME after. */
    u8                  in_vmx_root;        /* VMXON executed on this CPU. */

    /* VMXON region -- 4KB, revision id in first dword (SDM 24.11.5). Physical + virtual. */
    void               *vmxon_region;
    u64                 vmxon_pa;

    /* Active VMCS -- 4KB, revision id in first dword. Physical + virtual. */
    void               *vmcs_region;
    u64                 vmcs_pa;

    /* Host stack the VM-exit stub lands on. host_rsp is loaded into VMCS_HOST_RSP; the top
     * of this stack is arranged to hold a back-pointer to this VCPU so the exit stub can
     * recover its context. */
    void               *host_stack;         /* Base of the allocation. */
    u64                 host_rsp;           /* Value programmed into VMCS_HOST_RSP. */

    /* MSR bitmap -- 4KB, programmed into VMCS_CTRL_MSR_BITMAP (SDM 25.6.9). */
    void               *msr_bitmap;
    u64                 msr_bitmap_pa;

    EPT_STATE           ept;
    EPT_WATCH           watches[64];        /* TODO(hv): size against real workload. */
    u32                 watch_count;

    /* ---------------- AMD SVM-side region (populated only when vendor == HV_VENDOR_AMD) --- */
    /* VMCB -- 4 KiB, 4 KiB-aligned. Loaded by VMRUN; the *sole* argument to VMRUN is its PA. */
    VMCB               *vmcb;               /* Virtual pointer.                              */
    u64                 vmcb_pa;            /* Physical address (VMRUN input).               */

    /* HSAVE region -- 4 KiB per-CPU; hardware stashes host state here on VMRUN and restores
     * on VM-exit. Address goes into MSR_VM_HSAVE_PA (§15.30.4) before the first VMRUN. */
    void               *hsave_region;
    u64                 hsave_pa;

    /* IOPM (12 KiB) and MSRPM (8 KiB) permission bitmaps. Both start with EVERY bit CLEAR
     * (== "not intercepted"), then svm.c sets exactly the ports/MSRs we want observed. Base
     * physical addresses go into VMCB.control.iopm_base_pa / msrpm_base_pa. */
    void               *iopm;               /* 3 x 4 KiB.                                   */
    u64                 iopm_pa;
    void               *msrpm;              /* 2 x 4 KiB.                                   */
    u64                 msrpm_pa;

    NPT_STATE           npt;
    NPT_WATCH           npt_watches[64];    /* TODO(hv): size vs real workload.             */
    u32                 npt_watch_count;

    u32                 svm_asid;           /* Per-VCPU ASID (nonzero); default 1 + index.  */
    u8                  svm_launched;       /* First VMRUN has succeeded.                   */
    /* --------------------------------------------------------------------------------------*/

    GUEST_REGISTERS     gpr;                /* Scratch copy the exit path may read/write. */
    u64                 guest_rip;          /* Cached each exit (also in VMCS). */
    u64                 guest_rsp;
    u64                 guest_rflags;

    /* Opaque snapshot written by asm_capture_context() at the launch point (driver.c). The
     * hyperjack bring-up captures the host's continuation RIP/RSP/RFLAGS/GPRs here on the
     * setup pass; vmcs_setup_guest() consumes it to program GUEST_RIP/RSP/RFLAGS so the guest
     * resumes at the instruction after the launch call. One page, nonpaged. Added by the
     * driver.c build agent -- see note in its return.
     * TODO(hv): pin the exact blob layout once asm_x64.asm's asm_capture_context is written. */
    void               *launch_context;

    struct _HV_STATE   *hv;                 /* Back-pointer to global state. */
} VCPU;

/* ====================================================================================== */
/*  Global hypervisor state                                                               */
/* ====================================================================================== */
typedef struct _HV_STATE {
    u32                 vcpu_count;             /* Active logical processors virtualized. */
    VCPU               *vcpus[HV_MAX_VCPU];     /* Per-CPU, allocated on that CPU's node. */
    HV_VENDOR           vendor;                 /* Set at bring-up from CPUID.0 vendor string.  */
    VMX_CAPABILITIES    caps;                   /* Intel capability probe (if vendor==INTEL).   */
    SVM_CAPABILITIES    svm_caps;               /* AMD  capability probe (if vendor==AMD).      */
    HV_EVENT_LOG       *event_log;              /* Shared observation ring. */
    volatile long       vcpus_virtualized;      /* Interlocked success counter. */
    u8                  vt_supported;           /* Intel VMX + feature-control gate passed.    */
    u8                  ept_supported;
    u8                  svm_supported;          /* AMD  SVM  + VM_CR SVMDIS gate passed.       */
    u8                  npt_supported;
    PDEVICE_OBJECT      device_object;          /* Control device for the usermode analyzer. */
} HV_STATE;

/* Single global instance owned by driver.c. */
extern HV_STATE g_hv;

/* ====================================================================================== */
/*  Status codes returned across the C interface (distinct from NTSTATUS)                  */
/* ====================================================================================== */
typedef enum _HV_STATUS {
    HV_OK = 0,
    HV_ERR_NO_VT,               /* CPU lacks VMX or CPUID vendor mismatch. */
    HV_ERR_VMX_LOCKED_OFF,      /* IA32_FEATURE_CONTROL locked with VMXON disabled. */
    HV_ERR_NO_EPT,              /* Secondary controls / EPT not available. */
    HV_ERR_ALLOC,               /* Contiguous/nonpaged allocation failed. */
    HV_ERR_VMXON,               /* VMXON failed (CF/ZF set). */
    HV_ERR_VMCLEAR,
    HV_ERR_VMPTRLD,
    HV_ERR_VMWRITE,             /* A VMCS setup write failed. */
    HV_ERR_VMLAUNCH,            /* VMLAUNCH failed; check VMCS_RO_VM_INSTRUCTION_ERROR. */
    HV_ERR_EPT_BUILD,
    HV_ERR_INVALID_ARG,
    HV_ERR_NOT_VIRTUALIZED,     /* Operation requires the VCPU already be in VMX non-root. */
    HV_ERR_NO_SVM,
    HV_ERR_SVM_LOCKED_OFF,
    HV_ERR_NO_NPT,
    HV_ERR_VMRUN,
    HV_ERR_NPT_BUILD,
    HV_ERR_UNSUPPORTED_VENDOR,
} HV_STATUS;

/* Result of asm VMX instruction wrappers, mirroring the SDM's three outcomes (VMsucceed,
 * VMfailValid = ZF, VMfailInvalid = CF; SDM Vol 3C 31.2). */
typedef enum _VMX_RESULT {
    VMX_SUCCEED = 0,
    VMX_FAIL_VALID = 1,     /* ZF=1: error number is in VMCS_RO_VM_INSTRUCTION_ERROR. */
    VMX_FAIL_INVALID = 2,   /* CF=1: no current VMCS. */
} VMX_RESULT;

/* AMD SVM result. VMRUN itself has no CF/ZF outcome -- success is reflected in the VMCB's
 * exit_code (any legal SVM_EXIT_* value == succeeded; SVM_EXIT_INVALID == entry failed).
 * SVM_RESULT is the return code of the C-side SVM wrappers, mirroring VMX_RESULT's shape. */
typedef enum _SVM_RESULT {
    SVM_SUCCEED = 0,
    SVM_FAIL_ENTRY = 1,     /* VMRUN returned SVM_EXIT_INVALID (VMCB state rejected).        */
    SVM_FAIL_GENERAL = 2,   /* Wrapper-level failure (bad arg, no HSAVE, EFER.SVME clear).   */
} SVM_RESULT;

/* ====================================================================================== */
/*  asm_x64.asm exports (MASM). Thin wrappers over privileged instructions the C code       */
/*  cannot emit directly. Every one is a leaf with the Windows x64 calling convention.       */
/*  Where a boolean/VMX_RESULT is returned it comes back in EAX/RAX.                          */
/* ====================================================================================== */
VMX_RESULT __stdcall asm_vmxon(u64 vmxon_region_pa);
VMX_RESULT __stdcall asm_vmxoff(void);
VMX_RESULT __stdcall asm_vmclear(u64 vmcs_pa);
VMX_RESULT __stdcall asm_vmptrld(u64 vmcs_pa);
VMX_RESULT __stdcall asm_vmread(u64 field, u64 *out_value);
VMX_RESULT __stdcall asm_vmwrite(u64 field, u64 value);
VMX_RESULT __stdcall asm_vmlaunch(void);
VMX_RESULT __stdcall asm_vmresume(void);
VMX_RESULT __stdcall asm_invept(u64 type, INVEPT_DESCRIPTOR *desc);
VMX_RESULT __stdcall asm_invvpid(u64 type, INVVPID_DESCRIPTOR *desc);

/* The VM-exit trampoline: this is what VMCS_HOST_RIP points at. It saves GUEST_REGISTERS,
 * calls hv_vmexit_dispatch(), then VMRESUMEs. Never called from C -- referenced only to take
 * its address when programming the VMCS. */
void asm_vmexit_entry(void);

/* Capture the current segment/table descriptors and control state the C bring-up code needs
 * to fill guest/host VMCS fields but cannot read with an intrinsic. */
u16  __stdcall asm_read_cs(void);
u16  __stdcall asm_read_ss(void);
u16  __stdcall asm_read_ds(void);
u16  __stdcall asm_read_es(void);
u16  __stdcall asm_read_fs(void);
u16  __stdcall asm_read_gs(void);
u16  __stdcall asm_read_tr(void);
u16  __stdcall asm_read_ldtr(void);
void __stdcall asm_read_gdtr(PSEUDO_DESCRIPTOR_64 *out);
void __stdcall asm_read_idtr(PSEUDO_DESCRIPTOR_64 *out);
u32  __stdcall asm_read_seg_access_rights(u16 selector);  /* LAR-based access-rights fetch. */
u32  __stdcall asm_read_seg_limit(u16 selector);          /* LSL-based limit fetch. */
u64  __stdcall asm_read_rflags(void);

/* Small capture helper: snapshots the host GPR/return context so a freshly launched guest
 * resumes exactly at the instruction after the launch call (the SimpleVisor bring-up trick).
 * Returns 0 on the setup pass and 1 when re-entered as the running guest. TODO(hv): decide
 * whether we use this "capture context" model or a purpose-built guest entry stub. */
int  __stdcall asm_capture_context(void *context_out);
void __stdcall asm_restore_context(void *context_in);

/* Orderly per-VCPU devirtualization primitive (HEADER ADDITION, owned by asm_x64.asm). Executes
 * VMXOFF, restores the guest GPRs from *regs, loads RFLAGS, and jumps to guest_rip on guest_rsp
 * -- i.e. leaves VMX root and lets the guest run natively from the exact point it faulted. The
 * unload exit handler VMREADs guest RIP/RSP/RFLAGS (it owns the VMCS field encodings) and tail-
 * calls this; it never returns. TODO(hv): bugcheck if VMXOFF sets CF/ZF; CR4.VMXE is cleared
 * separately by vmx_disable_on_cpu(). */
DECLSPEC_NORETURN void __stdcall asm_devirtualize_and_resume(u64 guest_rip, u64 guest_rsp,
                                                             u64 guest_rflags, GUEST_REGISTERS *regs);

/* Emit a VMCALL from root-less (guest) context. There is no MSVC intrinsic for VMCALL, so the
 * control plane (driver.c teardown) reaches VMX root through this thin wrapper: it loads RAX/
 * RCX/RDX/R8 from the arguments, executes VMCALL, and returns whatever the exit handler leaves
 * in RAX. Used to drive HV_VMCALL_UNLOAD so the exit handler can VMXOFF the current CPU (VMXOFF
 * is only valid in VMX root, which a running guest can reach only via a VM-exit). Added by the
 * driver.c build agent -- see note in its return. TODO(hv): implement in asm_x64.asm and lock
 * the GPR ABI (RAX=magic/return, RCX=service, RDX/R8=args) against vmexit_handle_vmcall(). */
u64  __stdcall asm_vmcall(u64 rax, u64 rcx, u64 rdx, u64 r8);

/* ---- AMD SVM asm wrappers (owned by asm_x64.asm; peer of the VMX block above) --------- */
/* Enter guest via VMRUN in a loop; each iteration saves host state (VMSAVE), guards the
 * critical section (CLGI), executes VMRUN with vmcb_pa in RAX, then STGI + VMLOAD host
 * state back and returns to C on VM-exit. GUEST_REGISTERS layout matches the Intel path so
 * the exit dispatcher is source-compatible. Returns SVM_RESULT (see enum above). */
SVM_RESULT __stdcall asm_svm_run(u64 vmcb_pa, GUEST_REGISTERS *regs);
void       __stdcall asm_vmsave(u64 vmcb_pa);
void       __stdcall asm_vmload(u64 vmcb_pa);
void       __stdcall asm_clgi(void);
void       __stdcall asm_stgi(void);
void       __stdcall asm_invlpga(u64 va, u32 asid);
u64        __stdcall asm_vmmcall(u64 rax, u64 rcx, u64 rdx, u64 r8);

/* SVM VM-exit trampoline. Vendor-neutral hv_vmexit_dispatch() is reused; the trampoline
 * saves GUEST_REGISTERS in the same layout and calls it. Never called from C. */
void asm_svm_vmexit_entry(void);

/* ====================================================================================== */
/*  vmx.c -- VMX lifecycle: feature detection, VMXON/VMXOFF, per-VCPU bring-up               */
/* ====================================================================================== */
HV_STATUS   vmx_check_support(VMX_CAPABILITIES *caps_out);
HV_STATUS   vmx_read_capabilities(VMX_CAPABILITIES *caps_out);
HV_STATUS   vmx_enable_on_cpu(VCPU *vcpu);      /* Set CR4.VMXE, adjust CR0/CR4, VMXON. */
HV_STATUS   vmx_disable_on_cpu(VCPU *vcpu);     /* VMXOFF, clear CR4.VMXE. */
/* Adjust a control word so required-1 bits are set and required-0 bits are cleared, per the
 * allowed-settings encoding of a capability MSR (SDM Vol 3D A.3: low dword = allowed-0,
 * high dword = allowed-1). Returns the adjusted value to VMWRITE. */
u32         vmx_adjust_controls(u32 desired, u64 capability_msr);
/* Force CR0/CR4 to satisfy the FIXED0/FIXED1 constraints for VMX operation (SDM 24.8). */
u64         vmx_adjust_cr0(u64 cr0, const VMX_CAPABILITIES *caps);
u64         vmx_adjust_cr4(u64 cr4, const VMX_CAPABILITIES *caps);
/* Read VMCS_RO_VM_INSTRUCTION_ERROR from the currently loaded VMCS (SDM Vol 3C Table 31-1).
 * Meaningful only after a VMfailValid (ZF) with a VMCS loaded; returns 0 if none is current. */
u32         vmx_last_instruction_error(void);

/* ====================================================================================== */
/*  vmcs.c -- VMCS allocation and full guest/host/control state population                   */
/* ====================================================================================== */
HV_STATUS   vmcs_alloc(VCPU *vcpu);             /* Allocate + revision-stamp VMCS/VMXON pages. */
void        vmcs_free(VCPU *vcpu);
HV_STATUS   vmcs_clear_and_load(VCPU *vcpu);    /* VMCLEAR then VMPTRLD the VCPU's VMCS. */
HV_STATUS   vmcs_setup_guest(VCPU *vcpu);       /* Guest-state area from current host context. */
HV_STATUS   vmcs_setup_host(VCPU *vcpu);        /* Host-state area (where exits land). */
HV_STATUS   vmcs_setup_controls(VCPU *vcpu);    /* Pin/proc/proc2/entry/exit + EPTP + bitmaps. */
/* Convenience wrappers that assert on failure in checked builds. */
HV_STATUS   vmcs_write(u64 field, u64 value);
u64         vmcs_read(u64 field);

/* ====================================================================================== */
/*  ept.c -- Identity EPT construction and the write-then-execute watch primitives           */
/* ====================================================================================== */
HV_STATUS   ept_build_identity(VCPU *vcpu);     /* 1:1 GPA==HPA map honoring MTRR memtypes. */
void        ept_destroy(VCPU *vcpu);
/* Walk to (optionally splitting a large page into) the 4KB PTE mapping a GPA. */
EPT_PTE    *ept_get_pte(VCPU *vcpu, u64 gpa, int allocate_split);
HV_STATUS   ept_split_2mb(VCPU *vcpu, u64 gpa);       /* Demote a 2MB PDE to 512 4KB PTEs. */
HV_STATUS   ept_set_access(VCPU *vcpu, u64 gpa, u8 access);  /* EPT_ACCESS_* on the page. */
/* Arm/disarm a write-then-execute watch on a guest-physical page. */
HV_STATUS   ept_watch_page(VCPU *vcpu, u64 gpa);
HV_STATUS   ept_unwatch_page(VCPU *vcpu, u64 gpa);
EPT_WATCH  *ept_find_watch(VCPU *vcpu, u64 gpa);
/* TLB maintenance after a permission change. */
void        ept_invalidate(VCPU *vcpu);         /* INVEPT single-context for this EPTP. */
u8          ept_memtype_for_gpa(VCPU *vcpu, u64 gpa);  /* Compose MTRR-derived memory type. */

/* ====================================================================================== */
/*  vmexit.c -- The VM-exit dispatcher and per-reason handlers                               */
/* ====================================================================================== */
/* Called by asm_vmexit_entry with a pointer to the saved guest GPRs. Returns nonzero to
 * request VMRESUME (normal) and zero to request an orderly teardown (guest asked to unload).*/
int         hv_vmexit_dispatch(GUEST_REGISTERS *regs);
/* Continuation the asm exit stub jumps to when hv_vmexit_dispatch() returns 0 (guest asked to
 * unload). HEADER ADDITION (owned by vmexit.c): reads this VCPU's cached guest RIP/RSP/RFLAGS
 * and tail-calls asm_devirtualize_and_resume(); never returns. */
DECLSPEC_NORETURN void hv_vmexit_finish_unload(GUEST_REGISTERS *regs);
/* Last-resort handler the asm exit stub calls when an inline VMRESUME fails (VMfailValid/
 * Invalid). HEADER ADDITION (owned by vmexit.c/driver.c): reads VMCS_RO_VM_INSTRUCTION_ERROR
 * and bugchecks. `rflags` is the post-VMRESUME RFLAGS (CF/ZF distinguish the two failures). */
DECLSPEC_NORETURN void hv_vmx_failure(u64 rflags);
/* Per-reason handlers; each returns whether to advance guest RIP past the faulting instr. */
void        vmexit_handle_cpuid(VCPU *vcpu, GUEST_REGISTERS *regs);
void        vmexit_handle_ept_violation(VCPU *vcpu, GUEST_REGISTERS *regs);
void        vmexit_handle_ept_misconfig(VCPU *vcpu, GUEST_REGISTERS *regs);
void        vmexit_handle_cr_access(VCPU *vcpu, GUEST_REGISTERS *regs);
void        vmexit_handle_msr_read(VCPU *vcpu, GUEST_REGISTERS *regs);
void        vmexit_handle_msr_write(VCPU *vcpu, GUEST_REGISTERS *regs);
void        vmexit_handle_vmcall(VCPU *vcpu, GUEST_REGISTERS *regs);
void        vmexit_handle_exception_nmi(VCPU *vcpu, GUEST_REGISTERS *regs);
void        vmexit_handle_xsetbv(VCPU *vcpu, GUEST_REGISTERS *regs);
/* Handler for any VMX instruction executed by the guest (we do not support nesting): inject
 * #UD or set CF, per policy. */
void        vmexit_handle_vmx_instruction(VCPU *vcpu, GUEST_REGISTERS *regs);
/* RIP advance + interruptibility clear shared by handlers that consume the instruction. */
void        vmexit_advance_rip(VCPU *vcpu);
/* Inject an event of an explicit interruption type into the guest (SDM 25.8.3). Sets the
 * VM-entry instruction length for software-delivered types (4/5/6) from the exit's length. */
void        vmexit_inject_interruption(VCPU *vcpu, u8 vector, u32 intr_type,
                                       int has_errcode, u32 errcode);
/* Inject a hardware exception (interruption type 3) into the guest -- thin wrapper. */
void        vmexit_inject_exception(VCPU *vcpu, u8 vector, int has_errcode, u32 errcode);

/* ====================================================================================== */
/*  vmi.c -- The virtual-machine-introspection / unpacker policy layer                       */
/* ====================================================================================== */
/* Record one observation into the shared ring (called from exit handlers). */
void        vmi_log_event(VCPU *vcpu, HV_EVENT_TYPE type, u64 gpa, u64 gla, u64 aux0, u64 aux1);
/* Decode an EPT-violation exit into the structured form. */
void        vmi_decode_ept_violation(VCPU *vcpu, EPT_VIOLATION_INFO *out);
/* Core write-then-execute state machine: given a decoded violation on a watched page, flip
 * EPT permissions to catch the complementary access and emit the right event. Returns whether
 * the faulting access should now be allowed to retry. */
int         vmi_on_ept_violation(VCPU *vcpu, const EPT_VIOLATION_INFO *info);
/* Guest-memory reads for introspection: translate a guest-linear or guest-physical address
 * and copy out. TODO(hv): needs a guest-CR3 page-table walk for GVA->GPA. */
HV_STATUS   vmi_read_guest_physical(u64 gpa, void *dst, u32 length);
HV_STATUS   vmi_read_guest_virtual(u64 guest_cr3, u64 gva, void *dst, u32 length);
/* Drain the event ring toward the usermode analyzer. Returns count copied. */
u32         vmi_drain_events(HV_EVENT *dst, u32 max);

/* ====================================================================================== */
/*  driver.c -- WDM entry points and the per-CPU virtualize/devirtualize orchestration       */
/* ====================================================================================== */
DRIVER_INITIALIZE   DriverEntry;
/* Run a callback on every logical processor (KeIpiGenericCall-style broadcast). */
HV_STATUS   hv_virtualize_all_processors(void);
HV_STATUS   hv_devirtualize_all_processors(void);
/* Per-CPU worker executed at the target processor: full bring-up of one VCPU. */
HV_STATUS   hv_virtualize_current_processor(void *context);
HV_STATUS   hv_devirtualize_current_processor(void *context);
VCPU       *hv_current_vcpu(void);          /* VCPU for the executing logical processor. */
HV_STATUS   hv_alloc_state(void);           /* Allocate g_hv arrays + event log. */
void        hv_free_state(void);
/* CPUID-based vendor detection. Reads CPUID.0 and sets g_hv.vendor accordingly. */
HV_VENDOR   hv_detect_vendor(void);

/* ====================================================================================== */
/*  svm.c -- AMD SVM lifecycle: capability probe, EFER.SVME enable, per-VCPU bring-up      */
/* ====================================================================================== */
HV_STATUS   svm_check_support(SVM_CAPABILITIES *caps_out);
HV_STATUS   svm_enable_on_cpu(VCPU *vcpu);   /* Set EFER.SVME + program MSR_VM_HSAVE_PA.  */
HV_STATUS   svm_disable_on_cpu(VCPU *vcpu);  /* Clear EFER.SVME.                          */
HV_STATUS   svm_launch(VCPU *vcpu);          /* Loop asm_svm_run + dispatch until unload. */
u64         svm_last_exit_code(VCPU *vcpu);  /* VMCB->control.exit_code.                  */

/* ====================================================================================== */
/*  vmcb.c -- VMCB allocation and full guest/host/control population                       */
/* ====================================================================================== */
HV_STATUS   vmcb_alloc(VCPU *vcpu);          /* VMCB + HSAVE + IOPM + MSRPM pages.        */
void        vmcb_free(VCPU *vcpu);
HV_STATUS   vmcb_setup_guest(VCPU *vcpu);    /* Guest state from current host context.    */
HV_STATUS   vmcb_setup_intercepts(VCPU *vcpu);   /* CPUID, EFER writes, VMMCALL, ...      */
HV_STATUS   vmcb_setup_msrpm(VCPU *vcpu);    /* Zero MSRPM then set observed MSRs.        */
HV_STATUS   vmcb_setup_iopm(VCPU *vcpu);     /* Zero IOPM.                                */

/* ====================================================================================== */
/*  npt.c -- Identity NPT construction and the write-then-execute watch primitives         */
/* ====================================================================================== */
HV_STATUS   npt_build_identity(VCPU *vcpu);      /* 1:1 GPA==HPA, MTRR-correct types.     */
void        npt_destroy(VCPU *vcpu);
NPT_PTE    *npt_get_pte(VCPU *vcpu, u64 gpa, int allocate_split);
HV_STATUS   npt_split_2mb(VCPU *vcpu, u64 gpa);
HV_STATUS   npt_set_page_perms(VCPU *vcpu, u64 gpa, u8 state); /* NPT_WATCH_STATE_*.      */
HV_STATUS   npt_watch_page(VCPU *vcpu, u64 gpa);
HV_STATUS   npt_unwatch_page(VCPU *vcpu, u64 gpa);
NPT_WATCH  *npt_find_watch(VCPU *vcpu, u64 gpa);
void        npt_invalidate(VCPU *vcpu);          /* INVLPGA on this ASID, or full flush.  */

/* ====================================================================================== */
/*  vmexit.c -- AMD side: SVM dispatcher + per-reason handlers (peer of the Intel block)   */
/* ====================================================================================== */
int         hv_svm_vmexit_dispatch(GUEST_REGISTERS *regs);
void        svm_decode_exit(VCPU *vcpu, SVM_EXIT_INFO *out);
void        svm_decode_npf(const SVM_EXIT_INFO *in, NPF_INFO *out);
void        svm_handle_cpuid(VCPU *vcpu, GUEST_REGISTERS *regs);
void        svm_handle_npf(VCPU *vcpu, GUEST_REGISTERS *regs);
void        svm_handle_msr_read(VCPU *vcpu, GUEST_REGISTERS *regs);
void        svm_handle_msr_write(VCPU *vcpu, GUEST_REGISTERS *regs);
void        svm_handle_vmmcall(VCPU *vcpu, GUEST_REGISTERS *regs);
void        svm_handle_exception(VCPU *vcpu, GUEST_REGISTERS *regs);
void        svm_advance_rip(VCPU *vcpu);         /* Uses NRIP if available, else insn_len.*/

/* ====================================================================================== */
/*  vmi.c -- vendor-neutral seam. EPT violations AND NPT faults both flow through this.    */
/*  `kind` encodes the fault access (0=read, 1=write, 2=exec) so the write-then-execute    */
/*  state machine doesn't need to know which vendor produced the fault.                    */
/* ====================================================================================== */
int         vmi_on_page_fault(VCPU *vcpu, u64 gpa, u32 kind);

#endif /* ALETHEIA_HV_HV_H */
