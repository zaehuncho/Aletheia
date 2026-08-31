/*
 * driver.c -- WDM kernel-mode entry points and per-logical-processor virtualize/devirtualize
 * orchestration for the Aletheia clean-room VT-x/EPT VMI hypervisor.
 *
 * CLEAN-ROOM PROVENANCE: Written against the public Intel SDM Vol 3C (VMX operation, VMXON/
 * VMXOFF sequencing, VMCS lifecycle) and the public WDK documentation for kernel-mode drivers.
 * The per-CPU bring-up "hyperjack an already-running host" pattern is the same one described by
 * the public open-source VMMs (SimpleVisor, hvpp, Bareflank). No proprietary or anti-cheat
 * source was consulted.
 *
 * RESPONSIBILITY (this translation unit only):
 *   - DriverEntry: control device + symbolic link + IRP dispatch table.
 *   - IOCTLs: START / STOP virtualization, QUERY status, READ guest memory, DRAIN event log.
 *   - Per-logical-processor bring-up: run vmxon + VMCS setup + vmlaunch on EVERY CPU, with
 *     page-aligned, contiguous, non-paged allocations, at a correct IRQL.
 *   - Clean teardown: VMXOFF on all CPUs on unload.
 *
 * It CALLS -- never reimplements -- the vmx.c / vmcs.c / ept.c / vmi.c contracts declared in
 * hv.h. Everything VMX-architectural (control-bit adjustment, VMCS field population, EPT table
 * construction, the exit dispatcher) lives in those units.
 *
 * CANNOT BE BUILT, LOADED, OR RUN IN THIS ENVIRONMENT. It targets Windows x64 kernel mode on
 * real Intel VT-x + EPT silicon. Every unverified decision is marked "// TODO(hv):".
 */

#include "hv.h"

/* ptrdiff / offset helpers already pulled in via ntddk.h (arch.h -> ntddk.h). */

/* ====================================================================================== */
/*  Global hypervisor state (declared extern in hv.h; defined here -- driver.c owns it).    */
/* ====================================================================================== */
HV_STATE g_hv;

/* ====================================================================================== */
/*  Control-device names and the usermode IOCTL ABI.                                        */
/*                                                                                          */
/*  NOTE: these live in driver.c (not hv.h) on purpose -- a usermode analyzer includes      */
/*  <windows.h>, not the WDK-flavoured hv.h, so the shared control-plane ABI is duplicated  */
/*  into the usermode client's own header rather than pulled from here. Keep the two in sync.*/
/* ====================================================================================== */
#define ALETHEIA_DEVICE_NAME    L"\\Device\\AletheiaHv"
#define ALETHEIA_SYMLINK_NAME   L"\\DosDevices\\AletheiaHv"

/* Custom device type in the vendor-reserved range (SDM-independent; WDK IOCTL convention). */
#define ALETHEIA_DEVICE_TYPE    0x8000u

#define IOCTL_ALETHEIA_START     CTL_CODE(ALETHEIA_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALETHEIA_STOP      CTL_CODE(ALETHEIA_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALETHEIA_QUERY     CTL_CODE(ALETHEIA_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALETHEIA_READ_GPA  CTL_CODE(ALETHEIA_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALETHEIA_DRAIN     CTL_CODE(ALETHEIA_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* IOCTL_ALETHEIA_QUERY output. */
typedef struct _ALETHEIA_STATUS_OUT {
    u32 vt_supported;
    u32 ept_supported;
    u32 vcpu_count;             /* Logical processors the driver tried to virtualize. */
    u32 vcpus_virtualized;      /* Logical processors that reached VM non-root. */
    u32 events_dropped;         /* Ring-buffer overruns since load. */
    u32 event_capacity;         /* HV_EVENT_LOG_CAPACITY. */
    u32 reserved0;
    u32 reserved1;
} ALETHEIA_STATUS_OUT;

/* IOCTL_ALETHEIA_READ_GPA input (output is the raw bytes read). */
typedef struct _ALETHEIA_READ_GPA_IN {
    u64 gpa;                    /* Guest-physical address to read. */
    u32 length;                /* Bytes requested (<= output buffer, <= ALETHEIA_READ_MAX). */
    u32 reserved0;
} ALETHEIA_READ_GPA_IN;

#define ALETHEIA_READ_MAX       (1u << 20)   /* 1 MiB cap on a single introspection read. */

/* ====================================================================================== */
/*  Forward declarations of the WDM dispatch routines.                                      */
/* ====================================================================================== */
DRIVER_UNLOAD           HvDriverUnload;
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH         HvDispatchCreateClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH         HvDispatchDeviceControl;

static NTSTATUS         HvStatusToNtStatus(HV_STATUS s);

/* ====================================================================================== */
/*  Low-level allocation helpers.                                                           */
/*                                                                                          */
/*  Page-aligned, contiguous, non-paged, write-back memory for anything the CPU dereferences */
/*  by physical address (VMXON region, VMCS, MSR bitmap, EPT tables). MmAllocateContiguous-  */
/*  Memory returns page-aligned storage when the request is a page multiple, and the memory  */
/*  is non-paged with a WB cache type -- exactly what VMX structures require.                */
/*  MUST run at IRQL <= APC_LEVEL (we only ever call these at PASSIVE_LEVEL).                 */
/* ====================================================================================== */
_IRQL_requires_max_(APC_LEVEL)
static void *HvAllocContiguousPage(SIZE_T size, u64 *out_pa)
{
    PHYSICAL_ADDRESS highest;
    void *va;

    highest.QuadPart = ~0ull;   /* TODO(hv): clamp to CPUID.80000008 phys-addr width if a
                                 * platform ever rejects a high VMXON/VMCS physical address. */
    va = MmAllocateContiguousMemory(size, highest);
    if (va == NULL)
        return NULL;

    RtlZeroMemory(va, size);
    if (out_pa != NULL)
        *out_pa = (u64)MmGetPhysicalAddress(va).QuadPart;
    return va;
}

_IRQL_requires_max_(APC_LEVEL)
static void HvFreeContiguousPage(void *va)
{
    if (va != NULL)
        MmFreeContiguousMemory(va);
}

/* ====================================================================================== */
/*  Per-VCPU resource lifecycle.                                                            */
/*                                                                                          */
/*  Ownership split (documented so the vmcs.c/ept.c agents don't double-allocate):          */
/*    - driver.c allocates: the VCPU struct, the MSR bitmap, the host stack, the launch-     */
/*      context blob.                                                                        */
/*    - vmcs_alloc() (vmcs.c) allocates + revision-stamps: the VMXON region and the VMCS.    */
/*    - ept_build_identity() (ept.c) allocates: the EPT paging structures.                   */
/* ====================================================================================== */
_IRQL_requires_max_(APC_LEVEL)
static void HvFreeVcpu(VCPU *vcpu)
{
    if (vcpu == NULL)
        return;

    /* VMXON/VMCS pages are owned by vmcs.c. */
    vmcs_free(vcpu);
    /* EPT tables are owned by ept.c. */
    ept_destroy(vcpu);

    if (vcpu->msr_bitmap != NULL) {
        HvFreeContiguousPage(vcpu->msr_bitmap);
        vcpu->msr_bitmap = NULL;
    }
    if (vcpu->host_stack != NULL) {
        HvFreeContiguousPage(vcpu->host_stack);
        vcpu->host_stack = NULL;
    }
    if (vcpu->launch_context != NULL) {
        ExFreePoolWithTag(vcpu->launch_context, HV_POOL_TAG);
        vcpu->launch_context = NULL;
    }
    ExFreePoolWithTag(vcpu, HV_POOL_TAG);
}

/* Allocate the driver-owned per-VCPU memory and the VMX-architectural regions (via vmcs_alloc)
 * and the identity EPT (via ept_build_identity). All allocation happens here at PASSIVE_LEVEL,
 * BEFORE the IRQL is raised for the VMX-critical launch window (which must not allocate). */
_IRQL_requires_max_(APC_LEVEL)
static HV_STATUS HvAllocVcpu(u32 index, VCPU **out_vcpu)
{
    VCPU *vcpu;
    HV_STATUS status;
    u64 stack_top;

    *out_vcpu = NULL;

    /* TODO(hv): use MmAllocateContiguousNodeMemory / KeGetCurrentNodeNumber to place the VCPU
     * on the executing processor's NUMA node (hv.h documents vcpus[] as node-local). We are
     * already affinitized to the target CPU, so the default pool policy is node-local enough
     * for a first bring-up. */
    vcpu = (VCPU *)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(VCPU), HV_POOL_TAG);
    if (vcpu == NULL)
        return HV_ERR_ALLOC;
    RtlZeroMemory(vcpu, sizeof(*vcpu));

    vcpu->index = index;
    vcpu->hv = &g_hv;

    /* MSR bitmap -- 4KB, 4KB-aligned, physical address programmed into VMCS_CTRL_MSR_BITMAP. */
    vcpu->msr_bitmap = HvAllocContiguousPage(HV_MSR_BITMAP_SIZE, &vcpu->msr_bitmap_pa);
    if (vcpu->msr_bitmap == NULL) {
        status = HV_ERR_ALLOC;
        goto fail;
    }

    /* Host stack the VM-exit trampoline lands on. Page-aligned, non-paged. The very top slot
     * holds a back-pointer to this VCPU so asm_vmexit_entry can recover its context; host_rsp
     * is programmed into VMCS_HOST_RSP by vmcs_setup_host(). */
    vcpu->host_stack = HvAllocContiguousPage(HV_HOST_STACK_SIZE, NULL);
    if (vcpu->host_stack == NULL) {
        status = HV_ERR_ALLOC;
        goto fail;
    }
    stack_top = (u64)vcpu->host_stack + HV_HOST_STACK_SIZE;
    stack_top &= ~0xFull;                                   /* 16-byte align the frame base. */
    stack_top -= sizeof(void *);                            /* Reserve the back-pointer slot. */
    *(VCPU **)stack_top = vcpu;                             /* [host_rsp] == this VCPU. */
    vcpu->host_rsp = stack_top;
    /* TODO(hv): confirm this exact convention against asm_x64.asm's asm_vmexit_entry -- it must
     * read the VCPU pointer from [rsp] (or a fixed offset from it) on entry, and the ABI home
     * space / alignment it expects must match what vmcs_setup_host writes. */

    /* Launch-context blob for the capture-context bring-up (one page, non-paged, asm-written).*/
    vcpu->launch_context = ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE_4K, HV_POOL_TAG);
    if (vcpu->launch_context == NULL) {
        status = HV_ERR_ALLOC;
        goto fail;
    }
    RtlZeroMemory(vcpu->launch_context, PAGE_SIZE_4K);

    /* VMXON region + VMCS (revision-stamped) -- owned by vmcs.c. */
    status = vmcs_alloc(vcpu);
    if (status != HV_OK)
        goto fail;

    /* Identity EPT (1:1 GPA==HPA, MTRR-correct memory types) -- owned by ept.c. */
    status = ept_build_identity(vcpu);
    if (status != HV_OK)
        goto fail;

    *out_vcpu = vcpu;
    return HV_OK;

fail:
    HvFreeVcpu(vcpu);
    return status;
}

/* ====================================================================================== */
/*  Per-logical-processor bring-up (runs on the target CPU under thread affinity).          */
/*                                                                                          */
/*  Sequence (SDM Vol 3C 25.5 / 31.6 VMX bring-up):                                          */
/*    PASSIVE_LEVEL:  allocate VCPU + MSR bitmap + host stack + launch ctx + VMXON/VMCS + EPT */
/*    DISPATCH_LEVEL: VMXON, VMCLEAR+VMPTRLD, host/control VMCS state, capture, VMLAUNCH      */
/*  The IRQL is raised only across the VMX-critical window so the logical processor cannot be */
/*  preempted (and thread-migrated) between VMXON and a live VMCS. Allocation must precede    */
/*  the raise because contiguous/pool allocation is illegal above APC_LEVEL.                  */
/* ====================================================================================== */
_IRQL_requires_max_(APC_LEVEL)
static HV_STATUS hv_virtualize_current_processor_amd(void *context);

HV_STATUS hv_virtualize_current_processor(void *context)
{
    VCPU *vcpu;
    HV_STATUS status;
    ULONG index;
    KIRQL old_irql;
    VMX_RESULT vmx_res;
    int captured;

    /* Vendor dispatch: AMD path is delegated to the SVM peer of this function. Intel path
     * falls through to the existing VMX bring-up below. HV_VENDOR_UNKNOWN can only happen if
     * DriverEntry never populated g_hv.vendor; treat as unsupported. */
    if (g_hv.vendor == HV_VENDOR_AMD)
        return hv_virtualize_current_processor_amd(context);
    if (g_hv.vendor != HV_VENDOR_INTEL)
        return HV_ERR_UNSUPPORTED_VENDOR;

    UNREFERENCED_PARAMETER(context);
    /* TODO(hv): 'context' is reserved for a KeIpiGenericCall broadcast variant that would carry
     * a shared result/barrier structure. The current design uses serial thread-affinity
     * iteration (hv_for_each_cpu), so each call reports its own HV_STATUS by return value. */

    index = KeGetCurrentProcessorNumberEx(NULL);   /* System-wide logical processor index. */
    if (index >= HV_MAX_VCPU)
        return HV_ERR_INVALID_ARG;

    if (g_hv.vcpus[index] != NULL)
        return HV_OK;                              /* Already virtualized this CPU. */

    /* ---- PASSIVE_LEVEL: allocate everything the launch window will touch. ---- */
    status = HvAllocVcpu(index, &vcpu);
    if (status != HV_OK)
        return status;
    vcpu->launched = 0;
    vcpu->in_vmx_root = 0;
    g_hv.vcpus[index] = vcpu;

    /* ---- DISPATCH_LEVEL: the VMX-critical window (no allocation past this point). ---- */
    KeRaiseIrql(DISPATCH_LEVEL, &old_irql);

    /* Enter VMX operation: set CR4.VMXE, satisfy CR0/CR4 FIXED0/FIXED1, VMXON. */
    status = vmx_enable_on_cpu(vcpu);
    if (status != HV_OK)
        goto fail_locked;
    vcpu->in_vmx_root = 1;

    /* Make this VCPU's VMCS current: VMCLEAR (launch state = clear) then VMPTRLD. */
    status = vmcs_clear_and_load(vcpu);
    if (status != HV_OK)
        goto fail_vmxon;

    /* Host-state area (where every VM-exit lands) and the execution controls (pin/proc/proc2/
     * entry/exit + EPTP + MSR bitmap). These are pure VMWRITEs -- legal at DISPATCH_LEVEL. */
    status = vmcs_setup_host(vcpu);
    if (status != HV_OK)
        goto fail_vmxon;
    status = vmcs_setup_controls(vcpu);
    if (status != HV_OK)
        goto fail_vmxon;

    /* Capture the host continuation. On the setup pass this returns 0 and we proceed to launch;
     * once the guest is live it "returns" a second time with a nonzero value, at the same RSP,
     * and we take the resumed-guest branch below. (SimpleVisor-style hyperjack.) */
    captured = asm_capture_context(vcpu->launch_context);
    if (captured != 0) {
        /* We are now executing as the guest, immediately after VMLAUNCH. Virtualization live. */
        vcpu->launched = 1;
        InterlockedIncrement(&g_hv.vcpus_virtualized);
        KeLowerIrql(old_irql);
        return HV_OK;
    }

    /* Guest-state area: segments/CRs/descriptors from the current host context, and GUEST_RIP/
     * RSP/RFLAGS from vcpu->launch_context so the guest resumes right after asm_capture_context. */
    status = vmcs_setup_guest(vcpu);
    if (status != HV_OK)
        goto fail_vmxon;

    /* Launch. On success control never returns here -- it re-emerges from asm_capture_context
     * (the branch above). Reaching the next line means VM-entry failed. */
    vmx_res = asm_vmlaunch();
    (void)vmx_res;
    {
        u64 vm_error = vmcs_read(VMCS_RO_VM_INSTRUCTION_ERROR);
        /* TODO(hv): surface vm_error (SDM Table 31-1) to the event log / debugger. Common
         * culprits: 7 = invalid control field, 8 = invalid host-state field. */
        (void)vm_error;
    }
    status = HV_ERR_VMLAUNCH;

fail_vmxon:
    /* We are still in VMX root (VMLAUNCH failed or a setup VMWRITE failed). Leave VMX and drop
     * CR4.VMXE so the CPU is returned to its pre-driver state. */
    (void)asm_vmxoff();
    __writecr4(__readcr4() & ~CR4_VMXE);
    vcpu->in_vmx_root = 0;

fail_locked:
    KeLowerIrql(old_irql);
    /* Roll this CPU's allocation back; it never reached VM non-root. */
    g_hv.vcpus[index] = NULL;
    HvFreeVcpu(vcpu);
    return status;
}

/* Devirtualize the executing CPU. A CPU that reached VM non-root can only VMXOFF from VMX root,
 * which it reaches via a VM-exit -- so we ask the exit handler to unload us with a VMCALL. A CPU
 * that is only in VMX root (a failed launch we did not already unwind) VMXOFFs directly. */
_IRQL_requires_max_(APC_LEVEL)
HV_STATUS hv_devirtualize_current_processor(void *context)
{
    VCPU *vcpu;
    ULONG index;

    UNREFERENCED_PARAMETER(context);

    index = KeGetCurrentProcessorNumberEx(NULL);
    if (index >= HV_MAX_VCPU)
        return HV_ERR_INVALID_ARG;

    vcpu = g_hv.vcpus[index];
    if (vcpu == NULL)
        return HV_OK;                              /* Nothing virtualized on this CPU. */

    if (vcpu->launched) {
        /* Ask the hypervisor to tear this CPU down. vmexit_handle_vmcall() must, for
         * HV_VMCALL_UNLOAD: read GUEST_RIP/RSP/RFLAGS, execute VMXOFF, clear CR4.VMXE, and
         * resume the interrupted thread un-virtualized. asm_vmcall returns here afterward with
         * the CPU no longer in VMX operation. */
        (void)asm_vmcall(HV_VMCALL_MAGIC, HV_VMCALL_UNLOAD, 0, 0);
        /* TODO(hv): define a return protocol from the unload handler (e.g. RAX = HV_OK) and
         * check it here; a wedged guest that never exits would hang this call. */
        vcpu->launched = 0;
        vcpu->in_vmx_root = 0;
        InterlockedDecrement(&g_hv.vcpus_virtualized);
    } else if (vcpu->in_vmx_root) {
        (void)asm_vmxoff();
        vcpu->in_vmx_root = 0;
    }

    /* Defensive: ensure VMX is disabled in CR4 regardless of which path ran. */
    __writecr4(__readcr4() & ~CR4_VMXE);
    return HV_OK;
}

/* ====================================================================================== */
/*  Broadcast helper: run a per-CPU worker on every active logical processor, serialized by  */
/*  thread affinity so allocation and VMX bring-up happen on (and pin to) the target CPU.     */
/*  Uses group affinity so it is correct on >64-logical-processor (multi-group) systems.      */
/*  MUST be called at PASSIVE_LEVEL.                                                          */
/* ====================================================================================== */
_IRQL_requires_(PASSIVE_LEVEL)
static HV_STATUS hv_for_each_cpu(HV_STATUS (*worker)(void *), void *ctx)
{
    ULONG count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    HV_STATUS overall = HV_OK;
    ULONG i;

    for (i = 0; i < count; i++) {
        PROCESSOR_NUMBER proc_num;
        GROUP_AFFINITY target, previous;
        NTSTATUS nt;
        HV_STATUS s;

        nt = KeGetProcessorNumberFromIndex(i, &proc_num);
        if (!NT_SUCCESS(nt))
            continue;

        RtlZeroMemory(&target, sizeof(target));
        target.Group = proc_num.Group;
        target.Mask = (KAFFINITY)1 << proc_num.Number;

        /* Pin this thread to logical processor i. On return we are guaranteed to be running on
         * it, and cannot migrate until we revert. */
        KeSetSystemGroupAffinityThread(&target, &previous);
        s = worker(ctx);
        KeRevertToUserGroupAffinityThread(&previous);

        if (s != HV_OK && overall == HV_OK)
            overall = s;   /* Remember the first failure; keep going to unwind cleanly. */
    }
    return overall;
}

/* ====================================================================================== */
/*  Whole-machine virtualize / devirtualize.                                                */
/* ====================================================================================== */
_IRQL_requires_(PASSIVE_LEVEL)
HV_STATUS hv_virtualize_all_processors(void)
{
    HV_STATUS status;

    if (!g_hv.vt_supported)
        return HV_ERR_NO_VT;
    if (!g_hv.ept_supported)
        return HV_ERR_NO_EPT;

    status = hv_alloc_state();
    if (status != HV_OK)
        return status;

    g_hv.vcpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    status = hv_for_each_cpu(hv_virtualize_current_processor, NULL);
    if (status != HV_OK) {
        /* Partial failure: unwind every CPU that did come up, so we never leave the machine
         * half-virtualized. */
        (void)hv_for_each_cpu(hv_devirtualize_current_processor, NULL);
        return status;
    }
    return HV_OK;
}

_IRQL_requires_(PASSIVE_LEVEL)
HV_STATUS hv_devirtualize_all_processors(void)
{
    ULONG i;
    HV_STATUS status;

    status = hv_for_each_cpu(hv_devirtualize_current_processor, NULL);

    /* Free per-CPU resources after every CPU has left VMX operation. Freeing is CPU-agnostic,
     * so it need not run under affinity. */
    for (i = 0; i < HV_MAX_VCPU; i++) {
        if (g_hv.vcpus[i] != NULL) {
            HvFreeVcpu(g_hv.vcpus[i]);
            g_hv.vcpus[i] = NULL;
        }
    }
    g_hv.vcpu_count = 0;
    return status;
}

/* ====================================================================================== */
/*  Current-CPU VCPU accessor.                                                              */
/* ====================================================================================== */
VCPU *hv_current_vcpu(void)
{
    ULONG index = KeGetCurrentProcessorNumberEx(NULL);
    if (index >= HV_MAX_VCPU)
        return NULL;
    return g_hv.vcpus[index];
}

/* ====================================================================================== */
/*  CPUID vendor detection.                                                                 */
/*                                                                                          */
/*  Reads CPUID.0.  EBX/EDX/ECX carry the 12-byte ASCII vendor string.                      */
/*    "GenuineIntel" (EBX=756E6547 EDX=49656E69 ECX=6C65746E)  -> HV_VENDOR_INTEL           */
/*    "AuthenticAMD" (EBX=68747541 EDX=69746E65 ECX=444D4163)  -> HV_VENDOR_AMD             */
/*  Anything else stays HV_VENDOR_UNKNOWN and the dispatch path bails HV_ERR_UNSUPPORTED_   */
/*  VENDOR without touching CR0/EFER.                                                        */
/* ====================================================================================== */
HV_VENDOR hv_detect_vendor(void)
{
    int r[4];
    __cpuidex(r, 0, 0);
    /* Encoded as three little-endian dwords in EBX/EDX/ECX. */
    if ((u32)r[1] == 0x756E6547 && (u32)r[3] == 0x49656E69 && (u32)r[2] == 0x6C65746E)
        return HV_VENDOR_INTEL;
    if ((u32)r[1] == 0x68747541 && (u32)r[3] == 0x69746E65 && (u32)r[2] == 0x444D4163)
        return HV_VENDOR_AMD;
    return HV_VENDOR_UNKNOWN;
}

/* ====================================================================================== */
/*  AMD per-CPU bring-up (SVM peer of the Intel body above).                                */
/*                                                                                          */
/*  Same shape as the VMX path: allocate at PASSIVE, raise to DISPATCH, enable SVM, build   */
/*  the VMCB + NPT, populate guest state from the current host context, and issue VMRUN in  */
/*  a loop via svm_launch.  On success the guest is "us" running natively under nested      */
/*  paging; the function returns HV_OK from the resumed-guest branch.                        */
/*                                                                                          */
/*  NOTE: this is the driver-side dispatch entry.  The heavy lifting lives in svm.c /        */
/*  vmcb.c / npt.c; every prototype is declared in hv.h and every constant is APM-cited      */
/*  in svm_defs.h / npt_defs.h.                                                              */
/* ====================================================================================== */
static HV_STATUS hv_virtualize_current_processor_amd(void *context)
{
    VCPU *vcpu;
    HV_STATUS status;
    ULONG index;
    KIRQL old_irql;
    int captured;

    UNREFERENCED_PARAMETER(context);

    index = KeGetCurrentProcessorNumberEx(NULL);
    if (index >= HV_MAX_VCPU)
        return HV_ERR_INVALID_ARG;

    if (g_hv.vcpus[index] != NULL)
        return HV_OK;

    /* ---- PASSIVE_LEVEL: allocate everything the launch window will touch. ---- */
    status = HvAllocVcpu(index, &vcpu);
    if (status != HV_OK)
        return status;
    vcpu->launched = 0;
    vcpu->svm_launched = 0;
    g_hv.vcpus[index] = vcpu;

    /* VMCB + HSAVE + IOPM + MSRPM (contiguous nonpaged, 4KB-aligned). */
    status = vmcb_alloc(vcpu);
    if (status != HV_OK)
        goto fail_alloc;

    /* Identity NPT: one PDPT of 512 1-GiB pages covering [0, 512 GiB). */
    status = npt_build_identity(vcpu);
    if (status != HV_OK)
        goto fail_alloc;

    /* ---- DISPATCH_LEVEL: SVM-critical window; no allocations from here down. ---- */
    KeRaiseIrql(DISPATCH_LEVEL, &old_irql);

    /* Set EFER.SVME and program MSR_VM_HSAVE_PA on this CPU. */
    status = svm_enable_on_cpu(vcpu);
    if (status != HV_OK)
        goto fail_locked;

    /* Full VMCB state population: guest state save area, intercepts, permission bitmaps. */
    status = vmcb_setup_intercepts(vcpu);
    if (status != HV_OK)
        goto fail_svm;
    status = vmcb_setup_msrpm(vcpu);
    if (status != HV_OK)
        goto fail_svm;
    status = vmcb_setup_iopm(vcpu);
    if (status != HV_OK)
        goto fail_svm;

    /* Capture the host continuation. SimpleVisor-style: on the setup pass returns 0; when the
     * guest goes live it "returns" a second time with nonzero, at the same RSP, and we take
     * the resumed-guest branch below. */
    captured = asm_capture_context(vcpu->launch_context);
    if (captured != 0) {
        /* Now executing as the guest, immediately after the launch. */
        vcpu->launched = 1;
        InterlockedIncrement(&g_hv.vcpus_virtualized);
        KeLowerIrql(old_irql);
        return HV_OK;
    }

    /* Guest-state area comes from the current host context + the launch snapshot. */
    status = vmcb_setup_guest(vcpu);
    if (status != HV_OK)
        goto fail_svm;

    /* Enter the VMRUN loop. On success control never returns here -- it re-emerges from
     * asm_capture_context (above). Reaching the next line means VMRUN entry was rejected. */
    status = svm_launch(vcpu);
    if (status == HV_OK)
        status = HV_ERR_VMRUN;   /* svm_launch returning here without a resumed-guest branch. */

fail_svm:
    (void)svm_disable_on_cpu(vcpu);

fail_locked:
    KeLowerIrql(old_irql);

fail_alloc:
    npt_destroy(vcpu);
    vmcb_free(vcpu);
    g_hv.vcpus[index] = NULL;
    HvFreeVcpu(vcpu);
    return status;
}

/* ====================================================================================== */
/*  Global-state allocation (event ring). g_hv itself is a static global; only the shared    */
/*  observation ring needs a heap allocation. Idempotent so START can be issued repeatedly.   */
/* ====================================================================================== */
_IRQL_requires_max_(APC_LEVEL)
HV_STATUS hv_alloc_state(void)
{
    if (g_hv.event_log != NULL)
        return HV_OK;

    g_hv.event_log = (HV_EVENT_LOG *)ExAllocatePoolWithTag(NonPagedPoolNx,
                                                           sizeof(HV_EVENT_LOG), HV_POOL_TAG);
    if (g_hv.event_log == NULL)
        return HV_ERR_ALLOC;

    RtlZeroMemory(g_hv.event_log, sizeof(HV_EVENT_LOG));
    return HV_OK;
}

_IRQL_requires_max_(APC_LEVEL)
void hv_free_state(void)
{
    if (g_hv.event_log != NULL) {
        ExFreePoolWithTag(g_hv.event_log, HV_POOL_TAG);
        g_hv.event_log = NULL;
    }
}

/* ====================================================================================== */
/*  IRP dispatch.                                                                           */
/* ====================================================================================== */
static NTSTATUS HvStatusToNtStatus(HV_STATUS s)
{
    /* Mapped to universally-available NTSTATUS values (no STATUS_HV_* dependency, which is not
     * present in every WDK). TODO(hv): if a richer taxonomy is wanted, switch to the STATUS_HV_*
     * codes in <ntstatus.h> once the build's WDK version is pinned. */
    switch (s) {
    case HV_OK:                  return STATUS_SUCCESS;
    case HV_ERR_NO_VT:           return STATUS_NOT_SUPPORTED;
    case HV_ERR_NO_EPT:          return STATUS_NOT_SUPPORTED;
    case HV_ERR_VMX_LOCKED_OFF:  return STATUS_ACCESS_DENIED;
    case HV_ERR_ALLOC:           return STATUS_INSUFFICIENT_RESOURCES;
    case HV_ERR_INVALID_ARG:     return STATUS_INVALID_PARAMETER;
    case HV_ERR_NOT_VIRTUALIZED: return STATUS_INVALID_DEVICE_STATE;
    default:                     return STATUS_UNSUCCESSFUL;   /* VMXON/VMCLEAR/VMLAUNCH/etc. */
    }
}

NTSTATUS HvDispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS HvDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS nt = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;
    ULONG in_len = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG out_len = stack->Parameters.DeviceIoControl.OutputBufferLength;
    void *buffer = Irp->AssociatedIrp.SystemBuffer;   /* METHOD_BUFFERED: shared in/out. */

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {

    case IOCTL_ALETHEIA_START:
        nt = HvStatusToNtStatus(hv_virtualize_all_processors());
        break;

    case IOCTL_ALETHEIA_STOP:
        nt = HvStatusToNtStatus(hv_devirtualize_all_processors());
        break;

    case IOCTL_ALETHEIA_QUERY:
        if (out_len < sizeof(ALETHEIA_STATUS_OUT) || buffer == NULL) {
            nt = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            ALETHEIA_STATUS_OUT *st = (ALETHEIA_STATUS_OUT *)buffer;
            RtlZeroMemory(st, sizeof(*st));
            st->vt_supported       = g_hv.vt_supported;
            st->ept_supported      = g_hv.ept_supported;
            st->vcpu_count         = g_hv.vcpu_count;
            st->vcpus_virtualized  = (u32)g_hv.vcpus_virtualized;
            st->event_capacity     = HV_EVENT_LOG_CAPACITY;
            st->events_dropped     = (g_hv.event_log != NULL)
                                       ? (u32)g_hv.event_log->dropped : 0;
            info = sizeof(*st);
            nt = STATUS_SUCCESS;
        }
        break;

    case IOCTL_ALETHEIA_READ_GPA:
        if (in_len < sizeof(ALETHEIA_READ_GPA_IN) || buffer == NULL) {
            nt = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            /* Copy the request out before we overwrite the shared buffer with the result. */
            ALETHEIA_READ_GPA_IN req = *(ALETHEIA_READ_GPA_IN *)buffer;
            if (req.length == 0 || req.length > ALETHEIA_READ_MAX || req.length > out_len) {
                nt = STATUS_INVALID_PARAMETER;
                break;
            }
            {
                HV_STATUS hs = vmi_read_guest_physical(req.gpa, buffer, req.length);
                if (hs == HV_OK) {
                    info = req.length;
                    nt = STATUS_SUCCESS;
                } else {
                    nt = HvStatusToNtStatus(hs);
                }
            }
        }
        break;

    case IOCTL_ALETHEIA_DRAIN:
        if (out_len < sizeof(HV_EVENT) || buffer == NULL) {
            nt = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            u32 max = out_len / (u32)sizeof(HV_EVENT);
            u32 copied = vmi_drain_events((HV_EVENT *)buffer, max);
            info = (ULONG_PTR)copied * sizeof(HV_EVENT);
            nt = STATUS_SUCCESS;
        }
        break;

    default:
        nt = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = nt;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return nt;
}

/* ====================================================================================== */
/*  Unload: devirtualize every CPU, drop the control device + link, free global state.      */
/* ====================================================================================== */
VOID HvDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlink = RTL_CONSTANT_STRING(ALETHEIA_SYMLINK_NAME);

    UNREFERENCED_PARAMETER(DriverObject);

    /* VMXOFF on all CPUs first, while the device is still up (teardown touches no device). */
    (void)hv_devirtualize_all_processors();

    IoDeleteSymbolicLink(&symlink);

    if (g_hv.device_object != NULL) {
        IoDeleteDevice(g_hv.device_object);
        g_hv.device_object = NULL;
    }

    hv_free_state();
}

/* ====================================================================================== */
/*  DriverEntry: build the control device, wire dispatch, probe VT-x/EPT support.           */
/*  Virtualization is NOT started here -- it is driven explicitly by IOCTL_ALETHEIA_START so  */
/*  the operator controls exactly when the machine is hyperjacked.                            */
/* ====================================================================================== */
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING dev_name = RTL_CONSTANT_STRING(ALETHEIA_DEVICE_NAME);
    UNICODE_STRING symlink  = RTL_CONSTANT_STRING(ALETHEIA_SYMLINK_NAME);
    PDEVICE_OBJECT device   = NULL;
    NTSTATUS nt;
    HV_STATUS hs;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&g_hv, sizeof(g_hv));

    DriverObject->DriverUnload = HvDriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = HvDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = HvDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HvDispatchDeviceControl;

    nt = IoCreateDevice(DriverObject, 0, &dev_name, FILE_DEVICE_UNKNOWN,
                        FILE_DEVICE_SECURE_OPEN, FALSE, &device);
    if (!NT_SUCCESS(nt))
        return nt;

    nt = IoCreateSymbolicLink(&symlink, &dev_name);
    if (!NT_SUCCESS(nt)) {
        IoDeleteDevice(device);
        return nt;
    }

    device->Flags |= DO_BUFFERED_IO;                 /* METHOD_BUFFERED IOCTL path. */
    device->Flags &= ~DO_DEVICE_INITIALIZING;        /* Legacy driver: clear explicitly. */
    g_hv.device_object = device;

    /* CPUID vendor detect. Sets g_hv.vendor; the per-CPU dispatch in
     * hv_virtualize_current_processor honours it (INTEL -> VMX/EPT, AMD -> SVM/NPT). */
    g_hv.vendor = hv_detect_vendor();

    /* Probe support for whichever vendor we're on. Homogeneous package assumed (every logical
     * CPU reports the same capabilities). Non-fatal in either case: we load so QUERY can report
     * "unsupported"; START refuses. */
    if (g_hv.vendor == HV_VENDOR_INTEL) {
        hs = vmx_check_support(&g_hv.caps);
        if (hs == HV_OK) {
            g_hv.vt_supported = 1;
            g_hv.ept_supported =
                (g_hv.caps.ept_vpid_cap & VMX_EPT_CAP_PAGE_WALK_4) ? 1 : 0;
        } else {
            g_hv.vt_supported  = 0;
            g_hv.ept_supported = 0;
            /* TODO(hv): distinguish HV_ERR_NO_VT from HV_ERR_VMX_LOCKED_OFF for the operator. */
        }
    } else if (g_hv.vendor == HV_VENDOR_AMD) {
        hs = svm_check_support(&g_hv.svm_caps);
        if (hs == HV_OK) {
            g_hv.svm_supported = 1;
            g_hv.npt_supported = (u8)g_hv.svm_caps.nested_paging;
        } else {
            g_hv.svm_supported = 0;
            g_hv.npt_supported = 0;
            /* TODO(hv): distinguish HV_ERR_NO_SVM from HV_ERR_SVM_LOCKED_OFF for the operator. */
        }
    }
    /* HV_VENDOR_UNKNOWN: neither probe runs; every support flag stays 0 and any START call
     * will bounce HV_ERR_UNSUPPORTED_VENDOR from hv_virtualize_current_processor. */

    return STATUS_SUCCESS;
}
