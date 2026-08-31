/*
 * vmi.c -- VMI policy: write-then-execute state machine + event ring producer.
 *
 * This TU implements the "what do we DO with a trapped event" layer.
 * vmexit.c routes hardware VM-exits into vmi_* callbacks; those callbacks
 * decide whether to log, whether to flip a page's permission for the next
 * trap phase, and what to emit into the shared event ring.
 *
 * SCAFFOLD ONLY: this file exists to satisfy the linker so we can produce
 * a well-formed .sys artifact. The bodies are correct-shaped stubs that
 * emit nothing and always allow the guest to continue. Real implementations
 * belong to Phase 4 of the BRINGUP checklist (the write-then-execute state
 * machine, guest-memory readback). Every function is safe to call.
 *
 * Prototypes are exactly those declared in hv.h.
 */

#include "hv.h"

#if DBG
#define HV_LOG(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[aletheia-vmi] " fmt "\n", __VA_ARGS__)
#else
#define HV_LOG(fmt, ...) ((void)0)
#endif

void vmi_log_event(VCPU *vcpu, HV_EVENT_TYPE type, u64 gpa, u64 gla, u64 aux0, u64 aux1)
{
    UNREFERENCED_PARAMETER(vcpu);
    UNREFERENCED_PARAMETER(gla);
    UNREFERENCED_PARAMETER(aux0);
    UNREFERENCED_PARAMETER(aux1);
    /* TODO(hv): push into the per-VCPU MDL-backed ring. */
    HV_LOG("event type=%u gpa=0x%llx (scaffold: dropped)", (unsigned)type, gpa);
}

u32 vmi_drain_events(HV_EVENT *dst, u32 max)
{
    UNREFERENCED_PARAMETER(dst);
    UNREFERENCED_PARAMETER(max);
    return 0;
}

HV_STATUS vmi_read_guest_physical(u64 gpa, void *dst, u32 length)
{
    UNREFERENCED_PARAMETER(gpa);
    if (dst && length) RtlZeroMemory(dst, length);
    return HV_ERR_INVALID_ARG;   /* scaffold: no readback path yet */
}

void vmi_decode_ept_violation(VCPU *vcpu, EPT_VIOLATION_INFO *out)
{
    /* TODO(hv): read VMCS_EXIT_QUALIFICATION + VMCS_GUEST_PHYSICAL_ADDRESS +
     *           VMCS_GUEST_LINEAR_ADDRESS and unpack per SDM Vol 3C §29.3.3.1
     *           (bit 0=R, 1=W, 2=X, 3..5=perms present, 7=GLA valid). */
    UNREFERENCED_PARAMETER(vcpu);
    if (out) RtlZeroMemory(out, sizeof(*out));
}

int vmi_on_ept_violation(VCPU *vcpu, const EPT_VIOLATION_INFO *info)
{
    UNREFERENCED_PARAMETER(vcpu);
    UNREFERENCED_PARAMETER(info);
    /* Scaffold: continue. HV_VMI_ACTION values live in hv.h; 0 means continue. */
    return 0;
}

int vmi_on_page_fault(VCPU *vcpu, u64 gpa, u32 kind)
{
    UNREFERENCED_PARAMETER(vcpu);
    UNREFERENCED_PARAMETER(gpa);
    UNREFERENCED_PARAMETER(kind);
    return 0;
}

/* ------------------------------------------------------------------------ */
/*  Fatal-path stubs referenced by asm_x64.asm                              */
/* ------------------------------------------------------------------------ */

DECLSPEC_NORETURN
void hv_vmexit_finish_unload(GUEST_REGISTERS *regs)
{
    /* Called from the assembly VM-exit dispatcher when the guest issued a
     * "please devirtualize me" VMCALL/VMMCALL. Real body must restore the
     * pre-launch context and return to it un-virtualized. Scaffold halts:
     * a real unload is a Phase-5 workitem (BRINGUP.md). */
    UNREFERENCED_PARAMETER(regs);
    for (;;) { __halt(); }
}

DECLSPEC_NORETURN
void hv_vmx_failure(u64 rflags)
{
    /* VMLAUNCH failed or the assembly dispatcher's fall-through was hit.
     * Bugcheck cleanly so a WinDbg-attached VM captures the RFLAGS + the
     * VM-instruction error in VMCS_RO_VM_INSTRUCTION_ERROR. */
    KeBugCheckEx(0xE1u,                /* WORKER_THREAD_RETURNED_AT_BAD_IRQL — placeholder */
                 (ULONG_PTR)rflags,
                 (ULONG_PTR)0,
                 (ULONG_PTR)0,
                 (ULONG_PTR)0);
}
