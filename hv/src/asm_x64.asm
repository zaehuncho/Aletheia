;  ============================================================================================
;  asm_x64.asm -- MASM x64 privileged-instruction wrappers, the VM-exit trampoline, and the
;  bring-up context capture/restore for the Aletheia clean-room VT-x/EPT VMI hypervisor.
;
;  CLEAN-ROOM PROVENANCE: written from the public Intel(R) SDM Vol 3C (VMX instruction
;  reference: VMXON/VMXOFF/VMCLEAR/VMPTRLD/VMREAD/VMWRITE/VMLAUNCH/VMRESUME/INVEPT/INVVPID;
;  VMfail semantics in 31.2) and Vol 3A (SGDT/SIDT/STR/SLDT/LAR/LSL). No proprietary source
;  consulted. Only what genuinely cannot be emitted by an MSVC intrinsic lives here: the VM-exit
;  entry stub (VMCS_HOST_RIP target), the launch-context capture/restore, the segment/table
;  descriptor reads, and thin VMX-instruction wrappers that surface the three-way VMfail result
;  the C code's VMX_RESULT enum expects.
;
;  Windows x64 ABI: integer args in RCX, RDX, R8, R9; result in RAX/EAX; caller reserves 32 bytes
;  of shadow space; RSP is 16-byte aligned at the point of a CALL (so RSP%16==8 at callee entry);
;  RBX, RBP, RDI, RSI, RSP, R12-R15 are non-volatile. The __stdcall on the C prototypes is
;  ignored in x64 -- every symbol below is undecorated and uses the single x64 convention.
;
;  CANNOT BE ASSEMBLED/LINKED/RUN IN THIS ENVIRONMENT. Every assumption/unfinished spot is
;  marked "; TODO(hv):". A wrong field or a mis-decoded flag hangs the machine; correctness
;  against the SDM is the whole game.
;
;  NOTE on constants: MASM cannot see the C headers, so the struct byte-offsets below are
;  EQUated to mirror GUEST_REGISTERS (hv.h) and HV_LAUNCH_CONTEXT (hv.h). If either C struct
;  changes, these EQUs MUST change in lockstep. The VMX_RESULT return codes mirror the
;  VMX_RESULT enum in hv.h (VMX_SUCCEED=0, VMX_FAIL_VALID=1, VMX_FAIL_INVALID=2).
;  ============================================================================================

OPTION CASEMAP:NONE                     ; preserve case of C symbol names (case-sensitive linkage).

; -------- GUEST_REGISTERS byte offsets (must mirror hv.h; C_ASSERT pins its size at 16*8). -----
GR_RAX          EQU 000h
GR_RCX          EQU 008h
GR_RDX          EQU 010h
GR_RBX          EQU 018h
GR_RSP_DUMMY    EQU 020h                ; placeholder slot; guest RSP truly comes from the VMCS.
GR_RBP          EQU 028h
GR_RSI          EQU 030h
GR_RDI          EQU 038h
GR_R8           EQU 040h
GR_R9           EQU 048h
GR_R10          EQU 050h
GR_R11          EQU 058h
GR_R12          EQU 060h
GR_R13          EQU 068h
GR_R14          EQU 070h
GR_R15          EQU 078h
GR_SIZE         EQU 080h                ; sizeof(GUEST_REGISTERS) == 128.

; -------- HV_LAUNCH_CONTEXT byte offsets (must mirror hv.h; C_ASSERT pins its size at 18*8). ----
LC_RAX          EQU 000h
LC_RCX          EQU 008h
LC_RDX          EQU 010h
LC_RBX          EQU 018h
LC_RSP          EQU 020h
LC_RBP          EQU 028h
LC_RSI          EQU 030h
LC_RDI          EQU 038h
LC_R8           EQU 040h
LC_R9           EQU 048h
LC_R10          EQU 050h
LC_R11          EQU 058h
LC_R12          EQU 060h
LC_R13          EQU 068h
LC_R14          EQU 070h
LC_R15          EQU 078h
LC_RFLAGS       EQU 080h
LC_RIP          EQU 088h
LC_SIZE         EQU 090h                ; sizeof(HV_LAUNCH_CONTEXT) == 144.

SHADOW_SPACE    EQU 020h                ; 32-byte register-parameter home area (x64 ABI).

; -------- C functions this module transfers control to (all undecorated on x64). --------------
EXTERN hv_vmexit_dispatch:PROC          ; int  hv_vmexit_dispatch(GUEST_REGISTERS *regs)
EXTERN hv_vmexit_finish_unload:PROC     ; DECLSPEC_NORETURN void hv_vmexit_finish_unload(regs)
EXTERN hv_vmx_failure:PROC              ; DECLSPEC_NORETURN void hv_vmx_failure(u64 rflags)

; =============================================================================================
;  VMX_RESULT_DECODE -- turn the CPU's post-VMX-instruction flags into the VMX_RESULT enum.
;  SDM Vol 3C 31.2: VMsucceed (CF=0,ZF=0) => 0; VMfailInvalid (CF=1) => 2 (no current VMCS);
;  VMfailValid (ZF=1) => 1 (error number in VMCS_RO_VM_INSTRUCTION_ERROR). Emits the RET.
;  IMPORTANT: only flag-preserving instructions (MOV/POP/PUSH) may sit between the VMX
;  instruction and this macro. ADD/SUB/LEA-to-flags must not.
; =============================================================================================
VMX_RESULT_DECODE MACRO
    LOCAL vfail_valid, vfail_invalid, vdone
    jc      vfail_invalid               ; CF=1 -> VMfailInvalid.
    jz      vfail_valid                 ; ZF=1 -> VMfailValid.
    xor     eax, eax                    ; VMX_SUCCEED (0).
    jmp     vdone
vfail_valid:
    mov     eax, 1                      ; VMX_FAIL_VALID.
    jmp     vdone
vfail_invalid:
    mov     eax, 2                      ; VMX_FAIL_INVALID.
vdone:
    ret
ENDM

.code

; =============================================================================================
;  Thin VMX-instruction wrappers. Each returns VMX_RESULT in EAX.
;
;  RATIONALE: MSVC exposes __vmx_on/__vmx_vmclear/__vmx_vmptrld/__vmx_vmread/__vmx_vmwrite/
;  __vmx_vmlaunch/__vmx_vmresume/__vmx_off/__invept/__invvpid. They are, however, shaped for a
;  0/1/2 return and (for vmread) a size_t* out-param; the hv.h prototypes fix an exact __stdcall
;  signature returning VMX_RESULT. Implementing them here makes the ABI match byte-for-byte and
;  keeps the three-way VMfail decode in one audited place, at the cost of a tiny call.
;  TODO(hv): if the C side would rather use the intrinsics directly, delete these and drop the
;  matching prototypes from hv.h -- they are pure convenience, not load-bearing.
; =============================================================================================

; VMX_RESULT asm_vmxon(u64 vmxon_region_pa)  -- RCX = physical address of the 4KB VMXON region.
asm_vmxon PROC
    push    rcx                         ; VMXON takes an m64 operand holding the region PA.
    vmxon   qword ptr [rsp]
    pop     rcx                         ; POP does not disturb the VMX result flags.
    VMX_RESULT_DECODE
asm_vmxon ENDP

; VMX_RESULT asm_vmxoff(void)
asm_vmxoff PROC
    vmxoff
    VMX_RESULT_DECODE
asm_vmxoff ENDP

; VMX_RESULT asm_vmclear(u64 vmcs_pa)  -- RCX = physical address of the VMCS region.
asm_vmclear PROC
    push    rcx
    vmclear qword ptr [rsp]
    pop     rcx
    VMX_RESULT_DECODE
asm_vmclear ENDP

; VMX_RESULT asm_vmptrld(u64 vmcs_pa)  -- RCX = physical address of the VMCS region.
asm_vmptrld PROC
    push    rcx
    vmptrld qword ptr [rsp]
    pop     rcx
    VMX_RESULT_DECODE
asm_vmptrld ENDP

; VMX_RESULT asm_vmread(u64 field, u64 *out_value)  -- RCX = field encoding, RDX = out pointer.
;  SDM: VMREAD r/m64, r64  (destination first = where the value lands; source = the field in a
;  register). We read into RAX, store through RDX (MOV preserves flags), then decode.
asm_vmread PROC
    vmread  rax, rcx                    ; RAX <- VMCS[field=RCX]; sets VMfail flags.
    mov     qword ptr [rdx], rax        ; MOV does not affect flags.
    VMX_RESULT_DECODE
asm_vmread ENDP

; VMX_RESULT asm_vmwrite(u64 field, u64 value)  -- RCX = field encoding, RDX = value.
;  SDM: VMWRITE r64, r/m64  (destination first = the field register; source = the value).
asm_vmwrite PROC
    vmwrite rcx, rdx                    ; VMCS[field=RCX] <- RDX.
    VMX_RESULT_DECODE
asm_vmwrite ENDP

; VMX_RESULT asm_vmlaunch(void)  -- on VMsucceed control enters the guest and never returns here;
;  a return means VMfail, which the decode reports.
asm_vmlaunch PROC
    vmlaunch
    VMX_RESULT_DECODE
asm_vmlaunch ENDP

; VMX_RESULT asm_vmresume(void)  -- same non-returning-on-success contract as VMLAUNCH.
asm_vmresume PROC
    vmresume
    VMX_RESULT_DECODE
asm_vmresume ENDP

; VMX_RESULT asm_invept(u64 type, INVEPT_DESCRIPTOR *desc)  -- RCX = type, RDX = 16-byte desc.
;  SDM: INVEPT r64, m128.  TODO(hv): if the target ml64 predates INVEPT/INVVPID mnemonics,
;  replace with the encoded bytes (66 0F 38 80 /r for INVEPT, ...81 /r for INVVPID).
asm_invept PROC
    invept  rcx, xmmword ptr [rdx]
    VMX_RESULT_DECODE
asm_invept ENDP

; VMX_RESULT asm_invvpid(u64 type, INVVPID_DESCRIPTOR *desc)  -- RCX = type, RDX = 16-byte desc.
;  SDM: INVVPID r64, m128.
asm_invvpid PROC
    invvpid rcx, xmmword ptr [rdx]
    VMX_RESULT_DECODE
asm_invvpid ENDP

; =============================================================================================
;  Segment / descriptor-table reads. No MSVC intrinsic exposes these as data, so they must be
;  asm. Selectors are zero-extended into EAX (return type u16). LAR/LSL return 0 on an invalid
;  selector (ZF=0); vmcs.c then sets the "unusable" access-rights bit for that segment.
; =============================================================================================
asm_read_cs PROC
    mov     ax, cs
    movzx   eax, ax
    ret
asm_read_cs ENDP

asm_read_ss PROC
    mov     ax, ss
    movzx   eax, ax
    ret
asm_read_ss ENDP

asm_read_ds PROC
    mov     ax, ds
    movzx   eax, ax
    ret
asm_read_ds ENDP

asm_read_es PROC
    mov     ax, es
    movzx   eax, ax
    ret
asm_read_es ENDP

asm_read_fs PROC
    mov     ax, fs
    movzx   eax, ax
    ret
asm_read_fs ENDP

asm_read_gs PROC
    mov     ax, gs
    movzx   eax, ax
    ret
asm_read_gs ENDP

; u16 asm_read_tr(void)  -- Task Register selector.
asm_read_tr PROC
    str     ax
    movzx   eax, ax
    ret
asm_read_tr ENDP

; u16 asm_read_ldtr(void)  -- LDT selector.
asm_read_ldtr PROC
    sldt    ax
    movzx   eax, ax
    ret
asm_read_ldtr ENDP

; void asm_read_gdtr(PSEUDO_DESCRIPTOR_64 *out)  -- RCX = out. SGDT stores 10 bytes (limit:base).
asm_read_gdtr PROC
    sgdt    [rcx]                        ; 64-bit SGDT implies a 10-byte m16&64 store.
    ret
asm_read_gdtr ENDP

; void asm_read_idtr(PSEUDO_DESCRIPTOR_64 *out)  -- RCX = out. SIDT stores 10 bytes.
asm_read_idtr PROC
    sidt    [rcx]
    ret
asm_read_idtr ENDP

; u32 asm_read_seg_access_rights(u16 selector)  -- RCX(low16) = selector; returns LAR bits or 0.
asm_read_seg_access_rights PROC
    movzx   ecx, cx                     ; LAR uses the low 16 bits as the selector.
    lar     eax, ecx                    ; ZF=1 on success.
    jz      sar_ok
    xor     eax, eax                    ; invalid/inaccessible selector -> 0.
sar_ok:
    ret
asm_read_seg_access_rights ENDP

; u32 asm_read_seg_limit(u16 selector)  -- RCX(low16) = selector; returns the LSL limit or 0.
asm_read_seg_limit PROC
    movzx   ecx, cx
    lsl     eax, ecx                    ; ZF=1 on success.
    jz      lsl_ok
    xor     eax, eax
lsl_ok:
    ret
asm_read_seg_limit ENDP

; u64 asm_read_rflags(void)
asm_read_rflags PROC
    pushfq
    pop     rax
    ret
asm_read_rflags ENDP

; =============================================================================================
;  asm_capture_context / asm_restore_context -- the SimpleVisor-style bring-up snapshot.
;
;  asm_capture_context(HV_LAUNCH_CONTEXT *ctx)  [RCX = ctx]
;    Records the CALLER's register file, RFLAGS, RSP (as it was before the call, i.e. rsp+8), and
;    RIP (the return address). Returns 0 on this direct/"setup" pass. When the guest is later
;    launched with VMCS_GUEST_RIP=ctx.rip / RSP=ctx.rsp / RFLAGS=ctx.rflags, it re-enters exactly
;    at that return site; the launch glue (driver.c) arranges guest RAX=1 for that pass, so the
;    caller sees a second "return" of 1. VMCS carries no RAX, hence the glue -- not this routine
;    -- sets the discriminator. TODO(hv): confirm we keep this model vs. a dedicated guest stub.
;    TODO(hv): XMM/segment/CR state are NOT captured; guest inherits the live host values at
;    VMLAUNCH, which is correct only because we launch the same context we captured on this CPU.
;    TODO(hv): no .pdata/.xdata unwind info is emitted; add function tables before a build.
; =============================================================================================
asm_capture_context PROC
    mov     qword ptr [rcx + LC_RAX], rax
    mov     qword ptr [rcx + LC_RCX], rcx        ; stores the ctx pointer value; harmless (volatile).
    mov     qword ptr [rcx + LC_RDX], rdx
    mov     qword ptr [rcx + LC_RBX], rbx
    mov     qword ptr [rcx + LC_RBP], rbp
    mov     qword ptr [rcx + LC_RSI], rsi
    mov     qword ptr [rcx + LC_RDI], rdi
    mov     qword ptr [rcx + LC_R8],  r8
    mov     qword ptr [rcx + LC_R9],  r9
    mov     qword ptr [rcx + LC_R10], r10
    mov     qword ptr [rcx + LC_R11], r11
    mov     qword ptr [rcx + LC_R12], r12
    mov     qword ptr [rcx + LC_R13], r13
    mov     qword ptr [rcx + LC_R14], r14
    mov     qword ptr [rcx + LC_R15], r15

    lea     rax, [rsp + 8]                        ; caller RSP = current RSP after popping ret addr.
    mov     qword ptr [rcx + LC_RSP], rax
    mov     rax, qword ptr [rsp]                  ; return address == where the guest resumes.
    mov     qword ptr [rcx + LC_RIP], rax

    pushfq
    pop     rax
    mov     qword ptr [rcx + LC_RFLAGS], rax

    xor     eax, eax                             ; return 0 on the setup pass.
    ret
asm_capture_context ENDP

; =============================================================================================
;  asm_restore_context(HV_LAUNCH_CONTEXT *ctx)  [RCX = ctx]
;    Reloads every GPR + RFLAGS and transfers control to ctx.rip with RSP = ctx.rsp. Does NOT
;    return. This is a non-VMX resume of a captured point (e.g. a bring-up abort path). The
;    landing return address is planted at (ctx.rsp - 8) so a final RET both jumps to ctx.rip and
;    leaves RSP == ctx.rsp. That 8-byte slot is the dead return-address slot of the original
;    capture-call frame, so overwriting it is safe.
; =============================================================================================
asm_restore_context PROC
    mov     rax, rcx                             ; RAX = ctx base (kept live until the very end).

    push    qword ptr [rax + LC_RFLAGS]          ; restore RFLAGS on the current stack first.
    popfq

    mov     rdx, qword ptr [rax + LC_RSP]        ; plant ctx.rip at ctx.rsp-8 for the final RET.
    lea     r10, [rdx - 8]
    mov     r11, qword ptr [rax + LC_RIP]
    mov     qword ptr [r10], r11

    mov     rbx, qword ptr [rax + LC_RBX]
    mov     rbp, qword ptr [rax + LC_RBP]
    mov     rsi, qword ptr [rax + LC_RSI]
    mov     rdi, qword ptr [rax + LC_RDI]
    mov     r8,  qword ptr [rax + LC_R8]
    mov     r9,  qword ptr [rax + LC_R9]
    mov     r12, qword ptr [rax + LC_R12]
    mov     r13, qword ptr [rax + LC_R13]
    mov     r14, qword ptr [rax + LC_R14]
    mov     r15, qword ptr [rax + LC_R15]
    mov     rcx, qword ptr [rax + LC_RCX]
    mov     rdx, qword ptr [rax + LC_RDX]
    mov     r10, qword ptr [rax + LC_R10]        ; overwrite the scratch use with the guest r10.
    mov     r11, qword ptr [rax + LC_R11]

    mov     rsp, qword ptr [rax + LC_RSP]        ; switch to ctx.rsp, ...
    sub     rsp, 8                               ; ... then to the planted-RIP slot.
    mov     rax, qword ptr [rax + LC_RAX]        ; last use of the ctx base: restore RAX.
    ret                                          ; pops ctx.rip; RSP becomes ctx.rsp.
asm_restore_context ENDP

; =============================================================================================
;  asm_vmexit_entry -- the VMCS_HOST_RIP target. Never called from C.
;
;  On VM-exit the CPU has loaded RSP = VMCS_HOST_RSP (top of this VCPU's host stack, which the
;  driver MUST program 16-byte aligned) and RIP = here, with RFLAGS reset (IF=0) so we run with
;  interrupts masked in VMX root. Every GPR except RSP still holds the guest value; guest RSP/RIP/
;  RFLAGS live in the VMCS and are read by the dispatcher via VMREAD.
;
;  Sequence: build GUEST_REGISTERS on the host stack (matching hv.h field order), pass &regs to
;  hv_vmexit_dispatch(), then on a nonzero return restore the (possibly edited) GPRs and VMRESUME.
;  A zero return means "guest asked to unload" -> hand &regs to hv_vmexit_finish_unload(), which
;  devirtualizes this CPU and never comes back. A VMRESUME that falls through has failed -> report.
; =============================================================================================
asm_vmexit_entry PROC
    ; ---- Save guest GPRs, highest struct offset first, so RAX lands at the lowest address and
    ; ---- RSP ends up pointing at &regs (== &regs.rax). Field order mirrors GUEST_REGISTERS. ----
    push    r15                                  ; GR_R15  (0x78)
    push    r14                                  ; GR_R14  (0x70)
    push    r13                                  ; GR_R13  (0x68)
    push    r12                                  ; GR_R12  (0x60)
    push    r11                                  ; GR_R11  (0x58)
    push    r10                                  ; GR_R10  (0x50)
    push    r9                                   ; GR_R9   (0x48)
    push    r8                                   ; GR_R8   (0x40)
    push    rdi                                  ; GR_RDI  (0x38)
    push    rsi                                  ; GR_RSI  (0x30)
    push    rbp                                  ; GR_RBP  (0x28)
    push    rax                                  ; GR_RSP_DUMMY (0x20) -- filler; VMCS holds RSP.
    push    rbx                                  ; GR_RBX  (0x18)
    push    rdx                                  ; GR_RDX  (0x10)
    push    rcx                                  ; GR_RCX  (0x08)
    push    rax                                  ; GR_RAX  (0x00)  -> RSP now == &regs.

    mov     rcx, rsp                             ; arg0 = GUEST_REGISTERS *regs.
    sub     rsp, SHADOW_SPACE                    ; ABI home area; RSP stays 16-aligned pre-CALL
                                                 ; (host_rsp 16-aligned + 0x80 pushes + 0x20).
    call    hv_vmexit_dispatch                   ; int result in EAX.
    add     rsp, SHADOW_SPACE                    ; RSP back to &regs.

    test    eax, eax
    jz      vmexit_unload                        ; 0 -> orderly teardown of this VCPU.

    ; ---- Resume path: restore GPRs from the (possibly edited) struct, then VMRESUME. ----
    pop     rax                                  ; GR_RAX
    pop     rcx                                  ; GR_RCX
    pop     rdx                                  ; GR_RDX
    pop     rbx                                  ; GR_RBX
    add     rsp, 8                               ; skip GR_RSP_DUMMY (guest RSP is in the VMCS).
    pop     rbp                                  ; GR_RBP
    pop     rsi                                  ; GR_RSI
    pop     rdi                                  ; GR_RDI
    pop     r8                                   ; GR_R8
    pop     r9                                   ; GR_R9
    pop     r10                                  ; GR_R10
    pop     r11                                  ; GR_R11
    pop     r12                                  ; GR_R12
    pop     r13                                  ; GR_R13
    pop     r14                                  ; GR_R14
    pop     r15                                  ; GR_R15  -> RSP back to VMCS_HOST_RSP.

    vmresume                                     ; on success, control re-enters the guest.
    ; ---- Fall-through only on VMfail: capture RFLAGS and report; hv_vmx_failure never returns. --
    pushfq
    pop     rcx                                  ; arg0 = post-VMRESUME RFLAGS.
    sub     rsp, SHADOW_SPACE
    call    hv_vmx_failure
    int     3                                    ; unreachable guard if the handler ever returns.

vmexit_unload:
    ; RSP == &regs. Pass it to the unload continuation, which reads this CPU's cached guest
    ; RIP/RSP/RFLAGS and tail-calls asm_devirtualize_and_resume(); it does not return.
    mov     rcx, rsp                             ; arg0 = GUEST_REGISTERS *regs (above the shadow).
    sub     rsp, SHADOW_SPACE
    call    hv_vmexit_finish_unload
    int     3                                    ; unreachable guard.
asm_vmexit_entry ENDP

; =============================================================================================
;  asm_devirtualize_and_resume(u64 guest_rip, u64 guest_rsp, u64 guest_rflags,
;                              GUEST_REGISTERS *regs)   [RCX, RDX, R8, R9]
;    Leaves VMX root (VMXOFF) and resumes the guest natively at guest_rip on guest_rsp with the
;    saved GPRs and RFLAGS -- the orderly per-VCPU unload. Never returns.
;
;    guest_rip is planted at guest_rsp-8 so a final RET jumps there and leaves RSP == guest_rsp.
;    guest_rsp-8 is the dead return-address slot of the frame that faulted, so it is safe to use.
;    The landing RSP survives the GPR reload by being stashed into regs->rsp_dummy (offset 0x20),
;    a slot the resume path never consumes.
; =============================================================================================
asm_devirtualize_and_resume PROC
    vmxoff                                       ; exit VMX root operation.
    ; TODO(hv): on VMfail (CF/ZF set) VMXOFF did not leave root; bugcheck instead of proceeding.
    ; CR4.VMXE is cleared separately by vmx_disable_on_cpu().

    push    r8                                   ; restore guest RFLAGS on the current stack...
    popfq                                        ; ...while we still own it (before the switch).

    lea     r10, [rdx - 8]                       ; landing RSP = guest_rsp - 8.
    mov     qword ptr [r10], rcx                 ; plant guest_rip at the landing slot.
    mov     qword ptr [r9 + GR_RSP_DUMMY], r10   ; stash landing RSP where the reload won't touch.

    mov     rax, qword ptr [r9 + GR_RAX]
    mov     rcx, qword ptr [r9 + GR_RCX]
    mov     rdx, qword ptr [r9 + GR_RDX]
    mov     rbx, qword ptr [r9 + GR_RBX]
    mov     rbp, qword ptr [r9 + GR_RBP]
    mov     rsi, qword ptr [r9 + GR_RSI]
    mov     rdi, qword ptr [r9 + GR_RDI]
    mov     r8,  qword ptr [r9 + GR_R8]
    mov     r11, qword ptr [r9 + GR_R11]
    mov     r12, qword ptr [r9 + GR_R12]
    mov     r13, qword ptr [r9 + GR_R13]
    mov     r14, qword ptr [r9 + GR_R14]
    mov     r15, qword ptr [r9 + GR_R15]
    mov     r10, qword ptr [r9 + GR_R10]         ; overwrite the scratch use with the guest r10.
    mov     rsp, qword ptr [r9 + GR_RSP_DUMMY]   ; switch to the landing RSP (planted RIP at top).
    mov     r9,  qword ptr [r9 + GR_R9]          ; last use of R9 as the struct base.
    ret                                          ; pops guest_rip; RSP becomes guest_rsp.
asm_devirtualize_and_resume ENDP

; ========================================================================================
;  AMD SVM MASM block. Peer of the VMX block above. Written from AMD APM Vol 2:
;    VMRUN / VM-exit sequence      §15.6
;    VMSAVE / VMLOAD               §15.30.3
;    CLGI / STGI (GIF gate)        §15.17
;    INVLPGA                       §15.16
;    VMMCALL (hypercall)           §15.30.2
;
;  Windows x64 calling convention (RCX/RDX/R8/R9 for the first four args, RAX for return).
;  All wrappers preserve the nonvolatile GPRs Windows requires (RBX/RBP/RSI/RDI/R12-R15).
;
;  KEY BEHAVIOUR OF VMRUN. Unlike VMX (where a VM-exit jumps to VMCS_HOST_RIP), VMRUN is a
;  subroutine: hardware saves host state to the region programmed in MSR_VM_HSAVE_PA, loads
;  guest state from the VMCB, executes the guest, and on VM-exit auto-restores the host
;  state and returns to the instruction after VMRUN. Guest GPRs OTHER THAN RAX (which is
;  auto-saved into VMCB.state_save.rax) are LEFT IN THE CPU registers on exit -- the host
;  must save them itself. That is what asm_svm_run does.
; ========================================================================================

; ---------------------------------------------------------------------------------------
;  asm_svm_run(u64 vmcb_pa, GUEST_REGISTERS *regs) -> SVM_RESULT
;    RCX = vmcb_pa, RDX = regs
;    Load guest GPRs from *regs, run one VMRUN, save guest GPRs back to *regs, return
;    SVM_SUCCEED (0) in EAX. Loop is on the C side (svm_launch).
; ---------------------------------------------------------------------------------------
asm_svm_run PROC
    ; Save nonvolatile host GPRs.
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15

    ; Save the regs pointer on the host stack; we will need it after VMRUN. The push order
    ; matters -- see the pop-order comments after VMRUN.
    push    rdx                                  ; [rsp] = regs

    mov     rax, rcx                             ; RAX = vmcb_pa (VMRUN input)
    ; RDX still holds the regs pointer for one more load.
    mov     rbx, qword ptr [rdx + GR_RBX]
    mov     rcx, qword ptr [rdx + GR_RCX]
    mov     rbp, qword ptr [rdx + GR_RBP]
    mov     rsi, qword ptr [rdx + GR_RSI]
    mov     rdi, qword ptr [rdx + GR_RDI]
    mov     r8,  qword ptr [rdx + GR_R8]
    mov     r9,  qword ptr [rdx + GR_R9]
    mov     r10, qword ptr [rdx + GR_R10]
    mov     r11, qword ptr [rdx + GR_R11]
    mov     r12, qword ptr [rdx + GR_R12]
    mov     r13, qword ptr [rdx + GR_R13]
    mov     r14, qword ptr [rdx + GR_R14]
    mov     r15, qword ptr [rdx + GR_R15]
    mov     rdx, qword ptr [rdx + GR_RDX]        ; last use of the regs ptr in RDX

    clgi                                         ; APM: block virtual & physical interrupts
    DB 0Fh, 01h, 0D8h                            ; vmrun rax (SVM, APM §15.6)
    stgi                                         ; re-enable interrupts

    ; RSP has been restored to the host RSP (from HSAVE), so [rsp] is once again the
    ; pushed regs pointer. Recover it into a register that can be reused. We stash the
    ; guest RAX (currently in CPU RAX -- which VMRUN also auto-saved into VMCB.rax) via
    ; a push, then load RAX = regs pointer.
    push    rax                                  ; guest RAX at [rsp]; regs ptr at [rsp+8]
    mov     rax, qword ptr [rsp + 8]             ; RAX = regs ptr

    mov     qword ptr [rax + GR_RBX], rbx
    mov     qword ptr [rax + GR_RCX], rcx
    mov     qword ptr [rax + GR_RDX], rdx
    mov     qword ptr [rax + GR_RBP], rbp
    mov     qword ptr [rax + GR_RSI], rsi
    mov     qword ptr [rax + GR_RDI], rdi
    mov     qword ptr [rax + GR_R8],  r8
    mov     qword ptr [rax + GR_R9],  r9
    mov     qword ptr [rax + GR_R10], r10
    mov     qword ptr [rax + GR_R11], r11
    mov     qword ptr [rax + GR_R12], r12
    mov     qword ptr [rax + GR_R13], r13
    mov     qword ptr [rax + GR_R14], r14
    mov     qword ptr [rax + GR_R15], r15
    pop     rcx                                  ; RCX = guest RAX
    mov     qword ptr [rax + GR_RAX], rcx
    pop     rcx                                  ; discard the pushed regs pointer

    ; Restore nonvolatile host GPRs.
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx

    xor     eax, eax                             ; SVM_SUCCEED == 0
    ret
asm_svm_run ENDP

; ---------------------------------------------------------------------------------------
;  asm_vmsave(u64 vmcb_pa)  -- copy specific host MSRs / segment bases into a VMCB region.
;  asm_vmload(u64 vmcb_pa)  -- reverse.
;  Both take a physical address in RAX. Windows ABI: arg in RCX. See APM §15.30.3.
; ---------------------------------------------------------------------------------------
asm_vmsave PROC
    mov     rax, rcx
    DB 0Fh, 01h, 0DBh                            ; vmsave rax (SVM)
    ret
asm_vmsave ENDP

asm_vmload PROC
    mov     rax, rcx
    DB 0Fh, 01h, 0DAh                            ; vmload rax (SVM)
    ret
asm_vmload ENDP

; ---------------------------------------------------------------------------------------
;  asm_clgi()  /  asm_stgi()  -- Global-Interrupt-Flag gate (APM §15.17).
;  CLGI closes the GIF (blocks virtual and physical interrupts); STGI reopens it.
;  Only meaningful when SVM is enabled. No arguments, no return value.
; ---------------------------------------------------------------------------------------
asm_clgi PROC
    clgi
    ret
asm_clgi ENDP

asm_stgi PROC
    stgi
    ret
asm_stgi ENDP

; ---------------------------------------------------------------------------------------
;  asm_invlpga(u64 va, u32 asid)  -- invalidate one TLB entry for a given ASID.
;    APM §15.16: INVLPGA takes the virtual address in RAX and the ASID in ECX.
;    Windows ABI: args in RCX (va) and RDX (asid).
; ---------------------------------------------------------------------------------------
asm_invlpga PROC
    mov     rax, rcx
    mov     ecx, edx
    DB 0Fh, 01h, 0DFh                            ; invlpga rax, ecx (SVM)
    ret
asm_invlpga ENDP

; ---------------------------------------------------------------------------------------
;  asm_vmmcall(u64 rax, u64 rcx, u64 rdx, u64 r8) -> u64
;    Reach the hypervisor from guest context. There is no MSVC intrinsic for VMMCALL.
;    Windows ABI already places these args in RCX/RDX/R8/R9; we shuffle to (RAX, RCX,
;    RDX, R8) as our HV_VMCALL_* ABI expects, execute VMMCALL, return RAX in RAX.
; ---------------------------------------------------------------------------------------
asm_vmmcall PROC
    ; incoming: RCX=arg_rax, RDX=arg_rcx, R8=arg_rdx, R9=arg_r8
    mov     rax, rcx
    mov     rcx, rdx
    mov     rdx, r8
    mov     r8,  r9
    DB      0Fh, 01h, 0D9h                       ; vmmcall (SVM); ml64 mnemonic varies
    ret                                          ; RAX carries the service's return value
asm_vmmcall ENDP

; ---------------------------------------------------------------------------------------
;  asm_vmcall(u64 rax, u64 rcx, u64 rdx, u64 r8) -> u64
;    Intel VMX peer of asm_vmmcall. driver.c uses this from the vendor-neutral
;    unload path so we don't need to test at the call site which vendor we're on;
;    the switch happens inside the HV against g_hv.vendor.
;    VMCALL = 0F 01 C1 (SDM Vol 2C).
; ---------------------------------------------------------------------------------------
asm_vmcall PROC
    mov     rax, rcx
    mov     rcx, rdx
    mov     rdx, r8
    mov     r8,  r9
    DB      0Fh, 01h, 0C1h                       ; vmcall (VMX)
    ret
asm_vmcall ENDP

; ---------------------------------------------------------------------------------------
;  asm_svm_vmexit_entry
;    Declared in hv.h for symmetry with asm_vmexit_entry (the VMX trampoline pointed at
;    by VMCS_HOST_RIP). AMD's VM-exit is a subroutine return, not a jump to a host RIP,
;    so this symbol is NEVER used at runtime. Emit an INT 3 stub so a stray call/jump to
;    it bugchecks immediately rather than silently corrupting.
; ---------------------------------------------------------------------------------------
asm_svm_vmexit_entry PROC
    int     3
    ret
asm_svm_vmexit_entry ENDP

END
