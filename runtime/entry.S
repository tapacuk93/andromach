// Entry from a precompiled svc stub, and the full-context resume.
//
// A stub reaches am_syscall_entry with `blr x16`, after pushing the guest's x16 and x30:
//     [sp] = guest x16, [sp + 8] = guest x30, x30 = the stub's `ldp` that pops them.
// Linux preserves every register except x0 across a system call, vectors and flags included,
// so all of them are saved into an am_ctx on the guest stack and restored from it.

#define FRAME 800

    .text
    .p2align 4
    .globl _am_syscall_entry
_am_syscall_entry:
    sub sp, sp, #FRAME
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x17, x18, [sp, #136]
    stp x19, x20, [sp, #152]
    stp x21, x22, [sp, #168]
    stp x23, x24, [sp, #184]
    stp x25, x26, [sp, #200]
    stp x27, x28, [sp, #216]
    str x29, [sp, #232]
    add x11, sp, #FRAME
    ldp x9, x10, [x11]              // the guest's x16 and x30, pushed by the stub
    str x9, [sp, #128]
    str x10, [sp, #240]
    add x9, sp, #(FRAME + 16)       // guest sp once the stub has popped them
    str x9, [sp, #248]
    add x9, x30, #4                 // resume point: the stub's final `b back`
    str x9, [sp, #256]
    mrs x9, nzcv
    str x9, [sp, #264]
    add x9, sp, #272
    stp q0, q1, [x9, #0]
    stp q2, q3, [x9, #32]
    stp q4, q5, [x9, #64]
    stp q6, q7, [x9, #96]
    stp q8, q9, [x9, #128]
    stp q10, q11, [x9, #160]
    stp q12, q13, [x9, #192]
    stp q14, q15, [x9, #224]
    stp q16, q17, [x9, #256]
    stp q18, q19, [x9, #288]
    stp q20, q21, [x9, #320]
    stp q22, q23, [x9, #352]
    stp q24, q25, [x9, #384]
    stp q26, q27, [x9, #416]
    stp q28, q29, [x9, #448]
    stp q30, q31, [x9, #480]
    mrs x10, fpsr
    mrs x11, fpcr
    add x9, sp, #784
    stp w10, w11, [x9]

    // The runtime runs on the thread's host stack, never the guest's: guest stacks can be
    // small (bionic's 16 KiB signal stacks) and the runtime's frames are not.
    mov x19, sp
    mrs x9, tpidrro_el0
    ldr x9, [x9, #(112 * 8)]
    mov sp, x9
    mov x0, x19
    mov x1, #0                      // from a stub, not the trap handler
    bl _am_syscall
    mov sp, x19

    add x9, sp, #272
    ldp q0, q1, [x9, #0]
    ldp q2, q3, [x9, #32]
    ldp q4, q5, [x9, #64]
    ldp q6, q7, [x9, #96]
    ldp q8, q9, [x9, #128]
    ldp q10, q11, [x9, #160]
    ldp q12, q13, [x9, #192]
    ldp q14, q15, [x9, #224]
    ldp q16, q17, [x9, #256]
    ldp q18, q19, [x9, #288]
    ldp q20, q21, [x9, #320]
    ldp q22, q23, [x9, #352]
    ldp q24, q25, [x9, #384]
    ldp q26, q27, [x9, #416]
    ldp q28, q29, [x9, #448]
    ldp q30, q31, [x9, #480]
    add x9, sp, #784
    ldp w10, w11, [x9]
    msr fpsr, x10
    msr fpcr, x11
    ldr x9, [sp, #264]
    msr nzcv, x9
    ldr x30, [sp, #256]
    sub x30, x30, #4                // back to the stub's `ldp`
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x17, x18, [sp, #136]
    ldp x19, x20, [sp, #152]
    ldp x21, x22, [sp, #168]
    ldp x23, x24, [sp, #184]
    ldp x25, x26, [sp, #200]
    ldp x27, x28, [sp, #216]
    ldr x29, [sp, #232]
    add sp, sp, #FRAME
    ret

// am_call_on_host_stack(fn, arg): fn(arg) on the thread's host stack, then back.
    .p2align 4
    .globl _am_call_on_host_stack
_am_call_on_host_stack:
    stp x19, x30, [sp, #-16]!
    mov x19, sp
    mrs x9, tpidrro_el0
    ldr x9, [x9, #(112 * 8)]
    mov sp, x9
    mov x9, x0
    mov x0, x1
    blr x9
    mov sp, x19
    ldp x19, x30, [sp], #16
    ret

// am_resume(const am_ctx *): install a complete register state (new thread, signal delivery,
// rt_sigreturn). Only the kernel can set every register and pc at once, so this traps and the
// SIGTRAP handler copies the context into the signal frame it returns through.
    .p2align 4
    .globl _am_resume
_am_resume:
    brk #0xA5FF
    b _am_resume

// Where a guest signal handler returns when it has no SA_RESTORER: arm64 Linux has the
// equivalent in the vDSO, which andromach does not provide.
    .p2align 4
    .globl _am_sigreturn_trampoline
_am_sigreturn_trampoline:
    mov x8, #139                    // rt_sigreturn
    brk #0xA500                     // AM_TRAP_SVC
    b _am_sigreturn_trampoline
