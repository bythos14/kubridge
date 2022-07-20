.arch armv7-a
.cpu cortex-a9
.fpu neon
.align 4
.syntax unified
.arm

.section .text

@ Exception safety has 3 levels: 
@ 0 - No safety measures
@ 1 - Copies to/from user space are exception safe
@ 2 - The stack pointer validity and free space is checked
#if !defined(EXCEPTION_SAFETY)
#define EXCEPTION_SAFETY 1
#endif

.global GetProcessAbortHandler
.global GetProcessExitAddr
.global CheckStackPointer
.global ksceKernelCpuSpinLockIrqSave
.global ksceKernelCpuSpinLockIrqRestore
.global ksceKernelMemcpyToUser
.global ksceKernelMemcpyFromUser

.global userAbortBase
.global defaultUserAbortHandler
.global handlersMutex

.macro CopyFromUser
#if (EXCEPTION_SAFETY >= 1)
    cps #0x13
    str lr, [sp, #-0x4]!
    bl ksceKernelMemcpyFromUser
    ldr lr, [sp], #0x4
    cps #0x17
#else
    bl memcpy
    mov r0, #0
#endif
.endm

.macro CopyToUser
#if (EXCEPTION_SAFETY >= 1)
    cps #0x13
    str lr, [sp, #-0x4]!
    bl ksceKernelMemcpyToUser
    ldr lr, [sp], #0x4
    cps #0x17
#else
    bl memcpy
    mov r0, #0
#endif
.endm

LLockSpinLock:
    str lr, [sp, #-0x4]!
    ldr r0, =handlersMutex
    bl ksceKernelCpuSpinLockIrqSave
    ldr pc, [sp], #0x4

LUnlockSpinLock:
    str lr, [sp, #-0x4]!
    mov r1, r0
    ldr r0, =handlersMutex
    bl ksceKernelCpuSpinLockIrqRestore
    ldr pc, [sp], #0x4

LFatalError:
    bl GetProcessExitAddr
    bic r2, r0, #0x1
    mov r0, #0xFFFFFFFF
    mov r1, #0x30 @ Return to user mode in thumb execution state
    str r1, [sp, #-0x4]!
    str r2, [sp, #-0x4]!
    clrex
    rfeia sp!


LReturnFromAbortHandler:
    mov r1, #0 @ Clear FSR and FAR registers
    mcr p15, #0, r1, c5, c0, #0 
    mcr p15, #0, r1, c5, c0, #1 
    mcr p15, #0, r1, c5, c1, #0 
    mcr p15, #0, r1, c5, c1, #1 
    mcr p15, #0, r1, c6, c0, #0 
    mcr p15, #0, r1, c6, c0, #2
    sub sp, #0x160 @ 0x158 for the abort context, 0x8 for the PC and SPSR 
    mov r1, r0
    mov r0, sp
    mov r2, #0x158
    CopyFromUser
    cmp r0, #0
    addne sp, #0x160
    bne LFatalError
    mov r4, sp
    ldr r0, [r4, #0x144]
    ldr r1, [r4, #0x148]
    vmsr FPSCR, r0
    vmsr FPEXC, r1
    add r0, r4, #0x40
    vldmia r0!, {d0 - d15}
    vldmia r0!, {d16 - d31}
    mov r12, r4
    ldmia r12!, {r0 - r11}
    add r12, #0x4
    ldmia r12, {sp, lr}^
    sub r12, #0x34
    add sp, #0x158
    ldr lr, [r12, #0x140]
    str lr, [sp, #0x4]
    ldr lr, [r12, #0x3C]
    str lr, [sp]
    ldr r12, [r12, #0x30]
    clrex
    rfeia sp!

LReturnFromDefaultAbortHandler:
    mov r1, #0 @ Clear FSR and FAR registers
    mcr p15, #0, r1, c5, c0, #0 
    mcr p15, #0, r1, c5, c0, #1 
    mcr p15, #0, r1, c5, c1, #0 
    mcr p15, #0, r1, c5, c1, #1 
    mcr p15, #0, r1, c6, c0, #0 
    mcr p15, #0, r1, c6, c0, #2
    sub sp, #0x160 @ 0x158 for the abort context, 8 bytes for the address of the next handler and alignment
    mov r1, r0
    mov r0, sp
    mov r2, #0x158
    CopyFromUser
    cmp r0, #0
    addne sp, #0x160
    bne LFatalError
    mov r4, sp
    ldr r2, [r4, #0x154] @ abortType
    add r5, r4, #0x14C
    ldrd r0, r1, [r5]
    cmp r2, #0 @ Set the relevant FSR and FAR
    mcreq p15, #0, r0, c5, c0, #0
    mcreq p15, #0, r1, c6, c0, #0
    mcrne p15, #0, r0, c5, c0, #1
    mcrne p15, #0, r1, c6, c0, #2
    ldreq r2, DabtExceptionHandler_lvl0 @ Branch to next exception handler
    ldrne r2, PabtExceptionHandler_lvl0
    ldr lr, [r4, #0x3C]
    addeq lr, #0x8
    addne lr, #0x4
    add r2, #8
    str r2, [sp, #0x15C]!
    ldr r0, [r4, #0x144]
    ldr r1, [r4, #0x148]
    vmsr FPSCR, r0
    vmsr FPEXC, r1
    ldr r0, [r4, #0x140]
    msr SPSR, r0
    add r0, r4, #0x40
    vldmia r0!, {d0 - d15}
    vldmia r0!, {d16 - d31}
    mov r12, r4
    ldmia r12!, {r0 - r11}
    add r12, #0x4
    ldmia r12, {sp, lr}^
    sub r12, #0x34
    ldr r12, [r12, #0x30]
    ldr pc, [sp], #0x4

LReturnToAbortHandler:
    sub sp, #0x158 @ Save abort context to stack
    stmia sp, {r0 - r12}
    add r4, sp, #0x34
    stmia r4, {sp, lr}^
    add r4, #0xC
    mrs r0, SPSR
    vmrs r1, FPSCR
    vmrs r2, FPEXC
    add r3, sp, #0x140
    stmia r3!, {r0 - r2}
    vstmia r4!, {d0 - d15}
    vstmia r4!, {d16 - d31}
    ldr r2, [sp, #0x158] @ Load the passed abort type
    cmp r2, #0 @ Get the relevant FSR and FAR
    mrceq p15, #0, r0, c5, c0, #0
    mrceq p15, #0, r1, c6, c0, #0
    mrcne p15, #0, r0, c5, c0, #1
    mrcne p15, #0, r1, c6, c0, #2
    stmia r3, {r0 - r2}
    subeq r0, lr, #0x8
    subne r0, lr, #0x4
    str r0, [sp, #0x3C]
    bl LLockSpinLock
    mov r6, r0
    mov r0, #0xFFFFFFFF
    bl GetProcessAbortHandler
    cmp r0, #0
    beq LReturnToAbortHandler_return @ No process abort handler. Go to the next exception handler
    ldr r5, [r0, #0x8]
    ldr r1, =defaultUserAbortHandler
    ldr r1, [r1]
    cmp r5, r1
    beq LReturnToAbortHandler_return @ Process abort handler is default, Go to the next exception handler
#if (EXCEPTION_SAFETY >= 2)
    ldr r0, [sp, #0x34]
    bl CheckStackPointer
    cmp r0, #0x1
    bne LReturnToAbortHandler_return @ Go to next abort handler if the user stack isn't usable
#endif
    ldr r0, [sp, #0x34]
    sub r0, #0x158
    mov r4, r0
    mov r1, sp
    mov r2, #0x158
    CopyToUser
    cmp r0, #0
    bne LReturnToAbortHandler_return @ If copying fails, go to the next exception handler
    mov r0, r6
    bl LUnlockSpinLock
    mov r0, r4
    mov r1, r5
    add sp, #0x158
    str r0, [sp]
    ldmia sp, {sp}^
    ldr r2, =userAbortBase
    ldr r2, [r2]
    mov r3, #0x10 @ CPSR value
    strd r2, r3, [sp]
    clrex
    rfeia sp!
LReturnToAbortHandler_return:
    mov r0, r6
    bl LUnlockSpinLock
    mov   r1, #0 @ Clear FSR and FAR registers
    mcr   p15, #0, r1, c5, c0, #0 
    mcr   p15, #0, r1, c5, c0, #1 
    mcr   p15, #0, r1, c5, c1, #0 
    mcr   p15, #0, r1, c5, c1, #1 
    mcr   p15, #0, r1, c6, c0, #0 
    mcr   p15, #0, r1, c6, c0, #2
    add r4, sp, #0x40
    vldmia r4!, {d0 - d15}
    vldmia r4!, {d16 - d31}
    ldmia r4!, {r0 - r2}
    msr SPSR, r0
    vmsr FPSCR, r1
    vmsr FPEXC, r2
    ldmia r4!, {r0 - r2} @ Load the abort type
    cmp r2, #0 @ Get the relevant FSR and FAR
    mcreq p15, #0, r0, c5, c0, #0
    mcreq p15, #0, r1, c6, c0, #0
    mcrne p15, #0, r0, c5, c0, #1
    mcrne p15, #0, r1, c6, c0, #2
    ldreq r2, DabtExceptionHandler_lvl0 @ Branch to next exception handler
    ldrne r2, PabtExceptionHandler_lvl0
    ldr lr, [sp, #0x3C]
    addeq lr, #0x8
    addne lr, #0x4
    add r2, #8
    str r2, [sp, #0x15C]
    add r2, sp, #0x34
    ldmia r2, {sp, lr}^
    ldmia sp, {r0 - r12}
    add sp, #0x15C
    ldr pc, [sp], #0x4

.global DabtExceptionHandler_lvl0
DabtExceptionHandler_lvl0:
    .word 0x0
    .word 0x0
    push {r2 - r5} @ Save r2 and r3 for later, r4 for extra space, and r5 for alignment
    mrs r2, SPSR
    and r2, #0x1F
    cmp r2, #0x10 @ User mode
    bne LDabtExceptionHandler_lvl0_continue
    ldr r2, =userAbortBase
    ldr r2, [r2]
    lsr r3, lr, #0xC
    cmp r3, r2, lsr #0xC
    beq LDabtExceptionHandler_lvl0_ReturnFromHandler
    mov r2, #0
    str r2, [sp, #0x8]
    pop {r2, r3}
    b LReturnToAbortHandler @ Go to ReturnToAbortHandler with abortType in [sp, #0x4]
LDabtExceptionHandler_lvl0_ReturnFromHandler:
    add sp, #0x10
    cmp r1, #0
    beq LReturnFromAbortHandler
    bne LReturnFromDefaultAbortHandler
LDabtExceptionHandler_lvl0_continue:
    ldr r2, DabtExceptionHandler_lvl0
    add r2, #8
    str r2, [sp, #0xC]
    pop {r2 - r4, pc} @ Reload saved registers and branch to the regular lvl0 handler

.global PabtExceptionHandler_lvl0
PabtExceptionHandler_lvl0:
    .word 0x0
    .word 0x0
    push {r2 - r5}
    mrs r2, SPSR
    and r2, #0x1F
    cmp r2, #0x10
    bne LPabtExceptionHandler_lvl0_continue
    mov r2, #0x1
    str r2, [sp, #0x8]
    ldmia sp!, {r2, r3}
    b LReturnToAbortHandler
LPabtExceptionHandler_lvl0_continue:
    ldr r2, PabtExceptionHandler_lvl0
    add r2, #8
    str r2, [sp, #0xC]
    pop {r2 - r4, pc}
