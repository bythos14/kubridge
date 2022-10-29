.arch armv7-a
.cpu cortex-a9
.fpu neon
.align 4
.syntax unified
.arm

.section .text

#define KU_KERNEL_EXCEPTION_TYPE_DATA_ABORT 0
#define KU_KERNEL_EXCEPTION_TYPE_PREFETCH_ABORT 1
#define KU_KERNEL_EXCEPTION_TYPE_UNDEFINED_INSTRUCTION 2

@ Exception safety has 3 levels: 
@ 0 - No safety measures
@ 1 - The stack pointer validity and free space is checked
@ 2 - Copies to/from user space are exception safe
#if !defined(EXCEPTION_SAFETY)
#define EXCEPTION_SAFETY 1
#endif

.global GetExceptionHandler
.global GetProcessExitAddr
.global CheckStackPointer
.global ksceKernelCpuSpinLockIrqSave
.global ksceKernelCpuSpinLockIrqRestore
.global ksceKernelMemcpyToUser
.global ksceKernelMemcpyFromUser

.global exceptionBootstrapAddr
.global defaultUserExceptionHandler

.macro SwitchToSystemMode
    mov r12, sp
    cps #0x1F
    mov sp, r12
.endm

/**
 * Switch to the Exception mode
 * 
 * Inputs:
 * r0 - exceptionType
 */
.macro SwitchToExcpMode
    cmp r5, #KU_KERNEL_EXCEPTION_TYPE_UNDEFINED_INSTRUCTION
    beq 1f
    cps #0x17
    b 2f
1:
    cps #0x1B
2:
.endm

/**
 * Switch to the Exception mode impl.
 *
 * Inputs:
 * r5: exceptionType
 */

.macro CopyFromUser
#if (EXCEPTION_SAFETY >= 2)
    SwitchToSystemMode
    bl ksceKernelMemcpyFromUser
    SwitchToExcpMode
#else
    bl memcpy
    mov r0, #0
#endif
.endm

.macro CopyToUser
#if (EXCEPTION_SAFETY >= 2)
    SwitchToSystemMode
    bl ksceKernelMemcpyToUser
    SwitchToExcpMode
#else
    bl memcpy
    mov r0, #0
#endif
.endm


/**
 * FatalError:
 * Causes the thread to execute sceKernelExitProcess
 */
LFatalError:
    bl GetProcessExitAddr
    bic r2, r0, #0x1
    mov r0, #0xFFFFFFFF
    mov r1, #0x30 @ Return to user mode in thumb execution state
    str r1, [sp, #-0x4]!
    str r2, [sp, #-0x4]!
    clrex
    rfeia sp!


/**
 * SaveExceptionContext
 * Saves the exception register context on the stack.
 *
 * Inputs:
 * [sp, #0x0] - exceptionType
 * [sp, #0x4] - Exception PC
 *
 * Outputs:
 * r4 - exceptionContext pointer
 */
LSaveExceptionContext:
    sub sp, #0x158 @ Reserve space on the stack
    stmia sp, {r0 - r12} @ Save r0 - r12
    add r5, sp, #0x34
    stmia r5, {sp, lr}^ @ Save user-space sp and lr
    add r5, #0xC
    vstmia r5!, {d0 - d15} @ Save d0 - d15
    vstmia r5!, {d16 - d31} @ Save d16 - d31
    mrs r0, SPSR
    vmrs r1, FPSCR
    vmrs r2, FPEXC
    stmia r5!, {r0 - r2} @ Save SPSR, FPSCR and FPEXC
    ldrd r2, r3, [r5, #0xC] @ Load the passed exception type and exception PC
    str r2, [r5, #0x8] @ Save the exception type
    cmp r2, #KU_KERNEL_EXCEPTION_TYPE_UNDEFINED_INSTRUCTION @ Get the relevant FSR and FAR
    beq LSaveExceptionContext_Undef
LSaveExceptionContext_ABRT:
    cmp r2, #KU_KERNEL_EXCEPTION_TYPE_DATA_ABORT
    bne LSaveExceptionContext_PABT
LSaveExceptionContext_DABT:
    subeq r3, r3, #0x8
    mrc p15, #0, r0, c5, c0, #0 @ DFSR
    mrc p15, #0, r1, c6, c0, #0 @ DFAR
    b LSaveExceptionContext_finish
LSaveExceptionContext_PABT:
    sub r3, r3, #0x4
    mrc p15, #0, r0, c5, c0, #1 @ IFSR
    mrc p15, #0, r1, c6, c0, #2 @ IFAR
    b LSaveExceptionContext_finish
LSaveExceptionContext_Undef:
    ldr r2, [sp, #0x140] @ Load SPSR
    movw r0, #0x0
    movt r0, #0x0
    mov r1, r0 @ Zerofill FSR and FAR
    tst r2, #0x20 @ Test for T bit
    subeq r3, r3, #0x4
    subne r3, r3, #0x2
LSaveExceptionContext_finish:
    strd r0, r1, [r5] @ Store FSR and FAR
    str r3, [sp, #0x3C] @ Store the PC
    mov r4, sp
    ldr r5, [r4, #0x154]
    bx lr


/**
 * RestoreExceptionContext
 * Restores the exception register context
 * There should be 8 bytes of stack space pre-allocated
 *
 * Inputs:
 * r0 - abortContext pointer
 * r1 - Is context on user stack (0 - no, 1 - yes)
 * r2 - Target (0 - user space, 1 - exception handler)
 */
LRestoreExceptionContext:
    sub sp, #0x8
    str r2, [sp] @ Save the restore target on the stack
#if (EXCEPTION_SAFETY >= 2)
    cmp r1, #0x0
    beq LRestoreExceptionContext_copiedContext
    mov r5, #KU_KERNEL_EXCEPTION_TYPE_UNDEFINED_INSTRUCTION
    sub sp, #0x158 @ 0x158 for the abort context, 8 bytes work space
    mov r1, r0
    mov r0, sp
    mov r2, #0x158
    CopyFromUser
    cmp r0, #0
    addne sp, #0x160
    bne LFatalError
    mov r0, sp
    add sp, #0x158 @ Reset the stack pointer. sp to sp + 8 is the work area
#endif
LRestoreExceptionContext_copiedContext:
    mov r4, r0
    add r0, r4, #0x40
    vldmia r0!, {d0 - d15} @ First load the VFP/NEON registers
    vldmia r0!, {d16 - d31}
    ldr r1, [sp] @ Load the restore target from the stack
    add r0, #0x4
    ldmia r0!, {r2, r3} @ Then load the FPSCR and FPEXC
    cmp r1, #0x0
    vmsr FPSCR, r2
    vmsr FPEXC, r3
    bne LRestoreExceptionContext_nextHandler 
LRestoreExceptionContext_returnToUser:
    mov r12, r4
    ldmia r12!, {r0 - r11}
    add r12, #0x4
    ldmia r12, {sp, lr}^
    sub r12, #0x34
    ldr lr, [r12, #0x140]
    str lr, [sp, #0x4]
    ldr lr, [r12, #0x3C]
    str lr, [sp]
    ldr r12, [r12, #0x30]
    clrex
    rfeia sp!
LRestoreExceptionContext_nextHandler:
    ldr r2, [r4, #0x140] @ Load the SPSR
    ldr r1, [r4, #0x154] @ Load the exceptionType
    bic r2, #0xF
    msr SPSR, r2
    cmp r1, #KU_KERNEL_EXCEPTION_TYPE_UNDEFINED_INSTRUCTION
    beq LRestoreExceptionContext_nextHandler_Undef
LRestoreExceptionContext_nextHandler_ABRT:
    cmp r1, #KU_KERNEL_EXCEPTION_TYPE_DATA_ABORT
    ldrd r2, r3, [r0] @ Load the FSR and FAR
    mov r1, #0x0 
    bne LRestoreExceptionContext_nextHandler_PABT
LRestoreExceptionContext_nextHandler_DABT:
    mcr p15, #0, r2, c5, c0, #0 @ DFSR
    mcr p15, #0, r3, c6, c0, #0 @ DFAR
    mcr p15, #0, r1, c5, c1, #0 @ ADFSR
    ldr r2, DabtExceptionHandler_lvl0 @ Branch to next exception handler
    mov r3, #0x8
    b LRestoreExceptionContext_nextHandler_end
LRestoreExceptionContext_nextHandler_PABT:
    mcr p15, #0, r2, c5, c0, #1 @ IFSR
    mcr p15, #0, r3, c6, c0, #2 @ IFAR
    mcr p15, #0, r1, c5, c1, #1 @ AIFSR
    ldr r2, PabtExceptionHandler_lvl0 @ Branch to next exception handler
    mov r3, #0x4
    b LRestoreExceptionContext_nextHandler_end
LRestoreExceptionContext_nextHandler_Undef:
    ldr r1, [r4, #0x140]
    ldr r2, UndefExceptionHandler_lvl0
    tst r1, #0x20 @ Check for the T bit
    moveq r3, #0x4
    movne r3, #0x2
LRestoreExceptionContext_nextHandler_end:
    ldr lr, [r4, #0x3C] @ Load the exception PC
    add r2, #0x8
    str r2, [sp, #0x4]! @ Store the next exception handler address on the stack
    add lr, r3 @ Add the exception specific PC offset
    mov r12, r4
    ldmia r12!, {r0 - r11} @ Load the general purpose registers
    add r12, #0x4
    ldmia r12, {sp, lr}^ @ Load the user space banked registers
    sub r12, #0x34
    ldr r12, [r12, #0x30] @ Load r12
    ldr pc, [sp], #0x4 @ Branch to the next handler


/**
 * LReturnToExceptionHandler:
 * Saves register context to thread stack, and returns to user-space to execute the abort handler
 * 
 * Inputs:
 * [sp, #0x0] - exceptionType
 * [sp, #0x4] - Exception PC
 */
LReturnToExceptionHandler:
    bl LSaveExceptionContext
    ldr r0, [r4, #0x154] @ Load the exceptionType
    bl GetExceptionHandler
    cmp r0, #0x0
    beq LReturnToExceptionHandler_nextHandler @ No process exception handler. Go to the next exception handler
    mov r6, r0 @ Store the exception handler address in r6
#if (EXCEPTION_SAFETY >= 1)
    ldr r0, [r4, #0x34]
#if (EXCEPTION_SAFETY < 2)
    bl CheckStackPointer
#else
    SwitchToSystemMode
    bl CheckStackPointer
    SwitchToExcpMode
#endif
    cmp r0, #0x1
    bne LReturnToExceptionHandler_nextHandler @ Go to next abort handler if the user stack isn't usable
#endif
    ldr r0, [r4, #0x34]
    mov r1, r4
    mov r2, #0x158
    sub r0, #0x158
    mov r4, r0 @ Save the user exceptionContext in r4
    CopyToUser
    cmp r0, #0
    bne LReturnToExceptionHandler_nextHandler @ If copying fails, go to the next exception handler
    add sp, #0x158
    str r4, [sp]
    ldmia sp, {sp}^
    ldr r2, =exceptionBootstrapAddr @ Load the exceptionBootstrap address
    ldr r2, [r2]
    mov r3, #0x10 @ CPSR value (USR mode)
    strd r2, r3, [sp]
    mov r1, #0 @ Clear FSR and FAR registers
    mcr p15, #0, r1, c5, c0, #0 
    mcr p15, #0, r1, c5, c0, #1 
    mcr p15, #0, r1, c5, c1, #0 
    mcr p15, #0, r1, c5, c1, #1 
    mcr p15, #0, r1, c6, c0, #0 
    mcr p15, #0, r1, c6, c0, #2
    mov r0, r4 @ Move exceptionContext and exception handler address to r0 and r1
    mov r1, r6
    clrex
    rfeia sp!
LReturnToExceptionHandler_nextHandler:
    add sp, #0x160 @ Reset sp. The exceptionContext should be safe on the stack as is.
    mov r0, r4
    mov r1, #0x0 @ Context is on kernel stack, 
    mov r2, #0x1 @ Going to the next exception handler
    b LRestoreExceptionContext


.global DabtExceptionHandler_lvl0
DabtExceptionHandler_lvl0:
    .word 0x0
    .word 0x0
    push {r2, r3, r4, lr} @ Save r2 and r3 for later, r4 for extra space, and r5 for alignment
    mrs r2, SPSR
    and r2, #0x1F
    cmp r2, #0x10 @ User mode
    bne LDabtExceptionHandler_lvl0_nextHandler
    mov r2, #KU_KERNEL_EXCEPTION_TYPE_DATA_ABORT
    str r2, [sp, #0x8]
    pop {r2, r3}
    b LReturnToExceptionHandler @ Go to ReturnToExceptionHandler with exceptionType in [sp, #0x0]
LDabtExceptionHandler_lvl0_nextHandler:
    ldr r2, DabtExceptionHandler_lvl0
    add r2, #8
    str r2, [sp, #0xC]
    pop {r2 - r4, pc} @ Reload saved registers and branch to the regular lvl0 handler


.global PabtExceptionHandler_lvl0
PabtExceptionHandler_lvl0:
    .word 0x0
    .word 0x0
    push {r2, r3, r4, lr}
    mrs r2, SPSR
    and r2, #0x1F
    cmp r2, #0x10
    bne LPabtExceptionHandler_lvl0_nextHandler
    mov r2, #KU_KERNEL_EXCEPTION_TYPE_PREFETCH_ABORT
    str r2, [sp, #0x8]
    pop {r2, r3}
    b LReturnToExceptionHandler
LPabtExceptionHandler_lvl0_nextHandler:
    ldr r2, PabtExceptionHandler_lvl0
    add r2, #8
    str r2, [sp, #0xC]
    pop {r2 - r4, pc}


.global UndefExceptionHandler_lvl0
UndefExceptionHandler_lvl0:
    .word 0x0
    .word 0x0
    push {r2, r3, r4, lr} @ Save registers for restor
    mrs r2, SPSR
    and r3, r2, #0x1F
    cmp r3, #0x10 @ User mode
    bne LUndefExceptionHandler_lvl0_nextHandler
    tst r2, #0x20
    bne UndefExceptionHandler_lvl0_returnToHandler
    ldr r2, =exceptionBootstrapAddr
    ldr r2, [r2]
    lsr r2, #0xC
    cmp r2, lr, lsr #0xC
    beq LUndefExceptionHandler_lvl0_CheckUDF
UndefExceptionHandler_lvl0_returnToHandler:
    mov r2, #KU_KERNEL_EXCEPTION_TYPE_UNDEFINED_INSTRUCTION
    str r2, [sp, #0x8]
    pop {r2, r3}
    b LReturnToExceptionHandler @ Go to ReturnToExceptionHandler with exceptionType in [sp, #0x0]
LUndefExceptionHandler_lvl0_nextHandler:
    ldr r2, UndefExceptionHandler_lvl0 @ Load next exception handler address
    add r2, #8
    str r2, [sp, #0xC]
    pop {r2 - r4, pc} @ Reload saved registers and branch to the regular lvl0 handler
LUndefExceptionHandler_lvl0_CheckUDF:
    mov r2, r1 @ Passed from bootstrap, (0x0 - return to user, 0x1 - next handler)
    mov r1, #0x1 @ abortContext is in user memory
    add sp, #0x10
    b LRestoreExceptionContext
