.arch armv7-a
.cpu cortex-a9
.fpu neon
.align 4
.syntax unified
.arm
.text

.global exceptionsUserStart
.global exceptionsUserEnd
.global exceptionBootstrap
.global defaultExceptionHandler

exceptionsUserStart:
exceptionBootstrap:
    mov r4, r0
    blx r1
    mov r0, r4
    mov r1, #0x0
    udf #0x0 @ Trigger Undefined instruction exception to return to kernel

defaultExceptionHandler:
    mov r1, #0x1
    udf #0x0 @ Trigger Undefined instruction exception to return to kernel
exceptionsUserEnd: