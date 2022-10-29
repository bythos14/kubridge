#ifndef _INTERNAL_H_
#define _INTERNAL_H_

#include <psp2common/types.h>
#include <psp2kern/kernel/debug.h>

#ifndef NDEBUG
#define LOG(msg, ...) ksceDebugPrintf("[kubridge ]: %s:%d:"msg"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define LOG(msg, ...)
#endif

#define KU_KERNEL_PROT_NONE  (0x00)
#define KU_KERNEL_PROT_READ  (0x40)
#define KU_KERNEL_PROT_WRITE (0x20)
#define KU_KERNEL_PROT_EXEC  (0x10)

#define KU_KERNEL_MEM_COMMIT_ATTR_HAS_BASE (0x1)

#define KU_KERNEL_EXCEPTION_TYPE_DATA_ABORT 0
#define KU_KERNEL_EXCEPTION_TYPE_PREFETCH_ABORT 1
#define KU_KERNEL_EXCEPTION_TYPE_UNDEF_INSTR 2

typedef struct KuKernelExceptionContext
{
    SceUInt32 r0;
    SceUInt32 r1;
    SceUInt32 r2;
    SceUInt32 r3;
    SceUInt32 r4;
    SceUInt32 r5;
    SceUInt32 r6;
    SceUInt32 r7;
    SceUInt32 r8;
    SceUInt32 r9;
    SceUInt32 r10;
    SceUInt32 r11;
    SceUInt32 r12;
    SceUInt32 sp;
    SceUInt32 lr;
    SceUInt32 pc;
    SceUInt64 vfpRegisters[32];
    SceUInt32 SPSR;
    SceUInt32 FPSCR;
    SceUInt32 FPEXC;
    SceUInt32 FSR;
    SceUInt32 FAR;
    SceUInt32 exceptionType;
} KuKernelExceptionContext;

typedef void (*KuKernelExceptionHandler)(KuKernelExceptionContext *);

// Structure for future expansion
typedef struct KuKernelExceptionHandlerOpt
{
    SceSize size;
} KuKernelExceptionHandlerOpt;

typedef struct KuKernelMemCommitOpt
{
    SceSize size;
    SceUInt32 attr;
    SceUID baseBlock;
    SceUInt32 baseOffset;
} KuKernelMemCommitOpt;

typedef struct KuKernelProcessContext
{
    SceUID pid;
    SceUID exceptionBootstrapMemBlock;
    void *exceptionBootstrapBase;
    KuKernelExceptionHandler pExceptionHandlers[3];
    KuKernelExceptionHandler pDefaultHandler;
    int spinLock;
} KuKernelProcessContext;

void InitExceptionHandlers();

void InitMemProtect();
void TermMemProtect();

// Deprecated
typedef KuKernelExceptionContext KuKernelAbortContext;
typedef struct KuKernelAbortHandlerOpt KuKernelAbortHandlerOpt;
typedef KuKernelExceptionHandler KuKernelAbortHandler;

#endif