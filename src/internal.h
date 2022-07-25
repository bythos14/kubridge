#ifndef _INTERNAL_H_
#define _INTERNAL_H_

#include <psp2common/types.h>
#include <psp2kern/kernel/debug.h>

#ifndef NDEBUG
#define LOG(msg, ...) ksceDebugPrintf("[kubridge ]: %s:%d:"msg"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define LOG(msg, ...)
#endif

#define KU_KERNEL_ABORT_TYPE_DATA_ABORT 0
#define KU_KERNEL_ABORT_TYPE_PREFETCH_ABORT 1

typedef struct KuKernelAbortContext
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
    SceUInt32 abortType;
} KuKernelAbortContext;

typedef void (*KuKernelAbortHandler)(KuKernelAbortContext *);

// Options struct for future expansion
typedef struct KuKernelAbortHandlerOpt
{
    SceSize size;
} KuKernelAbortHandlerOpt;

typedef struct ProcessAbortHandler
{
    SceUID pid;
    SceUID userAbortMemBlock;
    KuKernelAbortHandler pHandler;
    struct ProcessAbortHandler *pNext;
} ProcessAbortHandler;

void InitExceptionHandlers();

#endif