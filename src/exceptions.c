#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/excpmgr.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/proc_event.h>
#include <psp2kern/kernel/processmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysmem/memtype.h>
#include <psp2kern/kernel/sysroot.h>
#include <psp2kern/kernel/threadmgr.h>

#include <psp2/kernel/error.h>

#include <stdbool.h>
#include <taihen.h>

#include "internal.h"

#if !defined(EXCEPTION_SAFETY)
#define EXCEPTION_SAFETY 1
#endif

typedef struct SceKernelExceptionHandler
{
    struct SceKernelExceptionHandler *nextHandler;
    SceUInt32 padding;

    SceUInt32 impl[];
} SceKernelExceptionHandler;

int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

static int (*_sceKernelRegisterExceptionHandler)(SceExcpKind excpKind, SceUInt32 prio, SceKernelExceptionHandler *handler);
static void *(*_sceKernelAllocRemoteProcessHeap)(SceUID pid, SceSize size, void *pOpt);
static void (*_sceKernelFreeRemoteProcessHeap)(SceUID pid, void *ptr);
static int (*_sceKernelProcCopyToUserRx)(SceUID pid, void *dst, const void *src, SceSize size);

extern SceKernelExceptionHandler DabtExceptionHandler_lvl0;
extern SceKernelExceptionHandler PabtExceptionHandler_lvl0;
extern SceKernelExceptionHandler UndefExceptionHandler_lvl0;

void *exceptionBootstrapAddr = NULL;

static int processContextPLSKey = -1;

extern uint32_t exceptionsUserStart[], exceptionsUserEnd[], exceptionBootstrap[], defaultExceptionHandler[];

int CheckStackPointer(void *stackPointer)
{
    void *stackBounds[2];
    uint32_t *tlsAddr;
    asm volatile("mrc p15, 0, %0, c13, c0, #3" : "=r" (tlsAddr)); // Load TLS address from TPIDRURO register
    if (tlsAddr == NULL)
    {
        LOG("Error: Invalid TLS Address");
        return 0;
    }

    tlsAddr -= (0x800 / sizeof(uint32_t));

#if (EXCEPTION_SAFETY >= 2)
    if (ksceKernelMemcpyFromUser(&stackBounds[0], &tlsAddr[2], sizeof(stackBounds)) < 0)
    {
        LOG("Error: Failed to load stack bounds from TLS");
        return 0;
    }
#else
    stackBounds[0] = (void *)tlsAddr[2];
    stackBounds[1] = (void *)tlsAddr[3];
#endif

    if (stackPointer > stackBounds[0] || stackPointer <= stackBounds[1])
    {
        LOG("Error: Stack pointer for thread 0x%X is out-of-bounds (sp: %p, stack bottom: %p, stack top: %p)", ksceKernelGetThreadId(), stackPointer, stackBounds[0], stackBounds[1]);
        return 0;
    }

    stackPointer -= (0x160 + 0x400); // 0x160 for the abort context, plus an extra 0x400 for use in the abort handler
    if (stackPointer > stackBounds[0] || stackPointer <= stackBounds[1])
    {
        LOG("Insufficient stack space on thread 0x%X to call the abort handler (sp: %p, stack bottom: %p, stack top: %p)", ksceKernelGetThreadId(), stackPointer + (0x160 + 0x400), stackBounds[0], stackBounds[1]);
        return 0;
    }

    return 1;
}

uintptr_t GetProcessExitAddr()
{
    uintptr_t addr;

    LOG("Fatal error encountered while reloading the abort context. Process will be terminated");

    module_get_export_func(ksceKernelGetProcessId(), "SceLibKernel", 0xCAE9ACE6, 0x7595D9AA, &addr); // sceKernelExitProcess

    return addr;
}

KuKernelProcessContext *GetProcessContext(SceUID pid, bool init)
{
    KuKernelProcessContext *processContext;

    if (ksceKernelGetProcessLocalStorageAddrForPid(pid, processContextPLSKey, (void **)&processContext, init) < 0)
    {
        LOG("Error: Failed to get process context from PLS");
        return NULL;
    }

    if (init == false)
        return processContext;

    int irqState = ksceKernelCpuSpinLockIrqSave(&processContext->spinLock);

    if (processContext->exceptionBootstrapMemBlock == 0)
    {
        processContext->pid = pid == 0 ? ksceKernelGetProcessId() : pid;
        bool setBootstrapAddr = exceptionBootstrapAddr == NULL;
        SceKernelAllocMemBlockKernelOpt opt;
        memset(&opt, 0, sizeof(opt));
        opt.size = sizeof(opt);
        if (setBootstrapAddr)
            opt.attr = 0x8000000 | SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID; // Attr 0x8000000 allocates the memBlock at the highest address available
        else
        {
            opt.attr = SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID | 0x00000001; // (HAS_PID | HAS_VBASE)
            opt.field_C = (uintptr_t)exceptionBootstrapAddr;
        }
        opt.pid = pid;
        processContext->exceptionBootstrapMemBlock = ksceKernelAllocMemBlock("KuBridgeExcpHandlerBootstrap", SCE_KERNEL_MEMBLOCK_TYPE_USER_SHARED_MAIN_RX, 0x1000, &opt);
        if (processContext->exceptionBootstrapMemBlock < 0)
        {
            LOG("Failed to allocate base memBlock for exception handler bootstrap code (0x%08X)", processContext->exceptionBootstrapMemBlock);
            processContext->exceptionBootstrapMemBlock = -1;
            goto exit;
        }
        ksceKernelGetMemBlockBase(processContext->exceptionBootstrapMemBlock, &processContext->exceptionBootstrapBase);
        if (setBootstrapAddr)
            exceptionBootstrapAddr = processContext->exceptionBootstrapBase;

        _sceKernelProcCopyToUserRx(pid, processContext->exceptionBootstrapBase, &exceptionsUserStart[0], (uintptr_t)&exceptionsUserEnd[0] - (uintptr_t)&exceptionsUserStart[0]);
        processContext->pDefaultHandler = processContext->exceptionBootstrapBase + ((uintptr_t)&defaultExceptionHandler[0] - (uintptr_t)&exceptionsUserStart[0]);
    }

exit:
    ksceKernelCpuSpinLockIrqRestore(&processContext->spinLock, irqState);

    return processContext;
}

KuKernelExceptionHandler GetExceptionHandler(uint32_t exceptionType)
{
    KuKernelProcessContext *processContext = GetProcessContext(0, false);
    if (processContext == 0)
        return NULL;

    int irqState = ksceKernelCpuSpinLockIrqSave(&processContext->spinLock);
    KuKernelExceptionHandler pHandler = processContext->pExceptionHandlers[exceptionType];
    ksceKernelCpuSpinLockIrqRestore(&processContext->spinLock, irqState);

    return pHandler;
}

static int DestroyProcess(SceUID pid, SceProcEventInvokeParam1 *a2, int a3)
{
    KuKernelProcessContext *processContext = GetProcessContext(pid, false);
    if (processContext == NULL)
        return 0;

    int irqState = ksceKernelCpuSpinLockIrqSave(&processContext->spinLock);
    
    if (processContext->exceptionBootstrapMemBlock != -1)
        ksceKernelFreeMemBlock(processContext->exceptionBootstrapMemBlock);

    ksceKernelCpuSpinLockIrqRestore(&processContext->spinLock, irqState);

    return 0;
}

void InitExceptionHandlers()
{
    if (module_get_export_func(KERNEL_PID, "SceExcpmgr", TAI_ANY_LIBRARY, 0x03499636, (uintptr_t *)&_sceKernelRegisterExceptionHandler) < 0) // 3.60
        module_get_export_func(KERNEL_PID, "SceExcpmgr", TAI_ANY_LIBRARY, 0x00063675, (uintptr_t *)&_sceKernelRegisterExceptionHandler); // >= 3.63

    if (module_get_export_func(KERNEL_PID, "SceSysmem", TAI_ANY_LIBRARY, 0x30931572, (uintptr_t *)&_sceKernelProcCopyToUserRx) < 0) // 3.60
        module_get_export_func(KERNEL_PID, "SceSysmem", TAI_ANY_LIBRARY, 0x2995558D, (uintptr_t *)&_sceKernelProcCopyToUserRx);     // >= 3.63

    module_get_export_func(KERNEL_PID, "SceProcessmgr", TAI_ANY_LIBRARY, 0x00B1CA0F, (uintptr_t *)&_sceKernelAllocRemoteProcessHeap);
    module_get_export_func(KERNEL_PID, "SceProcessmgr", TAI_ANY_LIBRARY, 0x9C28EA9A, (uintptr_t *)&_sceKernelFreeRemoteProcessHeap);

    _sceKernelRegisterExceptionHandler(SCE_EXCP_DABT, 0, &DabtExceptionHandler_lvl0);
    _sceKernelRegisterExceptionHandler(SCE_EXCP_PABT, 0, &PabtExceptionHandler_lvl0);
    _sceKernelRegisterExceptionHandler(SCE_EXCP_UNDEF_INSTRUCTION, 0, &UndefExceptionHandler_lvl0);

    SceProcEventHandler handler;
    memset(&handler, 0, sizeof(handler));
    handler.size = sizeof(handler);
    handler.exit = DestroyProcess;
    handler.kill = DestroyProcess;

    ksceKernelRegisterProcEventHandler("KuBridgeProcessHandler", &handler, 0);

    processContextPLSKey = ksceKernelCreateProcessLocalStorage("KuBridgeProcessContext", sizeof(KuKernelProcessContext));
    if (processContextPLSKey < 0)
        LOG("Error: Failed to create PLS for process context");
}

int kuKernelRegisterExceptionHandler(SceUInt32 exceptionType, KuKernelExceptionHandler pHandler, KuKernelExceptionHandler *pOldHandler, KuKernelExceptionHandlerOpt *pOpt)
{
    int ret;

    if (exceptionType > 2) // Highest supported type is 2
    {
        LOG("Error: Invalid exceptionType");
        return SCE_KERNEL_ERROR_INVALID_ARGUMENT;
    }

    if (pHandler == NULL)
    {
        LOG("Error: Invalid pHandler");
        return SCE_KERNEL_ERROR_INVALID_ARGUMENT;
    }

    if (pOpt != NULL)
    {
        KuKernelExceptionHandlerOpt opt;
        ret = ksceKernelMemcpyFromUser(&opt, pOpt, sizeof(KuKernelExceptionHandlerOpt));
        if (ret < 0)
        {
            LOG("Error: Invalid pOpt");
            return ret;
        }

        if (opt.size != sizeof(KuKernelExceptionHandlerOpt))
        {
            LOG("Error: pOpt->size != sizeof(KuKernelExceptionHandlerOpt)");
            return SCE_KERNEL_ERROR_INVALID_ARGUMENT_SIZE;
        }
    }

    KuKernelProcessContext *processContext = GetProcessContext(0, true);
    if ((processContext == NULL) || (processContext->exceptionBootstrapMemBlock == -1))
    {
        LOG("Error: Failed to get process context for process 0x%X", ksceKernelGetProcessId());
        return SCE_KERNEL_ERROR_NO_MEMORY;
    }

    int irqState = ksceKernelCpuSpinLockIrqSave(&processContext->spinLock);

    if (pOldHandler != NULL)
    {
        ret = ksceKernelMemcpyToUser(pOldHandler, &processContext->pExceptionHandlers[exceptionType], sizeof(KuKernelExceptionHandler));
        if (ret < 0)
        {
            LOG("Error: Invalid pOldHandler");
            goto exit;
        }
    }

    processContext->pExceptionHandlers[exceptionType] = pHandler == processContext->pDefaultHandler ? NULL : pHandler;

    ret = 0;
exit:
    ksceKernelCpuSpinLockIrqRestore(&processContext->spinLock, irqState);

    return ret;
}

void kuKernelReleaseExceptionHandler(SceUInt32 exceptionType)
{
    KuKernelProcessContext *processContext = GetProcessContext(0, false);
    if ((processContext == NULL) || (processContext->exceptionBootstrapMemBlock == -1))
        return;

    int irqState = ksceKernelCpuSpinLockIrqSave(&processContext->spinLock);

    processContext->pExceptionHandlers[exceptionType] = NULL;

    ksceKernelCpuSpinLockIrqRestore(&processContext->spinLock, irqState);
}

// Deprecated
int kuKernelRegisterAbortHandler(KuKernelAbortHandler pHandler, KuKernelAbortHandler *pOldHandler, KuKernelAbortHandlerOpt *pOpt)
{
    int ret = kuKernelRegisterExceptionHandler(KU_KERNEL_EXCEPTION_TYPE_DATA_ABORT, pHandler, NULL, NULL);
    if (ret != 0)
        return ret;
    ret = kuKernelRegisterExceptionHandler(KU_KERNEL_EXCEPTION_TYPE_PREFETCH_ABORT, pHandler, NULL, NULL);
    if (ret != 0)
    {
        goto release_dabt;
    }

    KuKernelProcessContext *processContext = GetProcessContext(0, false);

    if (pOldHandler != NULL)
    {
        ret = ksceKernelMemcpyToUser(pOldHandler, &processContext->pDefaultHandler, sizeof(KuKernelExceptionHandler));
        if (ret < 0)
        {
            LOG("Error: Invalid pOldHandler");
            goto release_pabt;
        }
    }

    return ret;

release_pabt:
    kuKernelReleaseExceptionHandler(KU_KERNEL_EXCEPTION_TYPE_PREFETCH_ABORT);
release_dabt:
    kuKernelReleaseExceptionHandler(KU_KERNEL_EXCEPTION_TYPE_DATA_ABORT);

    return ret;
}

void kuKernelReleaseAbortHandler()
{
    kuKernelReleaseExceptionHandler(KU_KERNEL_EXCEPTION_TYPE_PREFETCH_ABORT);
    kuKernelReleaseExceptionHandler(KU_KERNEL_EXCEPTION_TYPE_DATA_ABORT);
}
