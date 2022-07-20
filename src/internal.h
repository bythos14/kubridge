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

void InitMemProtect();
void TermMemProtect();

#endif