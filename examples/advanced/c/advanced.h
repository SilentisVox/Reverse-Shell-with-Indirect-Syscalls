#include "windows.h"

#ifndef _NTREVERSE_H
#define _NTREVERSE_H
#define NTREVERSE_H

typedef struct _MODULE_CONFIG {
        ULONG_PTR       pModule;
        ULONG           NumberOfNames;
        ULONG_PTR       ArrayOfNames;
        ULONG_PTR       ArrayOfAddresses;
        ULONG_PTR       ArrayOfOrdinals;
} MODULE_CONFIG, *PMODULE_CONFIG;

typedef struct _NTDLL_FUNCTION {
        ULONG_PTR       SyscallStub;
        ULONG           SystemServiceNumber;
        ULONG_PTR       SyscallInstruction;
} NTDLL_FUNCTION, *PNTDLL_FUNCTION;

typedef struct _NTDLL_API {
        NTDLL_FUNCTION NtCreateFile;
        NTDLL_FUNCTION NtDeviceIoControlFile;
        NTDLL_FUNCTION NtCreateUserProcess;
        NTDLL_FUNCTION NtExitProcess;
        NTDLL_FUNCTION RtlInitUnicodeString;
        NTDLL_FUNCTION RtlCreateProcessParametersEx;
} NTDLL_API, *PNTDLL_API;

VOID INIT_NTDLL_API();
VOID GET_NTDLL_FUN(ULONG SymbolHash, PNTDLL_FUNCTION SymbolData);

extern VOID SET_SYSCALL_ASM(ULONG SystemServiceNumber, ULONG_PTR SyscallInstruction);
extern ULONG_PTR RUN_SYSCALL_ASM();

#define SET_SYSCALL(Syscall)    SET_SYSCALL_ASM(Syscall.SystemServiceNumber, Syscall.SyscallInstruction)
#define RUN_SYSCALL             RUN_SYSCALL_ASM

#endif // !NTREVERSE_H