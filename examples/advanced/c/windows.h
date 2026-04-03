// Simplified windows header file.

#ifndef _WINDOWS_H
#define _WINDOWS_H
#define WINDOWS_H

#ifndef __stdcall
#define __stdcall
#endif

#define CONST                           const
#define WINAPI                          __stdcall
#define NTAPI                           __stdcall
#define VOID                            void
#define NULL                            ((void *) 0)
#define PVOID                           void *
#define HANDLE                          void *
#define INT                             int
#define PINT                            int *
#define UINT                            unsigned int
#define PUINT                           unsigned int *
#define CHAR                            char
#define PCHAR                           char *
#define UCHAR                           unsigned char
#define PUCHAR                          unsigned char *
#define SHORT                           short
#define PSHORT                          short *
#define USHORT                          unsigned short
#define WCHAR                           unsigned short
#define PWCHAR                          WCHAR *
#define PWSTR                           WCHAR *
#define PUSHORT                         unsigned short *
#define LONG                            long
#define LONG_PTR                        long
#define PLONG                           long *
#define ULONG                           unsigned long
#define PULONG                          unsigned long *
#define LONGLONG                        long long
#define PLONGLONG                       long long *
#define ULONG_PTR                       unsigned long long
#define ULONGLONG                       unsigned long long
#define PULONGLONG                      unsigned long long *
#define ACCESS_MASK                     unsigned long
#define ZERO                            ((ULONGLONG) 0)
#define BOOL                            int
#define TRUE                            1
#define FALSE                           0

#define PROCESS_ALL_ACCESS              0x001F0FFF
#define THREAD_ALL_ACCESS               0x001F03FF

#define CREATE_NO_WINDOW                0x08000000

typedef struct _STARTUPINFO {
        ULONG           cb;
        PCHAR           lpReserved;
        PCHAR           lpDesktop;
        PCHAR           lpTitle;
        ULONG           dwX;
        ULONG           dwY;
        ULONG           dwXSize;
        ULONG           dwYSize;
        ULONG           dwXCountChars;
        ULONG           dwYCountChars;
        ULONG           dwFillAttribute;
        ULONG           dwFlags;
        SHORT           wShowWindow;
        SHORT           cbReserved2;
        PCHAR           lpReserved2;
        HANDLE          hStdInput;
        HANDLE          hStdOutput;
        HANDLE          hStdError;
} STARTUPINFO, *PSTARTUPINFO;

typedef struct _PROCESS_INFORMATION {
        HANDLE          hProcess;
        HANDLE          hThread;
        ULONG           dwProcessId;
        ULONG           dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION;

BOOL
WINAPI
CreateProcessA(
        PCHAR                   pApplicationName,
        PCHAR                   pCommandLine,
        PVOID                   pProcessAttributes,
        PVOID                   pThreadAttributes,
        BOOL                    bInheritHandles,
        ULONG                   dwCreationFlags,
        PVOID                   pEnvironment,
        PCHAR                   pCurrentDirectory, 
        PSTARTUPINFO            pStartupInfo, 
        PPROCESS_INFORMATION    pProcessInformation
);

#define __readgsqword(Offset) ({ULONGLONG Value; __asm__ ("mov %%gs:%c1, %0" : "=r" (Value) : "i" (Offset)); Value;})

#endif // WINDOWS_H