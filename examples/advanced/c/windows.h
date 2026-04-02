// Simplified windows header file.

#ifndef _WINDOWS_H
#define _WINDOWS_H
#define WINDOWS_H

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

#define PROCESS_ALL_ACCESS              0x1F0FFF
#define THREAD_ALL_ACCESS               0x1F03FF

#define __readgsqword(Offset) ({ULONGLONG Value; __asm__ ("mov %%gs:%c1, %0" : "=r" (Value) : "i" (Offset)); Value;})

#endif // WINDOWS_H