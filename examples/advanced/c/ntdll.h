#include <windows.h>
#include "winsock2.h"

// Simplified windows ntdll header file.

#ifndef _NTDLL_H
#define _NTDLL_H
#define NTDLL_H

#define ZERO                            0

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#define NtCurrentConsole()              ((HANDLE) (LONG_PTR) -3)
#define NtCurrentThread()               ((HANDLE) (LONG_PTR) -2)
#define NtCurrentProcess()              ((HANDLE) (LONG_PTR) -1)
#define NT_SUCCESS(STATUS)              (((NTSTATUS) STATUS) >= 0x00)

typedef struct _LSA_UNICODE_STRING {
        USHORT                          Length;
        USHORT                          MaximumLength;
        PWSTR                           Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING, *PUNICODE_STR;

typedef struct _OBJECT_ATTRIBUTES {
        ULONG                           Length;
        HANDLE                          RootDirectory;
        PUNICODE_STRING                 ObjectName;
        ULONG                           Attributes;
        PVOID                           SecurityDescriptor;
        PVOID                           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CURDIR {
        UNICODE_STRING                  DosPath;
        HANDLE                          Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
        USHORT                          Flags;
        USHORT                          Length;
        ULONG                           TimeStamp;
        UNICODE_STRING                  DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
        ULONG                           MaximumLength;
        ULONG                           Length;
        ULONG                           Flags;
        ULONG                           DebugFlags;
        HANDLE                          ConsoleHandle;
        ULONG                           ConsoleFlags;
        HANDLE                          StandardInput;
        HANDLE                          StandardOutput;
        HANDLE                          StandardError;
        CURDIR                          CurrentDirectory;
        UNICODE_STRING                  DllPath;
        UNICODE_STRING                  ImagePathName;
        UNICODE_STRING                  CommandLine;
        PWCHAR                          Environment;
        ULONG                           StartingX;
        ULONG                           StartingY;
        ULONG                           CountX;
        ULONG                           CountY;
        ULONG                           CountCharsX;
        ULONG                           CountCharsY;
        ULONG                           FillAttribute;
        ULONG                           WindowFlags;
        ULONG                           ShowWindowFlags;
        UNICODE_STRING                  WindowTitle;
        UNICODE_STRING                  DesktopInfo;
        UNICODE_STRING                  ShellInfo;
        UNICODE_STRING                  RuntimeData;
        RTL_DRIVE_LETTER_CURDIR         CurrentDirectories[0x20];
        ULONG_PTR                       EnvironmentSize;
        ULONG_PTR                       EnvironmentVersion;
        PVOID                           PackageDependencyData;
        ULONG                           ProcessGroupId;
        ULONG                           LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PS_CREATE_INFO {
        SIZE_T                          Size;
        ULONG                           State;
        union {
                struct {
                        union {
                                ULONG   InitFlags;
                                struct {
                                        UCHAR  WriteOutputOnExit :              0x01;
                                        UCHAR  DetectManifest :                 0x01;
                                        UCHAR  IFEOSkipDebugger :               0x01;
                                        UCHAR  IFEODoNotPropagateKeyState :     0x01;
                                        UCHAR  SpareBits1 :                     0x04;
                                        UCHAR  SpareBits2 :                     0x08;
                                        USHORT ProhibitedImageCharacteristics : 0x10;
                                } s1;
                        } u1;
                        ACCESS_MASK AdditionalFileAccess;
                } InitState;

                struct {
                        HANDLE FileHandle;
                } FailSection;

                struct {
                        USHORT DllCharacteristics;
                } ExeFormat;

                struct {
                        HANDLE IFEOKey;
                } ExeName;

                struct {
                        union {
                                ULONG OutputFlags;
                                struct {
                                        UCHAR  ProtectedProcess :               0x01;
                                        UCHAR  AddressSpaceOverride :           0x01;
                                        UCHAR  DevOverrideEnabled :             0x01;
                                        UCHAR  ManifestDetected :               0x01;
                                        UCHAR  ProtectedProcessLight :          0x01;
                                        UCHAR  SpareBits1 :                     0x03;
                                        UCHAR  SpareBits2 :                     0x08;
                                        USHORT SpareBits3 :                     0x10;
                                } s2;
                        } u2;
                        HANDLE          FileHandle;
                        HANDLE          SectionHandle;
                        ULONG_PTR       UserProcessParametersNative;
                        ULONG           UserProcessParametersWow64;
                        ULONG           CurrentParameterFlags;
                        ULONG_PTR       PebAddressNative;
                        ULONG           PebAddressWow64;
                        ULONG_PTR       ManifestAddress;
                        ULONG           ManifestSize;
                } SuccessState;
        };
} PS_CREATE_INFO, *PPS_CREATE_INFO;

#define PS_ATTRIBUTE_IMAGE              0x00000005
#define PS_ATTRIBUTE_INPUT              0x00020000
#define PS_ATTRIBUTE_IMAGE_NAME ((PS_ATTRIBUTE_IMAGE) | (PS_ATTRIBUTE_INPUT))

typedef struct _PS_ATTRIBUTE {
        ULONG_PTR                       Attribute;
        ULONG_PTR                       Size;
        union {
                ULONG_PTR               Value;
                PVOID                   ValuePtr;
        };
        PSIZE_T                         ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
        SIZE_T                          TotalLength;
        PS_ATTRIBUTE                    Attributes[1]; // actually variable.
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES                0x00000004
#define THREAD_CREATE_FLAGS_NONE                            0x00000000

#define FILE_OPEN_IF                    0x00000003
#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020

typedef struct _IO_STATUS_BLOCK {
        ULONG_PTR                       Information;
        PVOID                           Pointer;
        NTSTATUS                        Status;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _IO_APC_ROUTINE {
        PVOID                           ApcContext;
        PIO_STATUS_BLOCK                pIoStatusBlock;
        ULONG                           Reserved;
} IO_APC_ROUTINE, *PIO_APC_ROUTINE;

typedef struct _AFD_CREATE_CONTEXT {
        ULONG_PTR                       Unknown1;
        ULONG                           Unknown2;
} AFD_CREATE_CONTEXT, *PAFD_CREATE_CONTEXT ;

typedef struct _AFD_OPEN_PACKET_EA {
        UINT                            NextEntryOffset;
        UCHAR                           Flags;
        UCHAR                           EaNameLength;
        USHORT                          EaValueLength;
        UCHAR                           EaName[0x10];
        UINT                            EndpointFlags;
        UINT                            GroupId;
        UINT                            AddressFamily;
        UINT                            SocketType;
        UINT                            Protocol;
        UINT                            SizeOfTransportName;
        LPVOID                          pAfdCreateContext;
} AFD_OPEN_PACKET_EA, *PAFD_OPEN_PACKET_EA;

#define IOCTL_AFD_BIND                  0x12003
#define IOCTL_AFD_CONNECT               0x12007

typedef struct _AFD_BIND_SOCKET {
        UINT                            Flags;
        SOCKADDR                        address;
} AFD_BIND_SOCKET, *PAFD_BIND_SOCKET;

typedef struct _AFD_CONNECT_SOCKET {
        ULONG_PTR                       SanActive;
        ULONG_PTR                       RootEndpoint;
        ULONG_PTR                       ConnectEndpoint;
        SOCKADDR                        address;
} AFD_CONNECT_SOCKET, *PAFD_CONNECT_SOCKET;

#endif // NTDLL_H