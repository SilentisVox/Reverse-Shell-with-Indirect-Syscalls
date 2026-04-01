#include <windows.h>

// Simplified windows socket header file.

#ifndef _WINSOCK2_H
#define _WINSOCK2_H
#define WINSOCK2_H

#define SOCKET                          HANDLE
#define INVALID_SOCKET                  (SOCKET)(~0)
#define SOCKET_ERROR                    (-1)

#define AF_INET                         0x02
#define SOCK_STREAM                     0x01
#define IPPROTO_TCP                     0x06

#define htons(x)                        (USHORT) (((USHORT) x << 8) | ((USHORT) x >> 8))
#define htonl(x)                        (ULONG) (((ULONG) x & 0xff000000) >> 24) | (((ULONG) x & 0x00FF0000) >> 8) | (((ULONG) x & 0x0000FF00) << 8) | (((ULONG) x & 0x000000FF) << 24)

typedef struct WSAData {
        USHORT                          wVersion;
        USHORT                          wHighVersion;
        CHAR                            szDescription[257];
        CHAR                            szSystemStatus[129];
        USHORT                          iMaxSockets;
        USHORT                          iMaxUpDbg;
        PCHAR                           lpVenderInfo;
} WSADATA, *LPWSADATA;

typedef struct sockaddr {
        USHORT                          sa_family;
        CHAR                            sa_data[14];
} SOCKADDR, *PSOCKADDR;

typedef struct in_addr {
        ULONG                           s_addr;
} IN_ADDR;

typedef struct sockaddr_in {
        SHORT                           sin_family;
        USHORT                          sin_port;
        IN_ADDR                         sin_addr;
        CHAR                            sin_zero[8];
} SOCKADDR_IN, *PSOCKADDR_IN;

// Must link against ws2_32 library.

INT __stdcall WSAStartup(
        WORD                            wVersionRequested,
        LPWSADATA                       lpWSAData
);

SOCKET __stdcall WSASocketA(
        INT                             AddressFamily,
        INT                             Type,
        INT                             Protocol,
        PVOID                           lpProtocolInfo,
        UINT                            Group,
        DWORD                           dwFlags
);

INT __stdcall connect(
        SOCKET                          s,
        CONST PSOCKADDR                 name,
        INT                             namelen
);

#endif // _WINSOCK2_H