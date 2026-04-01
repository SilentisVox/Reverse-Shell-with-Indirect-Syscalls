#include <windows.h>

// Simplified windows socket header file.

#ifndef _WINSOCK2_H
#define _WINSOCK2_H
#define WINSOCK2_H

#define SOCKET                          HANDLE
#define AF_INET                         0x02
#define SOCK_STREAM                     0x01
#define IPPROTO_TCP                     0x06

#define htons(x)                        (USHORT) (((USHORT) x << 0x08) | ((USHORT) x >> 0x08))
#define htonl(x)                        (ULONG) (((ULONG) x & 0xff000000) >> 0x18) | (((ULONG) x & 0x00FF0000) >> 0x08) | (((ULONG) x & 0x0000FF00) << 0x08) | (((ULONG) x & 0x000000FF) << 0x18)

typedef struct WSAData {
        USHORT                          wVersion;
        USHORT                          wHighVersion;
        CHAR                            szDescription[0x101];
        CHAR                            szSystemStatus[0x81];
        USHORT                          iMaxSockets;
        USHORT                          iMaxUpDbg;
        PCHAR                           lpVenderInfo;
} WSADATA, *LPWSADATA;

typedef struct sockaddr {
        USHORT                          sa_family;
        CHAR                            sa_data[0x0D];
} SOCKADDR, *PSOCKADDR;

typedef struct in_addr {
        ULONG                           s_addr;
} IN_ADDR;

typedef struct sockaddr_in {
        SHORT                           sin_family;
        USHORT                          sin_port;
        IN_ADDR                         sin_addr;
        CHAR                            sin_zero[0x08];
} SOCKADDR_IN, *PSOCKADDR_IN;

// Must link against ws2_32 library.

INT
WINAPI
WSAStartup(
        WORD                            wVersionRequested,
        LPWSADATA                       lpWSAData
);

SOCKET 
WINAPI
WSASocketA(
        INT                             AddressFamily,
        INT                             Type,
        INT                             Protocol,
        PVOID                           lpProtocolInfo,
        UINT                            Group,
        DWORD                           dwFlags
);

INT 
WINAPI
connect(
        SOCKET                          s,
        CONST PSOCKADDR                 name,
        INT                             namelen
);

#endif // _WINSOCK2_H