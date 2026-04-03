#include "windows.h"

// Simplified windows socket header file.

#ifndef _WINSOCK2_H
#define _WINSOCK2_H
#define WINSOCK2_H

#define SOCKET                          HANDLE
#define AF_INET                         2
#define SOCK_STREAM                     1
#define IPPROTO_TCP                     6

#define htons(x)                        (USHORT) (((USHORT) x << 8) | ((USHORT) x >> 8))
#define htonl(x)                        (ULONG) (((ULONG) x & 0xFF000000) >> 24) | (((ULONG) x & 0x00FF0000) >> 8) | (((ULONG) x & 0x0000FF00) << 8) | (((ULONG) x & 0x000000FF) << 24)

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
        CHAR                            sa_data[13];
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

BOOL
WINAPI
WSAStartup(
        SHORT                           wVersionRequested,
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
        ULONG                           dwFlags
);

BOOL
WINAPI
connect(
        SOCKET                          s,
        PSOCKADDR_IN                    name,
        INT                             namelen
);

#endif // _WINSOCK2_H