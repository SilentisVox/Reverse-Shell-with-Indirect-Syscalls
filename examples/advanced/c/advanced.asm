section         .data
SYSTEM_SERVICE_NUMBER:  DD 0
SYSCALL_ADDRESS:        DQ 0

section         .text
global          SET_SYSCALL_ASM
global          RUN_SYSCALL_ASM

SET_SYSCALL_ASM:
        XOR     RAX,    RAX
        MOV     DWORD   [REL SYSTEM_SERVICE_NUMBER],    EAX
        MOV     QWORD   [REL SYSCALL_ADDRESS],          RAX
        MOV     DWORD   [REL SYSTEM_SERVICE_NUMBER],    ECX
        MOV     QWORD   [REL SYSCALL_ADDRESS],          RDX
        RET

RUN_SYSCALL_ASM:
        MOV     R10,    RCX
        MOV     EAX,    DWORD   [REL SYSTEM_SERVICE_NUMBER]
        JMP     QWORD   [REL SYSCALL_ADDRESS]