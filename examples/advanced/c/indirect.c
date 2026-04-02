#include "windows.h"
#include "advanced.h"

MODULE_CONFIG NtdllConfig = { 0 };

ULONG_PTR GET_NTDLL() {
        ULONG_PTR pPEB          =  __readgsqword(0x60);
        ULONG_PTR pLdrData      = *(ULONG_PTR *) (pPEB + 0x18);
        ULONG_PTR pMdlList      = *(ULONG_PTR *) (pLdrData + 0x30);
        ULONG_PTR pModule       = *(ULONG_PTR *) (pMdlList + 0x10);

        return pModule;
}

VOID INIT_NTDLL_CONFIG() {
        ULONG_PTR pNtdll        = GET_NTDLL();
        ULONG_PTR pNtHdr        = (pNtdll + *(ULONG *) (pNtdll + 0x3C));
        ULONG_PTR pExpDir       = (pNtdll + *(ULONG *) (pNtHdr + 0x88));

        NtdllConfig.pModule             = pNtdll;
        NtdllConfig.NumberOfNames       = *(ULONG *) (pExpDir + 0x18);
        NtdllConfig.ArrayOfAddresses    = (pNtdll + *(ULONG *) (pExpDir + 0x1C));
        NtdllConfig.ArrayOfNames        = (pNtdll + *(ULONG *) (pExpDir + 0x20));
        NtdllConfig.ArrayOfOrdinals     = (pNtdll + *(ULONG *) (pExpDir + 0x24));
}

ULONG ROR7_32(PCHAR SymbolName) {
        UINT hash       = 0;
        UINT index      = 0;

        while (SymbolName[index]) {
                hash    = ((hash >> 7) | (hash << (32 - 7)))    & 0xFFFFFFFF;
                hash    = (hash + SymbolName[index])            & 0xFFFFFFFF;
                index++;
        }
        return hash;
}

VOID GET_NTDLL_FUN(ULONG SymbolHash, PNTDLL_FUNCTION SymbolData) {
        if (!NtdllConfig.pModule)
                INIT_NTDLL_CONFIG();

        UINT index;

        for (index = 0; index != NtdllConfig.NumberOfNames; index++) {
                PCHAR SymbolName = (PCHAR) (NtdllConfig.pModule + *(ULONG *) (NtdllConfig.ArrayOfNames + (index * 4)));

                if (ROR7_32(SymbolName) != SymbolHash)
                        continue;

                USHORT SymbolSlot       = *(USHORT *) (NtdllConfig.ArrayOfOrdinals + (index * 2));
                SymbolData->SyscallStub = (NtdllConfig.pModule + *(ULONG *) (NtdllConfig.ArrayOfAddresses + (SymbolSlot * 4)));
                break;
        }

        for (index = 0; index != 255; index++) {
                ULONG CurrentPattern = *(ULONG_PTR *) (SymbolData->SyscallStub + index);

                if ((*(ULONG *) (SymbolData->SyscallStub + index) & 0xFF0000FF) != 0x000000B8)
                        continue;

                SymbolData->SystemServiceNumber = *(ULONG_PTR *) (SymbolData->SyscallStub + index + 1);
                break;
        }

        for (index = 0; index != 255; index++) {
                if (*(USHORT *) (SymbolData->SyscallStub + index) != 0x050f)
                        continue;

                SymbolData->SyscallInstruction = SymbolData->SyscallStub + index;
                break;
        }

        if (!SymbolData->SyscallInstruction)
                SymbolData->SyscallInstruction = SymbolData->SyscallStub;
}