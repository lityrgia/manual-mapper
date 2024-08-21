#include "injector.h"

#include <winternl.h>
#include <iostream>

#if defined(DISABLE_OUTPUT)
#define ILog(data, ...)
#else
#define ILog(text, ...) printf(text, __VA_ARGS__);
#endif

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

//Vectors
//Minhook
//VirtualFree

#define MZ 0x5A4D
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef NTSYSAPI NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(
    IN HANDLE hProcess,
    OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
    );

typedef NTSTATUS(NTAPI* _NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID lpStartAddress,
    PVOID lpParameter,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewProtect,
    PULONG OldProtect
    );

typedef NTSTATUS(NTAPI* _NtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
    );

_NtAllocateVirtualMemory Get_NtAllocateVirtualMemory(const char* name)
{
    HMODULE ntdll = GetModuleHandleA("ntdll");
    _NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(ntdll, name);

    return NtAllocateVirtualMemory;
}

_NtCreateThreadEx Get_NtCreateThreadEx(const char* name)
{
    HMODULE ntdll = GetModuleHandleA("ntdll");
    _NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(ntdll, name);

    return NtCreateThreadEx;
}

_NtProtectVirtualMemory Get_NtProtectVirtualMemory(const char* name)
{
    HMODULE ntdll = GetModuleHandleA("ntdll");
    _NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetProcAddress(ntdll, name);

    return NtProtectVirtualMemory;
}

_NtFreeVirtualMemory Get_NtFreeVirtualMemory(const char* name)
{
    HMODULE ntdll = GetModuleHandleA("ntdll");
    _NtFreeVirtualMemory NtFreeVirtualMemory = (_NtFreeVirtualMemory)GetProcAddress(ntdll, name);

    return NtFreeVirtualMemory;
}

_NtAllocateVirtualMemory NtAllocateVirtualMemory = Get_NtAllocateVirtualMemory("NtAllocateVirtualMemory");
_NtCreateThreadEx NtCreateThreadEx = Get_NtCreateThreadEx("NtCreateThreadEx");
_NtProtectVirtualMemory NtProtectVirtualMemory = Get_NtProtectVirtualMemory("NtProtectVirtualMemory");
_NtFreeVirtualMemory NtFreeVirtualMemory = Get_NtFreeVirtualMemory("NtFreeVirtualMemory");

bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize,
    bool ClearHeader, bool ClearNonNeededSections, bool AdjustProtections, bool SEHExceptionSupport,
    DWORD fdwReason, LPVOID lpReserved)
{

    IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
    IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
    IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
    BYTE* pTargetBase = nullptr;

    NTSTATUS status = NULL;

    if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != MZ) {
        ILog("[!] Dll isn't correct\n");
        return false;
    }
    else {
        ILog("[+] Dll is correct\n");
    }

    pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
    pOldOptHeader = &pOldNtHeader->OptionalHeader;
    pOldFileHeader = &pOldNtHeader->FileHeader;

    if (pOldFileHeader->Machine != CURRENT_ARCH) {
        ILog("[!] Invalid platform\n");
        return false;
    }
    else {
        ILog("[+] Valid platform\n");
    }

    if (NtAllocateVirtualMemory == nullptr) {
        ILog("[!] Invalid NtAVM\n");
        return false;
    }
    if (NtCreateThreadEx == nullptr) {
        ILog("[!] Invalid NtCTE");
        return false;
    }
    if (NtProtectVirtualMemory == nullptr) {
        ILog("[!] Invalid NtPVM");
        return false;
    }
    if (NtFreeVirtualMemory == nullptr) {
        ILog("[!] Invalid NtPVM");
        return false;
    }

    SIZE_T sizeOfImage = pOldOptHeader->SizeOfImage;

    status = NtAllocateVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pTargetBase), 0, &sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        ILog("[!] Memory allocation target base failed 0x%X\n", status);
        return false;
    }
    
    if (pTargetBase == nullptr) {
        ILog("[!] Base is nullptr\n");
        return false;
    }

    DWORD oldp = 0;

    NtProtectVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pTargetBase), &sizeOfImage, PAGE_READWRITE, &oldp);

    MANUAL_MAPPING_DATA data{ 0 };
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
    data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else 
    SEHExceptionSupport = false;
#endif
    data.pbase = pTargetBase;
    data.fdwReasonParam = fdwReason;
    data.reservedParam = lpReserved;
    data.SEHSupport = SEHExceptionSupport;

    if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr)) { 
        ILog("[-] Can't write header 0x%X\n", GetLastError());
        NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pTargetBase), 0, MEM_RELEASE);
        return false;
    }

    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);

    for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
                ILog("[-] Can't write sections: 0x%x\n", GetLastError());
                NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pTargetBase), 0, MEM_RELEASE);
                return false;
            }
        }
    }

    BYTE* MappingDataAlloc = nullptr;
    SIZE_T sizeOfMappingData = sizeof(MANUAL_MAPPING_DATA);

    status = NtAllocateVirtualMemory(hProc, reinterpret_cast<PVOID*>(&MappingDataAlloc), 0, &sizeOfMappingData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        ILog("[!] Allocation mapping data failed (ex) 0x%X\n", status);
        NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pTargetBase), 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
        ILog("[!] Can't write mapping data 0x%X\n", GetLastError());
        NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pTargetBase), 0, MEM_RELEASE);
        NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&MappingDataAlloc), 0, MEM_RELEASE);
        return false;
    }

    void* pShellCode = nullptr;
    SIZE_T shellCodeSize = 0x1000;

    status = NtAllocateVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pShellCode), 0, &shellCodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        ILog("[!] Memory shellcode allocation failed (ex) 0x%X\n", status);
        NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pTargetBase), 0, MEM_RELEASE);
        NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&MappingDataAlloc), 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProc, pShellCode, Shellcode, 0x1000, nullptr)) {
        ILog("[!] Can't write shellcode 0x%X\n", GetLastError());
        NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pTargetBase), 0, MEM_RELEASE);
        NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&MappingDataAlloc), 0, MEM_RELEASE);
        NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pShellCode), 0, MEM_RELEASE);
        return false;
    } 

    HANDLE hThread = nullptr;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES objectAttributes;
    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);

    DWORD old;
    NtProtectVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pShellCode), &shellCodeSize, PAGE_EXECUTE_READ, &old);
    NtProtectVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pTargetBase), &sizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &objectAttributes, hProc, reinterpret_cast<PVOID>(pShellCode), MappingDataAlloc, 0, 0, 0, 0, nullptr);

    if (!NT_SUCCESS(status)) {
        ILog("[!] Thread creation failed 0x%X\n", status);
        NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pTargetBase), 0, MEM_RELEASE);
        NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&MappingDataAlloc), 0, MEM_RELEASE);
        NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pShellCode), 0, MEM_RELEASE);
        return false;
    }

    if (!hThread) {
        ILog("[!] Thread is null 0x%X\n", GetLastError());
        NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pTargetBase), 0, MEM_RELEASE);
        NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&MappingDataAlloc), 0, MEM_RELEASE);
        NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pShellCode), 0, MEM_RELEASE);
        return false;
    }
    
    CloseHandle(hThread);

    HINSTANCE hCheck = NULL;
    while (!hCheck) {
        DWORD exitcode = 0;
        GetExitCodeProcess(hProc, &exitcode);
        if (exitcode != STILL_ACTIVE) {
            ILog("[!] Process crashed, exit code: %d\n", exitcode);
            return false;
        }

        MANUAL_MAPPING_DATA data_checked{ 0 };
        ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
        hCheck = data_checked.hMod;

        if (hCheck == (HINSTANCE)0x404040) {
            ILog("[!] Wrong mapping ptr\n");
            NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pTargetBase), 0, MEM_RELEASE);
            NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&MappingDataAlloc), 0, MEM_RELEASE);
            NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pShellCode), 0, MEM_RELEASE);
            return false;
        }
        else if (hCheck == (HINSTANCE)0x505050) {
            ILog("[-] WARNING: Exception support failed!\n");
        }
    }

    NtProtectVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pTargetBase), &sizeOfImage, PAGE_EXECUTE_READ, &old);

    BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
    if (emptyBuffer == nullptr) {  
        ILog("[-] Unable to allocate memory\n");
    }
    else {
        memset(emptyBuffer, 0, 1024 * 1024 * 20);
    }

    if (ClearHeader) {
        if (!WriteProcessMemory(hProc, pTargetBase, emptyBuffer, 0x1000, nullptr)) {
            ILog("[-] WARNING!: Can't clear HEADER\n");
        }
    }

    if (ClearNonNeededSections) {
        pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
        for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->Misc.VirtualSize) {
                if ((SEHExceptionSupport ? 0 : strcmp((char*)pSectionHeader->Name, ".pdata") == 0) ||
                    strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 ||
                    strcmp((char*)pSectionHeader->Name, ".reloc") == 0) {
                    if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr)) {
                        ILog("[-] Can't clear section %s: 0x%x\n", pSectionHeader->Name, GetLastError());
                    }
                }
            }
        }
    }

    if (AdjustProtections) {
        pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
        for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->Misc.VirtualSize) {
                DWORD old = 0;
                DWORD newP = PAGE_READONLY;

                SIZE_T sectionVSize = pSectionHeader->Misc.VirtualSize;

                if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
                    newP = PAGE_READWRITE;
                }
                else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
                    newP = PAGE_EXECUTE_READ;
                }

                BYTE* sectionBase = pTargetBase + pSectionHeader->VirtualAddress;

                status = NtProtectVirtualMemory(hProc, reinterpret_cast<PVOID*>(&sectionBase), &sectionVSize, newP, &old);

                if (!NT_SUCCESS(status)) {
                    ILog("[-] FAIL: section %s not set as %lX\n", (char*)pSectionHeader->Name, newP);
                }
            }
        }
        DWORD old = 0;
        SIZE_T firstSectionSize = IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress;
        NtProtectVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pTargetBase + pSectionHeader->VirtualAddress), &firstSectionSize, PAGE_READONLY, &old);
    }

    if (!WriteProcessMemory(hProc, pShellCode, emptyBuffer, 0x1000, nullptr)) {
        ILog("[-] WARNING: Can't clear shellcode\n");
    }
    if (!NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&pShellCode), 0, MEM_RELEASE)) {
        ILog("[-] WARNING: can't release shellcode memory\n");
    }
    if (!NtFreeVirtualMemory(hProc, reinterpret_cast<PVOID*>(&MappingDataAlloc), 0, MEM_RELEASE)) {
        ILog("[-] WARNING: can't release mapping data memory\n");
    }

    return true;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
    if (!pData) {
        pData->hMod = (HINSTANCE)0x404040;
        return;
    }

    BYTE* pBase = pData->pbase;
    auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

    auto _LoadLibraryA = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
    auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif
    auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

    BYTE* LocationDelta = pBase - pOpt->ImageBase;
    if (LocationDelta) {
        if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
            auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
            while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
                UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

                for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
                    if (RELOC_FLAG(*pRelativeInfo)) {
                        UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                        *pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
                    }
                }
                pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
            }
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDescr->Name) {
            char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);

            ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

            if (!pThunkRef)
                pThunkRef = pFuncRef;

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
                }
                else {
                    auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
                }
            }
            ++pImportDescr;
        }
    }

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback)
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }

    bool ExceptionSupportFailed = false;

#ifdef _WIN64

    if (pData->SEHSupport) {
        auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excep.Size) {
            if (!_RtlAddFunctionTable(
                reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
                excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
                ExceptionSupportFailed = true;
            }
        }
    }

#endif

    _DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

    if (ExceptionSupportFailed)
        pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
    else
        pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}