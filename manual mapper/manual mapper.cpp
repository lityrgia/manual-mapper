#include <iostream>
#include <string>
#include <stdio.h>
#include <fstream>
#include <Windows.h>
#include <Shlwapi.h>
#include <ctime>
#include <cstdlib>
#include <memory> 
#include "memory.h"

#pragma comment(lib, "Shlwapi.lib")

#include "hijacker.h"
#include "injector.h"

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

bool IsValidPath(const std::wstring& path) {
    return PathFileExists(path.c_str()) != FALSE;
}

std::string generateRandomName(size_t length) {
    const std::string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string result;
    result.resize(length);
    for (size_t i = 0; i < length; ++i) {
        result[i] = characters[rand() % characters.size()];
    }
    return result;
}

int main()
{
    std::srand(static_cast<unsigned int>(std::time(nullptr)));

    const size_t nameLength = 10;

    std::string randomName = generateRandomName(nameLength);
    SetConsoleTitleA(randomName.c_str());

    const size_t BUFFER_SIZE = 260;
    std::unique_ptr<wchar_t[]> dllPath(new wchar_t[BUFFER_SIZE]);

    printf("[*] Enter dll path: ");

    std::wcin.getline(dllPath.get(), BUFFER_SIZE);

    if (GetFileAttributes(dllPath.get()) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] Can't find %ls\n", dllPath.get());
        system("PAUSE");
        return -4; 
    }
    else {
        printf("[+] Found dll\n");
    }

    std::wstring processName{};

    printf("[*] Enter process name: ");

    std::getline(std::wcin, processName);

    AttachProcess(processName.c_str());

    if (process::hProc == nullptr) {
        printf("[!] Error while attaching process\n");
        system("PAUSE");
        return -1;
    }
    else {
        printf("[+] Process attached!\n");
    }

    std::ifstream File(dllPath.get(), std::ios::binary | std::ios::ate);

    if (File.fail()) {
        printf("[!] Opening the dll failed: %X\n", (DWORD)File.rdstate());
        File.close();
        CloseHandle(process::hProc);
        system("PAUSE");
        return -5;
    }

    auto FileSize = File.tellg();
    if (FileSize < 0x1000) {
        printf("[!] Dll size invalid.\n");
        File.close();
        CloseHandle(process::hProc);
        system("PAUSE");
        return -6;
    }

    std::unique_ptr<BYTE[]> pSrcData(new BYTE[(UINT_PTR)FileSize]);

    File.seekg(0, std::ios::beg);
    File.read((char*)(pSrcData.get()), FileSize);
    File.close();

    printf("[+] Injecting...\n");
    if (!ManualMapDll(process::hProc, pSrcData.get(), FileSize, true, true, true, false, DLL_PROCESS_ATTACH, NULL)) {
        printf("[!] Error while injecting.\n");
        CloseHandle(process::hProc);
        system("PAUSE");
        return -8;
    }
    else {
        printf("[+] Succesfly injected\n");
        CloseHandle(process::hProc);
        system("pause");
        return 1;
    }
}