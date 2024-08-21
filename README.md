# ☂ Introduction

This is a manual mapper that injects a DLL into a process using functions from ntdll (such as NtCreateThreadEx, NtAllocateVirtualMemory, etc.) 
and hijacks the process by duplicating its handle. (it sometimes crashes, idk why)

![изображение](https://github.com/user-attachments/assets/9fa7be2f-5c2d-4ac9-a93e-858f5b2ef3a1)


# ⚡ How-to-use

1. Run mapper as administrator
2. Paste your dll path, example (witch.dll, B:\Folders\good.dll)
3. Enter process name, (minecraft.exe, cs2.exe)
4. Wait till inject end

# 🏠 Build

x86/x64 Release

# ☕ Credits

Thanks to https://github.com/TheCruZ for manual mapper base
