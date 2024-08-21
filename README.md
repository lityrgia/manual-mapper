# ☂ Introduction

It's manual mapper which is mapping dll into process using function from ntdll (NtCreateThreadEx, NtAllocateVirtualMemory,  etc), 
and hijacking process by duplicating it's handle to process. (It's sometimes crashing, idk why)

![изображение](https://github.com/user-attachments/assets/9fa7be2f-5c2d-4ac9-a93e-858f5b2ef3a1)


# ⚡ How-to-use

1. Run mapper as administrator
2. Paste your dll path, example (witch.dll, B:\Folders\good.dll)
3. Enter process name, (minecraft.exe, cs2.exe)
4. Wait till inject end

# ☕ Credits

Thanks to https://github.com/TheCruZ for manual mapper base
