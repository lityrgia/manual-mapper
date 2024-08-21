#pragma once
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <Windows.h>

#define SeDebugPriv 20
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define NtCurrentProcess ( (HANDLE)(LONG_PTR) -1 ) 
#define ProcessHandleType 0x7
#define SystemHandleInformation 16 



typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWCH   Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;



typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	ULONG ProcessId;
	BYTE ObjectTypeName;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;




typedef NTSTATUS(NTAPI* _RtlAdjustPrivilege)(
	ULONG Privilege,
	BOOLEAN Enable,
	BOOLEAN CurrentThread,
	PBOOLEAN Enabled
	);


typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtOpenProcess)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
	);

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass, 
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);


_NtOpenProcess Get_NtOpenProcess(const char* name)
{
	HMODULE ntdll = GetModuleHandleA("ntdll");
	_NtOpenProcess NtOpenProcess = (_NtOpenProcess)GetProcAddress(ntdll, name);

	return (_NtOpenProcess)NtOpenProcess;
}

_NtDuplicateObject Get_NtDuplicateObject(const char* name)
{
	HMODULE ntdll = GetModuleHandleA("ntdll");
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(ntdll, name);

	return (_NtDuplicateObject)NtDuplicateObject;
}

_NtQuerySystemInformation Get_NtQuerySystemInformation(const char* name)
{
	HMODULE ntdll = GetModuleHandleA("ntdll");
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, name);

	return (_NtQuerySystemInformation)NtQuerySystemInformation;
}

_RtlAdjustPrivilege Get_RtlAdjustPrivilege(const char* name)
{
	HMODULE ntdll = GetModuleHandleA("ntdll");

	_RtlAdjustPrivilege RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(ntdll, name);

	return (_RtlAdjustPrivilege)RtlAdjustPrivilege;
}

_OBJECT_ATTRIBUTES ObjectAttr(PUNICODE_STRING name, HANDLE hRoot, ULONG attributes, PSECURITY_DESCRIPTOR security)
{
	OBJECT_ATTRIBUTES object;

	object.Length = sizeof(OBJECT_ATTRIBUTES);

	object.Attributes = attributes;
	object.RootDirectory = hRoot;
	object.SecurityDescriptor = security;
	object.ObjectName = name;


	return object;
}

SYSTEM_HANDLE_INFORMATION* hInfo;

HANDLE hProcT = NULL;
HANDLE hProcess = NULL;
HANDLE HijackedProcess = NULL;

void CleanAndExit(const char* ErrorMessage)
{
	delete[] hInfo;

	hProcT ? CloseHandle(hProcT) : 0;

	std::cout << ErrorMessage << '\n';

}
bool IsHandleValid(HANDLE handle)
{
	if (handle == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	else if (handle)
		return true;
}

HANDLE GethijackedHandle(DWORD pID)
{

	_RtlAdjustPrivilege       RtlAdjustPrivilege = Get_RtlAdjustPrivilege("RtlAdjustPrivilege");
	_NtDuplicateObject        NtDuplicateObject = Get_NtDuplicateObject("NtDuplicateObject");
	_NtOpenProcess            NtOpenProcess = Get_NtOpenProcess("NtOpenProcess");
	_NtQuerySystemInformation NtQuerySystemInformation = Get_NtQuerySystemInformation("NtQuerySystemInformation");



	_OBJECT_ATTRIBUTES        ObjectAttributes = ObjectAttr(NULL, NULL, NULL, NULL);
	CLIENT_ID                 ClientID = { 0 };
	boolean                   OldPriv;



	RtlAdjustPrivilege(SeDebugPriv, TRUE, FALSE, &OldPriv);

	DWORD size = sizeof(SYSTEM_HANDLE_INFORMATION);

	hInfo = (SYSTEM_HANDLE_INFORMATION*) new byte[size];

	NTSTATUS ntRet = NULL;

	do
	{
		delete[] hInfo;

		size *= 1.5;

		try
		{
			hInfo = (PSYSTEM_HANDLE_INFORMATION) new byte[size];
		}
		catch (std::bad_alloc)
		{

			CleanAndExit("[!] Bad AlloC");
			system("PAUSE");
		}
		Sleep(1);

	} while ((ntRet = NtQuerySystemInformation(SystemHandleInformation, hInfo, size, NULL)) == STATUS_INFO_LENGTH_MISMATCH);



	if (!NT_SUCCESS(ntRet))
	{
		CleanAndExit("[!] NtQuery Didnt Success");
		system("PAUSE");
	}

	for (unsigned int i = 0; i < hInfo->HandleCount; ++i)
	{
		static int NumOfHandles = i;



		if (NumOfHandles > 100)
		{
			CleanAndExit("[!] Handle Leakage");
			system("PAUSE");
		}

		if (hInfo->Handles[i].ObjectTypeName != ProcessHandleType)
			continue;

		if (!IsHandleValid((HANDLE)hInfo->Handles[i].Handle))
			continue;



		ClientID.UniqueProcess = (DWORD*)hInfo->Handles[i].ProcessId;




		ntRet = NtOpenProcess(&hProcT, PROCESS_DUP_HANDLE, &ObjectAttributes, &ClientID);

		if (!IsHandleValid(hProcT) || !NT_SUCCESS(ntRet))
			continue;

		ntRet = NtDuplicateObject(hProcT, (HANDLE)hInfo->Handles[i].Handle, NtCurrentProcess, &HijackedProcess, PROCESS_ALL_ACCESS, 0, 0);

		if (!IsHandleValid(HijackedProcess) || !NT_SUCCESS(ntRet))
			continue;

		if (GetProcessId(HijackedProcess) == pID)
		{
			hProcess = HijackedProcess;
			break;
		}
		else
		{
			CloseHandle(HijackedProcess);
			hProcT ? CloseHandle(hProcT) : 0;
			continue;
		}
	}
	CleanAndExit("[+] Success");
	return hProcess;

}

namespace process {
	inline HANDLE hProc = nullptr;
	inline DWORD pID;
	inline bool isFound = false;
}
//uintptr_t client;

bool AttachProcess(const wchar_t* proc)
{
	PROCESSENTRY32 ProcEntry32;

	ProcEntry32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	while (Process32Next(hSnap, &ProcEntry32))
	{
		if (!wcscmp(ProcEntry32.szExeFile, proc))
		{ 
			process::isFound = true;

			process::pID = ProcEntry32.th32ProcessID;
			process::hProc = GethijackedHandle(process::pID);
			break;
		}
	}
	CloseHandle(hSnap);
	return true;
}
uintptr_t ModuleAddress(const char* proc)
{
	MODULEENTRY32 ModEntry32;

	ModEntry32.dwSize = sizeof(MODULEENTRY32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process::pID);

	uintptr_t result;

	while (Module32Next(hSnap, &ModEntry32))
	{
		if (!strcmp((char*)ModEntry32.szModule, proc))
		{
			result = (uintptr_t)ModEntry32.modBaseAddr;
			std::cout << "[+] Found: " << result << std::endl;
			break;
		}
	}
	CloseHandle(hSnap);
	return result;
}
