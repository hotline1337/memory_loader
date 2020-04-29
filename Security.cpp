#define CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <signal.h>
#include <iostream>
#include <stdio.h>
#include <conio.h>
#include <stdlib.h>
#include <intrin.h>       
#include <iphlpapi.h>
#include <cstdint>
#include <winternl.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include "Security.h"


#include <filesystem>
#include <future>

#include "xorstr.h"
#include "lazyimports.h"
#include "memory_injection.h"

UCHAR szFileSys[255], szVolNameBuff[255];
DWORD dwMFL, dwSysFlags;
DWORD dwSerial;
LPCTSTR szHD = "C:\\";

using namespace std;
#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

BOOLEAN BlockAPI(HANDLE hProcess, CHAR* libName, CHAR* apiName)
{
	CHAR pRet[] = { 0xC3 };
	HINSTANCE hLib = NULL;
	VOID* pAddr = NULL;
	BOOL bRet = FALSE;
	DWORD dwRet = 0;

	hLib = LoadLibrary(libName);
	if (hLib) {
		pAddr = (VOID*)GetProcAddress(hLib, apiName);
		if (pAddr) {
			if (WriteProcessMemory(hProcess,
				(LPVOID)pAddr,
				(LPVOID)pRet,
				sizeof(pRet),
				(size_t*)dwRet)) {
				if (dwRet) {
					bRet = TRUE;
				}
			}
		}
		FreeLibrary(hLib);
	}
	return bRet;
}

PVOID GetPEB()
{
  #ifdef _WIN64
	return (PVOID)__readgsqword(0x0C * sizeof(PVOID));
  #else
	return (PVOID)__readfsdword(0x0C * sizeof(PVOID));
  #endif
}
PVOID GetPEB64()
{
	PVOID pPeb = 0;
    #ifndef _WIN64
	if (IsWin8OrHigher())
	{
		BOOL isWow64 = FALSE;
		typedef BOOL(WINAPI* pfnIsWow64Process)(HANDLE hProcess, PBOOL isWow64);
		pfnIsWow64Process fnIsWow64Process = (pfnIsWow64Process)
			GetProcAddress(GetModuleHandleA("Kernel32.dll"), "IsWow64Process"); //no need to xor it
		if (fnIsWow64Process(GetCurrentProcess(), &isWow64))
		{
			if (isWow64)
			{
				pPeb = (PVOID)__readfsdword(0x0C * sizeof(PVOID));
				pPeb = (PVOID)((PBYTE)pPeb + 0x1000);
			}
		}
	}
    #endif
	return pPeb;
}

typedef struct _MY_SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} MY_SYSTEM_PROCESS_INFORMATION, * PMY_SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI* PNT_QUERY_SYSTEM_INFORMATION)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
);

PNT_QUERY_SYSTEM_INFORMATION OriginalNtQuerySystemInformation =
(PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandle("ntdll"),
	"NtQuerySystemInformation");

// Hooked function
NTSTATUS WINAPI HookedNtQuerySystemInformation(
	__in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout    PVOID                    SystemInformation,
	__in       ULONG                    SystemInformationLength,
	__out_opt  PULONG                   ReturnLength
)
{
	NTSTATUS status = OriginalNtQuerySystemInformation(SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength);
	if (SystemProcessInformation == SystemInformationClass && STATUS_SUCCESS == status)
	{
		// Loop through the list of processes
		PMY_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
		PMY_SYSTEM_PROCESS_INFORMATION pNext = (PMY_SYSTEM_PROCESS_INFORMATION)
			SystemInformation;

		do
		{
			pCurrent = pNext;
			pNext = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->
				NextEntryOffset);
			if (!wcsncmp(pNext->ImageName.Buffer, L"memory_loader.exe", pNext->ImageName.Length))
			{
				if (!pNext->NextEntryOffset)
				{
					pCurrent->NextEntryOffset = 0;
				}
				else
				{
					pCurrent->NextEntryOffset += pNext->NextEntryOffset;
				}
				pNext = pCurrent;
			}
		} while (pCurrent->NextEntryOffset != 0);
	}
	return status;
}

void __stdcall ProtectionThread()
{
	while (true) {
		LI_FN(TerminateProcess).get()(LI_FN(GetCurrentProcess).get()(), 0);
		PostQuitMessage(0);
		BYTE* trash = (BYTE*)("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
		PostQuitMessage(0);
		LI_FN(WriteProcessMemory).get()(GetCurrentProcess(), main, trash, 1024, 0);
		LI_FN(WriteProcessMemory).get()(GetCurrentProcess(), GetAsyncKeyState, trash, 1024, 0);
	}
}

namespace security
{
	namespace hardware
	{
		auto hotline_hwid = 473288157;
		void __stdcall check_hwid()
		{
			GetVolumeInformation(szHD, (LPTSTR)szVolNameBuff, 255, &dwSerial, &dwMFL, &dwSysFlags, (LPTSTR)szFileSys, 255);
			if (dwSerial != hotline_hwid)
			{
				ProtectionThread();
			}
		}
	}
	void __stdcall findwindow()
	{
		//! Recall that FindWindow will return NULL if it wasn't found
		if (FindWindowA(0, xorstr_("IDA v7.0.170914")) || FindWindowA(0, xorstr_("x64dbg")) || FindWindowA(0, xorstr_("Scylla x64 v0.9.8")) || FindWindowA(0, xorstr_("IAT Autosearch")))
		{
			ProtectionThread();
		}
		return;
	}
	void __stdcall isdebuggerpresent()
	{
		BOOL isdbgpresent = FALSE;
		if (IsDebuggerPresent())
		{
			ProtectionThread();
		}
		if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isdbgpresent))
		{
			if (isdbgpresent)
			{
				ProtectionThread();
			}
		}
		return;
	}
	void __stdcall outputdebugstring()
	{
		SetLastError(0);
		// Send a string to the debugger
		OutputDebugStringA(xorstr_("sylent anti-debug"));
		if (GetLastError() != 0)
		{
			ProtectionThread();
		}
		return;
	}
	void __stdcall blockapi()
	{
		HANDLE Process = GetCurrentProcess();
		BlockAPI(Process, (CHAR*)(xorstr_("NTDLL.DLL")), (CHAR*)(xorstr_("LdrLoadDll")));
	}
	void __stdcall ErasePE()
	{
		char* pBaseAddr = (char*)GetModuleHandle(NULL);
		DWORD dwOldProtect = 0;
		VirtualProtect(pBaseAddr, 4096, PAGE_READWRITE, &dwOldProtect);
		ZeroMemory(pBaseAddr, 4096);
		VirtualProtect(pBaseAddr, 4096, dwOldProtect, &dwOldProtect);
	}
	void __stdcall CheckNtGlobalFlag()
	{
		PVOID pPeb = GetPEB();
		PVOID pPeb64 = GetPEB64();
		DWORD offsetNtGlobalFlag = 0;
        #ifdef _WIN64
		      offsetNtGlobalFlag = 0xBC;
        #else
		      offsetNtGlobalFlag = 0x68;
        #endif
		DWORD NtGlobalFlag = *(PDWORD)((PBYTE)pPeb + offsetNtGlobalFlag);
		if (NtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
		{
			ProtectionThread();
		}
		if (pPeb64)
		{
			DWORD NtGlobalFlagWow64 = *(PDWORD)((PBYTE)pPeb64 + 0xBC);
			if (NtGlobalFlagWow64 & NT_GLOBAL_FLAG_DEBUGGED)
			{
				ProtectionThread();
			}
		}
	}
	void __stdcall forcedebug()
	{
		HANDLE hProcess = NULL;
		DEBUG_EVENT de;
		PROCESS_INFORMATION pi;
		STARTUPINFO si;
		ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		ZeroMemory(&si, sizeof(STARTUPINFO));
		ZeroMemory(&de, sizeof(DEBUG_EVENT));
		GetStartupInfo(&si);
		// Create the copy of ourself
		CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE,
			DEBUG_PROCESS, NULL, NULL, &si, &pi);
		// Continue execution
		ContinueDebugEvent(pi.dwProcessId, pi.dwThreadId, DBG_CONTINUE);
		// Wait for an event
		WaitForDebugEvent(&de, INFINITE);
	}
}