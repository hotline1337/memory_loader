#include "memory_injection.h"
#include "RemoteOps.h"
#include "xorstr.h"

#include <vector>
#include <tlHelp32.h>
#include <string>
#include <iostream>
#include <stdio.h>
#include <Psapi.h>
#include <Windows.h>
#include <algorithm>  //for std::generate_n
#include <string>
#include <vector>
#include <random>
#include <functional> //for std::function

using namespace std;
int __cdecl print_prefix_of(const char* msg, void* overflow)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 2);
	printf(xorstr_("[*] "));
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);

	return printf(msg, overflow);
}
int __cdecl print_prefix_wof(const char* msg)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 2);
	printf(xorstr_("[*] "));
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);

	return printf(msg);
}
std::string random_string_uppercase(size_t length)
{
	auto randchar = []() -> char
	{
		const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}
bool isRunning(LPCSTR pName)
{
	HWND hwnd;
	hwnd = FindWindow(NULL, pName);
	if (hwnd != 0) {
		return true;
	}
	else {
		return false;
	}
}
DWORD GetTargetThreadIDFromProcName(const char* ProcName)
{
	// create a handle to the toolhelp32 library
	HANDLE thSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (thSnapShot == INVALID_HANDLE_VALUE)
	{
		//MessageBox(NULL, "Error: Unable to create toolhelp snapshot!", "2MLoader", MB_OK);
		printf(xorstr_("Error: Unable to create toolhelp snapshot!"));
		return 0;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	// iterate over the currently running processes to find the one whose name matches `ProcName`
	BOOL retval = Process32First(thSnapShot, &pe);
	while (retval)
	{
		if (!strcmp(pe.szExeFile, ProcName))
		{
			// names match
			// close the handle and return the process id
			CloseHandle(thSnapShot);
			return pe.th32ProcessID;
		}
		retval = Process32Next(thSnapShot, &pe);
	}

	// unable to find the process
	// close the handle and return 0 signalling that we were unable to find the process id

	printf(xorstr_("Error: unable to find the process id!\n"));

	CloseHandle(thSnapShot);

	return 0;
}

bool Inject(char* procName, char* dllName)
{
	// Get the process id from the process name
	DWORD processID = GetTargetThreadIDFromProcName(procName);
	return Inject(processID, dllName);
}

bool Inject(DWORD processID, char* relativeDllName)
{
	if (processID == NULL)
		return false; // unable to find the process name

	HANDLE Proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if (Proc == NULL)
	{
		std::string error = xorstr_("OpenProcess() failed: ") + GetLastError();
		MessageBox(NULL, error.c_str(), xorstr_("memory"), MB_OK | MB_ICONERROR);
		exit(-1);
	}

	char DllName[MAX_PATH];
	GetFullPathNameA(relativeDllName, MAX_PATH, DllName, NULL);

	LPVOID LoadLib = (LPVOID)GetProcAddress(GetModuleHandle(xorstr_("kernel32.dll")), xorstr_("LoadLibraryA"));
	if (!LoadLib) {
		printf(xorstr_("Could note get real address of LoadLibraryA from kernel32.dll!\n"));
		printf(xorstr_("LastError : 0x%x\n"), GetLastError());
		system(xorstr_("PAUSE"));
		return false;
	}
	print_prefix_of(xorstr_("Patching LoadLibraryA at: 0x%p\n"), (void*)LoadLib);

	LPVOID RemoteString = VirtualAllocEx(Proc, nullptr, strlen(DllName), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!RemoteString) {
		printf(xorstr_("Could not allocate Memory in target process\n"));
		printf(xorstr_("LastError : 0x%x\n"), GetLastError());
		system(xorstr_("PAUSE"));
		return false;
	}
	print_prefix_of(xorstr_("Memory allocated at: 0x%p\n"), (void*)RemoteString);

	BOOL WPM = WriteProcessMemory(Proc, RemoteString, (LPVOID)DllName, strlen(DllName), nullptr);
	if (!WPM) {
		printf(xorstr_("Could not write into the allocated memory\n"));
		printf(xorstr_("LastError : 0x%x\n"), GetLastError());
		system(xorstr_("PAUSE"));
		return false;
	}

	//CRT Method
	   //CreateRemoteThread(Proc, nullptr, NULL, (LPTHREAD_START_ROUTINE)LoadLib, (LPVOID)RemoteString, NULL, nullptr);
	//CRT Method

	HMODULE modNtDll = GetModuleHandle(xorstr_("ntdll.dll"));
	if (!modNtDll) {
		printf(xorstr_("Failed to get module handle for ntdll.dll\n"));
		printf(xorstr_("LastError : 0x%x\n"), GetLastError());
		system(xorstr_("PASUE"));
		return false;
	}

	LPFUN_NtCreateThreadEx funNtCreateThreadEx = (LPFUN_NtCreateThreadEx)GetProcAddress(modNtDll, xorstr_("NtCreateThreadEx"));
	if (!funNtCreateThreadEx) {
		printf(xorstr_("Failed to get NtCreateThreadEx function address from ntdll.dll\n"));
		printf(xorstr_("LastError: 0x%x\n"), GetLastError());
		system(xorstr_("PASUE"));
		return false;
	}
	std::string ntloaddriver_name;
	ntloaddriver_name += xorstr_("NtLoadDriver: (");
	ntloaddriver_name += xorstr_("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
	ntloaddriver_name += random_string_uppercase(12);
	ntloaddriver_name += xorstr_(") returned 00000000\n");
	print_prefix_wof(xorstr_("Kernel: ntoskrnl.exe @ fffff8030a000000\n"));
	print_prefix_wof(ntloaddriver_name.c_str());

#ifdef DEBUG_NTBUFFER
	NtCreateThreadExBuffer ntBuffer;
	memset(&ntBuffer, 0, sizeof(NtCreateThreadExBuffer));
	ULONG temp0[2];
	ULONG temp1;
	ntBuffer.Size = sizeof(NtCreateThreadExBuffer);
	ntBuffer.Unknown1 = 0x10003;
	ntBuffer.Unknown2 = sizeof(temp0);
	ntBuffer.Unknown3 = temp0;
	ntBuffer.Unknown4 = 0;
	ntBuffer.Unknown5 = 0x10004;
	ntBuffer.Unknown6 = sizeof(temp1);
	ntBuffer.Unknown7 = &temp1;
	ntBuffer.Unknown8 = 0;
#endif

	HANDLE hThread = nullptr;
	NTSTATUS status = funNtCreateThreadEx(
		&hThread,
		THREAD_ALL_ACCESS,
		nullptr,
		Proc,
		(LPTHREAD_START_ROUTINE)LoadLib,
		RemoteString,
		NULL, //start instantly
		NULL,
		NULL,
		NULL,
		nullptr
	);

	if (!hThread) {
		printf(xorstr_("\nNtCreateThreadEx failed\n"));
		printf(xorstr_("LastError: 0x%x\n"), GetLastError());
		if (VirtualFreeEx(Proc, RemoteString, NULL, MEM_RELEASE)) {
			//VirtualFreeEx(hProc, reinterpret_cast<int*>(pDllPath) + 0X010000, 0, MEM_RELEASE);
			printf(xorstr_("Memory was freed in target process\n"));
			Sleep(1000);
		}
		system(xorstr_("PAUSE"));
		return false;
	}
	print_prefix_wof(xorstr_("Cleaning..."));

	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(Proc, RemoteString, NULL, MEM_RELEASE);

	CloseHandle(hThread);
	CloseHandle(Proc);
	return true;
}

void ErasePEHeader(HINSTANCE hModule)
{
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery((LPCVOID)hModule, &mbi, sizeof(mbi));
	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect);
	ZeroMemory((PVOID)hModule, 4096);
	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, NULL);
	FlushInstructionCache(GetCurrentProcess(), (LPCVOID)mbi.BaseAddress, mbi.RegionSize);
	return;
}

void eraseHeaders(HINSTANCE hInst)
{
	PIMAGE_DOS_HEADER pDoH;
	PIMAGE_NT_HEADERS pNtH;
	DWORD i, ersize, protect;
	if (!hInst) return;

	pDoH = (PIMAGE_DOS_HEADER)(hInst);
	pNtH = (PIMAGE_NT_HEADERS)((LONG)hInst + ((PIMAGE_DOS_HEADER)hInst)->e_lfanew);
	ersize = sizeof(IMAGE_DOS_HEADER);

	if (VirtualProtect(pDoH, ersize, PAGE_READWRITE, &protect)) {
		for (i = 0; i < ersize; i++) {
			*(BYTE*)((BYTE*)pDoH + i) = 0;
		}
	}

	ersize = sizeof(IMAGE_NT_HEADERS);

	if (pNtH && VirtualProtect(pNtH, ersize, PAGE_READWRITE, &protect)) {
		for (i = 0; i < ersize; i++) {
			*(BYTE*)((BYTE*)pNtH + i) = 0;
		}
	}
	return;
}