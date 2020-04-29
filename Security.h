#pragma once

namespace security
{
	namespace hardware
	{
		extern void __stdcall check_hwid();
	}
	extern void __stdcall findwindow();
	extern void __stdcall isdebuggerpresent();
	extern void __stdcall outputdebugstring();
	extern void __stdcall blockapi();
	extern void __stdcall ErasePE();
	extern void __stdcall CheckNtGlobalFlag();
	extern void __stdcall forcedebug();
}
