// wellknown one

#include <iostream>
#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")
#define SeShutDownPrivilage 19

typedef  NTSTATUS (NTAPI *_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);

typedef NTSTATUS(NTAPI* _NtRaiseHardError)(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, 
	PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);


template <typename T>
auto GetRoutineAddress(std::string routine_name, std::string module_name) -> T
{
    HMODULE mod = GetModuleHandleA(module_name.c_str());
    if (mod) {
        T RoutineAddress = (T)GetProcAddress(mod, routine_name.c_str());
        if (RoutineAddress)
            return RoutineAddress;
        return nullptr;
    }
    return nullptr;
}


void bsod()
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	BOOLEAN OldValue;

	ULONG Respone;

	if (ntdll != nullptr) {

		_RtlAdjustPrivilege RtlAdjustPrivilege = GetRoutineAddress<_RtlAdjustPrivilege>("RtlAdjustPrivilege", "ntdll.dll");

		_NtRaiseHardError NtRaiseHardError = GetRoutineAddress<_NtRaiseHardError>("NtRaiseHardError", "ntdll.dll");

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
