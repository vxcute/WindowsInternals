// This Technique doesn't work with process related to critical windows processes like winlogon.exe will always return garbage value because it couldn't optain a handle to it bassicly 

#include <iostream>
#include <Windows.h>
#include <Psapi.h>

#pragma comment(lib, "Psapi")
#pragma comment(lib,"ntdll.lib")

typedef NTSTATUS(NTAPI* _NtGetNextProcess)(
	_In_ HANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ULONG HandleAttributes,
	_In_ ULONG Flags,
	_Out_ PHANDLE NewProcessHandle
	);


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

auto get_proc_id(std::string procname) -> DWORD
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	HANDLE currp = nullptr;
	char buf[1024] = { 0 };

	_NtGetNextProcess NtGetNextProcess = GetRoutineAddress<_NtGetNextProcess>("NtGetNextProcess", "ntdll.dll");

	while (!NtGetNextProcess(currp, MAXIMUM_ALLOWED, 0, 0, &currp)) {
		GetModuleFileNameExA(currp, 0, buf, MAX_PATH);
		if (strstr(buf, procname.c_str()))
			return GetProcessId(currp);
	}
}

int main()
{
	  std::cout << "ProcessHacker ProcID: " << get_proc_id("ProcessHacker.exe") << std::endl;
    return 0;
}
