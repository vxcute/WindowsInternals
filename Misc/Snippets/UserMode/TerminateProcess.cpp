#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <TlHelp32.h>

#pragma comment(lib, "Psapi")
#pragma comment(lib,"ntdll.lib")

typedef NTSTATUS(NTAPI* _NtGetNextProcess)(
	_In_ HANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ULONG HandleAttributes,
	_In_ ULONG Flags,
	_Out_ PHANDLE NewProcessHandle
	);

std::vector<std::string> procs =
{
	"ProcessHacker.exe", 
	"Wireshark.exe"
};


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

auto terminate_process() -> void
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	HANDLE currp = nullptr;
	char buf[1024] = { 0 };

	_NtGetNextProcess NtGetNextProcess = GetRoutineAddress<_NtGetNextProcess>("NtGetNextProcess", "ntdll.dll");

	for (int i = 0; i < procs.size(); i++) {
		do {
			GetModuleFileNameExA(currp, 0, buf, MAX_PATH);
			if (strstr(buf, procs[i].c_str()))
				TerminateProcess(currp, -1);
		} while (!NtGetNextProcess(currp, MAXIMUM_ALLOWED, 0, 0, &currp));
	}
}

int main()
{
	terminate_process();
	return 0;
}
