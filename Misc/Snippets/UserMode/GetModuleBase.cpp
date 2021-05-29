#include <iostream>
#include <Windows.h>
#include <Psapi.h>
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

template <typename T = uintptr_t*>
auto get_modbase_addr(std::string procname, int procId) -> T {

	HANDLE modSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);

	if (modSnap) {
		MODULEENTRY32 modEntry{};
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(modSnap, &modEntry)) {
			do {
				if (std::strcmp(procname.c_str(), reinterpret_cast<const char*>(modEntry.szModule)))
					return (T)modEntry.modBaseAddr;
			} while (Module32Next(modSnap, &modEntry));
		}
	}

	else
		std::cout << "Error Optaining Handle" << std::endl;
}

int main()
{
	std::cout << get_modbase_addr("ProcessHacker.exe", get_proc_id("ProcessHacker.exe")) << std::endl;
	return 0;
}
