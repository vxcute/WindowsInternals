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

auto get_proc_id(std::string procname) -> DWORD
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	HANDLE currp = nullptr;
	char buf[1024] = { 0 };

	_NtGetNextProcess NtGetNextProcess = (_NtGetNextProcess)GetProcAddress(ntdll, "NtGetNextProcess");

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
