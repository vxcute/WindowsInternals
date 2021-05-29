#include "nt.hpp"

template <typename T>
auto GetRoutineAddress(std::string routine_name, std::string module_name) -> T
{
    HMODULE ntdll = GetModuleHandleA(module_name.c_str());
    if (ntdll) {
        T RoutineAddress = (T)GetProcAddress(ntdll, routine_name.c_str());
        if (RoutineAddress)
            return RoutineAddress;
        return nullptr;
    }
    return nullptr;
}

auto GetNtosImageBase1() -> PVOID
{
    PVOID NtImageBase;
    _NtQuerySystemInformation NtQuerySystemInformation = GetRoutineAddress< _NtQuerySystemInformation>("NtQuerySystemInformation", "ntdll.dll");
    PRTL_PROCESS_MODULES ModuleInfo = reinterpret_cast<PRTL_PROCESS_MODULES>(VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (ModuleInfo) {
        if (NT_SUCCESS(NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, 1024 * 1024, nullptr)))
        {
            NtImageBase = ModuleInfo->Modules[0].ImageBase;
            if (NtImageBase)
                return NtImageBase;
            return nullptr;
        }
    }
    return nullptr;
}

auto GetNtosImageBase2() -> PVOID
{
    LPVOID lpImageBase[1024];
    DWORD Needed;
    if (EnumDeviceDrivers(lpImageBase, sizeof(lpImageBase), &Needed))
        return lpImageBase[0];
    return nullptr;
}

int main()
{
    std::cout << GetNtosImageBase1() << std::endl;
    std::cout << GetNtosImageBase2() << std::endl;
    return 0;
}
