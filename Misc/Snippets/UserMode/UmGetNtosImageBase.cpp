#include <nt.hpp>
#include <iostream>
#include <Windows.h>
#include <Psapi.h>

#define ARRAY_SIZE 1024

PVOID GetNtosImageBase1()
{
    LPVOID ImageBase[ARRAY_SIZE];

    DWORD Needed;
    
    if (EnumDeviceDrivers(ImageBase, ARRAY_SIZE, &Needed))
    {
        return ImageBase[0];
    }

    return nullptr;
}

template <typename T>
T GetRoutineAddress(PCSTR RoutineName, PCSTR ModuleName) 
{
    HMODULE hModule = GetModuleHandleA(ModuleName);

    if (hModule)
    {
        T RoutineAddress = (T)GetProcAddress(hModule, RoutineName);

        if (RoutineAddress)
        {
            return RoutineAddress;
        }
    }

    return nullptr;
}

PVOID GetNtosImageBase2()
{
    PVOID NtosImageBase;

    _NtQuerySystemInformation NtQuerySystemInformation;

    PRTL_PROCESS_MODULES ModuleInfo;

    NtQuerySystemInformation = GetRoutineAddress<_NtQuerySystemInformation>("NtQuerySystemInformation", "ntdll.dll");
    
    ModuleInfo = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, MEM_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (ModuleInfo) 
    {
        if (NT_SUCCESS(NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, MEM_SIZE, nullptr)))
        {
            NtosImageBase = ModuleInfo->Modules[0].ImageBase;
            
            if (NtosImageBase) 
            {
                VirtualFree(&ModuleInfo, MEM_SIZE, MEM_RELEASE | MEM_DECOMMIT);
                return NtosImageBase;
            }   
        }
    }

    VirtualFree(&ModuleInfo, MEM_SIZE, MEM_RELEASE | MEM_DECOMMIT);
    return nullptr;
}

int main()
{
    std::cout << GetNtosImageBase1() << " =====[+]===== " << GetNtosImageBase2() << std::endl;

	return 0;
}
