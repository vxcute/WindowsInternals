// Kernel Mode 

#include <ntddk.h>
#include "nt.hpp"
#include "ia32.hpp"
#include <intrin.h>

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath);
VOID Unload(PDRIVER_OBJECT DriverObject);

template <class T>
auto GetRoutineAddress(UNICODE_STRING RoutineName) -> T
{
    __try {
        if (RoutineName.Buffer) {
            T RoutineAddress = (T)MmGetSystemRoutineAddress(&RoutineName);
            if (RoutineAddress)
                return RoutineAddress;
        }
        else
            DbgPrint("Couldn't Find Routine Address");
    }
    __except (1) {}
}

auto GetNtosImageBase1() -> PVOID
{
	__try {
		PSYSTEM_MODULE_INFORMATION ModInfo = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePool(NonPagedPool, 1024 * 1024));
		if (ModInfo) {
			UNICODE_STRING RoutineName = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
			_ZwQuerySystemInformation ZwQuerySystemInformation = GetRoutineAddress< _ZwQuerySystemInformation>(RoutineName);
			NTSTATUS SysInfoDrv = ZwQuerySystemInformation(SystemModuleInformation, ModInfo, 4096, nullptr);
			return ModInfo->Module[0].ImageBase;
		}
		else
			DbgPrint("Failed To Allocate ModuleInfo Memory");
	}

	__except(1){}
}

auto GetNtosImageBase2() -> PVOID
{
	__try {
		UNICODE_STRING RoutineName = RTL_CONSTANT_STRING(L"RtlLookupFunctionEntry");
		_RtlLookupFunctionEntry RtlLookupFunctionEntry = GetRoutineAddress< _RtlLookupFunctionEntry>(RoutineName);
		DWORD64 ImageBase;
		RtlLookupFunctionEntry((DWORD64)&MmFreeContiguousMemorySpecifyCache, &ImageBase, nullptr);
		if (ImageBase)
			return reinterpret_cast<PVOID>(ImageBase);
		else
			DbgPrint("Failed To Get ntoskrnl.exe ImageBase :(");
	}
	__except(1){}
}

auto GetNtosImageBase3() -> PVOID {

	auto entry = __readmsr(IA32_LSTAR) & ~0xfff;
	do {
		auto addr = *(USHORT*)entry;
		if (addr == 0x5A4D) {
		     for (int i = entry; i < entry + 0x400; i += 8) 
		     {
		     	if (*(ULONG64*)i == PAGELK)
		     		return (PVOID)entry;
		     }
		}
	     entry -= 0x1000;
	} while (true);
	return nullptr;
}

auto GetNtosImageBase4() -> PVOID
{
	__try {
		UNICODE_STRING RoutineName = RTL_CONSTANT_STRING(L"RtlPcToFileHeader");
		_RtlPcToFileHeader RtlPcToFileHeader = GetRoutineAddress<_RtlPcToFileHeader>(RoutineName);
		PVOID NtosImageBase;
		RtlPcToFileHeader(&MmFreeContiguousMemorySpecifyCache, &NtosImageBase);
		return NtosImageBase;
	}
	__except(1){}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
	DbgPrint("ntoskrnl.exe base address: %p", GetNtosImageBase1());
	DbgPrint("ntoskrnl.exe base address: %p", GetNtosImageBase2());
	DbgPrint("ntoskrnl.exe base address: %p", GetNtosImageBase3());
        DbgPrint("ntoskrnl.exe base address: %p", GetNtosImageBase4());
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	return VOID();
}

=================================================================================================================================================================================

// User Mode 
  
#include "nt.hpp"

template <typename T>
auto GetRoutineAddress(std::string routine_name) -> T
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        T RoutineAddress = (T)GetProcAddress(ntdll, routine_name.c_str());
        if (RoutineAddress)
            return RoutineAddress;
    }
    return nullptr;
}

auto GetNtosBase1() -> PVOID
{
    _NtQuerySystemInformation NtQuerySystemInformation = GetRoutineAddress< _NtQuerySystemInformation>("NtQuerySystemInformation");
    PRTL_PROCESS_MODULES ModuleInfo = reinterpret_cast<PRTL_PROCESS_MODULES>(VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (ModuleInfo != nullptr) {
        if (NT_SUCCESS(NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, 1024 * 1024, nullptr)))
            return ModuleInfo->Modules[0].ImageBase;
        else
            return 0;
    }
    std::cout << "Failed To Allocate ModuleInfo Memory" << std::endl;
    return 0;
}

auto GetNtosBase2() -> PVOID
{
    LPVOID Drivers[1024];

    DWORD Needed;

    int cDrivers;

    if (EnumDeviceDrivers(Drivers, sizeof(Drivers), &Needed))
    {
        cDrivers = Needed / sizeof(Drivers[0]);
        return Drivers[0];
    }
    return nullptr; 
}

int main()
{
    std::cout << GetNtosBase1() << std::endl;
    std::cout << GetNtosBase2() << std::endl;
    return 0;
}
