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
            T RoutineAddress = (T)MmGetSystemRoutineAddress(&RoutineName);
            if (RoutineAddress)
                return RoutineAddress;
	    return nullptr;
    }
    __except (1) {}
}

auto GetNtosImageBase1() -> PVOID
{
	__try {
		PVOID NtImageBase;
		PSYSTEM_MODULE_INFORMATION ModInfo = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePool(NonPagedPool, 1024 * 1024));
		UNICODE_STRING RoutineName = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
		_ZwQuerySystemInformation ZwQuerySystemInformation = GetRoutineAddress< _ZwQuerySystemInformation>(RoutineName);
		NTSTATUS SysInfoDrv = ZwQuerySystemInformation(SystemModuleInformation, ModInfo, 1024 * 1024, nullptr);
		NtImageBase = ModInfo->Module[0].ImageBase;
		if (NtImageBase)
			return NtImageBase;
		return nullptr;
	}
	__except(1){}
}

auto GetNtosImageBase2() -> PVOID
{
	__try {
		UNICODE_STRING RoutineName = RTL_CONSTANT_STRING(L"RtlLookupFunctionEntry");
		_RtlLookupFunctionEntry RtlLookupFunctionEntry = GetRoutineAddress< _RtlLookupFunctionEntry>(RoutineName);
		DWORD64 NtImageBase;
		RtlLookupFunctionEntry((DWORD64)&MmFreeContiguousMemorySpecifyCache, &NtImageBase, nullptr);
		if (NtImageBase)
			return reinterpret_cast<PVOID>(NtImageBase);
		return nullptr;
	}
	__except(1){}
}

PVOID GetNtosImageBase()
{
	__try
	{
		auto Page = __readmsr(IA32_LSTAR) & ~0xfff;

		for (; Page; Page -= PAGE_SIZE)
		{
			if (*(USHORT*)Page == IMAGE_DOS_SIGNATURE)
			{

				for (auto Bytes = Page; Bytes < Page + 0x400; Bytes += 8)
				{
					if (*(ULONG64*)(Bytes) == PAGELK_PATTERN)
						return (PVOID)Page;
				}
			}
		}

		return nullptr;
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {}
}

auto GetNtosImageBase4() -> PVOID
{
	__try {
		UNICODE_STRING RoutineName = RTL_CONSTANT_STRING(L"RtlPcToFileHeader");
		_RtlPcToFileHeader RtlPcToFileHeader = GetRoutineAddress<_RtlPcToFileHeader>(RoutineName);
		PVOID NtImageBase;
		RtlPcToFileHeader(&MmFreeContiguousMemorySpecifyCache, &NtImageBase);
		if(NtImageBase)
			return NtImageBase;
		return nullptr;
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
	DbgPrint("Driver Unloaded");
}
