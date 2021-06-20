#include <ntddk.h>
#include <intrin.h>
#include <nt.hpp>

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath);
VOID Unload(PDRIVER_OBJECT DriverObject);

template <typename T>
T GetKernelExport(PCWSTR zExportName) 
{
	__try
	{
		UNICODE_STRING ExportName;

		RtlInitUnicodeString(&ExportName, zExportName);

		T RoutineAddress = (T)MmGetSystemRoutineAddress(&ExportName);

		if (RoutineAddress)
		{
		    return RoutineAddress;
		}
		
		return T();
	}
	
	__except (EXCEPTION_EXECUTE_HANDLER) {}
}

PVOID GetNtosImageBase1()
{
	__try 
	{
		PVOID NtImageBase;
		
		PSYSTEM_MODULE_INFORMATION ModInfo;

		_ZwQuerySystemInformation ZwQuerySystemInformation;

		ZwQuerySystemInformation = GetKernelExport<_ZwQuerySystemInformation>(L"ZwQuerySystemInformation");

		ModInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, POOL_SIZE);

		if (ModInfo)
		{

		     if (NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, ModInfo, POOL_SIZE, nullptr)))
		     {
		     	  NtosImageBase = ModInfo->Module[0].ImageBase;     
			     
		     	  if (NtosImageBase)
		     	  {
		     	  	ExFreePool(ModInfo);
		     	  	return NtosImageBase;
		     	  }
		     }
		}

		ExFreePool(ModInfo);
		return nullptr;
	}
	
	__except (EXCEPTION_EXECUTE_HANDLER) {}
}

PVOID GetNtosImageBase2()
{
	__try 
	{
		uintptr_t NtosImageBase;

		_RtlLookupFunctionEntry RtlLookupFunctionEntry;

		RtlLookupFunctionEntry = GetKernelExport<_RtlLookupFunctionEntry>(L"RtlLookupFunctionEntry");

		RtlLookupFunctionEntry((DWORD64)&MmCopyMemory, &NtosImageBase, nullptr);

		if (NtosImageBase)
		{
		    return (PVOID)NtosImageBase;
		}

		return nullptr;
	}
	
	__except (EXCEPTION_EXECUTE_HANDLER) {}
}


PVOID GetNtosImageBase3()
{
	__try
	{

		PVOID NtosImageBase;

		_RtlPcToFileHeader RtlPcToFileHeader = GetKernelExport<_RtlPcToFileHeader>(L"RtlPcToFileHeader");

		RtlPcToFileHeader(&MmCopyMemory, &NtosImageBase);

		if (NtosImageBase)
		{
		    return NtosImageBase;
		}
		
		return nullptr;
	}
	
	__except (EXCEPTION_EXECUTE_HANDLER) {}
}


PVOID GetNtosImageBase4()
{
	__try
	{
		PIDT_ENTRY IdtBase = (PIDT_ENTRY)KeGetPcr()->IdtBase;

		auto Page = (uintptr_t)IdtBase[0].InterruptServiceRoutine & ~0xfff;

		for (; Page; Page -= PAGE_SIZE)
		{

			if (*(USHORT*)Page == IMAGE_DOS_SIGNATURE)
			{

				for (auto Bytes = Page; Bytes < Page + 0x400; Bytes += 8)
				{
					if (*(ULONG64*)(Bytes) == PAGELK_PATTERN)
					{
						return (PVOID)Page;
					}
				}
			}
		}

		return nullptr;
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {}
}


PVOID GetNtosImageBase5()
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
					{
						return (PVOID)Page;
					}
				}
			}
		}

		return nullptr;
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {}
}

PVOID GetNtosImageBase6()
{

	PKLDR_DATA_TABLE_ENTRY CurrentKldrEntry;

	PLIST_ENTRY PsLoadedModuleList;

	UNICODE_STRING UNtModName;

	RtlInitUnicodeString(&UNtModName, L"ntoskrnl.exe");

	PsLoadedModuleList = GetKernelExport<PLIST_ENTRY>(L"PsLoadedModuleList");

	CurrentKldrEntry = (PKLDR_DATA_TABLE_ENTRY)PsLoadedModuleList->Flink;

	while ((PLIST_ENTRY)CurrentKldrEntry != PsLoadedModuleList)
	{
		if (!RtlCompareUnicodeString(&CurrentKldrEntry->BaseDllName, &UNtModName, true))
		{
			return CurrentKldrEntry->DllBase;
		}

		CurrentKldrEntry = (PKLDR_DATA_TABLE_ENTRY)CurrentKldrEntry->InLoadOrderLinks.Flink;
	}
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
	UNREFERENCED_PARAMETER(RegPath);
	DbgPrint("%p", GetNtosImageBase1());
	DbgPrint("%p", GetNtosImageBase2());
	DbgPrint("%p", GetNtosImageBase3());
	DbgPrint("%p", GetNtosImageBase4());
	DbgPrint("%p", GetNtosImageBase5());
	DbgPrint("%p", GetNtosImageBase6());
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("Driver Unloaded");
}
