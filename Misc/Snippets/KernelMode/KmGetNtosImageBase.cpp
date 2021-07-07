#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include "nt.hpp"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath);
VOID Unload(PDRIVER_OBJECT DriverObject);

template <typename ExportType>
ExportType GetKernelExport(PCWSTR zExportName)
{
	UNICODE_STRING UExportName;

	RtlInitUnicodeString(&UExportName, zExportName);

	ExportType ExportAddress = (ExportType)MmGetSystemRoutineAddress(&UExportName);

	return ExportAddress ? ExportAddress : ExportType(nullptr);
}


PVOID GetNtosImageBase1()
{
	PVOID NtosImageBase;
	
	PSYSTEM_MODULE_INFORMATION ModInfo;

	_ZwQuerySystemInformation ZwQuerySystemInformation;

	ZwQuerySystemInformation = GetKernelExport<_ZwQuerySystemInformation>(L"ZwQuerySystemInformation");

	ModInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolZero(NonPagedPool, POOL_SIZE, POOL_TAG);

	if (ModInfo)
	{

		if (NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, ModInfo, POOL_SIZE, nullptr)))
		{
			NtosImageBase = ModInfo->Module[0].ImageBase;

			if (NtosImageBase)
			{
				ExFreePoolWithTag(ModInfo, POOL_TAG);
				return NtosImageBase;
			}
		}
	}

	ExFreePoolWithTag(ModInfo, POOL_TAG);
	return nullptr;
	
}

PVOID GetNtosImageBase2()
{
	PVOID NtosImageBase;

	_RtlLookupFunctionEntry RtlLookupFunctionEntry;

	RtlLookupFunctionEntry = GetKernelExport<_RtlLookupFunctionEntry>(L"RtlLookupFunctionEntry");

	RtlLookupFunctionEntry((DWORD64)&MmCopyMemory, (PDWORD64)&NtosImageBase, nullptr);

	return NtosImageBase ? NtosImageBase : nullptr;
}


PVOID GetNtosImageBase3()
{
	PVOID NtosImageBase;

	_RtlPcToFileHeader RtlPcToFileHeader = GetKernelExport<_RtlPcToFileHeader>(L"RtlPcToFileHeader");

	RtlPcToFileHeader(&MmCopyMemory, &NtosImageBase);

	return NtosImageBase ? NtosImageBase : nullptr;
}


PVOID GetNtosImageBase4()
{
	_KSPECIAL_REGISTERS SpecialRegisters;

	__sidt(&SpecialRegisters.Idtr.Limit);

	PIDT_ENTRY IdtBase = (PIDT_ENTRY)SpecialRegisters.Idtr.Base;

	for (auto Page = (uintptr_t)IdtBase[0].InterruptServiceRoutine & ~0xfff;; Page; Page -= PAGE_SIZE)
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


PVOID GetNtosImageBase5()
{
	for (auto Page = __readmsr(IA32_LSTAR) & ~0xfff;; Page; Page -= PAGE_SIZE)
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

PVOID GetNtosImageBase6()
{
	PKLDR_DATA_TABLE_ENTRY NtosKldr;

	PLIST_ENTRY PsLoadedModuleList;

	PsLoadedModuleList = GetKernelExport<PLIST_ENTRY>(L"PsLoadedModuleList");

	NtosKldr = (PKLDR_DATA_TABLE_ENTRY)PsLoadedModuleList->Flink;

	return NtosKldr ? NtosKldr->DllBase : nullptr;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
	UNREFERENCED_PARAMETER(RegPath);
	DbgPrint("ntoskrnl.exe base address: [%p]", GetNtosImageBase1());
	DbgPrint("ntoskrnl.exe base address: [%p]", GetNtosImageBase2());
	DbgPrint("ntoskrnl.exe base address: [%p]", GetNtosImageBase3());
	DbgPrint("ntoskrnl.exe base address: [%p]", GetNtosImageBase4());
	DbgPrint("ntoskrnl.exe base address: [%p]", GetNtosImageBase5());
	DbgPrint("ntoskrnl.exe base address: [%p]", GetNtosImageBase6());
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("Driver Unloaded");
}
