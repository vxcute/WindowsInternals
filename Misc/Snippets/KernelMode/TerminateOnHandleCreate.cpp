#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>

typedef NTSTATUS(NTAPI* _PsTerminateProcess)(
	PEPROCESS Process,
	NTSTATUS ExitStatus
);

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	struct _LIST_ENTRY InLoadOrderLinks;
	VOID* ExceptionTable;
	ULONG ExceptionTableSize;
	VOID* GpValue;
	struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
	VOID* DllBase;
	VOID* EntryPoint;
	ULONG SizeOfImage;
	struct _UNICODE_STRING FullDllName;
	struct _UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	union
	{
		USHORT SignatureLevel : 4;
		USHORT SignatureType : 3;
		USHORT Unused : 9;
		USHORT EntireField;
	} u1;
	VOID* SectionPointer;
	ULONG CheckSum;
	ULONG CoverageSectionSize;
	VOID* CoverageSection;
	VOID* LoadedImports;
	VOID* Spare;
	ULONG SizeOfImageNotRounded;
	ULONG TimeDateStamp;
}KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

EXTERN_C NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);
EXTERN_C PCSTR PsGetProcessImageFileName(PEPROCESS Process);

NTSTATUS DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
);

VOID Unload(
	PDRIVER_OBJECT DriverObject
);

OB_PREOP_CALLBACK_STATUS ObPreCallback(
	PVOID ObRegistrationContext,
	POB_PRE_OPERATION_INFORMATION PreOpInformation
);

VOID ObPostCallback(
	PVOID ObRegistrationContext,
	POB_POST_OPERATION_INFORMATION PostOpInformation
);


VOID LocateData(
	VOID
);

PCSTR GetProcessName(
	HANDLE ProcessId
);

template <typename ExportType>
ExportType GetKernelExport(
	PCWSTR ExportName
);

template <typename T>
bool GetAddress(
	UINT64 Base,
	UINT64 Size,
	PCUCHAR Pattern,
	PCSTR WildCard,
	INT OpcodeBytes,
	INT AddressBytes,
	T& Found
);

PVOID ObRegistrationHandle = nullptr;
_PsTerminateProcess PsTerminateProcess = nullptr;
PLIST_ENTRY PsLoadedModuleList = nullptr;
PERESOURCE PsLoadedModuleResource = nullptr;
PKLDR_DATA_TABLE_ENTRY Ntos = nullptr;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING Altitude = { 0 };
	OB_OPERATION_REGISTRATION ObOperationRegistration = { 0 };
	OB_CALLBACK_REGISTRATION ObCallbackRegistration = { 0 };

	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = Unload;

	LocateData();

	Altitude = RTL_CONSTANT_STRING(L"3560");

	ObOperationRegistration = { PsProcessType, OB_OPERATION_HANDLE_CREATE, ObPreCallback , ObPostCallback };

	ObCallbackRegistration = { OB_FLT_REGISTRATION_VERSION, 1,  Altitude, nullptr, &ObOperationRegistration };

	Status = ObRegisterCallbacks(&ObCallbackRegistration, &ObRegistrationHandle);

	if (NT_SUCCESS(Status))
	{
		DbgPrint("[LOG] Registered Callbacks\n");
	}

	else
	{
		DbgPrint("[ERROR] Failed to register Callbacks\n");
	}

	return Status;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	DbgPrint("[LOG] %wZ Unloaded\n", DriverObject->DriverName);

	if (ObRegistrationHandle != nullptr)
	{
		ObUnRegisterCallbacks(ObRegistrationHandle);
		DbgPrint("[LOG] Unregistered Callbacks\n");
	}

	else
	{
		DbgPrint("[ERROR] ObRegistrationHandle is null\n");
	}
}


PKLDR_DATA_TABLE_ENTRY GetKldrDataByName(PCWSTR ModuleName)
{
	PKLDR_DATA_TABLE_ENTRY LdrEntry = nullptr;

	UNICODE_STRING ModName = { 0 };

	RtlInitUnicodeString(&ModName, ModuleName);

	if (PsLoadedModuleList == nullptr)
	{
		return nullptr;
	}

	KeEnterCriticalRegion();

	ExAcquireResourceSharedLite(PsLoadedModuleResource, true);

	auto CurrentKldrEntry = (PKLDR_DATA_TABLE_ENTRY)(PsLoadedModuleList->Flink);

	while ((PLIST_ENTRY)(CurrentKldrEntry) != PsLoadedModuleList)
	{
		if (!RtlCompareUnicodeString(&CurrentKldrEntry->BaseDllName, &ModName, true))
		{
			LdrEntry = CurrentKldrEntry;
			break;
		}

		CurrentKldrEntry = (PKLDR_DATA_TABLE_ENTRY)(CurrentKldrEntry->InLoadOrderLinks.Flink);
	}

	ExReleaseResourceLite(PsLoadedModuleResource);

	KeLeaveCriticalRegion();

	return LdrEntry;
}


VOID LocateData(VOID)
{
	UCHAR PsTerminateProcessPattern[] = "\x48\x8B\xD9\xE8\x00\x00\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\xBA\x00\x00\x00\x00";

	PsLoadedModuleList = GetKernelExport<PLIST_ENTRY>(L"PsLoadedModuleList");

	PsLoadedModuleResource = GetKernelExport<PERESOURCE>(L"PsLoadedModuleResource");

	Ntos = GetKldrDataByName(L"ntoskrnl.exe");

	if (Ntos == nullptr)
	{
		DbgPrint("[ERROR] Failed to locate ntoskrnl.exe KLDR\n");
		return;
	}

	GetAddress((UINT64)Ntos->DllBase, Ntos->SizeOfImage, PsTerminateProcessPattern, "xxxx????xxxx????x????", 4, 4, PsTerminateProcess) ?
		DbgPrint("[LOG] Found PsTerminateProcess: %p\n", PsTerminateProcess) : DbgPrint("[ERROR] Failed to locate PsTerminateProcess\n");
}

OB_PREOP_CALLBACK_STATUS ObPreCallback(PVOID ObRegistrationContext, POB_PRE_OPERATION_INFORMATION PreOpInformation)
{
	UNREFERENCED_PARAMETER(ObRegistrationContext);

	PCSTR ProcessName = GetProcessName(PsGetProcessId((PEPROCESS)PreOpInformation->Object));

	if (!_stricmp(ProcessName, "notepad.exe"))
	{
		if (PreOpInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			PEPROCESS Process = (PEPROCESS)(PreOpInformation->Object);

			if (NT_SUCCESS(PsTerminateProcess(Process, 0x0)))
			{
				DbgPrint("[LOG] Terminated notepad.exe\n");
			}

			else
			{
				DbgPrint("[ERROR] Failed to terminate notepad.exe\n");
			}
		}
	}

	return OB_PREOP_SUCCESS;
}

VOID ObPostCallback(PVOID ObRegistrationContext, POB_POST_OPERATION_INFORMATION PostOpInformation)
{
	UNREFERENCED_PARAMETER(ObRegistrationContext);
	UNREFERENCED_PARAMETER(PostOpInformation);
}

PCSTR GetProcessName(HANDLE ProcessId)
{
	PEPROCESS Process = nullptr;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
	{
		DbgPrint("[ERROR] Failed to lookup process\n");
		return nullptr;
	}

	return PsGetProcessImageFileName(Process);
}

template <typename ExportType>
ExportType GetKernelExport(PCWSTR ExportName)
{
	UNICODE_STRING ExpName = { 0 };

	RtlInitUnicodeString(&ExpName, ExportName);

	ExportType ExportAddress = (ExportType)MmGetSystemRoutineAddress(&ExpName);

	return ExportAddress ? ExportAddress : ExportType(nullptr);
}

template <typename T>
bool GetAddress(UINT64 Base, UINT64 Size, PCUCHAR Pattern, PCSTR WildCard, INT OpcodeBytes, INT AddressBytes, T& Found)
{
	auto CheckMask = [&](PCUCHAR Data, PCUCHAR Pattern, PCSTR WildCard)
	{
		for (; *WildCard; ++WildCard, ++Data, ++Pattern)
		{
			if (*WildCard == 'x' && *Data != *Pattern)
			{
				return false;
			}
		}

		return *WildCard == 0;
	};

	auto Resolve = [&](PVOID InstructionAddress, INT OpcodeBytes, INT AddressBytes)
	{
		ULONG64 InstructionAddr = (ULONG64)InstructionAddress;

		AddressBytes += OpcodeBytes;

		ULONG32 RelativeOffset = *(ULONG32*)(InstructionAddr + OpcodeBytes);

		Found = (T)(InstructionAddr + RelativeOffset + AddressBytes);
	};


	for (auto i = 0; i < Size; i++)
	{
		if (CheckMask((PUCHAR)(Base + i), Pattern, WildCard))
		{
			PVOID InstrAddress = (PVOID)(Base + i);

			Resolve(InstrAddress, OpcodeBytes, AddressBytes);

			return true;
		}
	}

	return false;
}
