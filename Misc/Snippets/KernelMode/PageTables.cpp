#include <ntddk.h> 

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

typedef struct _PML4E
{
	union
	{
		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;
		};
		ULONG64 Value;
	};
} PML4E, * PPML4E;
static_assert(sizeof(PML4E) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef struct _PDPTE
{
	union
	{
		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;
		};
		ULONG64 Value;
	};
} PDPTE, * PPDPTE;
static_assert(sizeof(PDPTE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef struct _PDE
{
	union
	{
		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;
		};
		ULONG64 Value;
	};
} PDE, * PPDE;
static_assert(sizeof(PDE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef struct _PTE
{
	union
	{
		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Dirty : 1;
			ULONG64 PageAccessType : 1;
			ULONG64 Global : 1;
			ULONG64 Ignored2 : 3;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 7;
			ULONG64 ProtectionKey : 4;
			ULONG64 ExecuteDisable : 1;
		};
		ULONG64 Value;
	};
} PTE, * PPTE;
static_assert(sizeof(PTE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef struct _PTE_HIERARCHY
{
	PPTE Pte;
	PPDE Pde;
	PPDPTE Pdpte;
	PPML4E Pml4e;
}PTE_HIERARCHY, * PPTE_HIERARCHY;

NTSTATUS DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
);

VOID Unload(
	PDRIVER_OBJECT DriverObject
);

VOID LocateData(
	VOID
);

template <typename ExportType>
ExportType GetKernelExport(
	PCWSTR ExportName
);

PKLDR_DATA_TABLE_ENTRY GetKldrDataByName(
	PCWSTR ModuleName
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

typedef uintptr_t(__fastcall* _MiFillPteHierarchy)(
	PVOID VirtualAddress, 
	PPTE_HIERARCHY PteHierarchy
);

PLIST_ENTRY PsLoadedModuleList = nullptr; 
PERESOURCE PsLoadedModuleResource = nullptr; 
_MiFillPteHierarchy MiFillPteHierarchy = nullptr; 

PKLDR_DATA_TABLE_ENTRY GetKldrDataByName(PCWSTR ModuleName)
{
	PKLDR_DATA_TABLE_ENTRY LdrEntry = nullptr;

	UNICODE_STRING ModName = { 0 };

	RtlInitUnicodeString(&ModName, ModuleName);

	if (PsLoadedModuleList == nullptr || PsLoadedModuleResource == nullptr)
	{
		return nullptr;
	}

	KeEnterCriticalRegion();

	ExAcquireResourceSharedLite(PsLoadedModuleResource, true);

	auto CurrentKldrEntry = (PKLDR_DATA_TABLE_ENTRY)(PsLoadedModuleList->Flink);

	while ((PLIST_ENTRY)(CurrentKldrEntry) != PsLoadedModuleList)
	{
		if (RtlEqualUnicodeString(&CurrentKldrEntry->BaseDllName, &ModName, true))
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

template <typename ExportType>
ExportType GetKernelExport(PCWSTR ExportName)
{
	UNICODE_STRING ExpName = { 0 };

	RtlInitUnicodeString(&ExpName, ExportName);

	ExportType ExportAddress = (ExportType)MmGetSystemRoutineAddress(&ExpName);

	return ExportAddress ? ExportAddress : ExportType(nullptr);
}

VOID LocateData(VOID)
{
	UCHAR MiFillPteHierarchyPattern[] = "\xE8\x00\x00\x00\x00\x48\x8B\x74\xDC\x00";

	PsLoadedModuleList = GetKernelExport<PLIST_ENTRY>(L"PsLoadedModuleList");

	PsLoadedModuleResource = GetKernelExport<PERESOURCE>(L"PsLoadedModuleResource");

	auto Ntos = GetKldrDataByName(L"ntoskrnl.exe");

	GetAddress((UINT64)Ntos->DllBase, Ntos->SizeOfImage, MiFillPteHierarchyPattern, "x????xxxx?", 1, 4, MiFillPteHierarchy) ?
		DbgPrint("[+] Found MiFillPteHierarchy: %p\n", MiFillPteHierarchy) : DbgPrint("[+] Failed to locate MiFillPteHierarchy\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = Unload;

	LocateData();

	PTE_HIERARCHY PteHierarchy = { 0 };

	MiFillPteHierarchy(DriverObject, &PteHierarchy);

	DbgPrint("[+] DriverObject: %p\n", DriverObject);

	DbgPrint("[+] DriverObject PML4E: %p\n", PteHierarchy.Pml4e);

	DbgPrint("[+] DriverObject PDPTE: %p\n", PteHierarchy.Pdpte);

	DbgPrint("[+] DriverObject PDE: %p\n", PteHierarchy.Pde);

	DbgPrint("[+] DriverObject PTE: %p\n", PteHierarchy.Pte);

	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("[+] %wZ Unloaded", DriverObject->DriverName);
}
