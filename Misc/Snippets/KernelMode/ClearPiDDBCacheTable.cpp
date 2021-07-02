/*
      ready to paste code that's all 
      
      credits (I referenced this code with some small modifications) 
      
	  . https://www.unknowncheats.me/forum/anti-cheat-bypass/324665-clearing-piddbcachetable.html
	  . BlackBone: (SearchPattern and ScanSection Functions) 
	  . LocatePiDDB: https://github.com/ApexLegendsUC/anti-cheat-emulator/blob/9e53bb4a329e0286ff4f237c5ded149d53b0dd56/Source.cpp#L588
*/ 

#include <ntddk.h>
#include <intrin.h>

#define IMAGE_DOS_SIGNATURE      0x5A4D 
#define PAGELK_PATTERN           0x4B4C45474150
#define IA32_LSTAR               0xC0000082

typedef PIMAGE_NT_HEADERS(NTAPI* _RtlImageNtHeader)(
	IN PVOID ModuleAddress
);

NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath
);

VOID Unload(
	IN PDRIVER_OBJECT DriverObject
);

bool LocatePiDDB(
	OUT PERESOURCE* PiDDBLock,
	OUT PRTL_AVL_TABLE* PiDDBCacheTable
);

bool ClearPiDDBCache(
	IN PDRIVER_OBJECT DriverObject
);

NTSTATUS ScanSection(
	IN PCCHAR SectionName,
	IN PCUCHAR Pattern,
	IN UCHAR Wildcard,
	OUT PVOID* Found,
	PVOID Base = nullptr
);

NTSTATUS SearchPattern(
	IN PCUCHAR Pattern,
	IN UCHAR WildCard,
	IN PVOID Base,
	IN ULONG_PTR Size,
	OUT PVOID* Found,
	int Index = 0
);

PVOID ResolveRelativeAddress(
	IN PVOID Instruction,
	IN ULONG Offset,
	IN ULONG InstructionSize
);

PVOID GetNtosImageBase(
	VOID
);

template <class ExportType>
ExportType GetKernelExport(
	PCWSTR zExportName
);

typedef struct PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	CHAR			SomeValue[16];
}_PiDDBCacheEntry, * _PPiDDBCacheEntry;

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
}_KLDR_DATA_TABLE_ENTRY, * _PKLDR_DATA_TABLE_ENTRY;

typedef struct _IMAGE_FILE_HEADER 
{
	USHORT  Machine;
	USHORT  NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	USHORT  SizeOfOptionalHeader;
	USHORT  Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY 
{
	ULONG VirtualAddress;
	ULONG Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 
{
	USHORT        Magic;
	char        MajorLinkerVersion;
	char        MinorLinkerVersion;
	ULONG       SizeOfCode;
	ULONG       SizeOfInitializedData;
	ULONG       SizeOfUninitializedData;
	ULONG       AddressOfEntryPoint;
	ULONG       BaseOfCode;
	ULONGLONG   ImageBase;
	ULONG       SectionAlignment;
	ULONG       FileAlignment;
	USHORT        MajorOperatingSystemVersion;
	USHORT        MinorOperatingSystemVersion;
	USHORT        MajorImageVersion;
	USHORT        MinorImageVersion;
	USHORT        MajorSubsystemVersion;
	USHORT        MinorSubsystemVersion;
	ULONG       Win32VersionValue;
	ULONG       SizeOfImage;
	ULONG       SizeOfHeaders;
	ULONG       CheckSum;
	USHORT        Subsystem;
	USHORT        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	ULONG       LoaderFlags;
	ULONG       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 
{
	ULONG                   Signature;
	IMAGE_FILE_HEADER       FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER 
{
	char  Name[8];
	union {
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	} Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	USHORT  NumberOfRelocations;
	USHORT  NumberOfLinenumbers;
	ULONG Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	PERESOURCE Lock;

	PRTL_AVL_TABLE Table;

	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = Unload;

	ClearPiDDBCache(DriverObject);

	return STATUS_SUCCESS;
}

VOID Unload(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("Driver Unloaded ...");
}

bool LocatePiDDB(OUT PERESOURCE* PiDDBLock, OUT PRTL_AVL_TABLE* PiDDBCacheTable)
{
	PVOID* PiDDBLockPtr = nullptr, PiDDBCacheTablePtr = nullptr;
	UCHAR PiDDBLockPtrPattern[] = "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C";
	UCHAR PiDDBCacheTablePtrPattern[] = "\x66\x03\xD2\x48\x8D\x0D";

	if (!NT_SUCCESS(ScanSection("PAGE", PiDDBLockPtrPattern, 0, (PVOID*)(&PiDDBLockPtr))))
	{
		DbgPrint("Unable To Locate PiDDBLock");
		return false;
	}

	if (!NT_SUCCESS(ScanSection("PAGE", PiDDBCacheTablePtrPattern, 0, (PVOID*)(&PiDDBCacheTablePtr))))
	{
		DbgPrint("Unable To Locate PiDDBCacheTable");
		return false;
	}

	PiDDBCacheTablePtr = (PVOID)((uintptr_t)PiDDBCacheTablePtr + 3);

	*PiDDBLock = (PERESOURCE)(ResolveRelativeAddress(PiDDBLockPtr, 3, 7));

	*PiDDBCacheTable = (PRTL_AVL_TABLE)(ResolveRelativeAddress(PiDDBCacheTablePtr, 3, 7));

	return true;
}

bool ClearPiDDBCache(IN PDRIVER_OBJECT DriverObject)
{
	PERESOURCE PiDDBLock; PRTL_AVL_TABLE PiDDBCacheTable;

	_PiDDBCacheEntry PiDDBCacheEntry = { 0 };

	LocatePiDDB(&PiDDBLock, &PiDDBCacheTable);

	auto DriverkLdr = (_PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

	auto RtlImageNtHeader = GetKernelExport<_RtlImageNtHeader>(L"RtlImageNtHeader");

	auto NtHeaders = RtlImageNtHeader(DriverkLdr->DllBase);

	PiDDBCacheEntry.DriverName = DriverkLdr->BaseDllName;

	PiDDBCacheEntry.TimeDateStamp = NtHeaders->FileHeader.TimeDateStamp;

	ExAcquireResourceExclusiveLite(PiDDBLock, true);

	auto DriverEntry = (_PPiDDBCacheEntry)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &PiDDBCacheEntry);

	if (DriverEntry == nullptr)
	{
		DbgPrint("Failed to locate driver entry in PIDDBCacheTable");
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	RemoveEntryList(&DriverEntry->List);

	RtlDeleteElementGenericTableAvl(PiDDBCacheTable, DriverEntry);

	ExReleaseResourceLite(PiDDBLock);

	return true;
}

NTSTATUS SearchPattern(IN PCUCHAR Pattern, IN UCHAR WildCard, IN PVOID Base, IN ULONG_PTR Size, OUT PVOID* Found, int Index)
{
	if (Found == nullptr || Pattern == nullptr || Base == nullptr)
	{
		return STATUS_ACCESS_DENIED;
	}

	if (Base == nullptr)
	{
		Base = GetNtosImageBase();
	}

	int cIndex = 0;

	ULONG_PTR Length = sizeof(Pattern) - 1;

	for (ULONG_PTR i = 0; i < Size - Length; i++)
	{
		bool cFound = true;

		for (ULONG_PTR j = 0; j < Length; j++)
		{
			if (Pattern[j] != WildCard && Pattern[j] != ((PCUCHAR)Base)[i + j])
			{
				cFound = false;
				break;
			}
		}

		if (cFound != false && cIndex++ == Index)
		{
			*Found = (PUCHAR)Base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS ScanSection(IN PCCHAR SectionName, IN PCUCHAR Pattern, IN UCHAR Wildcard, OUT PVOID* Found, PVOID Base)
{
	ANSI_STRING zSectionName, xSectionName;

	ULONG Length = sizeof(Pattern) - 1;

	auto RtlImageNtHeader = GetKernelExport<_RtlImageNtHeader>(L"RtlImageNtHeader");

	if (Found == nullptr)
	{
		return STATUS_ACCESS_DENIED;
	}

	if (Base == nullptr)
	{
		Base = GetNtosImageBase();
	}

	if (Base == nullptr)
	{
		return STATUS_ACCESS_DENIED;
	}

	PIMAGE_NT_HEADERS64 NtHeaders = RtlImageNtHeader(Base);

	if (NtHeaders == nullptr)
	{
		return STATUS_ACCESS_DENIED;
	}

	PIMAGE_SECTION_HEADER FirstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&NtHeaders->FileHeader + NtHeaders->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

	for (PIMAGE_SECTION_HEADER Section = FirstSection; Section < FirstSection + NtHeaders->FileHeader.NumberOfSections; Section++)
	{

		RtlInitAnsiString(&zSectionName, SectionName);

		RtlInitAnsiString(&xSectionName, (PCCHAR)Section->Name);

		if (!RtlCompareString(&zSectionName, &xSectionName, true))
		{
			PVOID Address = NULL;

			NTSTATUS Status = SearchPattern(Pattern, Wildcard, (PUCHAR)Base + Section->VirtualAddress, Section->Misc.VirtualSize, &Address);

			if (NT_SUCCESS(Status))
			{
				*(PULONG64)Found = (ULONG_PTR)(Address);

				return Status;
			}
		}
	}

	return STATUS_ACCESS_DENIED;
}

PVOID ResolveRelativeAddress(
	IN PVOID Instruction,
	IN ULONG  Offset,
	IN ULONG InstructionSize
)

{
	ULONG_PTR xInstruction = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(xInstruction + Offset);
	PVOID ResolvedAddress = (PVOID)(xInstruction + InstructionSize + RipOffset);

	return ResolvedAddress;
}

template <class ExportType>
ExportType GetKernelExport(PCWSTR zExportName)
{
	__try
	{
		UNICODE_STRING UExportName;

		RtlInitUnicodeString(&UExportName, zExportName);

		ExportType ExportAddress = (ExportType)MmGetSystemRoutineAddress(&UExportName);

		return ExportAddress ? ExportAddress : ExportType();
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {}
}

PVOID GetNtosImageBase(VOID)
{
	__try
	{
		for (auto Page = __readmsr(IA32_LSTAR) & ~0xfff; Page != NULL; Page -= PAGE_SIZE)
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
