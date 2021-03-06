/*
      ready to paste code that's all 
      
      credits (I referenced this code with some small modifications) 
      
	  . https://www.unknowncheats.me/forum/anti-cheat-bypass/324665-clearing-piddbcachetable.html
*/ 

#include <ntddk.h>
#include <intrin.h>

typedef PIMAGE_NT_HEADERS(NTAPI* _RtlImageNtHeader)(
	PVOID ModuleAddress
);

NTSTATUS DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
);

VOID Unload(
	PDRIVER_OBJECT DriverObject
);

bool LocatePiDDB(
	PERESOURCE& PiDDBLock,
	PRTL_AVL_TABLE& PiDDBCacheTable
);

bool ClearPiDDBCache(
	PDRIVER_OBJECT DriverObject
);


NTSTATUS GetSysModInfo(
    PSYSTEM_MODULE_INFORMATION& SystemModInfo
); 

template <typename ExportType>
ExportType GetKernelExport(
	PCWSTR zExportName
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

typedef struct PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	        DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	CHAR			SomeValue[16];
}_PiDDBCacheEntry, * _PPiDDBCacheEntry;

struct NtosInfo
{
    PVOID ImageBase;
    ULONG64 ImageSize;
};

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
	union 
	{
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

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = Unload;

	ClearPiDDBCache(DriverObject);

	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("Driver Unloaded ...");
}

bool LocatePiDDB(PRTL_AVL_TABLE& PiDDBCacheTable, PERESOURCE& PiDDBLock)
{
    PSYSTEM_MODULE_INFORMATION SystemModInfo = nullptr;

    UCHAR PiDDBLockPattern[] = "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C";

    UCHAR PiDDBCacheTablePattern[] = "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x3D\x00\x00\x00\x00\x0F\x83\x00\x00\x00\x00";

    if (!NT_SUCCESS(GetSysModInfo(SystemModInfo)))
    {
        DbgPrint("Failed to get system module information");
        return false;
    }

    NtosInfo ntos = { SystemModInfo->Module[0].ImageBase, SystemModInfo->Module[0].ImageSize };

    if (!GetAddress((UINT64)ntos.ImageBase, ntos.ImageSize, PiDDBLockPattern, "xxx????x????xxx", 3, 4, PiDDBLock))
    {
        DbgPrint("Failed to find PiDDBLock");
        return false;
    }


    if (!GetAddress((UINT64)ntos.ImageBase, ntos.ImageSize, PiDDBCacheTablePattern, "xxx????x????x????xx????", 3, 4, PiDDBCacheTable))
    {
        DbgPrint("Failed to find PiDDBCacheTable");
        return false;
    }

    return true; 
}

bool ClearPiDDBCache(PDRIVER_OBJECT DriverObject)
{
	PERESOURCE PiDDBLock = nullptr; 
	PRTL_AVL_TABLE PiDDBCacheTable = nullptr; 
	_PiDDBCacheEntry PiDDBCacheEntry = { 0 };

	if(!LocatePiDDB(PiDDBCacheTable, PiDDBLock))
	{
	    return false; 
	}

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

    auto Resolve = [&](PVOID InstructionAddress, INT OpcodeBytes, INT AddressBytes, T& Found)
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

            Resolve(InstrAddress, OpcodeBytes, AddressBytes, Found);

            return true;
        }
    }

    return false;
}

template <typename ExportType>
ExportType GetKernelExport(PCWSTR zExportName)
{
	UNICODE_STRING UExportName;

	RtlInitUnicodeString(&UExportName, zExportName);

	ExportType ExportAddress = (ExportType)MmGetSystemRoutineAddress(&UExportName);

	return ExportAddress ? ExportAddress : ExportType(nullptr);
}

NTSTATUS GetSysModInfo(PSYSTEM_MODULE_INFORMATION& SystemModInfo)
{
   auto ZwQuerySystemInformation = GetKernelExport<_ZwQuerySystemInformation>(L"ZwQuerySystemInformation");

   SystemModInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolZero(NonPagedPool, POOL_SIZE, POOL_TAG);

   if (SystemModInfo)
   {
       NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, SystemModInfo, POOL_SIZE, nullptr);

       if (NT_SUCCESS(Status))
       {
           return STATUS_SUCCESS;
       }
   }

   ExFreePoolWithTag(SystemModInfo, POOL_TAG);
   return STATUS_UNSUCCESSFUL;
}
