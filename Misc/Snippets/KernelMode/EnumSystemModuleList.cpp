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
}_KLDR_DATA_TABLE_ENTRY, *_PKLDR_DATA_TABLE_ENTRY;

NTSTATUS DriverEntry(
	PDRIVER_OBJECT DriverObject, 
	PUNICODE_STRING RegPath
);

VOID Unload(
	PDRIVER_OBJECT DriverObject
);

VOID EnumSystemModuleList(
  VOID
); 

template <typename ExportType>
ExportType GetKernelExport(
  PCWSTR zExportName
);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
	UNREFERENCED_PARAMETER(RegPath);

	DriverObject->DriverUnload = Unload;
	
	EnumSystemModuleList();

	return NTSTATUS();
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{

	UNREFERENCED_PARAMETER(DriverObject);

	DbgPrint("%wZ Unloaded\n", DriverObject->DriverName);
}

VOID EnumSystemModuleList(VOID)
{
	auto PsLoadedModuleList = GetKernelExport<PLIST_ENTRY>(L"PsLoadedModuleList");

	for (auto CurrentKldrEntry = (_PKLDR_DATA_TABLE_ENTRY)PsLoadedModuleList->Flink; CurrentKldrEntry != (_PKLDR_DATA_TABLE_ENTRY)PsLoadedModuleList;
		CurrentKldrEntry = (_PKLDR_DATA_TABLE_ENTRY)CurrentKldrEntry->InLoadOrderLinks.Flink)

	{
		DbgPrint("Found %wZ at base address: %p", CurrentKldrEntry->BaseDllName, CurrentKldrEntry->DllBase); 
	}
}

template <typename ExportType>
ExportType GetKernelExport(PCWSTR zExportName)
{
	UNICODE_STRING UExportName = {0}; 

	RtlInitUnicodeString(&UExportName, zExportName);

	ExportType ExportAddress = (ExportType)MmGetSystemRoutineAddress(&UExportName);

	return ExportAddress ? ExportAddress : ExportType(nullptr);
}
