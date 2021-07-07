#include <ntddk.h>

#define POOL_TAG 0x6B65726E656C
#define POOL_SIZE 1024*1024

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemModuleInformation = 11,
} SYSTEM_INFORMATION_CLASS;

typedef struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONGLONG Locked : 1;                                        
            ULONGLONG Waiting : 1;                                       
            ULONGLONG Waking : 1;                                        
            ULONGLONG MultipleShared : 1;                                
            ULONGLONG Shared : 60;                                       
        };
        ULONGLONG Value;                                                 
        VOID* Ptr;                                                       
    };
}_EX_PUSH_LOCK, * _PEX_PUSH_LOCK;

typedef struct _HANDLE_TABLE_FREE_LIST
{
    struct _EX_PUSH_LOCK FreeListLock;                                    
    union _HANDLE_TABLE_ENTRY* FirstFreeHandleEntry;                      
    union _HANDLE_TABLE_ENTRY* LastFreeHandleEntry;                       
    LONG HandleCount;                                                     
    ULONG HighWaterMark;                                                  
}HANDLE_TABLE_FREE_LIST, * PHANDLE_TABLE_FREE_LIST;

typedef struct _HANDLE_TABLE
{
    ULONG NextHandleNeedingPool;                                          
    LONG ExtraInfoPages;                                                  
    volatile ULONGLONG TableCode;                                         
    struct _EPROCESS* QuotaProcess;                                       
    struct _LIST_ENTRY HandleTableList;                                   
    ULONG UniqueProcessId;                                                
    union
    {
        ULONG Flags;                                                      
        struct
        {
            UCHAR StrictFIFO : 1;                                         
            UCHAR EnableHandleExceptions : 1;                             
            UCHAR Rundown : 1;                                            
            UCHAR Duplicated : 1;                                         
            UCHAR RaiseUMExceptionOnInvalidHandleClose : 1;               
        };
    };
    struct _EX_PUSH_LOCK HandleContentionEvent;                           
    struct _EX_PUSH_LOCK HandleTableLock;                                 
    union
    {
        struct _HANDLE_TABLE_FREE_LIST FreeLists[1];                      
        struct
        {
            UCHAR ActualEntry[32];                                        
            struct _HANDLE_TRACE_DEBUG_INFO* DebugInfo;                   
        };
    };
}HANDLE_TABLE, *PHANDLE_TABLE;

typedef struct _EXHANDLE
{
    union
    {
        struct
        {
            ULONG TagBits : 2;
            ULONG Index : 30;
        };
        VOID* GenericHandleOverlay;
        ULONGLONG Value;
    };
}EXHANDLE, *PEXHANDLE;

typedef union _HANDLE_TABLE_ENTRY
{
    volatile LONGLONG VolatileLowValue;
    LONGLONG LowValue;
    struct
    {
        struct _HANDLE_TABLE_ENTRY_INFO* volatile InfoTable;
        LONGLONG HighValue;
        union _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;
        struct _EXHANDLE LeafHandleValue;
    };
    LONGLONG RefCountField;
    ULONGLONG Unlocked : 1;
    ULONGLONG RefCnt : 16;
    ULONGLONG Attributes : 3;
    struct
    {
        ULONGLONG ObjectPointerBits : 44;
        ULONG GrantedAccessBits : 25;
        ULONG NoRightsUpgrade : 1;
        ULONG Spare1 : 6;
    };
    ULONG Spare2;
}HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef struct _SYSTEM_MODULE_ENTRY
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _NtosInfo
{
    PVOID ImageBase;
    ULONG64 ImageSize;
}NtosInfo, *PNtosInfo;

typedef NTSTATUS(NTAPI* _ZwQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
    );

typedef BOOLEAN(NTAPI* _ExDestroyHandle)(
   PHANDLE_TABLE HandleTable,
   HANDLE Handle,
   PHANDLE_TABLE_ENTRY CidEntry
);

typedef PHANDLE_TABLE* PPHANDLE_TABLE;

NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
);

VOID Unload(
    PDRIVER_OBJECT DriverObject
);

bool RemoveThread(
   HANDLE ThreadId
);

bool LocateData(
    PPHANDLE_TABLE& PspCidTable, 
    _ExDestroyHandle& ExDestroyHandle
);

PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(
    PHANDLE_TABLE HandleTable,
    HANDLE Handle
);


template <typename ExportType>
ExportType GetKernelExport(
    PCWSTR zExportName
);

NTSTATUS GetSysModInfo(
    PSYSTEM_MODULE_INFORMATION& SystemModInfo
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

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    RemoveThread(PsGetCurrentThreadId()) ? DbgPrint("Removed Thread From PspCidTable") : DbgPrint("Failed to remove thread from PspCidTable");
       
    DriverObject->DriverUnload = Unload;

    return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("Driver Unloaded ...");
}

bool RemoveThread(HANDLE ThreadId)
{
    PPHANDLE_TABLE PspCidTable;
    _ExDestroyHandle ExDestroyHandle;

    if (!LocateData(PspCidTable, ExDestroyHandle))
    {
        return false;
    }

    PHANDLE_TABLE HandleTable = (PHANDLE_TABLE)(*PspCidTable);

    PHANDLE_TABLE_ENTRY CidEntry = ExpLookupHandleTableEntry(HandleTable, ThreadId);

    if (CidEntry)
    {
        ExDestroyHandle(HandleTable, ThreadId, CidEntry);

        return CidEntry->ObjectPointerBits == NULL;
    }
}


bool LocateData(PPHANDLE_TABLE& PspCidTable, _ExDestroyHandle& ExDestroyHandle)
{
    PSYSTEM_MODULE_INFORMATION SystemModInfo = nullptr;

    PVOID ExDestroyHandleInstrAddr = nullptr, PspCidTableInstrAddr = nullptr;

    UCHAR ExDestroyHandlePattern[] = "\xE8\x00\x00\x00\x00\x48\x8B\xCE\xE8\x00\x00\x00\x00\x33\xD2\x48\x8B\xCD";

    UCHAR PspCidTablePattern[] = "\x48\x8B\x05\x00\x00\x00\x00\x0F\xB6\xEA";

    if (!NT_SUCCESS(GetSysModInfo(SystemModInfo)))
    {
        DbgPrint("Failed to get system module information");
        return false;
    }

    NtosInfo ntos = { SystemModInfo->Module[0].ImageBase, SystemModInfo->Module[0].ImageSize };


    if (!GetAddress((UINT64)ntos.ImageBase, ntos.ImageSize, PspCidTablePattern, "xxx????xxx", 3, 4, PspCidTable))
    {
        DbgPrint("Failed to get PspCidTable");
        return false;
    }

    if (!GetAddress((UINT64)ntos.ImageBase, ntos.ImageSize, ExDestroyHandlePattern, "x????xxxx????xxxxx", 1, 4, ExDestroyHandle))
    {
        DbgPrint("Failed to get ExDestroyHandle");
        return false;
    }

    return true;
}

// https://github.com/notscimmy/libelevate/blob/56c2292157f900ac083344a6e3e4f4410978e91a/libelevate/libelevate.cpp#L7

PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(PHANDLE_TABLE HandleTable, HANDLE Handle)
{
    unsigned __int64 v2;
    __int64 v3;
    signed __int64 v4;
    __int64 v5;

    v2 = (__int64)Handle & 0xFFFFFFFFFFFFFFFCui64;

    if (v2 >= *(UINT32*)HandleTable)
        return 0i64;

    v3 = *((UINT64*)HandleTable + 1);
    v4 = *((UINT64*)HandleTable + 1) & 3i64;

    if ((UINT32)v4 == 1)
    {
        v5 = *(UINT64*)(v3 + 8 * (v2 >> 10) - 1);
        return (PHANDLE_TABLE_ENTRY)(v5 + 4 * (v2 & 0x3FF));
    }

    if ((UINT32)v4)
    {
        v5 = *(UINT64*)(*(UINT64*)(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF));
        return (PHANDLE_TABLE_ENTRY)(v5 + 4 * (v2 & 0x3FF));
    }
    return (PHANDLE_TABLE_ENTRY)(v3 + 4 * v2);
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
