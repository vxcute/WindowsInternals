#include <ntddk.h>

#define POOL_TAG 0x6B65726E656C
#define POOL_SIZE 1024*1024

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemModuleInformation = 11,
} SYSTEM_INFORMATION_CLASS;

struct NtosInfo
{
    PVOID ImageBase;
    ULONG64 ImageSize;
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

typedef struct _MM_UNLOADED_DRIVER
{
    UNICODE_STRING 	Name;
    PVOID 			ModuleStart;
    PVOID 			ModuleEnd;
    ULONG64 		UnloadTime;
} MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;

NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
);

VOID Unload(
    PDRIVER_OBJECT DriverObject
);

VOID EnumUnloadedDrivers(
    VOID
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

template <class ExportType>
ExportType GetKernelExport(
    PCWSTR zExportName
);

NTSTATUS GetSysModInfo(
    PSYSTEM_MODULE_INFORMATION& SystemModInfo
);

typedef NTSTATUS(NTAPI* _ZwQuerySystemInformation)
(
   SYSTEM_INFORMATION_CLASS SystemInformationClass,
   PVOID                    SystemInformation,
   ULONG                    SystemInformationLength,
   PULONG                   ReturnLength
);


PMM_UNLOADED_DRIVER pMmUnloadedDrivers;
PULONG pMmLastUnloadedDriver;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    EnumUnloadedDrivers();

    DriverObject->DriverUnload = Unload;

    return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("Driver Unloaded ...");
}

template <typename ExportType>
ExportType GetKernelExport(PCWSTR zExportName)
{
    UNICODE_STRING UExportName;

    RtlInitUnicodeString(&UExportName, zExportName);

    ExportType ExportAddress = (ExportType)MmGetSystemRoutineAddress(&UExportName);

    return ExportAddress ? ExportAddress : ExportType(nullptr);  
}

bool LocateMmUnloaded(PULONG64& MmLastUnloadedDriver, PMM_UNLOADED_DRIVER& MmUnloadedDrivers)
{
    PSYSTEM_MODULE_INFORMATION SystemModInfo = nullptr;

    UCHAR MmUnloadedDriversPattern[] = "\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9";

    UCHAR MmLastUnloadedDriverPattern[] = "\x8B\x05\x00\x00\x00\x00\x83\xF8\x32";

    if (!NT_SUCCESS(GetSysModInfo(SystemModInfo)))
    {
        DbgPrint("Failed to get system module information");
        return false;
    }

    NtosInfo ntos = { SystemModInfo->Module[0].ImageBase, SystemModInfo->Module[0].ImageSize };

    if (!GetAddress((UINT64)ntos.ImageBase, ntos.ImageSize, MmUnloadedDriversPattern, "xxx????xxx", 3, 4, MmUnloadedDrivers))
    {
        DbgPrint("Failed to get MmUnloadedDrivers");
        return false;
    }

    if (!GetAddress((UINT64)ntos.ImageBase, ntos.ImageSize, MmLastUnloadedDriverPattern, "xx????xxx", 2, 4, MmLastUnloadedDriver))
    {
        DbgPrint("Failed to get MmLastUnloadedDriver");
        return false
    }

    return true;
}

VOID EnumUnloadedDrivers()
{
    PULONG64 pMmLastUnloadedDriver; 
    PMM_UNLOADED_DRIVER pMmUnloadedDrivers;

    LocateMmUnloaded(pMmLastUnloadedDriver, pMmUnloadedDrivers);

    ULONG64 MmLastUnloadedDriver = *pMmLastUnloadedDriver;

    PMM_UNLOADED_DRIVER MmUnloadedDrivers = *(PMM_UNLOADED_DRIVER*)pMmUnloadedDrivers;

    for (auto i = 0; i < MmLastUnloadedDriver; i++)
    {
        DbgPrint("ModuleName: %wZ ModuleStart: %p ModuleEnd: %p UnloadTime: %lld\n",
            MmUnloadedDrivers[i].Name, MmUnloadedDrivers[i].ModuleStart, MmUnloadedDrivers[i].ModuleEnd, MmUnloadedDrivers[i].UnloadTime);
    }
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
