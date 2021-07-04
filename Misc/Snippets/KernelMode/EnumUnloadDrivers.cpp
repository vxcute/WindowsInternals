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
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
);

VOID Unload(
    IN PDRIVER_OBJECT DriverObject
);

VOID EnumUnloadedDrivers(
    VOID
);

bool FindPattern(
    IN UINT64 Base,
    IN UINT64 Size,
    IN PCUCHAR Pattern,
    IN PCSTR WildCard,
    OUT PVOID* Found
);

template <class T>
VOID Resolve(
    IN PVOID InstructionAddress,
    IN INT OpcodeBytes,
    IN INT AddressBytes,
    OUT T* Found
);

template <class ExportType>
ExportType GetKernelExport(
    IN PCWSTR zExportName
);

NTSTATUS GetSysModInfo(
    PSYSTEM_MODULE_INFORMATION& SystemModInfo
);

typedef NTSTATUS(NTAPI* _ZwQuerySystemInformation)
(
    _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Inout_   PVOID                    SystemInformation,
    _In_      ULONG                    SystemInformationLength,
    _Out_opt_ PULONG                   ReturnLength
);


PMM_UNLOADED_DRIVER pMmUnloadedDrivers;
PULONG pMmLastUnloadedDriver;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    EnumUnloadedDrivers();

    DriverObject->DriverUnload = Unload;

    return STATUS_SUCCESS;
}

VOID Unload(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("Driver Unloaded ...");
}

template<class ExportType>
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

bool ExposeKernelData(VOID)
{
    PSYSTEM_MODULE_INFORMATION SystemModInfo;

    PVOID MmUnloadedDriversInstr, MmLastUnloadedDriverInstr;

    if (!NT_SUCCESS(GetSysModInfo(SystemModInfo)))
    {
        DbgPrint("Failed to get system module information");
        return false;
    }

    NtosInfo ntos = { SystemModInfo->Module[0].ImageBase, SystemModInfo->Module[0].ImageSize };

    UCHAR MmUnloadedDriversPattern[] = "\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9";

    UCHAR MmLastUnloadedDriverPattern[] = "\x8B\x05\x00\x00\x00\x00\x83\xF8\x32";

    if (!FindPattern((UINT64)ntos.ImageBase, ntos.ImageSize, MmUnloadedDriversPattern, "xxx????xxx", &MmUnloadedDriversInstr))
    {
        DbgPrint("Failed to get MmUnloadedDrivers");
        return false;
    }

    if(!FindPattern((UINT64)ntos.ImageBase, ntos.ImageSize, MmLastUnloadedDriverPattern, "xx????xxx", &MmLastUnloadedDriverInstr))
    {
        DbgPrint("Failed to get MmLastUnloadedDriver");
        return false;
    }

    Resolve<PMM_UNLOADED_DRIVER>(MmUnloadedDriversInstr, 3, 4, &pMmUnloadedDrivers);

    Resolve<PULONG>(MmLastUnloadedDriverInstr, 2, 4, &pMmLastUnloadedDriver);

    return STATUS_SUCCESS;
}

VOID EnumUnloadedDrivers()
{
    ExposeKernelData();

    ULONG MmLastUnloadedDriver = *pMmLastUnloadedDriver;

    PMM_UNLOADED_DRIVER MmUnloadedDrivers = *(PMM_UNLOADED_DRIVER*)pMmUnloadedDrivers;

    for (auto i = 0; i < MmLastUnloadedDriver; i++)
    {
        DbgPrint("ModuleName: %wZ ModuleStart: %p ModuleEnd: %p UnloadTime: %lld\n",
            MmUnloadedDrivers[i].Name, MmUnloadedDrivers[i].ModuleStart, MmUnloadedDrivers[i].ModuleEnd, MmUnloadedDrivers[i].UnloadTime);
    }
}

NTSTATUS GetSysModInfo(PSYSTEM_MODULE_INFORMATION& SystemModInfo)
{
    __try
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

    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

bool FindPattern(IN UINT64 Base, IN UINT64 Size, IN PCUCHAR Pattern, IN PCSTR WildCard, OUT PVOID* Found)
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

    for (auto i = 0; i < Size; i++)
    {
        if (CheckMask((UCHAR*)(Base + i), Pattern, WildCard))
        {
            *Found = (PVOID)(Base + i);
            return true;
        }
    }

    return false;
}

template <class T>
VOID Resolve(IN PVOID InstructionAddress, IN INT OpcodeBytes, OUT INT AddressBytes, OUT T* Found)
{
    ULONG64 InstructionAddr = (ULONG64)InstructionAddress;
    AddressBytes += OpcodeBytes;
    ULONG32 RelativeOffset = *(ULONG32*)(InstructionAddr + OpcodeBytes);
    *Found = (T)(InstructionAddr + RelativeOffset + AddressBytes);
}
