#include <ntifs.h>
#include <ntddk.h>
#include "nt.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath);
VOID Unload(PDRIVER_OBJECT DriverObject);
auto get_ntoskrnl_base(PSYSTEM_MODULE_INFORMATION& ModInfo) -> PVOID;

typedef NTSTATUS (NTAPI* _ZwQuerySystemInformation)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
);


auto get_ntoskrnl_base(PSYSTEM_MODULE_INFORMATION& ModInfo) -> PVOID
{
	UNICODE_STRING FuncName = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
	_ZwQuerySystemInformation _pZwQuerySystemInformation = (_ZwQuerySystemInformation)MmGetSystemRoutineAddress(&FuncName);
	ModInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, 1024 * 1024);
	NTSTATUS SysInfoDrv = _pZwQuerySystemInformation(SystemModuleInformation, ModInfo, 4096, nullptr);

	for (int i = 0; i < ModInfo->Count; i++)
	{
		if (strstr(reinterpret_cast<const char*>(ModInfo->Module[i].FullPathName), "ntoskrnl.exe"))
			return ModInfo->Module[i].ImageBase;
	}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
	UNREFERENCED_PARAMETER(RegPath);
	PSYSTEM_MODULE_INFORMATION SysModInfo;
	DbgPrint("ntoskrnl.exe base addr: %p", get_ntoskrnl_base(SysModInfo));
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("Bye");
}
