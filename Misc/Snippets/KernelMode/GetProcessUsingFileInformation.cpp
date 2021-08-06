#include <ntifs.h>
#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry; 
DRIVER_UNLOAD Unload;
PEPROCESS GetProcess(PCSTR ProcessName);
PEPROCESS GetProcessByPid(UINT64 ProcessId); 

EXTERN_C PCSTR PsGetProcessImageFileName(PEPROCESS Process); 

PEPROCESS GetProcessByPid(UINT64 ProcessId)
{
	PEPROCESS Process = nullptr;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process)))
	{
	  	return nullptr;
	}

	ObDereferenceObject(Process);
	return Process;
}

PEPROCESS GetProcess(PCSTR ProcessName)
{
	PEPROCESS Process = nullptr; 

	IO_STATUS_BLOCK IoStatusBlock = { 0 };

	_OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

	UNICODE_STRING FilePath = { 0 };

	HANDLE hFile = nullptr;

	RtlInitUnicodeString(&FilePath, L"\\NTFS\\");

	InitializeObjectAttributes(&ObjectAttributes, &FilePath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	if (!NT_SUCCESS(
	
	NtCreateFile
	(
		&hFile,
		GENERIC_READ | SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		0,
		NULL,
		0
	)))

	{
		DbgPrint("[+] failed to optain handle to NTFS\n");
		return nullptr;
	}

	const auto ProcessIdInformation = static_cast<PFILE_PROCESS_IDS_USING_FILE_INFORMATION>(ExAllocatePool(NonPagedPool, 0x4000));

	if (ProcessIdInformation == nullptr)
	{
		return nullptr; 
	}

	RtlSecureZeroMemory(&IoStatusBlock, sizeof(IO_STATUS_BLOCK));

	if (!NT_SUCCESS(NtQueryInformationFile(hFile, &IoStatusBlock, ProcessIdInformation, 0x4000, FileProcessIdsUsingFileInformation)))
	{
		DbgPrint("[+] Failed to query file information\n");
		return nullptr;
	}

	for (auto i = 0; i < ProcessIdInformation->NumberOfProcessIdsInList; i++)
	{
		Process = GetProcessByPid(ProcessIdInformation->ProcessIdList[i]);
		
		PCSTR ProcName = PsGetProcessImageFileName(Process);
		
		if (!_stricmp(ProcName, ProcessName))
		{
			DbgPrint("[+] Found %s EPROCESS: %p\n", ProcName, Process);
			break;
		}
	}

	ExFreePool(ProcessIdInformation);
	return Process; 
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = Unload;

	GetProcess("csrss.exe");

	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("[+] %wZ Unloaded\n", DriverObject->DriverName);
}
