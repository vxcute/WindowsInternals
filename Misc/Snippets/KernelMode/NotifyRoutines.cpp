#include <ntddk.h>
#include <nt.hpp>

NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT DriverObject, 
	IN PUNICODE_STRING RegPath
);

VOID Unload(
	IN PDRIVER_OBJECT DriverObject
);

template <class ExportType>
ExportType GetKernelExport(
	PCWSTR zExportName
);

VOID LogImages
(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
);

VOID LogProcesses
(
	_In_ HANDLE ParentId,
	_In_ HANDLE ProcessId,
	_In_ BOOLEAN Create
);


VOID LogThreads
(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
);

typedef PCSTR (NTAPI *_PsGetProcessImageFileName)(
	PEPROCESS Process
);

typedef NTSTATUS (NTAPI* _PsLookupProcessByProcessId)(
	HANDLE    ProcessId,
	PEPROCESS* Process
);

NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegPath
)

{
	UNREFERENCED_PARAMETER(RegPath);

	DriverObject->DriverUnload = Unload;

	PsSetLoadImageNotifyRoutine(LogImages);

	PsSetCreateProcessNotifyRoutine(LogProcesses, true);

	PsSetCreateThreadNotifyRoutine(LogThreads);

	return STATUS_SUCCESS;
}

VOID Unload(
	IN PDRIVER_OBJECT DriverObject
)

{
	UNREFERENCED_PARAMETER(DriverObject);
	PsRemoveLoadImageNotifyRoutine(LogImages);
	PsRemoveCreateThreadNotifyRoutine(LogThreads);
}

VOID LogImages
(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,                
	_In_ PIMAGE_INFO ImageInfo
)

{
	_PEPROCESS Process = nullptr;

	auto PsGetProcessImageFileName = GetKernelExport<_PsGetProcessImageFileName>(L"PsGetProcessImageFileName");

	auto PsLookupProcessByProcessId = GetKernelExport<_PsLookupProcessByProcessId>(L"PsLookupProcessByProcessId");

	if (PsGetProcessImageFileName && PsLookupProcessByProcessId)
	{
		PsLookupProcessByProcessId(ProcessId, &Process);

		DbgPrint("%wZ Loaded By Process %s at ImageBase: %p\n", FullImageName, PsGetProcessImageFileName(Process), ImageInfo->ImageBase);
	}

	else
	{
		DbgPrint("Couldn't resolve PsGetProcessImageFileName and PsLookupProcessByProcessId\n");
	}
}

VOID LogProcesses
(
	_In_ HANDLE ParentId,
	_In_ HANDLE ProcessId,
	_In_ BOOLEAN Create
)

{
	_PEPROCESS ParentProcess = nullptr, ChildProcess = nullptr;


	auto PsGetProcessImageFileName = GetKernelExport<_PsGetProcessImageFileName>(L"PsGetProcessImageFileName");

	auto PsLookupProcessByProcessId = GetKernelExport<_PsLookupProcessByProcessId>(L"PsLookupProcessByProcessId");
	
	if (PsGetProcessImageFileName && PsLookupProcessByProcessId)
	{
		PsLookupProcessByProcessId(ParentId, &ParentProcess);

		PsLookupProcessByProcessId(ProcessId, &ChildProcess);

		DbgPrint("Process %s (PID: %d) Created Process %s (PID: %d)\n", PsGetProcessImageFileName(ParentProcess), ParentId,  
			PsGetProcessImageFileName(ChildProcess), ProcessId);
	}

	else
	{
		DbgPrint("Couldn't resolve PsGetProcessImageFileName and PsLookupProcessByProcessId\n");
	}
}

VOID LogThreads
(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
)

{
	_PEPROCESS Process = nullptr;


	auto PsGetProcessImageFileName = GetKernelExport<_PsGetProcessImageFileName>(L"PsGetProcessImageFileName");

	auto PsLookupProcessByProcessId = GetKernelExport<_PsLookupProcessByProcessId>(L"PsLookupProcessByProcessId");


	if (PsGetProcessImageFileName && PsLookupProcessByProcessId)
	{
		PsLookupProcessByProcessId(ProcessId, &Process);
		
		DbgPrint("Thread (TID: %d) Created By Process %s (PID: %d)\n", ThreadId, PsGetProcessImageFileName(Process), ProcessId);
	}

	else
	{
		DbgPrint("Couldn't resolve PsGetProcessImageFileName and PsLookupProcessByProcessId\n");
	}
}

template <class ExportType>
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
