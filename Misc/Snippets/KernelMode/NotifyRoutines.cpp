#include <ntddk.h>
#include <nt.hpp>

NTSTATUS DriverEntry(
	 PDRIVER_OBJECT DriverObject, 
	 PUNICODE_STRING RegPath
);

VOID Unload(
	PDRIVER_OBJECT DriverObject
);

template <typename ExportType>
ExportType GetKernelExport(
	PCWSTR zExportName
);

VOID LogImages(
	 PUNICODE_STRING FullImageName,
	 HANDLE ProcessId,
	 PIMAGE_INFO ImageInfo
);

VOID LogProcesses(
	HANDLE ParentId,
	HANDLE ProcessId,
	BOOLEAN Create
);


VOID LogThreads(
	 HANDLE ProcessId,
	 HANDLE ThreadId,
	 BOOLEAN Create
);

typedef PCSTR (NTAPI *_PsGetProcessImageFileName)(
	PEPROCESS Process
);

typedef NTSTATUS (NTAPI* _PsLookupProcessByProcessId)(
	 HANDLE    ProcessId,
	 PEPROCESS* Process
);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
	UNREFERENCED_PARAMETER(RegPath);

	DriverObject->DriverUnload = Unload;

	PsSetLoadImageNotifyRoutine(LogImages);

	PsSetCreateProcessNotifyRoutine(LogProcesses, true);

	PsSetCreateThreadNotifyRoutine(LogThreads);

	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	PsRemoveLoadImageNotifyRoutine(LogImages);
	PsRemoveCreateThreadNotifyRoutine(LogThreads);
}

VOID LogImages(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
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

VOID LogProcesses(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)

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

VOID LogThreads(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
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

template <typename ExportType>
ExportType GetKernelExport(PCWSTR zExportName)
{
	UNICODE_STRING UExportName;

	RtlInitUnicodeString(&UExportName, zExportName);

	ExportType ExportAddress = (ExportType)MmGetSystemRoutineAddress(&UExportName);

	return ExportAddress ? ExportAddress : ExportType(nullptr);
}
