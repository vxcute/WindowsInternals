#include <ntddk.h>
#include <nt.hpp>

#define PROCESS_TERMINATE	     0x0001
#define PROCESS_VM_OPERATION	     0x0008
#define PROCESS_VM_READ              0x0010
#define PROCESS_VM_WRITE	     0x0020
#define PROCESS_SUSPEND_RESUME	     0x0800

typedef NTSTATUS(NTAPI* _PsLookupProcessByProcessId)(
	 HANDLE ProcessID, 
	 _PEPROCESS* Process
);

PVOID ObRegistrationHandle = nullptr;

NTSTATUS DriverEntry(
	 PDRIVER_OBJECT DriverObject, 
	 PUNICODE_STRING RegistryPath
);

VOID Unload(
	 PDRIVER_OBJECT DriverObject
);

OB_PREOP_CALLBACK_STATUS ObPreCallback(
	 PVOID ObRegistrationContext, 
	 POB_PRE_OPERATION_INFORMATION PreOpInformation
);

VOID ObPostCallback(
	 PVOID ObRegistrationContext, 
	 POB_POST_OPERATION_INFORMATION PostOpInformation
);

PCSTR GetProcessNameById(
	 HANDLE ProcessId
);

template <typename ExportType>
ExportType GetKernelExport(
	 PCWSTR zExportName
);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = Unload;

	NTSTATUS Status = STATUS_SUCCESS;

	UNICODE_STRING Altitude = RTL_CONSTANT_STRING(L"8214");

	OB_OPERATION_REGISTRATION ObOperationRegistration = { PsProcessType, OB_OPERATION_HANDLE_CREATE, ObPreCallback , ObPostCallback };
	
	OB_CALLBACK_REGISTRATION ObCallbackRegistration = { OB_FLT_REGISTRATION_VERSION, 1,  Altitude, nullptr, &ObOperationRegistration };

	Status = ObRegisterCallbacks(&ObCallbackRegistration, &ObRegistrationHandle);

	if (NT_SUCCESS(Status))
	{
		DbgPrint("Registered Callbacks");
	}

	else
	{
		DbgPrint("Failed to register Callbacks");
	}

	return Status;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	DbgPrint("Driver Unloaded ...");

	if (ObRegistrationHandle != nullptr)
	{
		ObUnRegisterCallbacks(ObRegistrationHandle);
		DbgPrint("Unregistered Callbacks");
	}

	else
	{
		DbgPrint("ObRegistrationHandle is null");
	}
}

OB_PREOP_CALLBACK_STATUS ObPreCallback(PVOID ObRegistrationContext, POB_PRE_OPERATION_INFORMATION PreOpInformation)
{
	UNREFERENCED_PARAMETER(ObRegistrationContext);

	PCSTR ProcessName = GetProcessNameById(PsGetProcessId((_PEPROCESS)PreOpInformation->Object));

	if (!strcmp(ProcessName, "OSRLOADER.exe"))
	{
		if (PreOpInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			if ((PreOpInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				PreOpInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}

			if ((PreOpInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
			{
				PreOpInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}

			if ((PreOpInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			{
				PreOpInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}

			if ((PreOpInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
			{
				PreOpInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}

			if ((PreOpInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_SUSPEND_RESUME) == PROCESS_SUSPEND_RESUME)
			{
				PreOpInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
			}
		}
	}

	return OB_PREOP_SUCCESS;
}

VOID ObPostCallback(PVOID ObRegistrationContext, POB_POST_OPERATION_INFORMATION PostOpInformation)
{
	UNREFERENCED_PARAMETER(ObRegistrationContext);
	UNREFERENCED_PARAMETER(PostOpInformation);
}

PCSTR GetProcessNameById(HANDLE ProcessId)
{
	_PEPROCESS Process = nullptr;

	auto PsLookupProcessByProcessId = GetKernelExport<_PsLookupProcessByProcessId>(L"PsLookupProcessByProcessId");

	if (PsLookupProcessByProcessId != nullptr)
	{
		PsLookupProcessByProcessId(ProcessId, &Process);
		return (PCSTR)Process->ImageFileName;
	}

	else
	{
		DbgPrint("Couldn't Resolve PsLookupProcessByProcessId");
		return nullptr;
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
