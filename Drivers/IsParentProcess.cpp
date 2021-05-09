#include <ntifs.h>
#include <ntddk.h>
#include "nt.hpp"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath);
VOID Unload(PDRIVER_OBJECT DriverObject);


typedef NTSTATUS(NTAPI* pPsLookupProcessByProcessId)(_In_ HANDLE ProcessId, _Out_ _PEPROCESS* Process);


// Def: Checks If Its Parent Process or not 
// Status: Unexported 
bool NTAPI PspIsParentProcess(_PEPROCESS ProcessA, _PEPROCESS ProcessB)
{

	bool IsParentProcess = false;
	
	// If Its A Child Process Its InheritedFromUniqueProcessId Will Be Equal To Parent Process UniqueProcessId So Check For That 
	
	if (ProcessB->InheritedFromUniqueProcessId == ProcessA->UniqueProcessId)

		/*	
		     More Checking Windows Keeps Tracks Of Processes Sequence Using This Sequence Number 
			 According To Bruce Dang (The Only Thing I Found About Sequence Numbers Is His Tweet !)
			 Parent Process Will Have A Sequence Number Less Than Of Child Process Sequence Number 
			 So If Child Process Has Higher Sequence Number Set IsParentProcess To Be True 
		 */ 
		IsParentProcess = ProcessB->SequenceNumber > ProcessA->SequenceNumber;
	
	return IsParentProcess;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
	UNREFERENCED_PARAMETER(RegPath);
	_PEPROCESS eproc;
	_PEPROCESS eproc2;
	UNICODE_STRING FuncName = RTL_CONSTANT_STRING(L"PsLookupProcessByProcessId");
	pPsLookupProcessByProcessId _pPsLookupProcessByProcessId = (pPsLookupProcessByProcessId)MmGetSystemRoutineAddress(&FuncName);
	// Just Hardcoded pids for testing u shouldn't do that 
	_pPsLookupProcessByProcessId((HANDLE)392, &eproc);
	_pPsLookupProcessByProcessId((HANDLE)924, &eproc2);
	PspIsParentProcess(eproc2, eproc) ? DbgPrint("Parent Process ...") : DbgPrint("Not A Parent Process ...");
	DbgPrint("ProcessA Process Unique Process ID: %d", eproc->UniqueProcessId);
	DbgPrint("ProcessA Process InheritedFromUniqueProcessId %d", eproc->InheritedFromUniqueProcessId);
	DbgPrint("ProcessA Process Sequence Number: %d", eproc->SequenceNumber);
	DbgPrint("ProcessB Process UniqueProcessId: %d", eproc2->UniqueProcessId);
	DbgPrint("ProcessB Process InheritedFromUniqueProcessId %d", eproc2->InheritedFromUniqueProcessId);
	DbgPrint("ProcessB Process Sequence Number: %d", eproc2->SequenceNumber);
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("Bye");
}
