#include <ntifs.h>
#include <ntddk.h>
#include "nt.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath);
VOID Unload(PDRIVER_OBJECT DriverObject);
typedef NTSTATUS(NTAPI* pPsLookupProcessByProcessId)(_In_ HANDLE ProcessId, _Out_ _PEPROCESS* Process);
typedef PVOID(NTAPI* _PsGetProcessSectionBaseAddress)(_PEPROCESS eproc);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
	UNREFERENCED_PARAMETER(RegPath);
	_PEPROCESS eproc;
	UNICODE_STRING FuncName = RTL_CONSTANT_STRING(L"PsLookupProcessByProcessId");
	UNICODE_STRING FuncName2 = RTL_CONSTANT_STRING(L"PsGetProcessSectionBaseAddress");
	pPsLookupProcessByProcessId _pPsLookupProcessByProcessId = (pPsLookupProcessByProcessId)MmGetSystemRoutineAddress(&FuncName);
	_PsGetProcessSectionBaseAddress _pPsGetProcessSectionBaseAddress = (_PsGetProcessSectionBaseAddress)MmGetSystemRoutineAddress(&FuncName2);
	
	// Just Hardcoded For Test
	_pPsLookupProcessByProcessId((HANDLE)416, &eproc);
   
	/* 
		 U Don't Have Tot PsGetProcessSectionBaseAddress This Just Gets The Base Address From The EPROCESS 
		 https://github.com/vxcute/WindowsReversed/blob/main/Processes/PsGetProcessSectionBaseAddress.cpp
       */ 
	
	PVOID BaseAddr = _pPsGetProcessSectionBaseAddress(eproc);
	DbgPrint("Process Base Addr: %p", BaseAddr);
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("Bye");
}
