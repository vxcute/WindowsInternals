#include <ntddk.h>

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath);
VOID Unload(PDRIVER_OBJECT DriverObject);
VOID LogImage(PUNICODE_STRING FullImageName, HANDLE ProcessID, PIMAGE_INFO ImageInfo);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
	UNREFERENCED_PARAMETER(RegPath);
	PsSetLoadImageNotifyRoutine(LogImage);
	return STATUS_SUCCESS;
}

VOID LogImage(PUNICODE_STRING FullImageName, HANDLE ProcessID, PIMAGE_INFO ImageInfo)
{
	DbgPrint("Image Loaded With Base Address: %p", ImageInfo->ImageBase);
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
}
