// Just For Fun Nothing Special Here tbh

#include <ntifs.h>
#include <ntddk.h>

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath);
VOID Unload(PDRIVER_OBJECT DriverObject);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
	PKPCR Pcr = KeGetPcr();
	uintptr_t Prcb = (uintptr_t)Pcr->CurrentPrcb;
	int spoofed_cpuid[] = { 0x10 };			  // my age 
	int spoofed_mhz[] = { 0x539 };		   // 1337 
	char* VendorString = (char*)(Prcb + 0x8590);
	char* spoofed_vendor_name = "astr0";
	char* cpu_id = (char*)(Prcb + 0x041);
	ULONG* cpu_mhz = (ULONG*)(Prcb + 0x044);
	DbgPrint("CPU ID: %d", *cpu_id);
	DbgPrint("VendorString: %s", VendorString);
	DbgPrint("CPU MHz: %lld", *cpu_mhz);
	memcpy(VendorString, spoofed_vendor_name, sizeof(spoofed_vendor_name));
	memcpy(cpu_id, spoofed_cpuid, sizeof(spoofed_cpuid));
	memcpy(cpu_mhz, spoofed_mhz, sizeof(spoofed_mhz));
	DbgPrint("VendorString: %s", VendorString);
	DbgPrint("CPU ID: %d", (int)*cpu_id);
	DbgPrint("CPU MHz: %lld", *cpu_mhz);
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	DbgPrint("Bye");
}
