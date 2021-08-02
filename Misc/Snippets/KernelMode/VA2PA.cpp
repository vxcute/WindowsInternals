#include <ntifs.h>
#include <ntddk.h> 

/*
	credits:
		. https://www.unknowncheats.me/forum/anti-cheat-bypass/444289-read-process-physical-memory-attach.html
		. xeroxz (ptm, bluepill)
		. https://www.triplefault.io/2017/07/introduction-to-ia-32e-hardware-paging.html (page table structures, also very good article on page tables) 
*/ 

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD Unload;

constexpr auto WINDOWS_1803 = 17134;
constexpr auto WINDOWS_1809 = 17763;
constexpr auto WINDOWS_1903 = 18362;
constexpr auto WINDOWS_1909 = 18363;
constexpr auto WINDOWS_2004 = 19041;
constexpr auto WINDOWS_20H2 = 19569;
constexpr auto WINDOWS_21H1 = 20180;

typedef struct _PML4E
{
	union
	{
		ULONG64 Value;

		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;
		};
	};
} PML4E, * PPML4E;
static_assert(sizeof(PML4E) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef struct _PDPTE
{
	union
	{
		ULONG64 Value;

		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;
		};
	};
} PDPTE, * PPDPTE;
static_assert(sizeof(PDPTE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef struct _PDE
{
	union
	{
		ULONG64 Value;

		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;
		};
	};
} PDE, * PPDE;
static_assert(sizeof(PDE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef struct _PTE
{
	union
	{
		ULONG64 Value;

		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Dirty : 1;
			ULONG64 PageAccessType : 1;
			ULONG64 Global : 1;
			ULONG64 Ignored2 : 3;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 7;
			ULONG64 ProtectionKey : 4;
			ULONG64 ExecuteDisable : 1;
		};
	};
} PTE, * PPTE;
static_assert(sizeof(PTE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef union _VIRTUAL_ADDRESS
{
	ULONG64 Value;

	// 4Kb Pages 

	struct
	{
		ULONG64 Offset4Kb : 12;
		ULONG64 PtIndex : 9;
		ULONG64 PdIndex : 9;
		ULONG64 PdptIndex : 9;
		ULONG64 Pml4Index : 9;
		ULONG64 Reserved : 16;
	};

	// 2mb Pages 

	struct
	{
		ULONG64 Offset2mb : 21;
		ULONG64 PdIndex : 9;
		ULONG64 PdptIndex : 9;
		ULONG64 Pml4Index : 9;
		ULONG64 Reserved : 16;
	};

	// 1Gb Pages 

	struct
	{
		ULONG64 Offset1Gb : 30;
		ULONG64 PdptIndex : 9;
		ULONG64 Pml4Index : 9;
		ULONG64 Reserved : 16;
	};

}VIRTUAL_ADDRESS, * PVIRTUAL_ADDRESS;

ULONG64 GetUserDirOffset(VOID)
{
	RTL_OSVERSIONINFOW VersionInfo = { 0 };

	RtlGetVersion(&VersionInfo);

	switch (VersionInfo.dwBuildNumber)
	{
	case WINDOWS_1803:
		return 0x0278;
		break;
	case WINDOWS_1809:
		return 0x0278;
		break;
	case WINDOWS_1903:
		return 0x0280;
		break;
	case WINDOWS_1909:
		return 0x0280;
		break;
	case WINDOWS_2004:
		return 0x0388;
		break;
	case WINDOWS_20H2:
		return 0x0388;
		break;
	case WINDOWS_21H1:
		return 0x0388;
		break;
	default:
		return 0x0388;
	}
}

template <typename T>
auto ReadPhysicalMemory(T* TargetAddress) -> T
{
	T Buffer = { 0 };

	SIZE_T BytesReaden = 0;

	MM_COPY_ADDRESS Address = { 0 };

	Address.PhysicalAddress.QuadPart = reinterpret_cast<LONGLONG>(TargetAddress);

	if (!NT_SUCCESS(MmCopyMemory(&Buffer, Address, sizeof(T), MM_COPY_MEMORY_PHYSICAL, &BytesReaden)))
	{
		return T();
	}

	return Buffer;
}

template <typename T>
auto ReadKernelMemory(ULONG64 Address) -> T
{
	T Buffer = { 0 };

	if (memcpy((PVOID)&Buffer, (PVOID)Address, sizeof(T)) == nullptr)
	{
		return T();
	}

	return Buffer;
}

PVOID GetProcessCr3(HANDLE Pid)
{
	PEPROCESS Process = nullptr;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(Pid, &Process)))
	{
		return nullptr;
	}

	PVOID ProcessDirBase = reinterpret_cast<PVOID>(
		ReadKernelMemory<PTE>((ULONG64)Process + 0x28).PageFrameNumber << PAGE_SHIFT);

	if (ProcessDirBase == nullptr)
	{
		PVOID ProcessUserDirBase = reinterpret_cast<PVOID>(
			ReadKernelMemory<PTE>((ULONG64)Process + GetUserDirOffset()).PageFrameNumber << PAGE_SHIFT);

		return ProcessUserDirBase;
	}

	return ProcessDirBase;
}


ULONG64 GetPhysicalAddress(ULONG64 VirtualAddress, HANDLE Pid)
{
	SIZE_T BytesReaden = 0;
	VIRTUAL_ADDRESS VirtualAddr = { VirtualAddress };
	PVOID DirBase = GetProcessCr3(Pid);

	const auto Pml4ePhysc = reinterpret_cast<PPML4E>((ULONG64)DirBase) + VirtualAddr.Pml4Index;

	const auto Pml4e = ReadPhysicalMemory<PML4E>(Pml4ePhysc);

	if (Pml4e.Value == NULL || Pml4e.Present == NULL)
	{
		return 0;
	}

	const auto PdptePhysc = reinterpret_cast<PPDPTE>((ULONG64)Pml4e.PageFrameNumber << PAGE_SHIFT) + VirtualAddr.PdptIndex;

	const auto Pdpte = ReadPhysicalMemory<PDPTE>(PdptePhysc);

	if (Pdpte.Value == NULL || Pdpte.Present == NULL)
	{
		return 0;
	}

	// handle 1gb pages 

	if (Pdpte.PageSize)
	{
		return (Pdpte.PageFrameNumber << PAGE_SHIFT) + VirtualAddr.Offset1Gb;
	}

	const auto PdePhysc = reinterpret_cast<PPDE>((ULONG64)Pdpte.PageFrameNumber << PAGE_SHIFT) + VirtualAddr.PdIndex;

	const auto Pde = ReadPhysicalMemory<PDE>(PdePhysc);

	if (Pde.Value == NULL || Pde.Present == NULL)
	{
		return 0;
	}

	// handle 2mb pages 

	if (Pde.PageSize)
	{
		return (Pde.PageFrameNumber << PAGE_SHIFT) + VirtualAddr.Offset2mb;
	}

	const auto PtePhysc = reinterpret_cast<PPTE>((ULONG64)Pde.PageFrameNumber << PAGE_SHIFT) + VirtualAddr.PtIndex;

	const auto Pte = ReadPhysicalMemory<PTE>(PtePhysc);

	if (Pte.Value == NULL || Pte.Present == NULL)
	{
		return 0;
	}

	return (Pte.PageFrameNumber << PAGE_SHIFT) + VirtualAddr.Offset4Kb;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = Unload;

	DbgPrint("[+] DriverObject Virtual: %p\n", DriverObject);
	DbgPrint("[+] DriverObject Physical: %x\n", MmGetPhysicalAddress(DriverObject));
	DbgPrint("[+] DriverObject Physical: %x\n", GetPhysicalAddress((ULONG64)DriverObject, (HANDLE)4));

	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("[+] %wZ Unloaded\n", DriverObject->DriverName);
}
