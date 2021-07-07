#include <ntddk.h>

typedef struct _CALL_BACK_INFO
{
    ULONG64 Unknow;
    ULONG64 Unknow1;
    ULONG64 Unknow2;
    WCHAR* AltitudeString;
    LIST_ENTRY NextEntryItemList; 
    ULONG64 Operations;
    PVOID ObHandle;
    PVOID ObjectType;
    ULONG64 PreCallbackAddr;
    ULONG64 PostCallbackAddr;
}CALL_BACK_INFO, * PCALL_BACK_INFO;

typedef struct _OB_CALLBACK
{
    LIST_ENTRY	         ListEntry;
    ULONG64		         Operations;
    PCALL_BACK_INFO	   	 ObHandle;
    ULONG64		         ObjTypeAddr;
    ULONG64		         PreCall;
    ULONG64		         PostCall;
} OB_CALLBACK, * POB_CALLBACK;

NTSTATUS DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
);

VOID Unload(
    IN PDRIVER_OBJECT DriverObject
);

VOID EnumObCallbacks(
  VOID
);

VOID LocateCallbackListHeads(
  PLIST_ENTRY& ObProcessCallbackListHead, 
  PLIST_ENTRY& ObThreadCallbackListHead
); 

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    EnumObCallbacks();

    DriverObject->DriverUnload = Unload;

    return STATUS_SUCCESS;
}

VOID Unload(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("Driver Unloaded ...");
}

VOID EnumObCallbacks()
{
    POB_CALLBACK ObCallback = nullptr;
    PLIST_ENTRY ObProcessCallbackListHead = nullptr, ObThreadCallbackListHead = nullptr;

    LocateCallbackListHeads(ObProcessCallbackListHead, ObThreadCallbackListHead);
    
    DbgPrint("====================Enumerating Process Callbacks====================\n");

    for (PLIST_ENTRY ListEntry = ObProcessCallbackListHead->Flink; ListEntry != ObProcessCallbackListHead; ListEntry = ListEntry->Flink)
    {
        DbgPrint("Found ObProcessCallbackListHead at: %p\n", ObProcessCallbackListHead);

        ObCallback = (POB_CALLBACK)ListEntry;

        DbgPrint("AltitudeString: %s\n", ObCallback->ObHandle->AltitudeString);
        DbgPrint("Object Handle: %p\n", ObCallback->ObHandle);
        DbgPrint("PreCall: %p\n", ObCallback->PreCall);
        DbgPrint("PostCall: %p\n", ObCallback->PostCall);
        DbgPrint("Operations: %d\n", ObCallback->ObHandle->Operations);
        DbgPrint("ObjectType: %p", ObCallback->ObHandle->ObjectType);
        DbgPrint("=============================================\n");
    }

    DbgPrint("====================Enumerating Thread Callbacks====================\n");

    for (PLIST_ENTRY ListEntry = ObThreadCallbackListHead->Flink; ListEntry != ObThreadCallbackListHead; ListEntry = ListEntry->Flink)
    {
        DbgPrint("Found ObThreadCallbackListHead at: %p\n", ObThreadCallbackListHead);

        ObCallback = (POB_CALLBACK)ListEntry;

        DbgPrint("AltitudeString: %s\n", ObCallback->ObHandle->AltitudeString);
        DbgPrint("Object Handle: %p\n", ObCallback->ObHandle);
        DbgPrint("PreCall: %p\n", ObCallback->PreCall);
        DbgPrint("PostCall: %p\n", ObCallback->PostCall);
        DbgPrint("Operations: %d\n", ObCallback->ObHandle->Operations);
        DbgPrint("ObjectType: %p", ObCallback->ObHandle->ObjectType);
        DbgPrint("=============================================\n");
    }
}

// https://www.unknowncheats.me/forum/arma-2-a/175227-driver-disable-process-thread-object-callbacks.html

VOID LocateCallbackListHeads(PLIST_ENTRY& ObProcessCallbackListHead, PLIST_ENTRY& ObThreadCallbackListHead)
{
    POBJECT_TYPE ProcessType = *PsProcessType;

    __try
    {
        if (ProcessType && MmIsAddressValid((PVOID)ProcessType))
        {
            for (auto i = 0xF8; i > 0x0; i -= 0x8)
            {
                UINT64 First = *(UINT64*)((UINT64)ProcessType + i); 
                UINT64 Second = *(UINT64*)((UINT64)ProcessType + (i + 0x8));

                if (First && MmIsAddressValid((PVOID)First) && Second && MmIsAddressValid((PVOID)Second))
                {
                    UINT64 Test1First = *(UINT64*)(First + 0x0); 
                    UINT64 Test1Second = *(UINT64*)(First + 0x8);

                    if (Test1First && MmIsAddressValid((PVOID)Test1First) && Test1Second && MmIsAddressValid((PVOID)Test1Second))
                    {
                        UINT64 TestObjectType = *(UINT64*)(First + 0x20);

                        if (TestObjectType == (UINT64)ProcessType)
                        {
                            ObProcessCallbackListHead = (PLIST_ENTRY)(*(UINT64*)PsProcessType + i);
                            ObThreadCallbackListHead = (PLIST_ENTRY)(*(UINT64*)PsThreadType + i);
                        }
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
