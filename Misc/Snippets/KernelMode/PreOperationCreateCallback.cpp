#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

PFLT_FILTER FilterHandle = nullptr;

NTSTATUS FLTAPI DriverEntry(
    PDRIVER_OBJECT DriverObject, 
    PUNICODE_STRING RegPath
);

NTSTATUS FLTAPI FltrUnload(FLT_FILTER_UNLOAD_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationCreate(
    PFLT_CALLBACK_DATA CallBackData, 
    PCFLT_RELATED_OBJECTS FltObjects, 
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

NTSTATUS FLTAPI FltrSetupCallback(
    _In_ PCFLT_RELATED_OBJECTS  FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS  Flags,
    _In_ DEVICE_TYPE  VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE  VolumeFilesystemType
);

NTSTATUS FLTAPI FltrTearDownCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

CONST FLT_OPERATION_REGISTRATION CallBacks[]
{
    {
        IRP_MJ_CREATE,
        0,
        PreOperationCreate,
        0
   },

    { IRP_MJ_OPERATION_END }
};


CONST FLT_REGISTRATION FilterRegistration =
{
    sizeof(FLT_REGISTRATION),      
    FLT_REGISTRATION_VERSION,      
    0,                             
    nullptr,
    CallBacks,                     
    FltrUnload,                    
    FltrSetupCallback,             
    FltrTearDownCallback,          
    nullptr,                  
    nullptr,                  
    nullptr,                  
    nullptr,                  
    nullptr                 
}; 

NTSTATUS FLTAPI DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
    UNREFERENCED_PARAMETER(RegPath);

    NTSTATUS Status = STATUS_SUCCESS;

    Status = FltRegisterFilter(DriverObject, &FilterRegistration, &FilterHandle);

    if (NT_SUCCESS(Status))
    {
        DbgPrint("Registered The MiniFilter ...");
        
        Status = FltStartFiltering(FilterHandle);

        if (NT_SUCCESS(Status))
        {
            DbgPrint("Filtering Started ...");
        }

        else
        {
            DbgPrint("Failed To Filter");
        }
    }

    else
    {
        DbgPrint("Failed To Register Minifilter");
    }

    return Status;
}

NTSTATUS FLTAPI FltrUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);

    if (FilterHandle != nullptr)
    {
        FltUnregisterFilter(FilterHandle);
    }

    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationCreate(PFLT_CALLBACK_DATA CallBackData, PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);

    UNREFERENCED_PARAMETER(CompletionContext);

    DbgPrint("%wZ\n", &CallBackData->Iopb->TargetFileObject->FileName);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS FLTAPI FltrSetupCallback(
    _In_ PCFLT_RELATED_OBJECTS  FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS  Flags,
    _In_ DEVICE_TYPE  VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE  VolumeFilesystemType)
{

    UNREFERENCED_PARAMETER(FltObjects);
    
    UNREFERENCED_PARAMETER(Flags);
    
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    return STATUS_SUCCESS;
}

NTSTATUS FLTAPI FltrTearDownCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{

    UNREFERENCED_PARAMETER(FltObjects);

    UNREFERENCED_PARAMETER(Flags);

    return STATUS_SUCCESS;
}
