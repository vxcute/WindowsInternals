__int64 __fastcall MiReadWriteVirtualMemory(HANDLE ProcessHandle, size_t BaseAddress, size_t Buffer, size_t BufferSize, __int64 NumberOfBytesToReaden, ACCESS_MASK DesiredAccess)
{
    int BaseAddr; 
    __int64 value; 
    struct _KTHREAD* CurrentThread; 
    KPROCESSOR_MODE PreviousMode; 
    UINT64 * NumberOfBytesReaden_x; 
    __int64 BytesReaden; 
    NTSTATUS ObjectRef; 
    struct KPROCESS* Process; 
    PVOID Obj; 
    int TargetAddress; 
    int TargetProcess; 
    int SourceAddress; 
    int SourceProcess; 
    NTSTATUS MmCopy; 
    int v22; 
    char PreviousMode_x; 
    __int64 ReturnSize; 
    PVOID Object[2];
    int Buf; 

    Buf = Buffer;
    BaseAddr = BaseAddress;
    value = 0;
    Object[0] = 0;
    CurrentThread = KeGetCurrentThread();         // Get Current Thread Information of Thread Is Stored In KTHREAD Structure Since KeGetCurrentThread Returns KTHREAD  
    PreviousMode = CurrentThread->PreviousMode;   // Store PreviousMode of Thread In a Temp Variable 
    PreviousMode_x = PreviousMode;
    if (PreviousMode)                           // If Previous Mode Is Bigger Than 0 
    {
        if (BufferSize + BaseAddress < BaseAddress // Check If BufferSize + BaseAddress Is Less Than BaseAddress 
            || BufferSize + BaseAddress > 0x7FFFFFFF0000i64// Check If BufferSize + BaseAddress Is BiggerThan User Space Memory Address Limit 
            || Buffer + BufferSize < Buffer           // Check If Buffer + BufferSize Less Than Buffer 
            || Buffer + BufferSize > 0x7FFFFFFF0000i64)// Check If Buffer + BufferSize Is Bigger Than User Memory Address Space Limit 
        {
            return STATUS_ACCESS_VIOLATION;                     // Either Return ACCESS_VIOLATION 
        }
        NumberOfBytesReaden_x = (UINT64 *)NumberOfBytesToReaden;
        if (NumberOfBytesToReaden)                // If Number Of Bytes To Read Is Bigger Than Zero 
        {
            BytesReaden = NumberOfBytesToReaden;
            if ((unsigned __int64)NumberOfBytesToReaden >= 0x7FFFFFFF0000)
                BytesReaden = 0x7FFFFFFF0000;
            *(UINT64*)BytesReaden = *(UINT64*)BytesReaden;
        }
    }
    else
    {
        NumberOfBytesReaden_x = (UINT64 *)NumberOfBytesToReaden;
    }
    ReturnSize = 0i64;
    ObjectRef = 0;
    if (BufferSize)                             // Check If BufferSize Is Bigger Than 0 
    {
        ObjectRef = ObReferenceObjectByHandleWithTag(// increments the reference count of the object that is identified by the specified handle (Process)
            ProcessHandle,
            DesiredAccess,
            (POBJECT_TYPE)PsProcessType,
            PreviousMode,
            0x6D566D4Du,
            Object,
            0);
        if (ObjectRef >= 0)
        {
            Process = CurrentThread->ApcState.Process;
            Object[1] = Process;
            Obj = Object[0];
            if ((*((BYTE*)Object[0] + 0x3E0) & 1) == 0 || Process == Object[0] || *(UINT64*)Object[0] + 0xAF)
            {
                if (DesiredAccess == 0x10)               // Write Process Virtual Memory 
                {
                    TargetAddress = Buf;
                    TargetProcess = (int)Process;         // Since The Process We Are Writing To Is Process Set TargetProcess 
                    SourceAddress = BaseAddr;
                    SourceProcess = (int)Object[0];       // SourceProcess = Process That Is Writing 
                }
                else                                    // Else Read Process Virtual Memory 
                {
                    TargetAddress = BaseAddr;
                    TargetProcess = (int)Object[0];       // Object[0] = Our Process Since We Will Be Reading The Output Will Directed To It So Set It To Be TargetProcess 
                    SourceAddress = Buf;
                    SourceProcess = (int)Process;         // Since Process Will Be The Source and Our Process Will Be The Target Process or the Distnation Set SourceProcess To Be Input Process Parameter 
                }
                MmCopy = MmCopyVirtualMemory(           // Use MmCopyVirtualMemory To Read or Write Based on What We End Up With 
                    SourceProcess,
                    (char*)SourceAddress,
                    TargetProcess,
                    (char*)TargetAddress,
                    BufferSize,
                    PreviousMode_x,
                    (__int64)&ReturnSize);
                value = ReturnSize;
                ObjectRef = MmCopy;
            }
            else
            {
                ObjectRef = STATUS_ACCESS_VIOLATION; // object is in accessible access violatiy happend
            }

            // Check If Process Logging Is Enabled
            // If Log The Read or Write To The Process to etw (Event Log) 

            if ((unsigned int)((__int64(__fastcall*)(PVOID, UINT64))PsIsProcessLoggingEnabled)(Obj, DesiredAccess)) 
                EtwTiLogReadWriteVm(ObjectRef, v22, (unsigned int)Obj, DesiredAccess, BaseAddr, value);        
            ObfDereferenceObjectWithTag(Obj, 0x6D566D4Du);// Decrements The Reference Count To The Object (Process)  
        }
    }
    if (NumberOfBytesReaden_x)
        *NumberOfBytesReaden_x = value;
    return (unsigned int)ObjectRef;
}
