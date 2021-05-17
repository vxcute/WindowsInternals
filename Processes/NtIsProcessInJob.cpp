// Determines If Process In In Job Passing The A Handle To The Process and A Job Object Handle 

NTSTATUS __fastcall NtIsProcessInJob(HANDLE ProcessHandle, HANDLE JobHandle)
{
  _KTHREAD *CurrentThread; 
  KPROCESSOR_MODE PreviousMode; 
  NTSTATUS ObjReference;
  _EPROCESS *eproc;
  NTSTATUS ProcessObjReference; 
  _EJOB *ProcessJob; 
  NTSTATUS IsProcessInJob; 
  _DMA_ADAPTER *DmaAdapter; 
  PVOID Eproc;
  PVOID Object;

  CurrentThread = KeGetCurrentThread();         // Obtain Pointer To KTHREAD
  Eproc = 0;
  PreviousMode = CurrentThread->PreviousMode;   // Save Previous Mode
  if ( ProcessHandle == (HANDLE)0xFFFFFFFFFFFFFFFF)// If Current Process 
  {
    eproc = (_EPROCESS*)CurrentThread->ApcState.Process;// Obtain The EPROCESS From Current Thread
    Eproc = eproc;
  }
  else                                          // Else Its Another Process 
  {
    // Obtain An Object Reference Passing The Process Handle It Will Also Return The EPROCESS For The Process
    
    ObjReference = ObReferenceObjectByHandleWithTag( 
                     ProcessHandle,
                     0x1000,
                     (POBJECT_TYPE)PsProcessType,
                     PreviousMode,
                     0x624A7350,    // bJsP
                     &Eproc,
                     0);
    if ( ObjReference < 0 )                     // If It Failed 
      return ObjReference;                      // Just Return 
    eproc = (_EPROCESS *)Eproc;
  }
  if ( !JobHandle )
  {
    ProcessJob = eproc->Job;
    eproc = (_EPROCESS *)Eproc;
CheckIsProcessInJob:
    
    // Checks If Process Is In Job
    IsProcessInJob = PspIsProcessInJob(eproc, ProcessJob);
    if ( JobHandle )      
      HalPutDmaAdapter(DmaAdapter);
    goto DereferenceObjectAndReturn;
  }
  Object = 0;
  ProcessObjReference = ObReferenceObjectByHandle(JobHandle, 4u, (POBJECT_TYPE)PsJobType, PreviousMode, &Object, 0i64);
  ProcessJob = (_EJOB*)Object;
  IsProcessInJob = ProcessObjReference;
  if ( ProcessObjReference >= 0 )
    goto CheckIsProcessInJob;
DereferenceObjectAndReturn:
  // If Process Handle Is Not Current Process 
  if ( ProcessHandle != (HANDLE)0xFFFFFFFFFFFFFFFF )
    ObfDereferenceObjectWithTag(eproc, 0x624A7350u);      // decrements the reference count of the specified object in the object manager 
  return IsProcessInJob;
}
