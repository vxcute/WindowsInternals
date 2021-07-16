NTSTATUS __fastcall NtSuspendProcess(HANDLE Handle)
{
  NTSTATUS Status; 
  PEPROCESS Process; 
  
  Process = NULL;
  
  Status = ObReferenceObjectByHandleWithTag(
             Handle,
             0x800u,
             (POBJECT_TYPE)PsProcessType,
             KeGetCurrentThread()->PreviousMode,
             'uSsP',
             &Process,
             0);
  
  if (Status >= 0)
  {
    Status = PsSuspendProcess(Process);
    ObfDereferenceObjectWithTag(Process, 'uSsP');
  }
  return Status;
}
