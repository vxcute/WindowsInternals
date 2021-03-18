__int64 __fastcall MiReadWriteVirtualMemory

(
  HANDLE ProcessHandle, 
  size_t BaseAddress, 
  size_t Buffer, 
  size_t BufferSize,
  __int64 NumberOfBytesToReaden, 
  ACCESS_MASK DesiredAccess
  )
  
{
  int BaseAddr; // er13
  __int64 value; // rsi
  struct _KTHREAD *CurrentThread; // r14
  KPROCESSOR_MODE PreviousMode; // al
  _QWORD *NumberOfBytesReaden_x; // rbx
  __int64 BytesReaden; // rcx
  NTSTATUS ObjectRef; // edi
  _KPROCESS *Process; // r10
  PVOID Obj; // r14
  int TargetAddress; // er9
  int TargetProcess; // er8
  int SourceAddress; // edx
  int SourceProcess; // ecx
  NTSTATUS MmCopy; // eax
  int v22; // er10
  char PreviousMode_x; // [rsp+40h] [rbp-48h]
  __int64 ReturnSize; // [rsp+48h] [rbp-40h] BYREF
  PVOID Object[2]; // [rsp+50h] [rbp-38h] BYREF
  int Buf; // [rsp+A0h] [rbp+18h]

  Buf = Buffer;
  BaseAddr = BaseAddress;
  value = 0i64;
  Object[0] = 0i64;
  CurrentThread = KeGetCurrentThread();
  PreviousMode = CurrentThread->PreviousMode;
  PreviousMode_x = PreviousMode;
  if ( PreviousMode )
  {
    if ( BufferSize + BaseAddress < BaseAddress
      || BufferSize + BaseAddress > 0x7FFFFFFF0000i64
      || Buffer + BufferSize < Buffer
      || Buffer + BufferSize > 0x7FFFFFFF0000i64 )
    {
      return 3221225477i64;
    }
    NumberOfBytesReaden_x = (_QWORD *)NumberOfBytesToReaden;
    if ( NumberOfBytesToReaden )
    {
      BytesReaden = NumberOfBytesToReaden;
      if ( (unsigned __int64)NumberOfBytesToReaden >= 0x7FFFFFFF0000i64 )
        BytesReaden = 0x7FFFFFFF0000i64;
      *(_QWORD *)BytesReaden = *(_QWORD *)BytesReaden;
    }
  }
  else
  {
    NumberOfBytesReaden_x = (_QWORD *)NumberOfBytesToReaden;
  }
  ReturnSize = 0i64;
  ObjectRef = 0;
  if ( BufferSize )
  {
    ObjectRef = ObReferenceObjectByHandleWithTag(
                  ProcessHandle,
                  DesiredAccess,
                  (POBJECT_TYPE)PsProcessType,
                  PreviousMode,
                  0x6D566D4Du,
                  Object,
                  0i64);
    if ( ObjectRef >= 0 )
    {
      Process = CurrentThread->ApcState.Process;
      Object[1] = Process;
      Obj = Object[0];
      if ( (*((_BYTE *)Object[0] + 992) & 1) == 0 || Process == Object[0] || *((_QWORD *)Object[0] + 175) )
      {
        if ( DesiredAccess == 16 )
        {
          TargetAddress = Buf;
          TargetProcess = (int)Process;
          SourceAddress = BaseAddr;
          SourceProcess = (int)Object[0];
        }
        else
        {
          TargetAddress = BaseAddr;
          TargetProcess = (int)Object[0];
          SourceAddress = Buf;
          SourceProcess = (int)Process;
        }
        MmCopy = MmCopyVirtualMemory(
                   SourceProcess,
                   SourceAddress,
                   TargetProcess,
                   TargetAddress,
                   BufferSize,
                   PreviousMode_x,
                   (__int64)&ReturnSize);
        value = ReturnSize;
        ObjectRef = MmCopy;
      }
      else
      {
        ObjectRef = -1073741819;
      }
      if ( (unsigned int)PsIsProcessLoggingEnabled(Obj, DesiredAccess) )
        EtwTiLogReadWriteVm(ObjectRef, v22, (_DWORD)Obj, DesiredAccess, BaseAddr, value);
      ObfDereferenceObjectWithTag(Obj, 0x6D566D4Du);
    }
  }
  if ( NumberOfBytesReaden_x )
    *NumberOfBytesReaden_x = value;
  return (unsigned int)ObjectRef;
}
