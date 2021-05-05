__int64 __fastcall PspSetCreateProcessNotifyRoutine(__int64 NotifyRoutine, unsigned int Remove)
{
  __int64 remove; 
  unsigned int IsExRoutine;
  int LdrDataTableEntryFlags; 
  void *CallBackPtr; 
  __int64 Index; 
  struct _KTHREAD *CurrentThread;
  __int64 Idx;
  struct _EX_RUNDOWN_REF *CallBack; 
  struct _EX_RUNDOWN_REF *Mem; 
  volatile signed __int32 *PspNotifyRoutinePtr; 

  remove = Remove;
  IsExRoutine = Remove & 2;                     // Checks If Bit 1 Is Set This will be true if the caller called PsSetCreateProcessNotifyRoutineEx or PsSetCreateProcessNotifyRoutineEx2
  if ( (Remove & 1) != 0 )                      // Bit Zero will be set to 1 if remove == true 
  {
    CurrentThread = KeGetCurrentThread();
    --CurrentThread->KernelApcDisable;
    Idx = 0i64;
    while ( 1 )
    {
      CallBack = ExReferenceCallBackBlock((signed __int64 *)&PspCreateProcessNotifyRoutine.Ptr + Idx);
      Mem = CallBack;
      if ( CallBack )
      {
        LODWORD(remove) = remove & 0xFFFFFFFE;
        if ( CallBack[1].Count == NotifyRoutine
          && LODWORD(CallBack[2].Count) == (_DWORD)remove
          && (unsigned __int8)ExCompareExchangeCallBack(&PspCreateProcessNotifyRoutine + Idx, 0i64, CallBack) )
        {
          PspNotifyRoutinePtr = &PspCreateProcessNotifyRoutineCount;
          if ( IsExRoutine )
            PspNotifyRoutinePtr = &PspCreateProcessNotifyRoutineExCount;
          _InterlockedDecrement(PspNotifyRoutinePtr);
          ExDereferenceCallBackBlock(&PspCreateProcessNotifyRoutine + Idx, Mem);
          KeLeaveCriticalRegionThread(CurrentThread);
          ExWaitForRundownProtectionRelease(Mem);
          ExFreePoolWithTag(Mem, 0);
          return 0i64;
        }
        ExDereferenceCallBackBlock(&PspCreateProcessNotifyRoutine + Idx, Mem);
      }
      Idx = (unsigned int)(Idx + 1);
      if ( (unsigned int)Idx >= 0x40 )
      {
        KeLeaveCriticalRegionThread(CurrentThread);
        return 0xC000007Ai64;
      }
    }
  }
  if ( (Remove & 2) != 0 )
    LdrDataTableEntryFlags = 0x20;
  else
    LdrDataTableEntryFlags = 0;
  if ( !(unsigned int)MmVerifyCallbackFunctionCheckFlags(NotifyRoutine, LdrDataTableEntryFlags) )
    return 0xC0000022i64;
  CallBackPtr = (void *)ExAllocateCallBack(NotifyRoutine, remove);
  if ( !CallBackPtr )
    return 0xC000009Ai64;
  Index = 0i64;
  while ( !(unsigned __int8)ExCompareExchangeCallBack(&PspCreateProcessNotifyRoutine + Index, CallBackPtr, 0i64) )
  {
    Index = (unsigned int)(Index + 1);
    if ( (unsigned int)Index >= 0x40 )
    {
      ExFreePoolWithTag(CallBackPtr, 0);
      return 0xC000000Di64;
    }
  }
  if ( IsExRoutine )
  {
    _InterlockedIncrement(&PspCreateProcessNotifyRoutineExCount);
    if ( (PspNotifyEnableMask & 4) == 0 )
      _interlockedbittestandset(&PspNotifyEnableMask, 2u);
  }
  else
  {
    _InterlockedIncrement(&PspCreateProcessNotifyRoutineCount);
    if ( (PspNotifyEnableMask & 2) == 0 )
      _interlockedbittestandset(&PspNotifyEnableMask, 1u);
  }
  return 0i64;
}
