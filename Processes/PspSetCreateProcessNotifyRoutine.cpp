__int64 __fastcall PspSetCreateProcessNotifyRoutine(__int64 NotifyRoutine, unsigned int Remove)
{
  __int64 remove; 
  unsigned int IsExRoutine;
  int LdrDataTableEntryFlags; 
  void *CallBackPtr; 
  __int64 Index; 
   _KTHREAD *CurrentThread;
  __int64 Idx;
   _EX_RUNDOWN_REF *CallBack; 
   _EX_RUNDOWN_REF *Mem; 
  volatile signed __int32 *PspNotifyRoutinePtr; 

  remove = Remove;
  IsExRoutine = Remove & 2;                     // Checks If Bit 1 Is Set This will be true if the caller called PsSetCreateProcessNotifyRoutineEx or PsSetCreateProcessNotifyRoutineEx2
  if ( (Remove & 1) != 0 )                      // Bit Zero will be set to 1 if remove == true if so start removing the callback for system notify routines table 
  {
    CurrentThread = KeGetCurrentThread();     // optain pointer to KTHREAD
    --CurrentThread->KernelApcDisable;      // Disable APC Set Decremeanting means Setting It From 1 to 0 
    Idx = 0i64;            
    while ( 1 )
    {
      CallBack = ExReferenceCallBackBlock((signed __int64 *)&PspCreateProcessNotifyRoutine.Ptr + Idx);   // Checks If Same Routines 
      Mem = CallBack;
      if ( CallBack ) 
      {
        LODWORD(remove) = remove & 0xFFFFFFFE;   
        if ( CallBack[1].Count == NotifyRoutine
          && LODWORD(CallBack[2].Count) == (DWORD)remove
          && (unsigned __int8)ExCompareExchangeCallBack(&PspCreateProcessNotifyRoutine + Idx, 0i64, CallBack) )     // Does It Have The Same Type 
        {
          PspNotifyRoutinePtr = &PspCreateProcessNotifyRoutineCount;      
          if ( IsExRoutine )      // Checks If The Caller Called PsSetCreateProcessNotifyRoutineEx or PsSetCreateProcessNotifyRoutineEx2
            PspNotifyRoutinePtr = &PspCreateProcessNotifyRoutineExCount;      // if set the PspNotifyRoutinePtr To The Address of PspCreateProcessNotifyRoutineExCount
          _InterlockedDecrement(PspNotifyRoutinePtr);
          ExDereferenceCallBackBlock(&PspCreateProcessNotifyRoutine + Idx, Mem);
          KeLeaveCriticalRegionThread(CurrentThread);
          ExWaitForRundownProtectionRelease(Mem);
          ExFreePoolWithTag(Mem, 0);
          return 0;
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
  Index = 0;
  while ( !(unsigned __int8)ExCompareExchangeCallBack(&PspCreateProcessNotifyRoutine + Index, CallBackPtr, 0i64) )
  {
    Index = (unsigned int)(Index + 1);
    if ( (unsigned int)Index >= 0x40 )
    {
      ExFreePoolWithTag(CallBackPtr, 0);
      return 0xC000000D;
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
