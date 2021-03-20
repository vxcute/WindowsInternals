__int64 __fastcall KiSystemCall64(__int64 a1, __int64 value_1, __int64 a3, __int64 a4, char a5)
{
  __int64 v5; // rax
  __int64 v6; // rbp
  __int64 v7; // r10
  __int64 v8; // r11
  __int128 v9; // xmm0
  __int128 v10; // xmm1
  __int128 v11; // xmm2
  __int128 v12; // xmm3
  __int128 v13; // xmm4
  __int128 v14; // xmm5
  unsigned __int64 ActiveProcessorCount; // rcx
  unsigned __int8 BpbKernelSpecCtrl; // al
  struct _KTHREAD *CurrentThread; // rbx
  char v19; // al
  bool v20; // cc
  __int64 result; // rax
  ULONG64 v22; // rax
  _QWORD *v23; // rdx
  unsigned int v24; // eax
  __int64 v25; // rcx
  __int64 v26; // rdx
  __int64 v27; // rdi
  __int64 v28; // rax
  __int128 *KeServiceDescriptorTablePointer; // r10
  __int128 *KeServiceDescriptorTableShadowPointer; // r11
  __int64 v31; // r10
  __int64 v32; // rax
  __int64 (__fastcall *v33)(_QWORD, _QWORD, _QWORD, _QWORD); // r10
  __int64 v34; // rbx
  __int64 v35; // rdi
  __int64 (__fastcall *v36)(_QWORD, _QWORD, _QWORD, _QWORD); // rsi
  struct _KTHREAD *v38; // r11
  struct _KTHREAD *v39; // rcx
  void *v40; // rax
  unsigned __int8 v41; // al
  struct _KTHREAD *v45; // rcx
  unsigned __int8 v46; // al
  __int64 v47; // rsi
  __int64 v48; // rcx
  __int64 v49; // r9
  __int64 v50; // r8
  __int64 v51; // rax
  __int64 v52; // rax
  __int64 v53; // [rsp+28h] [rbp-1C0h] BYREF
  __int64 v54; // [rsp+30h] [rbp-1B8h]
  __int64 v55; // [rsp+38h] [rbp-1B0h]
  __int64 v56; // [rsp+40h] [rbp-1A8h]
  __int64 (__fastcall *v57)(__int64, __int64, __int64, __int64); // [rsp+48h] [rbp-1A0h]
  __int64 v58; // [rsp+50h] [rbp-198h]
  __int64 v59; // [rsp+58h] [rbp-190h] BYREF
  __int64 v60; // [rsp+60h] [rbp-188h]
  __int64 v61; // [rsp+68h] [rbp-180h]
  __int64 v62; // [rsp+70h] [rbp-178h]
  __int64 v63; // [rsp+78h] [rbp-170h] BYREF
  __int64 v64; // [rsp+80h] [rbp-168h]
  __int64 v65; // [rsp+88h] [rbp-160h]
  __int64 v66; // [rsp+90h] [rbp-158h]
  __int64 v67; // [rsp+98h] [rbp-150h]
  __int64 v68; // [rsp+A0h] [rbp-148h]
  __int64 v69; // [rsp+A8h] [rbp-140h]
  __int64 v70; // [rsp+B0h] [rbp-138h]
  __int64 v71; // [rsp+B8h] [rbp-130h]
  __int64 v72; // [rsp+C0h] [rbp-128h]
  __int128 v73; // [rsp+C8h] [rbp-120h]
  __int128 v74; // [rsp+D8h] [rbp-110h]
  __int128 v75; // [rsp+E8h] [rbp-100h]
  __int128 v76; // [rsp+F8h] [rbp-F0h]
  __int128 v77; // [rsp+108h] [rbp-E0h]
  __int128 v78; // [rsp+118h] [rbp-D0h]
  __int64 v79; // [rsp+128h] [rbp-C0h]
  __int64 v80; // [rsp+130h] [rbp-B8h]
  __int64 v81; // [rsp+138h] [rbp-B0h]
  __int64 v82; // [rsp+140h] [rbp-A8h]
  __int64 v83; // [rsp+148h] [rbp-A0h]
  __int64 v84; // [rsp+158h] [rbp-90h]
  _KTRAP_FRAME *v85; // [rsp+190h] [rbp-58h]
  __int64 v86; // [rsp+1B0h] [rbp-38h]
  __int64 v87; // [rsp+1C0h] [rbp-28h]
  __int64 value; // [rsp+1C8h] [rbp-20h]
  __int64 v89; // [rsp+1D0h] [rbp-18h]
  void *StackLimit; // [rsp+1D8h] [rbp-10h]
  __int64 v91; // [rsp+1E0h] [rbp-8h]
  void *retaddr; // [rsp+1E8h] [rbp+0h] BYREF

  __asm { swapgs }                              // swapgs change gs segment base with the value in the address C0000102H of the MSR the value = gs base segment of the kernel (IA32_KERNEL_GS_BASE)
  __writegsqword(0x10u, (unsigned __int64)&retaddr);// save the process calling stack with = mov gs:10, retaddr 
  v91 = 0x2Bi64;
  StackLimit = KeGetPcr()->NtTib.StackLimit;    // PCR -> offset 0x0 => NtTib + offset 10 => StackLimit 
  v89 = v8;
  value = 0x33i64;
  v87 = a1;
  v86 = v6;
  if ( (_BYTE)KeSmapEnabled && (value & 1) != 0 )// Check If SMAP (Supervisor Mode Access Prevention) Is Enabled 
    __asm { stac }                              // Sets the AC flag bit in EFLAGS register. This may enable alignment checking of user-mode data accesses. This allows explicit supervisor-mode data accesses to user-mode pages even if the SMAP bit is set in the CR4 register.
                                                // 
                                                // 
  v65 = v5;
  v66 = v7;
  v67 = value_1;
  ActiveProcessorCount = *(_QWORD *)&KeGetCurrentThread()->Process[2].ActiveProcessors.Count;
  __writegsqword(0x270u, ActiveProcessorCount);
  __writegsbyte(0x851u, KeGetPcr()->Prcb.BpbRetpolineExitSpecCtrl);
  LOBYTE(ActiveProcessorCount) = KeGetPcr()->Prcb.BpbState;
  __writegsbyte(0x852u, ActiveProcessorCount);
  BpbKernelSpecCtrl = KeGetPcr()->Prcb.BpbKernelSpecCtrl;
  if ( KeGetPcr()->Prcb.BpbCurrentSpecCtrl != BpbKernelSpecCtrl )
  {
    __writegsbyte(0x27Au, BpbKernelSpecCtrl);
    ActiveProcessorCount = 0x48i64;
    HIDWORD(value_1) = 0;
    __writemsr(0x48u, BpbKernelSpecCtrl);
  }
  LODWORD(value_1) = KeGetPcr()->Prcb.BpbState;
  if ( (value_1 & 8) != 0 )
  {
    value_1 = 0i64;
    ActiveProcessorCount = 0x49i64;
    __writemsr(0x49u, 1ui64);
  }
  else
  {
    if ( (value_1 & 2) != 0 && (KeGetPcr()->Prcb.BpbFeatures & 4) == 0 )
    {
      v58 = 0x1404070D9i64;
      v83 = 0x1404071F0i64;
      v82 = 0x1404071E7i64;
      v81 = 0x1404071DEi64;
      v80 = 0x1404071D5i64;
      v79 = 0x1404071CCi64;
      *((_QWORD *)&v78 + 1) = 0x1404071C3i64;
      *(_QWORD *)&v78 = 0x1404071BAi64;
      *((_QWORD *)&v77 + 1) = 0x1404071B1i64;
      *(_QWORD *)&v77 = 0x1404071A8i64;
      *((_QWORD *)&v76 + 1) = 0x14040719Fi64;
      *(_QWORD *)&v76 = 0x140407196i64;
      *((_QWORD *)&v75 + 1) = 0x14040718Di64;
      *(_QWORD *)&v75 = 0x140407184i64;
      *((_QWORD *)&v74 + 1) = 0x14040717Bi64;
      *(_QWORD *)&v74 = 0x140407172i64;
      *((_QWORD *)&v73 + 1) = 0x140407169i64;
      *(_QWORD *)&v73 = 0x140407160i64;
      v72 = 0x140407157i64;
      v71 = 0x14040714Ei64;
      v70 = 0x140407145i64;
      v69 = 0x14040713Ci64;
      v68 = 0x140407133i64;
      v67 = 0x14040712Ai64;
      v66 = 0x140407121i64;
      v65 = 0x140407118i64;
      v64 = 0x14040710Fi64;
      v63 = 0x140407106i64;
      v62 = 0x1404070FDi64;
      v61 = 0x1404070F4i64;
      v60 = 0x1404070EBi64;
      v59 = 0x1404070E2i64;
    }
    _mm_lfence();
  }
  __writegsbyte(0x853u, 0);
  BYTE3(v64) = 2;
  CurrentThread = KeGetCurrentThread();
  _m_prefetchw(&CurrentThread->TrapFrame);
  HIDWORD(v64) = _mm_getcsr();
  _mm_setcsr(KeGetPcr()->Prcb.MxCsr);
  _ZF = CurrentThread->Header.Reserved1 == 0;
  LOWORD(v84) = 0;
  if ( _ZF )
  {
LABEL_29:
    v24 = v65;
    v25 = v66;
    v26 = v67;
    _enable();
    CurrentThread->FirstArgument = (void *)v25;
    CurrentThread->SystemCallNumber = v24;
    CurrentThread->TrapFrame = (_KTRAP_FRAME *)&v59;
    v27 = (v24 >> 7) & 0x20;
    v28 = v24 & 0xFFF;
    do
    {
      KeServiceDescriptorTablePointer = &KeServiceDescriptorTable;
      KeServiceDescriptorTableShadowPointer = &KeServiceDescriptorTableShadow;
      if ( (*((_DWORD *)&CurrentThread->0 + 1) & 0x80) != 0 )
      {
        if ( (*((_DWORD *)&CurrentThread->0 + 1) & 0x200000) != 0 )
          KeServiceDescriptorTableShadowPointer = &KeServiceDescriptorTableFilter;
        KeServiceDescriptorTablePointer = KeServiceDescriptorTableShadowPointer;
      }
      if ( (unsigned int)v28 < *(_DWORD *)((char *)KeServiceDescriptorTablePointer + v27 + 0x10) )
      {
        v31 = *(_QWORD *)((char *)KeServiceDescriptorTablePointer + v27);
        v32 = *(int *)(v31 + 4 * v28);
        v33 = (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD, _QWORD))((v32 >> 4) + v31);
        if ( (_DWORD)v27 == 0x20 && *((_DWORD *)CurrentThread->Teb + 0x5D0) )
        {
          v65 = v32;
          v66 = v25;
          v67 = v26;
          v34 = a3;
          v35 = a4;
          v36 = v33;
          PsInvokeWin32Callout(7i64, 0i64, 0i64, 0i64);
          LOBYTE(v32) = v65;
          v25 = v66;
          v26 = v67;
          a3 = v34;
          a4 = v35;
          v33 = v36;
        }
        if ( v32 & 0xF )
          __asm { jmp     r11 }
        if ( (KiDynamicTraceMask & 1) != 0 )
        {
          v53 = v25;
          v54 = v26;
          v55 = a3;
          v56 = a4;
          v57 = v33;
          v65 = KiTrackSystemCallEntry(v33, &v53, 4i64, &v63);
          v51 = v57(v53, v54, v55, v56);
          result = KiTrackSystemCallExit(v65, v51);
        }
        else if ( (BYTE8(PerfGlobalGroupMask) & 0x40) != 0 )
        {
          v53 = v25;
          v54 = v26;
          v55 = a3;
          v56 = a4;
          v57 = v33;
          PerfInfoLogSysCallEntry(v33);
          v52 = v57(v53, v54, v55, v56);
          result = PerfInfoLogSysCallExit(v52);
        }
        else
        {
          result = v33(v25, v26, a3, a4);
        }
        __incgsdword(0x2EB8u);
        goto KiSystemServiceExit;
      }
      if ( (_DWORD)v27 != 0x20 )
        goto LABEL_94;
      v63 = a4;
      _ZF = (unsigned int)KiConvertToGuiThread() == 0;
      v28 = (unsigned int)v59;
      v25 = v60;
      v26 = v61;
      a3 = v62;
      a4 = v63;
      CurrentThread->TrapFrame = (_KTRAP_FRAME *)&v59;
    }
    while ( _ZF );
    v47 = *((unsigned int *)&xmmword_140CFCA60 + 4);
    if ( (unsigned int)v28 >= (unsigned int)v47 )
      goto LABEL_94;
    result = (unsigned int)*(char *)(xmmword_140CFCA60 + 4 * v47 + v28);
    if ( (int)result > 0 )
    {
LABEL_94:
      result = 0xC000001Ci64;
      goto KiSystemServiceExit;
    }
    goto KiSystemServiceExit;
  }
  _ZF = (CurrentThread->Header.Reserved1 & 3) == 0;
  v68 = a3;
  v69 = a4;
  if ( !_ZF )
    KiSaveDebugRegisterState(ActiveProcessorCount, value_1);
  if ( (CurrentThread->Header.Reserved1 & 0x24) == 0 )
    goto LABEL_24;
  v71 = v7;
  v70 = v7;
  v73 = v9;
  v74 = v10;
  v75 = v11;
  v76 = v12;
  v77 = v13;
  v78 = v14;
  _enable();
  v19 = PsAltSystemCallDispatch(&v59, value_1);
  v20 = v19 < 1;
  if ( v19 == 1 )
  {
LABEL_24:
    if ( (CurrentThread->Header.Reserved1 & 0x80u) == 0 )
      goto LABEL_26;
    v22 = __readmsr(0xC0000102);
    if ( v22 >= MmUserProbeAddress )
      v22 = MmUserProbeAddress;
    if ( CurrentThread->Teb == (void *)v22 )
    {
LABEL_26:
      if ( (CurrentThread->Header.Reserved1 & 0x40) != 0 )
        CurrentThread->MiscFlags |= 0x10000u;
    }
    else
    {
      v23 = CurrentThread->WaitBlock[3].Object;
      CurrentThread->MiscFlags |= 0x100u;
      --CurrentThread->SpecialApcDisable;
      v23[0x10] = v22;
      _enable();
      KiUmsCallEntry(0xC0000102i64);
    }
    a3 = v68;
    a4 = v69;
    goto LABEL_29;
  }
  result = v65;
  if ( !v20 )
  {
    KiExceptionDispatch(0xC000001Ci64, 0i64, v87);
    __debugbreak();
  }
  if ( (CurrentThread->Header.Reserved1 & 4) != 0 )
  {
    v38 = KeGetCurrentThread();
    if ( !(v38->WaitBlock[3].SpareLong | (unsigned __int8)(v38->ApcStateIndex | KeGetCurrentIrql())) )
    {
      _disable();
      while ( (KeGetCurrentThread()->ApcState.UserApcPendingAll & 3) != 0 )
      {
        __writecr8(1ui64);
        _enable();
        KiInitiateUserApc();
        __writecr8(0i64);
        _disable();
      }
      if ( (*((_BYTE *)&KeGetPcr()->Prcb.2 + 0xE) & 2) != 0 )
        KiUpdateStibpPairing(0i64);
      if ( (KeGetCurrentThread()->Header.LockNV & 0x8000000) != 0 )
        KiRestoreSetContextState();
      v45 = KeGetCurrentThread();
      if ( (v45->Header.Size & 1) != 0 )
      {
        KiCopyCounters();
        v45 = KeGetCurrentThread();
      }
      if ( (_WORD)v84 )
        KiRestoreDebugRegisterState(v45);
      __writegsbyte(0x853u, 0);
      v46 = KeGetPcr()->Prcb.BpbUserSpecCtrl;
      if ( KeGetPcr()->Prcb.BpbCurrentSpecCtrl != v46 )
      {
        __writegsbyte(0x27Au, v46);
        __writemsr(0x48u, v46);
      }
      __asm { btr     word ptr gs:278h, 2 }
      if ( _CF )
        __writemsr(0x49u, 1ui64);
      _mm_setcsr(HIDWORD(v64));
      if ( (KiKvaShadow & 1) == 0 )
      {
        __asm
        {
          swapgs
          iretq
        }
      }
      return KiKernelExit(v66, v67, v68, v69, a5);
    }
LABEL_95:
    v48 = 0x4Ai64;
    v49 = 0i64;
    v50 = KeGetCurrentIrql();
    if ( !(_DWORD)v50 )
    {
      v48 = 1i64;
      v50 = v38->ApcStateIndex;
      v49 = v38->CombinedApcDisable;
    }
    KiBugCheckDispatch(v48, v87, v50, v49);
  }
KiSystemServiceExit:
  v38 = KeGetCurrentThread();
  if ( (value & 1) == 0 )
  {
    v38->TrapFrame = v85;
    v38->PreviousMode = v64;
    _disable();
    _enable();
    return result;
  }
  if ( v38->WaitBlock[3].SpareLong | (unsigned __int8)(v38->ApcStateIndex | KeGetCurrentIrql()) )
    goto LABEL_95;
  _disable();
  while ( (KeGetCurrentThread()->ApcState.UserApcPendingAll & 3) != 0 )
  {
    v65 = result;
    v66 = 0i64;
    v67 = 0i64;
    v68 = 0i64;
    v69 = 0i64;
    v70 = 0i64;
    v71 = 0i64;
    v73 = 0i64;
    v74 = 0i64;
    v75 = 0i64;
    v76 = 0i64;
    v77 = 0i64;
    v78 = 0i64;
    __writecr8(1ui64);
    _enable();
    KiInitiateUserApc();
    _disable();
    __writecr8(0i64);
    result = v65;
  }
  if ( (*((_BYTE *)&KeGetPcr()->Prcb.2 + 0xE) & 2) != 0 )
  {
    v65 = result;
    KiUpdateStibpPairing(0i64);
    result = v65;
  }
  if ( (KeGetCurrentThread()->Header.LockNV & 0x8000000) != 0 )
  {
    v65 = result;
    v66 = 0i64;
    v67 = 0i64;
    v68 = 0i64;
    v69 = 0i64;
    v70 = 0i64;
    v71 = 0i64;
    v73 = 0i64;
    v74 = 0i64;
    v75 = 0i64;
    v76 = 0i64;
    v77 = 0i64;
    v78 = 0i64;
    result = KiRestoreSetContextState();
  }
  v39 = KeGetCurrentThread();
  if ( (v39->Header.LockNV & 0x40010000) != 0 )
  {
    v65 = result;
    if ( (v39->Header.Size & 1) != 0 )
    {
      KiCopyCounters();
      v39 = KeGetCurrentThread();
    }
    if ( (v39->Header.Reserved1 & 0x40) != 0 )
      KiUmsExit(0i64);
    result = v65;
  }
  _mm_setcsr(HIDWORD(v64));
  if ( (_WORD)v84 )
  {
    v65 = result;
    KiRestoreDebugRegisterState(v39);
    v40 = KeGetCurrentThread()->ApcState.Process->InstrumentationCallback;
    if ( v40 && (_WORD)value == 0x33 )
      v87 = (__int64)v40;
    result = v65;
  }
  v65 = result;
  __writegsbyte(0x853u, 0);
  v41 = KeGetPcr()->Prcb.BpbUserSpecCtrl;
  if ( KeGetPcr()->Prcb.BpbCurrentSpecCtrl != v41 )
  {
    __writegsbyte(0x27Au, v41);
    __writemsr(0x48u, v41);
  }
  __asm { btr     word ptr gs:278h, 2 }
  if ( _CF )
    __writemsr(0x49u, 1ui64);
  if ( (KiKvaShadow & 1) == 0 )
  {
    __asm
    {
      swapgs
      sysret
    }
  }
  return KiKernelSysretExit(v87, 0i64, StackLimit, v86);
}
