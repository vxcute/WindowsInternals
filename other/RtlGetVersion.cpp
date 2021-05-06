// Gets OS Version 

NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation)
{
  ULONG dwOSVersionInfoSize;
  __int16 NtCSDVersion; 
  bool initializationPhase; 
  __int16 Mask; 
  int NT_Type; 

  *(UINT16*)&lpVersionInformation->dwMajorVersion = 0xA;
  lpVersionInformation->dwBuildNumber = (unsigned __int16)NtBuildNumber;// Moves NtBuildNumber Which Is A Build Hardcoded In The Binary It Self To dwBuildNumber
  dwOSVersionInfoSize = lpVersionInformation->dwOSVersionInfoSize - 0x11C;    // Gets The Info OS Info Size and Subtracts 0x11C From It 
  NT_Type = 0;        // used to store the nt type (WinNT, LanmanNT, ServerNT) returned by RtlGetNtProductType
  lpVersionInformation->dwPlatformId = 2;
  if ( (dwOSVersionInfoSize & 0xFFFFFFF7) == 0 )
  {
    LOWORD(lpVersionInformation[1].dwOSVersionInfoSize) = (unsigned __int8)byte_140C4C139;
    NtCSDVersion = CmNtCSDVersion;
    LOWORD(lpVersionInformation[1].dwMajorVersion) = 0;
    initializationPhase = (_DWORD)InitializationPhase == 0;
    HIWORD(lpVersionInformation[1].dwOSVersionInfoSize) = NtCSDVersion;
    BYTE2(lpVersionInformation[1].dwMajorVersion) = 0;
    if ( !initializationPhase )                 // Checks What Phase Boot The System Is In There Is Phase 0, 1, 2, 3
    {
      if ((UINT8)RtlGetNtProductType(&NT_Type) )// Get Windows Version Type WinNT, LanmanNT, ServerNT
        BYTE2(lpVersionInformation[1].dwMajorVersion) = NT_Type;
      Mask = RtlGetSuiteMask();
      initializationPhase = lpVersionInformation->dwOSVersionInfoSize == 0x124;
      LOWORD(lpVersionInformation[1].dwMajorVersion) = Mask;
      if ( initializationPhase )
        lpVersionInformation[1].dwMinorVersion = RtlGetSuiteMask() & 0x1FFFF;
    }
    HIBYTE(lpVersionInformation[1].dwMajorVersion) = 0;
  }
  return 0;
}
