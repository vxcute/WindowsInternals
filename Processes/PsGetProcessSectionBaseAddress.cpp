// Gets Base Address of A Process By Reading The SectionBaseAddress In EPROCESS 

PVOID NTAPI PsGetProcessSectionBaseAddress(_EPROCESS *eproc)
{
  return eproc->SectionBaseAddress;   
  
  /*
    IDA:
      mov     rax, [rcx+520h]   ; rcx = EPROCESS + 0x520 = SectionBaseAddress
      retn
  */
}
