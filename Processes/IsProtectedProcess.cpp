/* 
  Checks If Process Is Protected 
  Fun Fact Protected Process If Terminated You BSOD With StopCode CRITICAL_PROCESS_DIED (0x000000EF)
*/

bool __fastcall PsIsProtectedProcess(_EPROCESS* eproc)
{
  return (eproc->Protection.Level & 7) != 0;  // returns true if its 1 and not equal to zero 
  
  /*
    IDA:
          test    byte ptr [rcx+87Ah], 7      ; rcx = _EPROCESS + 0x87a = _PS_PROTECTION
          mov     eax, 0
          setnbe  al      ; Set byte to 1 if not below zero or equal to zero if the byte is set the result is true the process is protected ! 
          retn
  */ 
}
