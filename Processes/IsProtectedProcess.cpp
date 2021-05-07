bool __fastcall PsIsProtectedProcess(_EPROCESS* eproc)
{
  return (*(BYTE*)(eproc + 0x87A) & 7) != 0;  //  +0x87a Protection: _PS_PROTECTION Ands with 7 and returns true if its 1 and not equal to zero 
  
  /*
    IDA:
          test    byte ptr [rcx+87Ah], 7      ; rcx = _EPROCESS 
          mov     eax, 0
          setnbe  al
          retn
  */ 
}
