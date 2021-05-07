bool __fastcall PsIsProtectedProcess(_EPROCESS* eproc)
{
  return (*(BYTE*)(eproc + 0x87A) & 7) != 0;  //  +0x87a Protection: _PS_PROTECTION Ands with 7 and returns true if its 1 and not equal to zero 
}
