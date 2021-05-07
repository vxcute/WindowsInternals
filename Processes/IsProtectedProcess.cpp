bool __fastcall PsIsProtectedProcess(KPROCESS* kproc)
{
  return (*(BYTE*)(kproc + 0x87A) & 7) != 0;  //  +0x87a Protection : _PS_PROTECTION & 7 Returns True If Its Set to 1 and not equal to zero 
}
