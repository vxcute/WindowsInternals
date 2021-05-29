// Queries Windows NT Type Checks If It WinNT, ServerNT or LanmanNT

__int64 __fastcall RtlpGetNtProductTypeFromRegistry(DWORD *NT_Type)
{
  NTSTATUS RegStatus; 
  ULONG ResultLength; 
  HANDLE KeyHandle; 
  UNICODE_STRING FinalNtType; 
  __int64 RegPath[2];
  UNICODE_STRING ValueName; 
  UNICODE_STRING WinNT; 
  UNICODE_STRING LanmanNT; 
  UNICODE_STRING ServerNT; 
  OBJECT_ATTRIBUTES ObjectAttributes; 
  PVOID KeyValueInformation; 
  __int64 MaximumLength; 

  *(&ObjectAttributes.Length + 1) = 0;
  *(&ObjectAttributes.Attributes + 1) = 0;
  ResultLength = 0;
  *(_DWORD *)(&FinalNtType.MaximumLength + 1) = 0;
  KeyHandle = 0;
  ObjectAttributes.RootDirectory = 0i64;
  RegPath[1] = (__int64)L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ProductOptions";// Registry Path Contains The Windows NT Type In ProductType Field
  ValueName.Buffer = L"ProductType";
  LanmanNT.Buffer = L"LanmanNt";
  ServerNT.Buffer = L"ServerNt";
  WinNT.Buffer = L"WinNt";
  ObjectAttributes.ObjectName = (_UNICODE_STRING *)RegPath;
  RegPath[0] = 0x840082;
  *(UINT64*)&ValueName.Length = 0x180016;
  *(UINT64*)&LanmanNT.Length = 0x120010;
  *(UINT64*)&ServerNT.Length = 0x120010;
  *(UINT64*)&WinNT.Length = 0xC000A;
  ObjectAttributes.Length = 0x30;
  ObjectAttributes.Attributes = 0x240;
  *(UINT64*)&ObjectAttributes.SecurityDescriptor = 0;
  RegStatus = ZwOpenKey(&KeyHandle, 1u, &ObjectAttributes);
  if ( RegStatus >= 0 )
  {
    RegStatus = ZwQueryValueKey(
                  KeyHandle,
                  &ValueName,                   // Query ProductTypes
                  KeyValuePartialInformation,   // Information Returned Is Stored As KEY_VALUE_PARTIAL_INFORMATION 
                  &KeyValueInformation,         // Pointer Holds Base Address of Information Returned By ZwQueryValueKey
                  0x24u,
                  &ResultLength);
    if ( RegStatus >= 0 )
    {
      if ( HIDWORD(KeyValueInformation) == 1 && (unsigned int)MaximumLength >= 2 )
      {
        FinalNtType.MaximumLength = MaximumLength;
        FinalNtType.Buffer = (wchar_t *)&v14 + 2;
        FinalNtType.Length = MaximumLength - 2;
        if ( RtlEqualUnicodeString(&FinalNtType, &WinNT, 1u) )
        {
          *NT_Type = 1;                         // WinNT
                                                // 
          goto CloseRegHandleAndReturn;
        }
        if ( RtlEqualUnicodeString(&FinalNtType, &LanmanNT, 1u) )
        {
          *NT_Type = 2;                         // LanmanNT
          goto CloseRegHandleAndReturn;
        }
        if ( RtlEqualUnicodeString(&FinalNtType, &ServerNT, 1u) )
        {
          *NT_Type = 3;                         // ServerNT
          goto CloseRegHandleAndReturn;
        }
      }
      RegStatus = 0xC000090B;
    }
  }
CloseRegHandleAndReturn:
  if ( KeyHandle )
    ZwClose(KeyHandle);                         // Close Handle which Was Opened To Registry 
  return (unsigned int)RegStatus;
}
