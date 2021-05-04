void NTAPI RtlFreeAnsiString(PANSI_STRING AnsiString)
{
	ULONG PoolTag; 
	CHAR* AnsiStringBuffer; 

	AnsiStringBuffer = AnsiString->Buffer;
	
	if (AnsiStringBuffer) 
		ExFreePoolWithTag(AnsiStringBuffer, PoolTag);
	*(&AnsiString) = nullptr;
}
