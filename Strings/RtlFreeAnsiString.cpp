void NTAPI RtlFreeAnsiString(PANSI_STRING AnsiString)
{
	ULONG PoolTag; 
	CHAR* AnsiStringBuffer; 

	AnsiStringBuffer = AnsiString->Buffer;			// PANSI_STRING Is Struct Contains A Variable Called Buffer Which Will Contain THe String 
	
	if (AnsiStringBuffer) 				// If The Buffer Is Not Equal To Null 
		ExFreePoolWithTag(AnsiStringBuffer, PoolTag);			// Free The Pool Allocated 
	*(&AnsiString) = nullptr;			// Set AnsiString To null pointer 
}
