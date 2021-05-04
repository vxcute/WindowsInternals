#define LOWORD(l) ((SHORT)(((DWORD_PTR)(l)) & 0xffff))

void NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
	unsigned __int64 i;
	unsigned __int64 length;
	*(__int64*)(&DestinationString->Length) = 0;
	DestinationString->Buffer = (wchar_t*)SourceString;
	__int64 NewLen = 0;

	if (SourceString) {
		i = 0xFFFFFFFFFFFFFFFF;
		
		do
			++i;
		while (SourceString[i]);

		length = i * 2;

		if (length >= 0xFFE)
			NewLen = LOWORD(length);
		DestinationString->Length = NewLen;
		DestinationString->MaximumLength = NewLen + 2;
	}
}
