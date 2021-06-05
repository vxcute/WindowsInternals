void NTAPI KeUnstackDetachProcess(PRKAPC_STATE ApcState)
{
	PKPROCESS Process; 

	Process = ApcState->Process;
	
	if (Process != (PKPROCESS)1)
	{
		if (!Process)
			ApcState = &KeGetCurrentThread()->SavedApcState;
		KiDetachProcess(ApcState, NULL);
	}
}
