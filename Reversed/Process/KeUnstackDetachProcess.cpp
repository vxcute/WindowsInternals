void NTAPI KeUnstackDetachProcess(PRKAPC_STATE ApcState)
{
	PKPROCESS Process;

	// optain kprocess from PRKAPC_STATE structure 

	Process = ApcState->Process;

	/*
		 when calling KeStackAttachProcess to attach a process this function firstly checks if you are trying to attach to ur current process by 
		 getting the CurrentProcess from the CurrentThread and checks if its equal to the passed process if the condition is true 
		 it will then set the Process field to 1 and just exiting the function ending not attaching to the process. 

		  if ( CurrentThread->ApcState.Process == Process )
		  {
			ApcState->Process = (PKPROCESS)1;
		  }

		  so here KeUnstackDetachProcess checks the Process is not equal to 1 (i.e. not the current process). 
		  if it is it will de-attach the process using KiDetachProcess
	*/

	if (Process != (PKPROCESS)1)
	{
		if (!Process)
			ApcState = &KeGetCurrentThread()->SavedApcState;
		KiDetachProcess(ApcState, NULL);
	}
}
