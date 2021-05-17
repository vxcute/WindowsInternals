// Checks If Process In Job or Not 

NTSTATUS __fastcall NtIsProcessInJob(HANDLE ProcessHandle, HANDLE JobHandle)
{
	 _KTHREAD* CurrentThread; 
	KPROCESSOR_MODE PreviousMode; 
	NTSTATUS ObjReference;
	_EPROCESS* eproc; 
	NTSTATUS JobObjectRef;
	_EJOB* ProcessJob; 
	NTSTATUS IsProcessInJob; 
	struct _DMA_ADAPTER* DmaAdapter; 
	_EPROCESS* Eproc; 
	PVOID Object; 

	// Obtain Pointer To KTHREAD 

	CurrentThread = KeGetCurrentThread();    


	Eproc = 0i64;
	
	// Save Previous Mode (User / Kernel) To Be Used Later As Access Mode 

	PreviousMode = CurrentThread->PreviousMode;   
	
	// If The Handle Passed Is Handle To Current Process 

	if (ProcessHandle == (HANDLE)0xFFFFFFFFFFFFFFFFi64)
	{
		// So Obtain The KPROCESS From Current Thread and Cast To _EPROCESS* 

		eproc = (_EPROCESS*)CurrentThread->ApcState.Process;
		Eproc = eproc;
	}

	// Else Its Another Process 
	// Obtain An Object Reference Passing The Process Handle It Will Also Return The EPROCESS For The Process


	else                                         
	{
		ObjReference = ObReferenceObjectByHandleWithTag
		( 
			ProcessHandle,					// Handle To The Process 
			0x1000u,						// Desired Mode 
			(POBJECT_TYPE)PsProcessType,	// Object Has Type of Process  
			PreviousMode,					// Pass PreviousMode As Access Mode 
			0x624A7350u,					// Tag "bJsp"  
			(PVOID*)&Eproc,					// Pointer To Variable That Will Recieve The EPROCESS Structure 
			0i64
		);							// HandleInformation 

		// If We Didn't Succeded 

		if (ObjReference < 0)                   
			return ObjReference;                     
	
		eproc = Eproc;
	}

	// If JobHandle Argument Was Passed as NULL  

	if (!JobHandle)
	{
		// So Obtain Job From Its EPROCESS 

		ProcessJob = eproc->Job;
		
		eproc = Eproc;
	
	CheckIsProcessInJob:
	
		// Checks If Process Is In Job or not 

		IsProcessInJob = PspIsProcessInJob(eproc, ProcessJob);
		
		if (JobHandle)
			HalPutDmaAdapter(DmaAdapter);
		
		goto DereferenceObjectAndReturn;		// Will Derefernece Object and Exit The Function 
	}

	Object = 0i64;

	// If It Was not Null Obtain A Reference To It 

	JobObjectRef =
		ObReferenceObjectByHandle
		(
			JobHandle,					      // JobObject Handle 
			4u,							     // Desired Access 
			(POBJECT_TYPE)PsJobType,        // Object Has Type of JobObject 
			PreviousMode,                  // User PreviousMode As The Access Mode 
			&Object,                      // Pointer To The Variable That Will EJOB Pointer   
			0                            // HandleInformation 
		);



	ProcessJob = (_EJOB*)Object;

	IsProcessInJob = JobObjectRef;

	// If We Succed goto CheckIsProcessInJob 

	if (JobObjectRef >= 0)
		goto CheckIsProcessInJob;

DereferenceObjectAndReturn:
	if (ProcessHandle != (HANDLE)0xFFFFFFFFFFFFFFFFi64)
		ObfDereferenceObjectWithTag(eproc, 0x624A7350u);
	return IsProcessInJob;
}
