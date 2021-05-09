// Def: Checks If Its Parent Process or not 
// Status: Unexported | Undocumented 

bool PspIsParentProcess(_PEPROCESS ProcessA, _PEPROCESS ProcessB)
{

	bool IsParentProcess = false;
	
	// If Its A Child Process Its InheritedFromUniqueProcessId Will Be Equal To Parent Process UniqueProcessId So Check For That 
	
	if (ProcessB->InheritedFromUniqueProcessId == ProcessA->UniqueProcessId)

		/*	
		   More Checking Windows Keeps Tracks Of Processes Sequence Using This Sequence Number 
			 According To Bruce Dang (The Only Thing I Found About Sequence Numbers Is His Tweet !)
			 Parent Process Will Have A Sequence Number Less Than Of Child Process Sequence Number 
			 So If Child Process Has Higher Sequence Number Set IsParentProcess To Be True 
		 */ 
		IsParentProcess = ProcessB->SequenceNumber > ProcessA->SequenceNumber;
	
	return IsParentProcess;
}
