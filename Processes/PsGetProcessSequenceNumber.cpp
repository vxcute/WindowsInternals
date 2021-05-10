/*
  Def: Gets The Process Sequence Number For Its EPROCESS
  Status: Exported | Not Documented 
  
  # Windows Uses Sequence Numbers To Keep Track of Processes Sequence, 
  For Example Parent and Child Process The Child Cames After The Parent 
  So It Will Have A Higher Sequence Number 
  Than The Parent Process 
*/

unsigned long long PsGetProcessSequenceNumber(_EPROCESS *Process)
{
  return Process->SequenceNumber;
}
