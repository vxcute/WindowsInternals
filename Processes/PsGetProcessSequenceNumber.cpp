unsigned long long PsGetProcessSequenceNumber(_EPROCESS *Process)
{
  return Process->SequenceNumber;
}
