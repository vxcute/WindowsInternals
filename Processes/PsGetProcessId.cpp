// gets process id by from its eprocess 

HANDLE NTAPI PsGetProcessId(_EPROCESS *Process)
{
  return Process->UniqueProcessId;
}
