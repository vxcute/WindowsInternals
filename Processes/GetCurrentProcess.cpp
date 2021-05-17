/*
   Windows Has Two Routines For That Both Works The Same Way 
   PsGetCurrentProcess Just Doesn't Take An Argument And Uses KeGetCurrentThread To Obtain Pointer To Current Thread 
   Which Just Returns A KTHREAD Pointer However PsGetCurrentProcessByThread From Its Name You Should Pass A KTHREAD Pointer 
   Which Is Just Done By Calling KeGetCurrentThread() 
*/

_KPROCESS *PsGetCurrentProcess()
{
  return KeGetCurrentThread()->ApcState.Process;
}

_KPROCESS *PsGetCurrentProcessByThread(_KTHREAD *Thread)
{
  return Thread->ApcState.Process;
}
