#pragma D option quiet 
#pragma D option destructive 

uintptr_t CurrentEProcessPtr;
struct nt`_EPROCESS* CurrentEProcess;

BEGIN
{
    CurrentEProcessPtr = (uintptr_t)((struct nt`_LIST_ENTRY*)(void*)&nt`PsActiveProcessHead)->Flink;
}

tick-1ms  
{
    CurrentEProcess = (struct nt`_EPROCESS*)(CurrentEProcessPtr - offsetof(nt`_EPROCESS, ActiveProcessLinks));

    ProcessName = (string)CurrentEProcess->ImageFileName;

    ProcessId = (uintptr_t)CurrentEProcess->UniqueProcessId;

    if(ProcessName == $1)
    {
        printf("[+] Found %s (PID: %d)\n", ProcessName, ProcessId);
        exit(0);
    }

    else
    {
        CurrentEProcessPtr = (uintptr_t)((struct nt`_LIST_ENTRY*)(void*)CurrentEProcessPtr)->Flink;
    }
}
