#pragma D option quiet 
#pragma D option destructive 

uintptr_t CurrentEProcessPtr;
struct nt`_EPROCESS* CurrentEProcess;

BEGIN
{
    system("cls");
    CurrentEProcessPtr = (uintptr_t)((struct nt`_LIST_ENTRY*)(void*)&nt`PsActiveProcessHead)->Flink;
    Found = 0;
}

tick-1ms  / Found == 0 /
{
    if(Found == 0)
    {
        CurrentEProcess = (struct nt`_EPROCESS*)(CurrentEProcessPtr - offsetof(nt`_EPROCESS, ActiveProcessLinks));

        ProcessName = (string)CurrentEProcess->ImageFileName;

        ProcessId = (uintptr_t)CurrentEProcess->UniqueProcessId;

        if(ProcessName == $1)
        {
            printf("[+] Found %s (PID: %d)\n", ProcessName, ProcessId);
            Found = 1;
        }

        else
        {
            CurrentEProcessPtr = (uintptr_t)((struct nt`_LIST_ENTRY*)(void*)CurrentEProcessPtr)->Flink;
        }
    }
}
