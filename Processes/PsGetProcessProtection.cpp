// Def: Gets Process Protection  
// Return Value: Returns PPS_PROTECTION 
// Status: Unexported on all systems like windows 7, exported on windows 10

PPS_PROTECTION PsGetProcessProtection(_EPROCESS *eproc)
{
    return eproc->Protection;
    
    /*  
    IDA:
        mov     al, [rcx+87Ah]      0x87A offset to PPS_PROTECTION 
        retn
    */
}
