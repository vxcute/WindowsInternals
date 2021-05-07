// Def: Gets Process Protection  
// Return Value: Returns PPS_PROTECTION 
// Status: Unexported

PPS_PROTECTION PsGetProcessProtection(_EPROCESS *eproc)
{
    return eproc->Protection;
    
    /*  
    IDA:
        mov     al, [rcx+87Ah]      0x87A offset to PPS_PROTECTION 
        retn
    */
}
