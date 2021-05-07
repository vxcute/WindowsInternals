// Gets Process Protection Returns PPS_PROTECTION (Unexported)

PPS_PROTECTION PsGetProcessProtection(_EPROCESS *eproc)
{
    return eproc->Protection;

    /*  
        mov     al, [rcx+87Ah]      0x87A offset to PPS_PROTECTION 
        retn
    */
}
