struct _DMA_ADAPTER {
  USHORT          Version;
  USHORT          Size;
  PDMA_OPERATIONS DmaOperations;
} *PADAPTER_OBJECT, DMA_ADAPTER, *PDMA_ADAPTER;

UINT MiIsUserQueryVmCallerTrusted(PACCESS_TOKEN ProcessToken)
{
    UINT IsTrusted {};
    PSECURITY_IMPERSONATION_LEVEL  ImpersonationLevel{};
    PTOKEN_TYPE TokenType; 
    _DMA_ADAPTER *TokenReference; 
    PBOOLEAN EffectiveOnly
    
    // Returns A Pointer To The Effective Token of A Thread 
    TokenReference = (PDMA_ADAPTER)PsReferenceEffectiveToken(ProcessToken, &TokenType, &EffectiveOnly, &ImpersonationLevel, 0);

    // SeTokenAdmin: Checks If Token Is Admin 
    // SeSinglePrivilegeCheck: The SeSinglePrivilegeCheck routine checks for the passed privilege value in the context of the current thread 
    // SeProfileSingleProcessPrivilege Luid of the privilage being checked
    if(SeTokenAdmin(TokenReference) || SeSinglePrivilegeCheck(SeProfileSingleProcessPrivilege, 1))
        ++IsTrusted;            // increments and set IsTrusted To 1 Means Its Trusted And Can Query VM 
    HalPutDmaAdapter(TokenReference);
    return IsTrusted;
}
