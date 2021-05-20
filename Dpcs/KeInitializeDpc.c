// Initlize The KDPC For A DPC Routine 

void NTAPI KeInitializeDpc(PRKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine, PVOID DeferredContext)
{
  /*
      TargetInfoAsUlong Is Just A Union
      
       union
      {
        ULONG TargetInfoAsUlong;                                            //0x0
        struct
        {
            UCHAR Type;                                                     //0x0
            UCHAR Importance;                                               //0x1
            volatile USHORT Number;                                         //0x2
        };
     };
     
     Type: Type of Object (Process, Thread, DPC, Mutex, etc ... ) 
     Importance: Where The DPC Will Be Placed In The DPC Queue 
     Number: The Processor Number It Will Be Queued & Executed On 
  */ 
  
  
  
  Dpc->TargetInfoAsUlong = 0x113;                      
  
  // Pointer To KDPC_DATA (Contains DPC Information) Zero It. 
  
  Dpc->DpcData = 0;                                     
  
  /*
    Not Sure About This One But It Looks Like Its The Number of DPCs Pending. 
    I Made This Assumption Based on I Had One DPC Running On CPU 0 I Checked Its KDPC ProcessorHistory 
    Field Was Set To 1, It So Looks Like It Mean Its The Only One Pending But Not Sure. But Here It Just Init It To Zero     
  */
  
  Dpc->ProcessorHistory = 0;                         
  
  // Function Pointer To DPC Routine It Will Run At DISPATCH_LEVEL IRQL 
  
  Dpc->DeferredRoutine = (PVOID)DeferredRoutine;      
  
   // Parameter To Pass To The DPC
  
  Dpc->DeferredContext = DeferredContext;           
}
