Windows Uses cr8 to store the current irql 

```x64
  public KeGetCurrentIrql
  KeGetCurrentIrql proc near
  mov     rax, cr8
  retn
  KeGetCurrentIrql endp
```

C Code For This Would Be Simple As That 

```c
__int64 cr8 = __readcr8(); 
```

U Can Also Read It Using Windbg: 

```
  0: kd> r cr8 
  cr8=000000000000000f
```
