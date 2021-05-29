Page 181 Question 10: 
======================

Windows Uses cr8 to store the current irql 

```asm
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

For More Info Check My [Paper](https://github.com/vxcute/WindowsInternals/blob/main/Papers/Windows%20Irqs/Windows%20Irqls.pdf)
