# A Minimal KVM prototype
tkvm is a minimal VMM which can run a very simple VM and can run a whole operation system in the future. It uses KVM API to simulate a VM. It is a learning project contemporarly.

## Steps
Learning of tkvm can be divided into 4 steps:
- [x] Build a prototype of KVM API usage
- [x] Accomplish the part of Memory set
- [ ] Accomplish the part of load kernel boot and initrd
- [ ] Accomplish the part of CPU

## Example
Run the `tkvm` and then run the command
> `` pidstat -p `pidof tkvm` 1 ``

you will see the following output

```bash
 UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command
  0    126933    0.00    0.00  100.00    0.00  100.00     0  tkvm
  0    126933    0.00    0.00  100.00    0.00   99.00     0  tkvm
  0    126933    0.00    0.00   96.00    0.00   96.00     0  tkvm
  0    126933    1.00    0.00   98.00    0.00   99.00     0  tkvm
  0    126933    0.00    0.00  100.00    0.00  100.00     0  tkvm
```

We simply ran an empty loop in the Guest, which can see in the [guest/kernel.S](guest/kernel.S), and it can be observed that the VCPU's Guest state is 100%, even when there are passive VM exits such as clock interrupt or network card interrupt landing on this CPU. After the VM exit, the VCPU stays in Host kernel state for a very short period of time before immediately switching back to the Guest. Therefore, the %system state in the statistics is 0.

## Relevant notes
- [kvmtool阅读笔记(一) | 通用结构体&函数执行概括](https://christa.top/details/62/)
- [kvmtool阅读笔记(二) | 内存初始化](https://christa.top/details/63/)

## Reference
- [https://github.com/kvmtool/kvmtool](https://github.com/kvmtool/kvmtool)
- *Inside the Linux Virtualization Principle and Implementation*
