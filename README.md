# A Minimal KVM prototype
tkvm is a minimal VMM which can run a very simple VM and can run a whole operation system in the future. It uses KVM API to simulate a VM. It is a learning project contemporarly.

## Steps
Learning of tkvm can be divided into 4 steps:
- [x] Build a prototype of KVM API usage
- [x] Accomplish the part of Memory set
- [x] Accomplish the part of load kernel boot and initrd
- [x] Accomplish the part of CPU

## Example
Run the `tkvm` and then run the command
> ``./tkvm``


![tkvm_terminal](https://github.com/christasa/trivial-kvm/assets/35037256/b999fbf1-512f-4896-9c07-6875b39d6270)

You may need to re-run the programme many time for successfully get the terminal. Only for x86 structure yet.

## Relevant notes
- [kvmtool阅读笔记(一) | 通用结构体&函数执行概括](https://christa.top/details/62/)
- [kvmtool阅读笔记(二) | 内存初始化](https://christa.top/details/63/)

## Reference
- [https://github.com/kvmtool/kvmtool](https://github.com/kvmtool/kvmtool)
- *Inside the Linux Virtualization Principle and Implementation*
