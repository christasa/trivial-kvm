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
> ``./tkvm -kernel image/bzImage -initrd image/initramfs-busybox-x86.cpio.gz``

![tkvm_terminal](https://github.com/christasa/trivial-kvm/assets/35037256/b999fbf1-512f-4896-9c07-6875b39d6270)

**Build your own Linux image**
- [https://mgalgs.io/2015/05/16/how-to-build-a-custom-linux-kernel-for-qemu-2015-edition.html](https://mgalgs.io/2015/05/16/how-to-build-a-custom-linux-kernel-for-qemu-2015-edition.html)

Notice: If you need to build the KVM acceleration kernel, change the command `make kvmconfig` to `make kvm_guest.config`. Reference: [https://www.mail-archive.com/linux-kernel@vger.kernel.org/msg2140886.html](https://www.mail-archive.com/linux-kernel@vger.kernel.org/msg2140886.html)


*You may need to re-run the programme many time for successfully get the terminal. Only for x86 structure yet.*

## Relevant notes
- [kvmtool阅读笔记(一) | 通用结构体&函数执行概括](https://christa.top/details/62/)
- [kvmtool阅读笔记(二) | 内存初始化](https://christa.top/details/63/)
- [kvmtool阅读笔记(三) | Linux内核加载](https://christa.top/details/64/)
- [kvmtool阅读笔记(四) | 设置BIOS](https://christa.top/details/65/)

## Reference
- [https://github.com/kvmtool/kvmtool](https://github.com/kvmtool/kvmtool)
- *Inside the Linux Virtualization Principle and Implementation*
