#include "trivial-kvm.h"

#include <linux/kvm.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <asm/bootparam.h>


struct kvm_cpu *single_kvm__cpu(struct kvm *kvm, unsigned long cpu_id) {

    struct kvm_cpu *vcpu = malloc(sizeof(struct kvm_cpu));

    vcpu->kvm = kvm;

    vcpu->cpu_id = cpu_id;
    vcpu->vcpu_fd = ioctl(vcpu->kvm->vm_fd, KVM_CREATE_VCPU, cpu_id);

    if (!vcpu)
        return NULL;
    
    return vcpu;
}

int kvm_cpu__init(struct kvm *kvm) {
    int max_cpus, recommended_cpus;

    // Set number of CPUS
    kvm->nrcpus = 1;
    kvm->cpus = calloc(kvm->nrcpus + 1, sizeof(void *));
    
    if (!kvm->cpus) {
        printf("Couldn't allocate array for %d CPUs\n", kvm->nrcpus);
        return -1;
    }

    for (int i = 0; i < kvm->nrcpus; i++) {
        kvm->cpus[i] = single_kvm__cpu(kvm, i);
        if (!kvm->cpus[i]) {
            printf("unable to initialize KVM VCPU\n");
            goto fail_alloc;
        }
    }

    return 0;

fail_alloc:
    for (int i = 0; i < kvm->nrcpus; i++)
        free(kvm->cpus[i]);
    
    return -1;
}

int kvm_cpu__start(struct kvm_cpu *cpu) {
    int err = 0;

    // always run the kvm
    while (1) {
        err = ioctl(cpu->vcpu_fd, KVM_RUN, 0);
        if (err < 0) 
            perror("KVM_RUN ioctl");
    }
    
    return err;
}

void kvm__arch_init(struct kvm *kvm) {

    kvm->ram_slots = 0;
    kvm->ram_size = 1024*1024; // memory size: 1GB
    struct kvm_pit_config pit_config = {
        .flags = 0,
    };
    int ret;

    ret = ioctl(kvm->vm_fd, KVM_SET_TSS_ADDR, 0xfffbd000);
    if (ret < 0)
        perror("KVM_SET_TSS_ADDR ioctl");

    ret = ioctl(kvm->vm_fd, KVM_CREATE_PIT2, &pit_config);
    if (ret < 0)
        perror("KVM_CREATE_PIT2 ioctl");
    
    kvm->ram_pagesize = 4096;  // set the default page size as 4KB
    kvm->ram_start = mmap(NULL, kvm->ram_size, 
    PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

    if (kvm->ram_size >= KVM_32BIT_GAP_START) {
        kvm->ram_size = kvm->ram_size + KVM_32BIT_GAP_SIZE;
        // if ram size is bigger than the 32bit RAM, then mprotect the gap PROT_NONE
        // so that we will konw if the programme accidently writes to this address
        if (kvm->ram_start != MAP_FAILED) 
            mprotect(kvm->ram_start + KVM_32BIT_GAP_START, KVM_32BIT_GAP_START, PROT_NONE);
    }

    if (kvm->ram_start == MAP_FAILED)
        perror("out of memory");
    
    ret = ioctl(kvm->vm_fd, KVM_CREATE_IRQCHIP);
	if (ret < 0)
		perror("KVM_CREATE_IRQCHIP ioctl");

}

void kvm__init_page(struct kvm *kvm) {
    u64 phys_start, phys_size;
	void *host_mem;

    if (kvm->ram_size < KVM_32BIT_GAP_START) {
        // 1GB is smaller than the KVM_32BIT_GAP_START
        phys_start = 0;
        phys_size = kvm->ram_size;
        host_mem = kvm->ram_start;


    }
    else {

    }
}

int kvm_ram__init(struct kvm *kvm) {
    int ret = 0;

    struct kvm_userspace_memory_region mem;

    // get the address of ram start
    kvm__arch_init(kvm);


    mem = (struct kvm_userspace_memory_region){
        .slot = kvm->ram_slots,
        .flags = 0,
        .guest_phys_addr = 0,  /* Memory begins at 0KB of Physical Memory*/
        .memory_size = kvm->ram_size,
        .userspace_addr = (unsigned long)kvm->ram_start,
    };

    ret = ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &mem);
    if (ret < 0) {
        perror("KVM_SET_USER_MEMORY_REGION ioctl");

        return ret;
    }


    return ret;
}

int load_image(struct kvm *kvm) {
    int ret = 0, fd;
    fd = open("./guest/kernel.bin", O_RDONLY);
    if (fd < 0) {
        printf("can not open guest image\n");
        return -1;
    }

    // load the image to the address of (0x1000 << 4) + 0x0 of Guest
    char *p = (char *)kvm->ram_start + ((0x1000 << 4) + 0x0);
    while (1) {
        if ((ret = read(fd, p, 4096)) <= 0)
            break;
        
        p += ret;
    }


    return ret;
}

int main(int argc, char **argv) {
    int ret = 0;
    struct kvm *kvm = malloc(sizeof(struct kvm));


    kvm->sys_fd = -1;
    kvm->vm_fd = -1;

    kvm->sys_fd = open("/dev/kvm", O_RDONLY);
    if (kvm->sys_fd < 0) {
        perror("open /dev/kvm");
        return ret;
    }

    ret = ioctl(kvm->sys_fd, KVM_GET_API_VERSION, 0);
    if (ret != KVM_API_VERSION) {
        perror("KVM_API_VERSION ioctl");
        ret = -1;
        goto err_sys_fd;
    }

    kvm->vm_fd = ioctl(kvm->sys_fd, KVM_CREATE_VM, 0);
    if (kvm->vm_fd < -1) {
        perror("KVM_CREATE_VM ioctl");
        ret = -1;
        goto err_sys_fd;
    }

    // init the vm memory
    ret = kvm_ram__init(kvm);
    if (ret < 0) 
        goto err_sys_fd;

    // load the kernel
    ret = load_image(kvm);
    if (ret < 0)
        goto err_sys_fd;

    // init the kvm cpu
    ret = kvm_cpu__init(kvm);
    if (ret < 0) {
        perror("KVM CPU INIT");
        goto err_sys_fd;
    }

    // start the kvm
    for (int i = 0; i < kvm->nrcpus; i++) {
        if (pthread_create(&kvm->cpus[i]->thread, NULL, kvm_cpu__start, kvm->cpus[i]) != 0)
            perror("unable to create KVM VCPU thread");
    }

    if (pthread_join(kvm->cpus[0]->thread, NULL) != 0) 
        perror("unable to join with vcpu 0");

    

    // do not need to pause kvm, kill the thread directly
    for (int i = 0; i < kvm->nrcpus; i++) {
        pthread_kill(kvm->cpus[i]->thread, SIGRTMIN);
    }

    free(kvm->cpus[0]);
    kvm->cpus[0] = NULL;

    free(kvm->cpus);

    kvm->nrcpus = 0;


err_sys_fd:
    close(kvm->sys_fd);

    return ret;
}
