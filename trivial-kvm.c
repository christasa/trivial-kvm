#include "trivial-kvm.h"
#include "list.h"

#include <linux/kvm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
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

    if (!kvm->cpus)
    {
        printf("Couldn't allocate array for %d CPUs\n", kvm->nrcpus);
        return -1;
    }

    for (int i = 0; i < kvm->nrcpus; i++)
    {
        kvm->cpus[i] = single_kvm__cpu(kvm, i);
        if (!kvm->cpus[i])
        {
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
    while (1)
    {
        err = ioctl(cpu->vcpu_fd, KVM_RUN, 0);
        if (err < 0)
            perror("KVM_RUN ioctl");
    }

    return err;
}

static u64 host_ram_size(void) {
    long page_size;
    long nr_pages;

    nr_pages = sysconf(_SC_PHYS_PAGES);
    if (nr_pages < 0)
    {
        printf("sysconf(_SC_PHYS_PAGES) failed\n");
        return 0;
    }

    page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size < 0)
    {
        printf("sysconf(_SC_PAGE_SIZE) failed\n");
        return 0;
    }

    return (u64)nr_pages * page_size;
}

ssize_t xread(int fd, void *buf, size_t count) {
    ssize_t nr;

restart:
    nr = read(fd, buf, count);
    if ((nr < 0) && ((errno == EAGAIN) || (errno == EINTR)))
        goto restart;

    return nr;
}

ssize_t read_in_full(int fd, void *buf, size_t count) {
    ssize_t total = 0;
    char *p = buf;

    while (count > 0)
    {
        ssize_t nr;

        nr = xread(fd, p, count);
        if (nr <= 0)
        {
            if (total > 0)
                return total;

            return -1;
        }

        count -= nr;
        total += nr;
        p += nr;
    }

    return total;
}

ssize_t read_file(int fd, char *buf, size_t max_size) {
    ssize_t ret;
    char dummy;

    errno = 0;
    ret = read_in_full(fd, buf, max_size);

    /* Probe whether we reached EOF. */
    if (xread(fd, &dummy, 1) == 0)
        return ret;

    errno = ENOMEM;
    return -1;
}

void kvm__arch_init(struct kvm *kvm) {

    kvm->ram_slots = 0;

    // kvm->ram_size = host_ram_size() * 0.8;

    if (!kvm->ram_size)
        kvm->ram_size = 8 * 1024*1024; // memory size: 8GB

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

    kvm->ram_pagesize = 4096; // set the default page size as 4KB
    kvm->ram_start = mmap(NULL, kvm->ram_size,
                          PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

    if ((unsigned)kvm->ram_size >= (unsigned)KVM_32BIT_GAP_START) {
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

int kvm_ram__init(struct kvm *kvm) {
    struct kvm_userspace_memory_region mem;
    struct kvm_mem_bank *bank;
    struct list_head *prev_entry;
    int ret = 0;

    // get the address of ram start
    kvm__arch_init(kvm);

    INIT_LIST_HEAD(&kvm->mem_banks);

    // lock each CPU thread
    if (pthread_mutex_lock(&kvm->mutex) != 0)
    {
        perror("unexpected pthread_mutex_init() failure!");
    }

    prev_entry = &kvm->mem_banks;

    bank = malloc(sizeof(*bank));
    if (!bank) {
        ret = -1;
        goto out;
    }

    INIT_LIST_HEAD(&bank->list);
    bank->guest_phys_addr = 0;
    bank->host_addr = (unsigned long)kvm->ram_start;
    bank->size = kvm->ram_size;
    bank->slot = 0;

    
    if ((unsigned)kvm->ram_size < (unsigned)KVM_32BIT_GAP_START) {
        mem = (struct kvm_userspace_memory_region){
            .slot = 0,
            .flags = 0,
            .guest_phys_addr = 0,
            .memory_size = kvm->ram_size,
            .userspace_addr = (unsigned long)kvm->ram_start,
        };

        ret = ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &mem);
        if (ret < 0)
        {
            perror("KVM_SET_USER_MEMORY_REGION ioctl");
            goto out;
        }

        list_add(&bank->list, prev_entry);

        ret = 0;
    }

out:
    if (pthread_mutex_unlock(&kvm->mutex) != 0)
        perror("unexpected pthread_mutex_unlock() failure!");

    return ret;
}

void *guest_flat_to_host(struct kvm *kvm, u64 offset) {
    struct kvm_mem_bank *bank;

    list_for_each_entry(bank, &kvm->mem_banks, list)
    {
        u64 bank_start = bank->guest_phys_addr;
        u64 bank_end = bank_start + bank->size;

        if (offset >= bank_start && offset < bank_end)
            return bank->host_addr + (offset - bank_start);
    }

    printf("unable to translate guest address 0x%llx to host\n",
           (unsigned long long)offset);
    return NULL;
}

static inline void *guest_real_to_host(struct kvm *kvm, u16 selector, u16 offset) {
    unsigned long flat = ((u32)selector << 4) + offset;

    return guest_flat_to_host(kvm, flat);
}

int load_image(struct kvm *kvm) {
    int ret = 0, fd;
    fd = open("./guest/kernel.bin", O_RDONLY);
    if (fd < 0)
    {
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

int kvm__load_kernel(struct kvm *kvm, const char *kernel_filename,
                     const char *initrd_filename) {

    int ret = 0;
    int fd_kernel = -1, fd_initrd = -1;

    struct boot_params *kern_boot;
    struct boot_params boot;
    size_t cmdline_size;
    ssize_t file_size;
    void *p;
    u16 vidmode;

    fd_kernel = open(kernel_filename, O_RDONLY);
    if (fd_kernel < 0) {
        printf("Unable to open kernel %s\n", kernel_filename);
        return -1;
    }

    fd_initrd = open(initrd_filename, O_RDONLY);
    if (fd_initrd < 0) {
        printf("Unable to open initrd %s\n", initrd_filename);
        return -1;
    }

    if (read_in_full(fd_kernel, &boot, sizeof(boot)) != sizeof(boot))
        return -1;

    if (memcmp(&boot.hdr.header, "HdrS", 4))
        return -1;
    

    if (lseek(fd_kernel, 0, SEEK_SET) < 0)
        perror("lseek");

    if (!boot.hdr.setup_sects)
        boot.hdr.setup_sects = 4;
    file_size = (boot.hdr.setup_sects + 1) << 9;
    p = guest_real_to_host(kvm, 0x1000, 0x0000);
    if (read_in_full(fd_kernel, p, file_size) != file_size)
        perror("kernel setup read");

    p = guest_flat_to_host(kvm, 0x100000UL);
    file_size = read_file(fd_kernel, p, kvm->ram_size - 0x100000UL);

    if (file_size < 0)
        perror("kernel read");

    // copy cmdline to host
    p = guest_flat_to_host(kvm, 0x20000);
    cmdline_size = strlen(kern_cmdline) + 1;
    memset(p, 0, cmdline_size);
    memcpy(p, kern_cmdline, cmdline_size - 1);

    // read initrd image into guest memory
    struct stat initrd_stat;
    unsigned long addr;

    if (fstat(fd_initrd, &initrd_stat))
        perror("fstat");

    addr = boot.hdr.initrd_addr_max & ~0xfffff;
    for (;;)
    {
        if (addr < 0x100000UL)
        {
            printf("Not enough memory for initrd\n");
            return -1;
        }
        else if (addr < (kvm->ram_size - initrd_stat.st_size))
            break;

        addr -= 0x100000;
    }

    p = guest_flat_to_host(kvm, addr);
    if (read_in_full(fd_initrd, p, initrd_stat.st_size) < 0)
        perror("Failed to read initrd");

    close(fd_initrd);
    close(fd_kernel);

    printf("kernel loading complete\n");

    return ret;
}

static void e820_setup(struct kvm *kvm) {
    struct e820map *e820;
	struct e820entry *mem_map;
	unsigned int i = 0;

    e820 = guest_flat_to_host(kvm, 0x0009fc00);
    mem_map = e820->map;

    mem_map[i++]	= (struct e820entry) {
		.addr		= 0x00000000,
		.size		= 0x0009fc00,
		.type		= 1,
	};
	mem_map[i++]	= (struct e820entry) {
		.addr		= 0x0009fc00,
		.size		= 0x00000400,
		.type		= 2,
	};
	mem_map[i++]	= (struct e820entry) {
		.addr		= 0x000f0000,
		.size		= 0x0000ffff,
		.type		= 2,
	};
    
    if (kvm->ram_size < KVM_32BIT_GAP_START) {
		mem_map[i++]	= (struct e820entry) {
			.addr		= 0x100000UL,
			.size		= kvm->ram_size - 0x100000UL,
			.type		= 1,
		};
	} else {
		mem_map[i++]	= (struct e820entry) {
			.addr		= 0x100000UL,
			.size		= KVM_32BIT_GAP_START - 0x100000UL,
			.type		= 1,
		};
		mem_map[i++]	= (struct e820entry) {
			.addr		= KVM_32BIT_MAX_MEM_SIZE,
			.size		= kvm->ram_size - KVM_32BIT_MAX_MEM_SIZE,
			.type		= 1,
		};
	}

    if (i > 128)
        perror("BUG too big");
    
    e820->nr_map = i;

}

static void setup_vga_rom(struct kvm *kvm) {
    u16 *mode;
    void *p;

    p = guest_flat_to_host(kvm, 0x000c0000);
    memset(p, 0, 16);
    strncpy(p, "KVM VESA", 16);

    mode = guest_flat_to_host(kvm, 0x000c0000 + 16);
    mode[0] = 0x0112;
    mode[1] = 0xffff;
}

void interrupt_table__setup(struct interrupt_table *itable, struct real_intr_desc *entry) {
	unsigned int i;

	for (i = 0; i < 256; i++)
		itable->entries[i] = *entry;
}

void interrupt_table__copy(struct interrupt_table *itable, void *dst, unsigned int size)
{
	if (size < sizeof(itable->entries))
		perror("An attempt to overwrite host memory");

	memcpy(dst, itable->entries, sizeof(itable->entries));
}

int kvm__arch_setup_firmware(struct kvm *kvm) {
    int ret = 0;
    unsigned long address = 0x000f0000;
    struct real_intr_desc intr_desc;
    unsigned int i;
	void *p;

    p = guest_flat_to_host(kvm, 0x00000400);
	memset(p, 0, 0x000000ff);

	p = guest_flat_to_host(kvm, 0x0009fc00);
	memset(p, 0, 0x000003ff);

	p = guest_flat_to_host(kvm, 0x000f0000);
	memset(p, 0, 0x0000ffff);

	p = guest_flat_to_host(kvm, 0x000c0000);
	memset(p, 0, 0x00007fff);

	p = guest_flat_to_host(kvm, 0x000f0000);
	memcpy(p, bios_rom, bios_rom_size);

    e820_setup(kvm);

    setup_vga_rom(kvm);

    address = 0x000f0030;
    intr_desc = (struct real_intr_desc) {
        .segment = 0x000f0000 >> 4,
        .offset  = address - 0x000f0000,
    };

    interrupt_table__setup(&kvm->interrupt_table, &intr_desc);
    
    p = guest_flat_to_host(kvm, 0);
    interrupt_table__copy(&kvm->interrupt_table, p, 1024);

    return ret;
}

int main(int argc, char **argv) {
    int ret = 0;
    struct kvm *kvm = malloc(sizeof(struct kvm));

    kvm->sys_fd = -1;
    kvm->vm_fd = -1;

    kvm->sys_fd = open("/dev/kvm", O_RDONLY);
    if (kvm->sys_fd < 0)
    {
        perror("open /dev/kvm");
        return ret;
    }

    ret = ioctl(kvm->sys_fd, KVM_GET_API_VERSION, 0);
    if (ret != KVM_API_VERSION)
    {
        perror("KVM_API_VERSION ioctl");
        ret = -1;
        goto err_sys_fd;
    }

    kvm->vm_fd = ioctl(kvm->sys_fd, KVM_CREATE_VM, 0);
    if (kvm->vm_fd < -1)
    {
        perror("KVM_CREATE_VM ioctl");
        ret = -1;
        goto err_sys_fd;
    }

    // init the vm memory
    ret = kvm_ram__init(kvm);
    if (ret < 0)
        goto err_sys_fd;

    // load the kernel
    // ret = load_image(kvm);
    ret = kvm__load_kernel(kvm, "bzImage", "initramfs-busybox-x86.cpio.gz");
    if (ret < 0)
        goto err_sys_fd;

    ret = kvm__arch_setup_firmware(kvm);
    if (ret < 0)
        goto err_sys_fd;
    
    // init the kvm cpu
    ret = kvm_cpu__init(kvm);
    if (ret < 0)
    {
        perror("KVM CPU INIT");
        goto err_sys_fd;
    }

    // start the kvm
    for (int i = 0; i < kvm->nrcpus; i++)
    {
        if (pthread_create(&kvm->cpus[i]->thread, NULL, kvm_cpu__start, kvm->cpus[i]) != 0)
            perror("unable to create KVM VCPU thread");
    }

    if (pthread_join(kvm->cpus[0]->thread, NULL) != 0)
        perror("unable to join with vcpu 0");

    // do not need to pause kvm, kill the thread directly
    for (int i = 0; i < kvm->nrcpus; i++)
    {
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
