#include "trivial-kvm.h"
#include "list.h"
#include "mmio.h"
#include "devices.h"
#include "terminal.h"
#include "i8402.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <asm/bootparam.h>
#include <limits.h>

struct kvm_cpu *kvm_cpu__arch_init(struct kvm *kvm, unsigned long cpu_id) {

    struct kvm_cpu *vcpu = malloc(sizeof(struct kvm_cpu));
    int mmap_size;

    vcpu->kvm = kvm;

    if (!vcpu)
        return NULL;

    vcpu->cpu_id = cpu_id;
    vcpu->vcpu_fd = ioctl(vcpu->kvm->vm_fd, KVM_CREATE_VCPU, cpu_id);
    if (vcpu->vcpu_fd < 0)
        perror("KVM_CREATE_VCPU ioctl");
    
    mmap_size = ioctl(vcpu->kvm->sys_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (mmap_size < 0)
		perror("KVM_GET_VCPU_MMAP_SIZE ioctl");
    
    vcpu->kvm_run = mmap(NULL, mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, vcpu->vcpu_fd, 0);
	if (vcpu->kvm_run == MAP_FAILED)
		perror("unable to mmap vcpu fd");
    

    return vcpu;
}

int kvm_cpu__init(struct kvm *kvm) {

    // Set number of CPUS
    kvm->cpus = calloc(kvm->nrcpus + 1, sizeof(void *));

    if (!kvm->cpus)
    {
        printf("Couldn't allocate array for %d CPUs\n", kvm->nrcpus);
        return -1;
    }

    for (int i = 0; i < kvm->nrcpus; i++)
    {
        kvm->cpus[i] = kvm_cpu__arch_init(kvm, i);
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

void filter_cpuid(struct kvm_cpuid2 *kvm_cpuid, int cpu_id) {
	unsigned int i;

	for (i = 0; i < kvm_cpuid->nent; i++) {
		struct kvm_cpuid_entry2 *entry = &kvm_cpuid->entries[i];

		switch (entry->function) {
		case 1:
			entry->ebx &= ~(0xff << 24);
			entry->ebx |= cpu_id << 24;
			/* Set X86_FEATURE_HYPERVISOR */
			if (entry->index == 0)
				entry->ecx |= (1 << 31);
			break;
		case 6:
			entry->ecx = entry->ecx & ~(1 << 3);
			break;
		case 10: { /* Architectural Performance Monitoring */
			union cpuid10_eax {
				struct {
					unsigned int version_id		:8;
					unsigned int num_counters	:8;
					unsigned int bit_width		:8;
					unsigned int mask_length	:8;
				} split;
				unsigned int full;
			} eax;

			if (entry->eax) {
				eax.full = entry->eax;
				if (eax.split.version_id != 2 ||
				    !eax.split.num_counters)
					entry->eax = 0;
			}
			break;
		}
		default:
			break;
		};
	}
}

void kvm_cpu__setup_cpuid(struct kvm_cpu *vcpu) {
	struct kvm_cpuid2 *kvm_cpuid;

	kvm_cpuid = calloc(1, sizeof(*kvm_cpuid) +
				100 * sizeof(*kvm_cpuid->entries));

	kvm_cpuid->nent = 100;
	if (ioctl(vcpu->kvm->sys_fd, KVM_GET_SUPPORTED_CPUID, kvm_cpuid) < 0)
		perror("KVM_GET_SUPPORTED_CPUID failed");

	filter_cpuid(kvm_cpuid, vcpu->cpu_id);

	if (ioctl(vcpu->vcpu_fd, KVM_SET_CPUID2, kvm_cpuid) < 0)
		perror("KVM_SET_CPUID2 failed");

	free(kvm_cpuid);
}

static inline u32 selector_to_base(u16 selector) {
	return (u32)selector << 4;
}

static void kvm_cpu__setup_sregs(struct kvm_cpu *vcpu) {
	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &vcpu->sregs) < 0)
		perror("KVM_GET_SREGS failed");

	vcpu->sregs.cs.selector	= 0x1000;
	vcpu->sregs.cs.base	= selector_to_base(0x1000);
	vcpu->sregs.ss.selector	= 0x1000;
	vcpu->sregs.ss.base	= selector_to_base(0x1000);
	vcpu->sregs.ds.selector	= 0x1000;
	vcpu->sregs.ds.base	= selector_to_base(0x1000);
	vcpu->sregs.es.selector	= 0x1000;
	vcpu->sregs.es.base	= selector_to_base(0x1000);
	vcpu->sregs.fs.selector	= 0x1000;
	vcpu->sregs.fs.base	= selector_to_base(0x1000);
	vcpu->sregs.gs.selector	= 0x1000;
	vcpu->sregs.gs.base	= selector_to_base(0x1000);

	if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &vcpu->sregs) < 0)
		perror("KVM_SET_SREGS failed");
}

static void kvm_cpu__setup_regs(struct kvm_cpu *vcpu) {
	vcpu->regs = (struct kvm_regs) {
		/* We start the guest in 16-bit real mode  */
		.rflags	= 0x0000000000000002ULL,

		.rip	= 0x200,
		.rsp	= 0x8000,
		.rbp	= 0x8000,
	};

	if (vcpu->regs.rip > USHRT_MAX)
		printf("ip 0x%llx is too high for real mode\n", (u64)vcpu->regs.rip);

	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &vcpu->regs) < 0)
		perror("KVM_SET_REGS failed");
}

void kvm_cpu__reset_vcpu(struct kvm_cpu *vcpu) {
	kvm_cpu__setup_cpuid(vcpu);
	kvm_cpu__setup_sregs(vcpu);
	kvm_cpu__setup_regs(vcpu);
}

void kvm__irq_line(struct kvm *kvm, int irq, int level)
{
	struct kvm_irq_level irq_level;

	irq_level = (struct kvm_irq_level){
		{
			.irq = irq,
		},
		.level = level,
	};

	if (ioctl(kvm->vm_fd, KVM_IRQ_LINE, &irq_level) < 0)
		perror("KVM_IRQ_LINE failed");
}


struct rb_int_node *rb_int_search_single(struct rb_root *root, u64 point) {
	struct rb_node *node = root->rb_node;

	while (node) {
		struct rb_int_node *cur = rb_int(node);

		if (point < cur->low)
			node = node->rb_left;
		else if (cur->high <= point)
			node = node->rb_right;
		else
			return cur;
	}

	return NULL;
}

struct rb_int_node *rb_int_search_range(struct rb_root *root, u64 low, u64 high) {
	struct rb_int_node *range;

	range = rb_int_search_single(root, low);
	if (range == NULL)
		return NULL;

	if (range->high < high)
		return NULL;

	return range;
}

int rb_int_insert(struct rb_root *root, struct rb_int_node *i_node) {
	struct rb_node **node = &root->rb_node, *parent = NULL;

	while (*node) {
		struct rb_int_node *cur = rb_int(*node);

		parent = *node;
		if (i_node->high <= cur->low)
			node = &cur->node.rb_left;
		else if (cur->high <= i_node->low)
			node = &cur->node.rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&i_node->node, parent, node);
	rb_insert_color(&i_node->node, root);

	return 0;
}

static struct mmio_mapping *mmio_search(struct rb_root *root, u64 addr, u64 len) {
	struct rb_int_node *node;

	if (addr + len <= addr)
		return NULL;

	node = rb_int_search_range(root, addr, addr + len);
	if (node == NULL)
		return NULL;

	return mmio_node(node);
}

static struct mmio_mapping *mmio_search_single(struct rb_root *root, u64 addr) {
	struct rb_int_node *node;

	node = rb_int_search_single(root, addr);
	if (node == NULL)
		return NULL;

	return mmio_node(node);
}

static void mmio_remove(struct rb_root *root, struct mmio_mapping *data) {
    rb_erase(&data->node, root);
}


static void mmio_deregister(struct kvm *kvm, struct rb_root *root, struct mmio_mapping *mmio) {
	struct kvm_coalesced_mmio_zone zone = (struct kvm_coalesced_mmio_zone) {
		.addr	= rb_int_start(&mmio->node),
		.size	= 1,
	};
	ioctl(kvm->vm_fd, KVM_UNREGISTER_COALESCED_MMIO, &zone);

	mmio_remove(root, mmio);
	free(mmio);
}

static int mmio_insert(struct rb_root *root, struct mmio_mapping *data) {
	return rb_int_insert(root, &data->node);
}

static struct mmio_mapping *mmio_get(struct rb_root *root, u64 phys_addr, u32 len) {
	struct mmio_mapping *mmio;

	pthread_mutex_lock(&mmio_lock);
	mmio = mmio_search(root, phys_addr, len);
	if (mmio)
		mmio->refcount++;
	pthread_mutex_unlock(&mmio_lock);

	return mmio;
}

static void mmio_put(struct kvm *kvm, struct rb_root *root, struct mmio_mapping *mmio)
{
	pthread_mutex_lock(&mmio_lock);
	mmio->refcount--;
	if (mmio->remove && mmio->refcount == 0)
		mmio_deregister(kvm, root, mmio);
	pthread_mutex_unlock(&mmio_lock);
}

static int trap_is_mmio(unsigned int flags) {
	return (flags & 0xf) == DEVICE_BUS_MMIO;
}

int kvm__register_iotrap(struct kvm *kvm, u64 phys_addr, u64 phys_addr_len,
			 mmio_handler_fn mmio_fn, void *ptr,
			 unsigned int flags) {
	struct mmio_mapping *mmio;
	int ret;

	mmio = malloc(sizeof(*mmio));
	if (mmio == NULL)
		return -ENOMEM;

	*mmio = (struct mmio_mapping) {
		.node		= RB_INT_INIT(phys_addr, phys_addr + phys_addr_len),
		.mmio_fn	= mmio_fn,
		.ptr		= ptr,
		/*
		 * Start from 0 because kvm__deregister_mmio() doesn't decrement
		 * the reference count.
		 */
		.refcount	= 0,
		.remove		= 0,
	};

	pthread_mutex_lock(&mmio_lock);
	ret = mmio_insert(&pio_tree, mmio);
	pthread_mutex_unlock(&mmio_lock);

	return ret;
}

int kvm__deregister_iotrap(struct kvm *kvm, u64 phys_addr, unsigned int flags) {
	struct mmio_mapping *mmio;
	struct rb_root *tree;

	tree = &pio_tree;

	pthread_mutex_lock(&mmio_lock);
	mmio = mmio_search_single(tree, phys_addr);
	if (mmio == NULL) {
		pthread_mutex_unlock(&mmio_lock);
		return 0;
	}

	if (mmio->refcount == 0)
		mmio_deregister(kvm, tree, mmio);
	else
		mmio->remove = 1;
	pthread_mutex_unlock(&mmio_lock);

	return 1;
}

void serial8250__update_consoles(struct kvm *kvm)
{
	unsigned int i;

	for (i = 0; i < 4; i++) {
		struct serial8250_device *dev = &devices[i];

		pthread_mutex_lock(&dev->mutex);

		/* Restrict sysrq injection to the first port */
		serial8250__receive(kvm, dev, i == 0);

		serial8250_update_irq(kvm, dev);

		pthread_mutex_unlock(&dev->mutex);
	}
}

int serial8250__init(struct kvm *kvm) {
	unsigned int i, j;
	int r = 0;

	for (i = 0; i < 4; i++) {
		struct serial8250_device *dev = &devices[i];

		r = kvm__register_iotrap(kvm, dev->iobase, 8, serial8250_mmio, dev,
				 SERIAL8250_BUS_TYPE);
		if (r < 0)
			break;
	}

	return r;
}

int term_init(struct kvm *kvm)
{
	struct termios term;
	int i, r;

	for (i = 0; i < 4; i++)
		if (term_fds[i][0] == 0) {
			term_fds[i][0] = STDIN_FILENO;
			term_fds[i][1] = STDOUT_FILENO;
		}

	if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))
		return 0;

	r = tcgetattr(STDIN_FILENO, &orig_term);
	if (r < 0) {
		printf("unable to save initial standard input settings\n");
		return r;
	}


	term = orig_term;
	term.c_iflag &= ~(ICRNL);
	term.c_lflag &= ~(ICANON | ECHO | ISIG);
	tcsetattr(STDIN_FILENO, TCSANOW, &term);


	/* Use our own blocking thread to read stdin, don't require a tick */
	if(pthread_create(&term_poll_thread, NULL, term_poll_thread_loop, kvm))
		perror("Unable to create console input poll thread\n");

	signal(SIGTERM, term_sig_cleanup);
	atexit(term_cleanup);

	return 0;
}

static inline int kvm_cpu__emulate_io(struct kvm_cpu *vcpu, u16 port, void *data, 
                        int direction, int size, u32 count) {

    struct mmio_mapping *mmio;
    int is_write;

    if (direction == 1) 
        is_write = 1;
    else 
        is_write = 0;
    
    
    mmio = mmio_get(&pio_tree, port, size);
    if (!mmio) {
        return 1;
    }

    while (count--) {
        mmio->mmio_fn(vcpu, port, data, size, is_write, mmio->ptr);

        data += size;
    }
    mmio_put(vcpu->kvm, &pio_tree, mmio);

    return 1;
}

int kvm_cpu__start(struct kvm_cpu *cpu) {
    int err = 0;

    kvm_cpu__reset_vcpu(cpu);

    // always run the kvm
    while (1) {
        err = ioctl(cpu->vcpu_fd, KVM_RUN, 0);
        if (err < 0)
            perror("KVM_RUN ioctl");
        
		// printf("switch kvm run exit reason: %d\n", cpu->kvm_run->exit_reason);
        switch (cpu->kvm_run->exit_reason) {
        case KVM_EXIT_UNKNOWN:
			break;
        case KVM_EXIT_IO: {
            int ret;

            ret = kvm_cpu__emulate_io(cpu,
						  cpu->kvm_run->io.port,
						  (u8 *)cpu->kvm_run +
						  cpu->kvm_run->io.data_offset,
						  cpu->kvm_run->io.direction,
						  cpu->kvm_run->io.size,
						  cpu->kvm_run->io.count); 
            if (!ret) {
                err = 1;
                goto panic_kvm;
            }

            break;
        }

        default: {
            goto panic_kvm;

            break;
        }

        }
    }

panic_kvm:
	return err;

}

static u64 host_ram_size(void) {
	long page_size;
	long nr_pages;

	nr_pages	= sysconf(_SC_PHYS_PAGES);
	if (nr_pages < 0) {
		printf("sysconf(_SC_PHYS_PAGES) failed\n");
		return 0;
	}

	page_size	= sysconf(_SC_PAGE_SIZE);
	if (page_size < 0) {
		printf("sysconf(_SC_PAGE_SIZE) failed\n");
		return 0;
	}

	return (u64)nr_pages * page_size;
}

static u64 get_ram_size(int nr_cpus) {
	u64 available;
	u64 ram_size;

	ram_size	= (u64)0x04000000 * (nr_cpus + 3);

	available	= host_ram_size() * 0.8;
	if (!available)
		available = 0x04000000; // set the default size as 64MB

	if (ram_size > available)
		ram_size	= available;

	return ram_size;
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

    kvm->ram_size = get_ram_size(kvm->nrcpus);

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

    // Create virtual interrupt chip
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

int kvm__load_kernel(struct kvm *kvm) {

    int ret = 0;
    int fd_kernel = -1, fd_initrd = -1;

    struct boot_params *kern_boot;
    struct boot_params boot;
    size_t cmdline_size;
    ssize_t file_size;
    void *p;

    fd_kernel = open(kvm->kernel_filename, O_RDONLY);
    if (fd_kernel < 0) {
        printf("Unable to open kernel %s\n", kvm->kernel_filename);
        return -1;
    }

    fd_initrd = open(kvm->initrd_filename, O_RDONLY);
    if (fd_initrd < 0) {
        printf("Unable to open initrd %s\n", kvm->initrd_filename);
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
    p = guest_real_to_host(kvm, 0x1000, 0x00);
    if (read_in_full(fd_kernel, p, file_size) != file_size)
        perror("kernel setup read");

    p = guest_flat_to_host(kvm, 0x100000UL);
    file_size = read_file(fd_kernel, p, kvm->ram_size - 0x100000UL);

    if (file_size < 0)
        perror("kernel read");

    // copy cmdline to host
    p = guest_flat_to_host(kvm, 0x20000);
    cmdline_size = strlen(kern_cmdline) + 1;
    if (cmdline_size > boot.hdr.cmdline_size)
        cmdline_size = boot.hdr.cmdline_size;

    memset(p, 0, boot.hdr.cmdline_size);
    memcpy(p, kern_cmdline, cmdline_size - 1);

    kern_boot = guest_real_to_host(kvm, 0x1000, 0x00);

    kern_boot->hdr.cmd_line_ptr = 0x20000;
    kern_boot->hdr.type_of_loader = 0xff;
    kern_boot->hdr.heap_end_ptr = 0xfe00;
    kern_boot->hdr.loadflags |= CAN_USE_HEAP;
    kern_boot->hdr.vid_mode = 0;

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
    
    kern_boot->hdr.ramdisk_image = addr;
    kern_boot->hdr.ramdisk_size = initrd_stat.st_size;

    close(fd_initrd);
    close(fd_kernel);

    return ret;
}

static void setup_irq_handler(struct kvm *kvm, struct irq_handler *handler) {
	struct real_intr_desc intr_desc;
	void *p;

	p = guest_flat_to_host(kvm, handler->address);
	memcpy(p, handler->handler, handler->size);

	intr_desc = (struct real_intr_desc) {
		.segment	= (0x000f0000 >> 4),
		.offset		= handler->address - 0x000f0000,
	};

	interrupt_table__set(&kvm->interrupt_table, &intr_desc, handler->irq);
}


static void e820_setup(struct kvm *kvm) {
    struct e820map *e820;
	struct e820entry *mem_map;
	unsigned int i = 0;

    e820 = guest_flat_to_host(kvm, 0x0009fc00);
    mem_map = e820->map;

    // Storing the IVT in real mode
    mem_map[i++]	= (struct e820entry) {
		.addr		= 0x00000000,
		.size		= 0x0009fc00,
		.type		= 1,
	};

    // Traditional bottom segment memory
	mem_map[i++]	= (struct e820entry) {
		.addr		= 0x0009fc00,
		.size		= 0x00000400,
		.type		= 2,
	};

    // BIOS
	mem_map[i++]	= (struct e820entry) {
		.addr		= 0x000f0000,
		.size		= 0x0000ffff,
		.type		= 2,
	};
    
    // Extended memory - usage memory
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

    mode = guest_flat_to_host(kvm, 0x000c0010);
    mode[0] = 0x0112;
    mode[1] = 0xffff;
}

void interrupt_table__setup(struct interrupt_table *itable, struct real_intr_desc *entry) {
	unsigned int i;

	for (i = 0; i < 256; i++)
		itable->entries[i] = *entry;
}

void interrupt_table__set(struct interrupt_table *itable,
				struct real_intr_desc *entry, unsigned int num) {
	if (num < 256)
		itable->entries[num] = *entry;
}


void interrupt_table__copy(struct interrupt_table *itable, void *dst, unsigned int size)
{
	if (size < sizeof(itable->entries))
		perror("An attempt to overwrite host memory");

	memcpy(dst, itable->entries, sizeof(itable->entries));
}

void kvm__setup_bios(struct kvm *kvm) {
    unsigned long address = 0x000f0000;
    struct real_intr_desc intr_desc;
	void *p;
/*
0xFFFFFFFF  ------------------------- 4 G
           |                         |
           |          ....           |
            ------------------------- 16 G
           |                         |
           |          ....           |
  0x100000  ------------------------- 1 M
           |     ROM BIOS Sector     |
   0xF0000  -------------------------
           |    Others BIOS Sector   |
   0xE0000  -------------------------
           |   Memory of Other ROM   |   
   0xC7FFF  -------------------------       
           |      VGA ROM BIOS       |   
   0xC0000  ------------------------- 768 K
       	   |      Display Buffer     |
   0xA0000  ------------------------- 640 K
           |                         |
           |          ....           |
   0x00500  ------------------------- 
           |        BIOS Data        |
   0x00400  -------------------------   
           |            IVT          |
   0x00000  ------------------------- 0             

*/

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

    for (int i = 0; i < 2; i++)
        setup_irq_handler(kvm, &bios_irq_handlers[i]);
    
    // The IVT stores in 0 of physical address
    p = guest_flat_to_host(kvm, 0);
    interrupt_table__copy(&kvm->interrupt_table, p, 1024);
}

int kbd__init(struct kvm *kvm)
{
	int r;

	kbd_reset();
	state.kvm = kvm;
	r = kvm__register_iotrap(kvm, 0x60, 2, kbd_io, NULL, DEVICE_BUS_IOPORT);
	if (r < 0)
		return r;
	r = kvm__register_iotrap(kvm, 0x64, 2, kbd_io, NULL, DEVICE_BUS_IOPORT);
	if (r < 0) {
		kvm__deregister_iotrap(kvm, 0x60, DEVICE_BUS_IOPORT);
		return r;
	}

	return 0;
}

int handle__command(int argc, char **argv, struct kvm *kvm) {
	char *kernel = NULL;
    char *initrd = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-kernel") == 0) {
            // Check if the next argument exists
            if (i + 1 < argc) {
                kernel = argv[i + 1];
            }
        } else if (strcmp(argv[i], "-initrd") == 0) {
            // Check if the next argument exists
            if (i + 1 < argc) {
                initrd = argv[i + 1];
            }
        }
    }

	if (!kernel || !initrd) {
		printf("Please specify the files of kernel and initrd\n");
		return -1;
	}

	kvm->kernel_filename = kernel;
	kvm->initrd_filename = initrd;

	return 0;
}

int main(int argc, char **argv) {
    int ret = 0;
    struct kvm *kvm = malloc(sizeof(struct kvm));

    kvm->sys_fd = -1;
    kvm->vm_fd = -1;
    kvm->nrcpus = sysconf(_SC_NPROCESSORS_ONLN); // setup number of cpu

    kvm->sys_fd = open("/dev/kvm", O_RDONLY);
    if (kvm->sys_fd < 0) {
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

	ret = handle__command(argc, argv, kvm);
	if (ret < 0)
		goto err_sys_fd;

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
    ret = kvm__load_kernel(kvm);
    if (ret < 0)
        goto err_sys_fd;

    kvm__setup_bios(kvm);
    
    // init the kvm cpu
    ret = kvm_cpu__init(kvm);
    if (ret < 0)
    {
        perror("KVM CPU INIT");
        goto err_sys_fd;
    }

    // set the serial
    ret = serial8250__init(kvm);
    if (ret < 0) {
        perror("KVM SERIAL INIT");
        goto err_sys_fd;
    }

	// init terminal
	ret = term_init(kvm);
	if (ret < 0)
		perror("TERMINAL INIT");

	// init kbd
	ret = kbd__init(kvm);
	if (ret < 0)
		perror("KBD INIT");

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
