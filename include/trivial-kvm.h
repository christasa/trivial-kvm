#include "types.h"

#include <linux/kvm.h>

#define KVM_API_VERSION 12
#define KVM_32BIT_MAX_MEM_SIZE (1ULL << 32)
#define KVM_32BIT_GAP_SIZE (768 << 20)
#define KVM_32BIT_GAP_START (KVM_32BIT_MAX_MEM_SIZE - KVM_32BIT_GAP_SIZE)

#define BIOS_IRQ_PA_ADDR(name)	(0x000f0000 + BIOS_OFFSET__##name)
#define BIOS_IRQ_FUNC(name)	((char *)&bios_rom[BIOS_OFFSET__##name])
#define BIOS_IRQ_SIZE(name)	(BIOS_ENTRY_SIZE(BIOS_OFFSET__##name))

#define DEFINE_BIOS_IRQ_HANDLER(_irq, _handler)			\
    {							\
        .irq		= _irq,				\
        .address	= BIOS_IRQ_PA_ADDR(_handler),	\
        .handler	= BIOS_IRQ_FUNC(_handler),	\
        .size		= BIOS_IRQ_SIZE(_handler),	\
    }

static char kern_cmdline[2048] = "noapic noacpi pci=conf1 reboot=k panic=1 i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1 earlyprintk=serial i8042.noaux=1 console=ttyS0 root=/dev/vda rw ";

#ifndef BIOS_EXPORT_H_
#define BIOS_EXPORT_H_

extern char bios_rom[0];
extern char bios_rom_end[0];

#define bios_rom_size		(bios_rom_end - bios_rom)

#endif /* BIOS_EXPORT_H_ */

static inline void kvm__set_thread_name(const char *name) {
    prctl(15, name);
}

void kvm__arch_read_term(struct kvm *kvm) {
    serial8250__update_consoles(kvm);
}


struct list_head {
    struct list_head *next, *prev;
};

struct kvm_mem_bank {
    struct list_head	list;
    u64			guest_phys_addr;
    void			*host_addr;
    u64			size;
    u32			slot;
};

struct real_intr_desc {
    u16 offset;
    u16 segment;
} __attribute__((packed));

struct e820entry {
    u64 addr;     /* start of memory segment */
    u64 size;     /* size of memory segment */
    u32 type;     /* type of memory segment */
} __attribute__((packed));

struct e820map {
    u32 nr_map;
        struct e820entry map[128];
};

struct irq_handler {
    unsigned long		address;
    unsigned int		irq;
    void			*handler;
    size_t			size;
};

struct interrupt_table {
    struct real_intr_desc entries[256];
};

struct kvm {
    int sys_fd;      /* For system ioctls(), i.e. /dev/kvm */
    int vm_fd;       /* For VM ioctls() */
    char *kernel_filename;    /* Filename of kernel**/
    char *initrd_filename;

    u32 ram_slots;    /* for KVM_SET_USER_MEMORY_REGION */
    u64 ram_size;		/* Guest memory size, in bytes */
    void *ram_start;
    u64 ram_pagesize;
    pthread_mutex_t mutex;

    int nrcpus; /* Number of cpus to run */
    struct kvm_cpu **cpus;

    u32 mem_slots; /* for KVM_SET_USER_MEMORY_REGION */
    struct list_head mem_banks;

    struct interrupt_table	interrupt_table;
    
};

struct kvm_cpu {
    pthread_t		thread;		/* VCPU thread */

    unsigned long		cpu_id;

    struct kvm		*kvm;		/* parent KVM */
    int			vcpu_fd;	/* For VCPU ioctls() */
    struct kvm_run		*kvm_run;

    struct kvm_regs  regs;
    struct kvm_sregs sregs;

};

static struct irq_handler bios_irq_handlers[] = {
    DEFINE_BIOS_IRQ_HANDLER(0x10, bios_int10),
    DEFINE_BIOS_IRQ_HANDLER(0x15, bios_int15),
};