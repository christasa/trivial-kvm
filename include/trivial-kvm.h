#include <pthread.h>

#define KVM_API_VERSION 12
#define KVM_32BIT_MAX_MEM_SIZE (1ULL << 32)
#define KVM_32BIT_GAP_SIZE (768 << 20)
#define KVM_32BIT_GAP_START (KVM_32BIT_MAX_MEM_SIZE - KVM_32BIT_GAP_SIZE)

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

static char kern_cmdline[2048] = "noapic noacpi pci=conf1 reboot=k panic=1 i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1 earlyprintk=serial i8042.noaux=1 console=ttyS0 root=/dev/vda rw";

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

struct kvm {
    int sys_fd;      /* For system ioctls(), i.e. /dev/kvm */
    int vm_fd;       /* For VM ioctls() */

    u32 ram_slots;    /* for KVM_SET_USER_MEMORY_REGION */
    u64 ram_size;		/* Guest memory size, in bytes */
    void *ram_start;
    u64 ram_pagesize;
    pthread_mutex_t mutex;

    int nrcpus; /* Number of cpus to run */
    struct kvm_cpu **cpus;

    u32 mem_slots; /* for KVM_SET_USER_MEMORY_REGION */
    struct list_head mem_banks;
    
};

struct kvm_cpu {
	pthread_t		thread;		/* VCPU thread */

	unsigned long		cpu_id;

	struct kvm		*kvm;		/* parent KVM */
	int			vcpu_fd;	/* For VCPU ioctls() */
    struct kvm_run		*kvm_run;

};
