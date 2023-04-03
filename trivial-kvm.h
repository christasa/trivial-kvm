#include <pthread.h>

#define KVM_API_VERSION 12
#define KVM_32BIT_MAX_MEM_SIZE (1ULL << 32)
#define KVM_32BIT_GAP_SIZE (768 << 20)
#define KVM_32BIT_GAP_START (KVM_32BIT_MAX_MEM_SIZE - KVM_32BIT_GAP_SIZE)


typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;


struct kvm {
    int sys_fd;      /* For system ioctls(), i.e. /dev/kvm */
    int vm_fd;       /* For VM ioctls() */

    u32 ram_slots;    /* for KVM_SET_USER_MEMORY_REGION */
    u64 ram_size;		/* Guest memory size, in bytes */

    int nrcpus; /* Number of cpus to run */
    struct kvm_cpu **cpus;

    u32 mem_slots; /* for KVM_SET_USER_MEMORY_REGION */
    void *ram_start;


};

struct kvm_cpu {
	pthread_t		thread;		/* VCPU thread */

	unsigned long		cpu_id;

	struct kvm		*kvm;		/* parent KVM */
	int			vcpu_fd;	/* For VCPU ioctls() */
    struct kvm_run		*kvm_run;

};

