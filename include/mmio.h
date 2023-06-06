#include "types.h"
#include "rbtree.h"

#define RB_ROOT	{ NULL, }
#define RB_INT_INIT(l, h) \
	(struct rb_int_node){.low = l, .high = h}
#define rb_int(n)	rb_entry(n, struct rb_int_node, node)
#define rb_int_start(n)	((n)->low)
#define rb_int_end(n)	((n)->low + (n)->high - 1)
#define mmio_node(n) rb_entry(n, struct mmio_mapping, node)

typedef void (*mmio_handler_fn)(struct kvm_cpu *vcpu, u64 addr, u8 *data,
				u32 len, u8 is_write, void *ptr);

pthread_mutex_t mmio_lock;

struct rb_int_node {
	struct rb_node	node;
	u64		low;
	u64		high;
};

static struct rb_root pio_tree = RB_ROOT;

struct mmio_mapping {
	struct rb_int_node	node;
	mmio_handler_fn		mmio_fn;
	void			*ptr;
	u32			refcount;
	int			remove;
};
