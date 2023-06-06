CC := gcc

CFLAGS := -w -pthread

OBJS += rbtree.o
OBJS += bios-rom.o

INCLUDE := include

PROGRAM := tkvm

all: $(PROGRAM)

$(PROGRAM): trivial-kvm.c
	$(CC) -I$(INCLUDE) $(CFLAGS) $^ $(OBJS) -o $@

.PHONY: clean
clean:
	rm -f $(PROGRAM)
