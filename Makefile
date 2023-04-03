CC := gcc
CFLAGS := -w -pthread

OBJ += trivial-kvm.c
OBJ += trivial-kvm.h

PROGRAM := tkvm

all: $(PROGRAM)

$(PROGRAM): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@

.PHONY: clean
clean:
	rm -f $(PROGRAM)
