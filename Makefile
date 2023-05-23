CC := gcc

CFLAGS := -w -pthread

OBJ += trivial-kvm.c

INCLUDE := include

PROGRAM := tkvm

all: $(PROGRAM)

$(PROGRAM): $(OBJ)
	$(CC) -I$(INCLUDE) $(CFLAGS) $^ -o $@

.PHONY: clean
clean:
	rm -f $(PROGRAM)
