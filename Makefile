NORM_CC = g++
NORM_CFLAGS = -Wall -g -O2 -I.

EBPF_CC = clang
EBPF_CFLAGS = -Wall -g -O2 -I.

all: sched progA progB

sched: sched.bpf.c
	$(EBPF_CC) -target bpf $(EBPF_CFLAGS) -c sched.bpf.c -o sched.bpf.o

cache: cache.bpf.c
	$(EBPF_CC) -target bpf $(EBPF_CFLAGS) -c cache.bpf.c -o cache.bpf.o

prog%: prog%.cpp
	$(NORM_CC) $(NORM_CFLAGS) $@.cpp -o $@
