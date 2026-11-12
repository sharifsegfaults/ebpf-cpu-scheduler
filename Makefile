NORM_CC = g++
NORM_CFLAGS = -Wall -g -O2 -I.

EBPF_CC = clang
EBPF_CFLAGS = -Wall -g -O2 -I.

USPACE_CC = g++
USPACE_CFLAGS = -O2 -lbpf -lelf -lz

all: sched progA progB

sched: sched.bpf.c
	$(EBPF_CC) -target bpf $(EBPF_CFLAGS) -c sched.bpf.c -o sched.bpf.o

cache: cache.bpf.c
	$(EBPF_CC) -target bpf $(EBPF_CFLAGS) -c cache.bpf.c -o cache.bpf.o

uspace_%: uspace_%.cpp %.bpf.c
	bpftool gen skeleton $*.bpf.o > $*.skel.h
	$(USPACE_CC) $(USPACE_CFLAGS) uspace_$*.cpp -o uspace_$*

prog%: prog%.cpp
	$(NORM_CC) $(NORM_CFLAGS) $@.cpp -o $@
