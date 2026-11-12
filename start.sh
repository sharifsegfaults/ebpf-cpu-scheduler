#!/bin/sh

PROG=${1:-sched}

make
sudo ./stop.sh

# Register scheduler
sudo bpftool struct_ops register $PROG.bpf.o /sys/fs/bpf/sched_ext || (echo "ERROR")

# Print scheduler to see if it's been successfully mounted
cat /sys/kernel/sched_ext/root/ops
