#include <iostream>
#include <linux/types.h>
#include "sched.skel.h"

int main() {
    struct sched_bpf *skel;
    int err = 0;

    // Open eBPF program
    skel = sched_bpf__open();
    if (!skel) {
        return 1;
    }

    // Load and verify eBPF program into kernel
    err = sched_bpf__load(skel);
    if (err) {
        goto cleanup;
    }

    // Attach the eBPF program to the things it needs
    err = sched_bpf__attach(skel);
    if (err) {
        goto cleanup;
    }

    // Setting the CPU and slice dynamically
    while (true) {
        std::cout << "Target CPU   : ";
        std::cin >> skel->data->target_cpu;
        std::cout << "\n";

        std::cout << "Slice (in ns): ";
        std::cin >> skel->bss->slice;
        std::cout << "\n";

        if (skel->bss->slice == 111) {
            break;
        }
    }

cleanup:
    sched_bpf__destroy(skel);
    return err;
}

