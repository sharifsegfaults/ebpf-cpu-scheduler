#include <iostream>
#include "cache.skel.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <csignal>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>

struct cache_key {
    __u32 tid;
    __u64 cache_line;
};

static volatile bool exiting = false;
static void sig_handler(int sig) {
    exiting = true;
}

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int main() {
    cache_bpf* skel;
    int num_cpus = libbpf_num_possible_cpus();
    int* perf_fds = (int*)calloc(num_cpus, sizeof(int));
    bpf_link** links = (bpf_link**)calloc(num_cpus, sizeof(bpf_link*));
    pid_t target_tid;

    std::cout << "TID to target: ";
    std::cin >> target_tid;
    std::cout << "\n";

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = cache_bpf__open_and_load();
    if (!skel) {
        return 1;
    }

    // Hardware PMU event
    perf_event_attr attr = {
        .type = PERF_TYPE_RAW,
        .size = sizeof(attr),
        .config = 0x81D0,
        .sample_period = 10000,
        .sample_type = PERF_SAMPLE_ADDR,
        .exclude_kernel = 1,
        .precise_ip = 2,
    };

    perf_fds[0] = perf_event_open(&attr, target_tid, 8, -1, 0);
    if (perf_fds[0] < 0) {
        perror("perf_event_opened");
        return 1;
    }

    links[0] = bpf_program__attach_perf_event(skel->progs.on_cache_sample, perf_fds[0]);
    if (!links[0]) {
        perror("attach_perf_event");
        return 1;
    }

    std::cout << "Loading the eBPF program succeeded! Sampling cache line accesses for TID " << target_tid << "..." << "\n";
    while (!exiting) {
        sleep(1);
    }

    // On program end
    printf("\n%-10s %-18s %-10s\n", "TID", "CACHE_LINE_ADDR", "SAMPLES");
    cache_key lookup_key = {};
    cache_key next_key;
    __u64 count = 0;
    int map_fd = bpf_map__fd(skel->maps.cache_line_hits);

    while (bpf_map_get_next_key(map_fd, &lookup_key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &count) == 0) {
            printf("%-10u 0x%016llx %-10llu\n", next_key.tid, next_key.cache_line, count);
        }
        lookup_key = next_key;
    }

cleanup:
    if (links[0]) bpf_link__destroy(links[0]);
    if (perf_fds[0] > 0) close(perf_fds[0]);

    cache_bpf__destroy(skel);
    free(links);
    free(perf_fds);
    return 0;
}
