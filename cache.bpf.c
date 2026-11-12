#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef struct {
    u32 tid;
    u64 cache_line;
} cache_key;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, cache_key);
    __type(value, u64);
} cache_line_hits SEC(".maps");

SEC("perf_event")
int on_cache_sample(struct bpf_perf_event_data *ctx) {
    __u64 addr = ctx->addr;
    if (!addr) {
        return 0;
    }

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    cache_key key = {
        .tid = tid,
        .cache_line = addr & ~0x3FULL
    };

    __u64* count = bpf_map_lookup_elem(&cache_line_hits, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&cache_line_hits, &key, &init_val, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
