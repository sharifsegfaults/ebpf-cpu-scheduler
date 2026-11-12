#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SHARED_DSQ_ID 0

#define BPF_STRUCT_OPS(name, args...) \
    SEC("struct_ops/"#name) BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
    SEC("struct_ops.s/"#name)                   \
    BPF_PROG(name, ##args)

s32 BPF_STRUCT_OPS_SLEEPABLE(sched_init) {
    return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
}

s32 BPF_STRUCT_OPS(select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags) {
    s32 target_cpu = 8;
    u64 slice = 5000000000u;

    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);
    return target_cpu;
}

void BPF_STRUCT_OPS(sched_enqueue, struct task_struct *p, u64 enq_flags) {
    u64 num_tasks_enqueued = scx_bpf_dsq_nr_queued(SHARED_DSQ_ID);
    u64 slice = 5000000000u;
    scx_bpf_dsq_insert(p, SHARED_DSQ_ID, slice, enq_flags);
}

void BPF_STRUCT_OPS(sched_dispatch, s32 cpu, struct task_struct *prev) {
    scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
}

SEC(".struct_ops.link")
struct sched_ext_ops sched_ops = {
    .select_cpu = (void*)select_cpu,

    .enqueue = (void*)sched_enqueue,
    .dispatch = (void*) sched_dispatch,
    .init = (void*) sched_init,

    .flags = SCX_OPS_KEEP_BUILTIN_IDLE,

    .name = "minimal_scheduler"
};

char _license[] SEC("license") = "GPL";
