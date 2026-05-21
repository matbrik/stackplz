#include "types.h"
#include "common/arguments.h"
#include "common/common.h"
#include "common/consts.h"
#include "common/context.h"
#include "common/filtering.h"

#include "utils.h"

#define UPROBE_PC_INDEX 0xffffffff

SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    long ret = 0;
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    struct task_struct *parent = (struct task_struct *) ctx->args[0];
    struct task_struct *child = (struct task_struct *) ctx->args[1];

    u32 parent_ns_pid = get_task_ns_pid(parent);
    u32 parent_ns_tgid = get_task_ns_tgid(parent);
    u32 child_ns_pid = get_task_ns_pid(child);
    u32 child_ns_tgid = get_task_ns_tgid(child);

    u32* pid = bpf_map_lookup_elem(&child_parent_map, &parent_ns_pid);
    if (unlikely(pid == NULL)) return 0;

    if (*pid == parent_ns_pid){
        ret = bpf_map_update_elem(&child_parent_map, &child_ns_pid, &parent_ns_pid, BPF_ANY);
    } else {
        bpf_printk("[stack] parent pid from map:%d\n", *pid);
    }
    return 0;
}

static __always_inline int save_stack_header(event_data_t* event, u32 point_key, u64 lr, u64 sp, u64 pc)
{
    event->args[0] = 0;
    if (bpf_probe_read(&(event->args[1]), sizeof(point_key), &point_key) != 0)
        return 0;

    event->args[5] = 1;
    if (bpf_probe_read(&(event->args[6]), sizeof(lr), &lr) != 0)
        return 0;

    event->args[14] = 2;
    if (bpf_probe_read(&(event->args[15]), sizeof(sp), &sp) != 0)
        return 0;

    event->args[23] = 3;
    if (bpf_probe_read(&(event->args[24]), sizeof(pc), &pc) != 0)
        return 0;

    event->buf_off = 32;
    event->context.argnum = 4;
    return 1;
}

static __always_inline u32 probe_stack_warp(struct pt_regs* ctx, u32 point_key) {
    int zero = 0;
    program_data_t p = {};
    event_data_t* event = bpf_map_lookup_elem(&event_data_map, &zero);
    if (unlikely(event == NULL)) return 0;
    p.event = event;

    if (!init_program_data(&p, ctx)) {
        return 0;
    }

    if (!should_trace(&p))
        return 0;

    u32 filter_key = 0;
    common_filter_t* filter = bpf_map_lookup_elem(&common_filter, &filter_key);
    if (unlikely(filter == NULL)) return 0;

    u64 lr = 0;
    u64 sp = 0;
    if(filter->is_32bit) {
        bpf_probe_read_kernel(&lr, sizeof(lr), &ctx->regs[14]);
        bpf_probe_read_kernel(&sp, sizeof(sp), &ctx->regs[13]);
    }
    else {
        bpf_probe_read_kernel(&lr, sizeof(lr), &ctx->regs[30]);
        bpf_probe_read_kernel(&sp, sizeof(sp), &ctx->sp);
    }
    u64 pc = 0;
    bpf_probe_read_kernel(&pc, sizeof(pc), &ctx->pc);
    if (!save_stack_header(event, point_key, lr, sp, pc)) return 0;

    events_perf_submit(&p, UPROBE_ENTER);
    if (filter->signal > 0) {
        bpf_send_signal(filter->signal);
    }
    if (filter->tsignal > 0) {
        bpf_send_signal_thread(filter->tsignal);
    }
    return 0;
}

SEC("uprobe/stack")
int probe_stack(struct pt_regs* ctx) {
    return probe_stack_warp(ctx, UPROBE_PC_INDEX);
}
