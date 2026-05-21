#include "types.h"
#include "common/arguments.h"
#include "common/common.h"
#include "common/consts.h"
#include "common/context.h"
#include "common/filtering.h"

#include "utils.h"

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
    point_args_t* point_args = bpf_map_lookup_elem(&uprobe_point_args, &point_key);
    if (unlikely(point_args == NULL)) return 0;

    u32 filter_key = 0;
    common_filter_t* filter = bpf_map_lookup_elem(&common_filter, &filter_key);
    if (unlikely(filter == NULL)) return 0;

    ctx_regs_t saved_regs = {};
    for (int i = 0; i < 31; i++) {
        saved_regs.regs[i] = READ_KERN(ctx->regs[i]);
    }
    saved_regs.sp = READ_KERN(ctx->sp);
    saved_regs.pc = READ_KERN(ctx->pc);

    if (point_args->enter_key == 0) {
        /* pass */
    } else if (point_args->enter_key == point_key + 1) {
        // 保存寄存器
        save_regs(&saved_regs, UPROBE_ENTER + point_key + 1);
    } else {
        // 加载寄存器
        if (load_regs(&saved_regs, UPROBE_ENTER + point_args->enter_key) != 0) {
            return 0;
        }
        // 清理map中的寄存器
        del_regs(UPROBE_ENTER + point_args->enter_key);
    }

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

    int ctx_index = 0;
    op_ctx_t* op_ctx = bpf_map_lookup_elem(&op_ctx_map, &ctx_index);
    if (unlikely(op_ctx == NULL)) return 0;
    __builtin_memset((void *)op_ctx, 0, sizeof(op_ctx));

    op_ctx->reg_0 = saved_regs.regs[0];
    op_ctx->save_index = 4;
    op_ctx->op_key_index = 0;

    read_args(&p, point_args, op_ctx, &saved_regs);

    if (op_ctx->skip_flag) {
        op_ctx->skip_flag = 0;
        return 0;
    }

    events_perf_submit(&p, UPROBE_ENTER);
    if (filter->signal > 0) {
        bpf_send_signal(filter->signal);
    }
    if (filter->tsignal > 0) {
        bpf_send_signal_thread(filter->tsignal);
    }
    if (point_args->signal > 0) {
        bpf_send_signal_thread(point_args->signal);
    }
    return 0;
}

#define PROBE_STACK(name)                          \
    SEC("uprobe/stack_" #name)                     \
    int probe_stack_##name(struct pt_regs* ctx)    \
    {                                              \
        u32 point_key = name;                       \
        return probe_stack_warp(ctx, point_key);    \
    }

#include "uprobe_probes.h"
