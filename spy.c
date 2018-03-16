// https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#7-bpf_get_current_task
// #defines needed for linux 4.13
#define randomized_struct_fields_start  struct {
#define randomized_struct_fields_end    };

#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h> 
#include <linux/sched.h>

struct event_t {
    char fname[NAME_MAX];
    u32 pid;
    u32 ppid;
};

BPF_PERF_OUTPUT(events);

int trace_open(struct pt_regs *ctx, int dfd, const char __user *filename)
{
    u32 pid, ppid;
    struct task_struct *task = NULL;
    struct event_t event = {};


    pid = bpf_get_current_pid_tgid();
    task = (struct task_struct *)bpf_get_current_task();
    if (!task){
        return 0;
    }

    if (task->flags & PF_KTHREAD)
        return 0;

    ppid = task->real_parent->pid;
 
    FILTER

    event.pid = pid;
    event.ppid = ppid;
    bpf_probe_read(&event.fname, sizeof(event.fname), (void *)filename);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

