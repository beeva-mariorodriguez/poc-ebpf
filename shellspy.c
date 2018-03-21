/*
 * spy.c
 */

// https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#7-bpf_get_current_task
// #defines needed for linux 4.13
#define randomized_struct_fields_start  struct {
#define randomized_struct_fields_end    };

#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h> 
#include <linux/sched.h>

// Creates a buffer for pushing out event data to user space
BPF_PERF_OUTPUT(events);

// the struct we will be pushing to user space via events
enum event_type {
    OPEN,
    EXEC,
    CLONE,
};

struct event_t {
    enum event_type type;
    char fname[NAME_MAX];
    u32 pid;
    u32 ppid;
};


/*
 * trace open files
 * man 2 open:
 *  int open(const char *pathname, int flags);
 *  int open(const char *pathname, int flags, mode_t mode);
 *  int creat(const char *pathname, mode_t mode);
 *  int openat(int dirfd, const char *pathname, int flags);
 *  int openat(int dirfd, const char *pathname, int flags, mode_t mode);
 * 5 different syscalls ($LINUX_SOURCES/fs/open.c)
 * all call do_sys_open()!
 * ./include/linux/fs.h
 *  extern long do_sys_open(int dfd, const char __user *filename, int flags,
 *                          umode_t mode);
 * trace common point: do_sys_open()
*/
int kprobe__do_sys_open(struct pt_regs *ctx, int dfd, const char __user *filename)
{
    u64 id;
    u32 pid, ppid;
    struct task_struct *task = NULL;
    struct event_t event = {};

    // get in kernel process identificator (thread group id + process id)
    // userspace PID == kernel TGID
    // userspace TID == kernel PID
    // linux is hard
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    // get task_struct
    // lots of info (including a link to the parent's task_struct
    // defined in $LINUX_SOURCES/include/linux/sched.h
    task = (struct task_struct *)bpf_get_current_task();
    if (!task){
        return 0;
    }

    // ignore kernel tasks
    if (task->flags & PF_KTHREAD)
        return 0;

    // task->real_parent is the task_struct for the parent process
    ppid = task->real_parent->pid;
 
    // placeholder for a user defined filter
    // spoiler: it's the target's pid
    FILTER

    // populate event
    event.type =  OPEN;
    event.pid = pid;
    event.ppid = ppid;
    // *filename is a pointer to a string containing the filename
    // we can't (directly) read kernel memory
    // bpf_probe_read() macro will (safely) copy it for us
    bpf_probe_read(&event.fname, sizeof(event.fname), (void *)filename);
    // event ready, submit
    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_fork)
{
    // args from /sys/kernel/debug/tracing/events/sched/sched_process_fork/format
	// field:char parent_comm[16];     offset:8;       size:16;        signed:1;
	// field:pid_t parent_pid; offset:24;      size:4; signed:1;
	// field:char child_comm[16];      offset:28;      size:16;        signed:1;
	// field:pid_t child_pid;  offset:44;      size:4; signed:1;
    u32 pid = args->parent_pid;
	u32 ppid;
    struct task_struct *task = NULL;
    task = (struct task_struct *)bpf_get_current_task();
    if (!task){
        return 0;
    }
    if (task->flags & PF_KTHREAD)
        return 0;
    ppid = task->real_parent->pid;

    FILTER

	struct event_t event = {};

    event.type = CLONE;
    event.pid = pid;
    event.ppid = ppid;
    events.perf_submit(args, &event, sizeof(event));

    return 0;
}

// man 2 execve
TRACEPOINT_PROBE(sched, sched_process_exec)
{
    u64 id;
    u32 pid = args->pid;
    u32 ppid;

    struct task_struct *task = NULL;
    struct event_t event = {};
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    if (!task){
        return 0;
    }
    if (task->flags & PF_KTHREAD)
        return 0;
    ppid = task->real_parent->pid;

    FILTER

    event.type = EXEC;
    event.pid = pid;
    event.ppid = ppid;
    TP_DATA_LOC_READ_CONST(event.fname, filename, NAME_MAX)

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
