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
    u32 pid, ppid;
    struct task_struct *task = NULL;
    struct event_t event = {};

    // get in kernel process identificator (thread group id + process id)
    // userspace PID == kernel TGID
    // userspace TID == kernel PID
    // linux is hard
    // cast 64 bit tgid+pid to u32 variable to get the tgid
    pid = (u32) bpf_get_current_pid_tgid();
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

// man 2 execve
int kprobe__sys_execve(struct pt_regs *ctx,
                       const char __user *filename,
                       const char __user *const __user *__argv,
                       const char __user *const __user *__envp)
{
    u32 pid, ppid;
    struct task_struct *task = NULL;
    struct event_t event = {};
    pid = (u32) bpf_get_current_pid_tgid();
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
    bpf_probe_read(&event.fname, sizeof(event.fname), (void *)filename);

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
