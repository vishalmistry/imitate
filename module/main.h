#ifndef _IMITATE_PRIVATE_H
#define _IMITATE_PRIVATE_H

#include <linux/list.h>
#include "include/imitate.h"

/*
 * Module name for logging
 */
#define MODULE_NAME "imitate"

/*
 * Character device parameters
 */
#define DEVICE_NAME     "imitate"
#define DEVICE_MINOR    0
#define DEVICE_NR_DEVS  1

/*
 * Monitored process modes
 */
#define MODE_NULL       0
#define MODE_MONITOR    1
#define MODE_RECORD     2
#define MODE_REPLAY     3

/*
 * Replay result macros
 */
#define replay_void(P)    seek_to_next_syscall_entry(); \
                          (P)->replay_syscall = 1
#define replay_value(P,X) seek_to_next_syscall_entry(); \
                          (P)->replay_syscall = 1; \
                          (P)->syscall_replay_value = (X)->return_value

/*
 * Debug message macros
 */
#ifdef DEBUG
#define DLOG(msg, args...) (printk(KERN_DEBUG MODULE_NAME " (debug): " msg "\n", ##args))
#else
#define DLOG(msg, args...) /* No Message */
#endif

#define LOG(msg, args...) (printk(KERN_INFO MODULE_NAME ": " msg "\n", ##args))
#define ERROR(msg, args...) (printk(KERN_ERR MODULE_NAME ": " msg "\n", ##args))

#define REPLAY_COPY_ERR(P,X) ERROR("Unable to copy replay data for process %d (PID %d). Call %d not replayed.", (P)->child_id, current->pid, (X))


/*
 * Type definition of a system call
 */
typedef void *syscall_t;

/*
 * "Type definition" of a post-syscall callback
 */
#define pre_syscall_callback_t void (*) (long, long, long, long, long, long)
#define post_syscall_callback_t void (*) (long, long, long, long, long, long, long)

typedef struct process process_t;
typedef struct monitor monitor_t;

/*
 * Process list struct for use with <linux/list.h>
 */
struct process_list
{
    process_t *process;
    struct list_head list;
};

/*
 * Monitor process struct
 */
struct monitor
{
    struct semaphore syscall_sem;
    struct semaphore data_available_sem;
    struct semaphore data_write_complete_sem;
    struct process_list syscall_queue;
	pid_t app_pid;
    unsigned int child_count;
    callback_t ready_data;
    unsigned int syscall_size;
    unsigned int sched_size;
    unsigned int syscall_offset;
    unsigned int sched_offset;
    char *syscall_data;
    char *sched_data;
};

/*
 * Process struct
 */
struct process
{
    pid_t pid;
    char mode;
    monitor_t *monitor;
    unsigned int child_id;

    /*
     * Storage for data between pre-/post- system call
     * handlers
     */
    unsigned short last_syscall_no;
    unsigned char replay_syscall;
    long syscall_replay_value;
};

/*
 * System call arguments struct
 */
typedef struct
{
    long arg1;
    long arg2;
    long arg3;
    long arg4;
    long arg5;
    long arg6;
} syscall_args_t;

#endif
