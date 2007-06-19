/*
 * Imitate record/replay framework kernel module
 * Copyright (c) 2007, Vishal Mistry
 */

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
 * BLock types
 */
#define BLOCK_NONE              0   /* Not blocked */
#define BLOCK_CLONE             1   /* Blocked in clone, send SIGCONT to wake */
#define BLOCK_INTERRUPTIBLE     2   /* Blocked from scheduler, use wake */
#define BLOCK_SEMAPHORE         3   /* Blocked on semaphore, use up() */

/*
 * Context switch point
 */
#define SWITCH_NONE     0
#define SWITCH_SYSCALL  1
#define SWITCH_BPOINT   2

/*
 * mmap() selection
 */
#define MAP_SYSCALL_BUFFER  0
#define MAP_SCHED_BUFFER    1

/*
 * System call exit point
 */
#define SYSCALL_EXIT_POINT 0xFFFFE410

/*
 * Debug message macros
 */
#if DEBUG > 0
#define DLOG(msg, args...) (printk(KERN_DEBUG MODULE_NAME " (debug): " msg "\n", ##args))
#else
#define DLOG(msg, args...) /* No Message */
#endif

#if DEBUG > 1
#define VDLOG(msg, args...) DLOG(msg, ##args)
#else
#define VDLOG(msg, args...) /* No Message */
#endif

#if DEBUG > 2
#define VVDLOG(msg, args...) DLOG(msg, ##args)
#else
#define VVDLOG(msg, args...) /* No Message */
#endif

#define LOG(msg, args...) (printk(KERN_INFO MODULE_NAME ": " msg "\n", ##args))
#define ERROR(msg, args...) (printk(KERN_ERR MODULE_NAME ": " msg "\n", ##args))

/*
 * Type definition of a system call
 */
typedef void *syscall_t;

/*
 * "Type definition" of a post-syscall callback
 */
#define pre_syscall_callback_t void (*) (syscall_args_t*)
#define post_syscall_callback_t void (*) (long*, syscall_args_t*)

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
    struct process_list app_processes;
    char   mmap_select;
    unsigned int child_count;
    struct task_struct *last_running_thread;
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
    sched_counter_t sched_counter;  /* This MUST be first element in struct, otherwise mmap() will result in random behaviour */
    sched_counter_t *sched_counter_addr;
    char   mmap_counter;
    pid_t pid;
    char mode;
    monitor_t *monitor;
    unsigned int child_id;
    char block_type;
    unsigned long bpoint_addr;
    char bpoint_byte;

    struct semaphore syscall_lock_sem;
    char block_syscall;

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

/*
 * Process list
 */
extern process_t *processes[PID_MAX_LIMIT];

#endif
