#ifndef _IMITATE_PRIVATE_H
#define _IMITATE_PRIVATE_H

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
#define MODE_RECORD     1
#define MODE_REPLAY     2
#define MODE_MONITOR    3

/*
 * record
 */
#define on_record		if (processes[current->pid] != NULL && processes[current->pid]->mode == MODE_RECORD)
#define on_replay		if (processes[current->pid] != NULL && processes[current->pid]->mode == MODE_REPLAY)

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


/*
 * Type definition of a system call
 */
typedef void *syscall_t;

/*
 * Monitor process struct
 */
typedef struct
{
    struct semaphore syscall_sem;
    struct semaphore data_available_sem;
    struct semaphore data_write_complete_sem;
	pid_t app_pid;
    callback_t ready_data;
    unsigned int syscall_offset;
    unsigned int sched_offset;
    char *syscall_data;
    char *sched_data;
    
} monitor_t;

/*
 * Process struct
 */
typedef struct
{
    pid_t pid;
    char mode;
    monitor_t *monitor;
    long pre_syscall_ret;
    unsigned long syscall_ret_addr;
} process_t;

/*
 * System call arguments struct
 */
typedef struct
{
    int arg1;
    int arg2;
    int arg3;
    int arg4;
    int arg5;
} syscall_args_t;

#endif
