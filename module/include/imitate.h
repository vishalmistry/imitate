#ifndef _IMITATE_H
#define _IMITATE_H

#include <linux/ioctl.h>

/* Magic number for ioct() command code generation */
#define IMITATE_IOC_MAGIC 0xE0

/* Maximum command number */
#define IMITATE_IOC_MAXNR 6

/*
 * ioctl() commands
 */

/* Notify driver to reset data structures for calling monitor
   and associated child - not implemented */
#define IMITATE_RESET _IO(IMITATE_IOC_MAGIC, 0)
/* Notify driver that the caller is the application monitor */
#define IMITATE_MONITOR _IO(IMITATE_IOC_MAGIC, 1)
/* Notify driver that the caller is child that is being recorded 
   with monitor in _arg_ */
#define IMITATE_APP_RECORD _IOW(IMITATE_IOC_MAGIC, 2, pid_t)
/* Notify driver that the caller is child that is being replayed
   with monitor in _arg_ */
#define IMITATE_APP_REPLAY _IOW(IMITATE_IOC_MAGIC, 3, pid_t)
/* Notify driver of callback on monitor to request/remove data
   from mmap'ed buffer */
#define IMITATE_MONITOR_CB _IOR(IMITATE_IOC_MAGIC, 4, callback_t)
/* Notify driver of initial buffer sizes during replay */
#define IMITATE_PREP_REPLAY _IOR(IMITATE_IOC_MAGIC, 5, prep_replay_t)
/* Notify driver of the schedule counter address */
#define IMITATE_NOTIFY_SCHED_COUNTER _IOR(IMITATE_IOC_MAGIC, 6, unsigned long*)

#define NO_DATA         0x0
#define SYSCALL_DATA    0x1
#define SCHED_DATA      0x2
#define APP_EXIT        0x4
#define APP_KILLED      0x8
#define COUNTER_PATCH   0x10

/*
 * Buffer size of syscall storage (10 MB)
 */
#define SYSCALL_BUFFER_SIZE 10485760
//#define SYSCALL_BUFFER_SIZE 16384

/*
 * Buffer size of schedule storage 128K
 */
#define SCHED_BUFFER_SIZE 131072

typedef struct
{
    int type;
    int size;
} callback_t;

typedef struct
{
    int syscall_size;
    int sched_size;
} prep_replay_t;

/*
 * System call log entry
 */
typedef struct
{
    unsigned int child_id;
    unsigned short call_no;
    long return_value;
    unsigned long out_param_len;
    char out_param;
} __attribute__((packed)) syscall_log_entry_t;

/*
 * Schedule log entry
 */
typedef struct
{
    unsigned int child_id;
    unsigned long counter;
    unsigned long ip;
} __attribute__((packed)) sched_log_entry_t;

#endif
