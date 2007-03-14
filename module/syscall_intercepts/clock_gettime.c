/*
 * Imitate record/replay framework kernel module
 * clock_gettime system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"

void pre_clock_gettime(syscall_args_t *args)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;
    
    struct timespec __user *tp = (struct timespec __user *) args->arg2;

    if (replaying(process))
    {
        VDLOG("Replaying clock_gettime() for process %d (PID: %d)", process->child_id, process->pid);
        entry = get_next_syscall_log_entry(__NR_clock_gettime);

        if (entry->return_value == 0)
            if (copy_to_user(tp, (struct timespec __user*) &(entry->out_param), sizeof(struct timespec)))
                goto copy_error;

        replay_value(process, entry);
    }

    return;

    copy_error:
        REPLAY_COPY_ERR(process, __NR_clock_gettime);
}

void post_clock_gettime(long *return_value, syscall_args_t *args)
{
    process_t *process = processes[current->pid];

    struct timespec __user *tp = (struct timespec __user *) args->arg2;

    if (recording(process))
        write_syscall_log_entry(__NR_clock_gettime, *return_value, (char*) tp, *return_value == 0 ? sizeof(struct timespec) : 0);
}
