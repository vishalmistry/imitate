/*
 * Imitate record/replay framework kernel module
 * fstat64 system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"

void pre_fstat64(syscall_args_t *args)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;

    struct stat64 __user *statbuf = (struct stat64 __user *) args->arg2;

    if (replaying(process))
    {
        entry = get_next_syscall_log_entry(__NR_fstat64);

        if (entry->return_value == 0)
            if (copy_to_user(statbuf, (struct stat64 __user*) &(entry->out_param), sizeof(struct stat64)))
                goto copy_error;

        replay_value(process, entry);
    }
    
    return;

    copy_error:
        REPLAY_COPY_ERR(process, __NR_fstat64);
}

void post_fstat64(long *return_value, syscall_args_t *args)
{
    process_t *process = processes[current->pid];

    struct stat64 __user *statbuf = (struct stat64 __user *) args->arg2;

    if (recording(process))
        write_syscall_log_entry(__NR_fstat64, *return_value, (char*) statbuf, *return_value == 0 ? sizeof(struct stat64) : 0);
}
