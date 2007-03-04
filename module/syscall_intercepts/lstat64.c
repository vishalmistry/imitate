/*
 * Imitate record/replay framework kernel module
 * lstat64 system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"

void pre_lstat64(char __user *filename, struct stat64 __user *statbuf)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;

    if (process->mode == MODE_REPLAY)
    {
        entry = get_next_syscall_log_entry(__NR_lstat64);

        if (entry->return_value == 0)
            if (copy_to_user(statbuf, (struct stat64 __user*) &(entry->out_param), sizeof(struct stat64)))
                goto copy_error;

        replay_value(process, entry);
    }

    return;

    copy_error:
        REPLAY_COPY_ERR(process, __NR_lstat64);
}

void post_lstat64(long return_value, char __user *filename, struct stat64 __user *statbuf)
{
    write_syscall_log_entry(__NR_lstat64, return_value, (char*) statbuf, return_value == 0 ? sizeof(struct stat64) : 0);
}