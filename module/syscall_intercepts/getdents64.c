/*
 * Imitate record/replay framework kernel module
 * getdents64 system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"

void pre_getdents64(syscall_args_t *args)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;
    
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *) args->arg2;

    if (replaying(process))
    {
        entry = get_next_syscall_log_entry(__NR_getdents64);

        if (entry->return_value > 0)
            if (copy_to_user(dirent, (struct linux_dirent64 __user*) &(entry->out_param), entry->return_value))
                goto copy_error;

        replay_value(process, entry);
    }

    return;

    copy_error:
        REPLAY_COPY_ERR(process, __NR_getdents64);
}

void post_getdents64(long *return_value, syscall_args_t *args)
{
    process_t *process = processes[current->pid];

    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *) args->arg2;

    if (recording(process))
        write_syscall_log_entry(__NR_getdents64, *return_value, (char*) dirent, *return_value > 0 ? *return_value : 0);
}
