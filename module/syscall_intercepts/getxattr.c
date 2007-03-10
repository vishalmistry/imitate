/*
 * Imitate record/replay framework kernel module
 * getxattr system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"

void pre_getxattr(syscall_args_t *args)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;
    
    void *value = (void*) args->arg3;

    if (replaying(process))
    {
        entry = get_next_syscall_log_entry(__NR_getxattr);

        if (entry->return_value > 0)
            if (copy_to_user(value, &(entry->out_param), entry->return_value))
                goto copy_error;

        replay_value(process, entry);
    }

    return;

    copy_error:
        REPLAY_COPY_ERR(process, __NR_getxattr);
}

void post_getxattr(long *return_value, syscall_args_t *args)
{
    process_t *process = processes[current->pid];

    void *value = (void*) args->arg3;

    if (recording(process))
        write_syscall_log_entry(__NR_getxattr, *return_value, (char*) value, *return_value > 0 ? *return_value : 0);
}
