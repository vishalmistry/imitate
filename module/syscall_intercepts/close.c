/*
 * Imitate record/replay framework kernel module
 * close system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"

void pre_close(syscall_args_t *args)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;

    if (replaying(process))
    {
        entry = get_next_syscall_log_entry(__NR_close);
        replay_value(process, entry);
    }

    return;
}

void post_close(long *return_value, syscall_args_t *args)
{
    process_t *process = processes[current->pid];

    if (recording(process))
        write_syscall_log_entry(__NR_close, *return_value, NULL, 0);
}
