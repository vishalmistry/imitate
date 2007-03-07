/*
 * Imitate record/replay framework kernel module
 * open system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"

void pre_open(const char __user *filename, int flags, int mode)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;

    if (replaying(process))
    {
        entry = get_next_syscall_log_entry(__NR_open);
        replay_value(process, entry);
    }

    return;
}

void post_open(long return_value, const char __user *filename, int flags, int mode)
{
    process_t *process = processes[current->pid];

    if (recording(process))
        write_syscall_log_entry(__NR_open, return_value, NULL, 0);
}
