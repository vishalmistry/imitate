/*
 * Imitate record/replay framework kernel module
 * open system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"

void pre_open(syscall_args_t *args)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;

    if (replaying(process))
    {
        VDLOG("Replaying open() for process %d (PID: %d)", process->child_id, process->pid);
        entry = get_next_syscall_log_entry(__NR_open);

        replay_value(process, entry);
    }

    return;
}

void post_open(long *return_value, syscall_args_t *args)
{
    process_t *process = processes[current->pid];

    if (recording(process))
        write_syscall_log_entry(__NR_open, *return_value, NULL, 0);
}
