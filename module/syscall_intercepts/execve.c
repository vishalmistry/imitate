/*
 * Imitate record/replay framework kernel module
 * execve system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"

void pre_execve(syscall_args_t *args)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;
    
    VVDLOG("execve() entered");

    if (replaying(process))
    {
        entry = get_next_syscall_log_entry(__NR_execve);
            
        /* Only replay if there was an error during record */
        if (entry->return_value < 0)
        {
            VDLOG("Replaying execve() for process %d (PID: %d)", process->child_id, process->pid);
            replay_value(process, entry);
        }
        else
            cancel_replay(process);
    }

    return;
}

void post_execve(long *return_value, syscall_args_t *args)
{
    process_t *process = processes[current->pid];
    monitor_t *monitor = process->monitor;
    
    VVDLOG("execve() returned");

    if (*return_value >= 0)
    {
        VDLOG("Notifying user space of COUNTER_PATCH");

        /* Patch process image */
        down(&(monitor->data_write_complete_sem));
        monitor->ready_data.type = COUNTER_PATCH;
        monitor->ready_data.size = 0;
        up(&(monitor->data_available_sem));

        /* Wait for write to complete before trying again */
        down(&(monitor->data_write_complete_sem));
        monitor->ready_data.type = NO_DATA;
        up(&(monitor->data_available_sem));
    }

    if (recording(process))
    {
        write_syscall_log_entry(__NR_execve, *return_value, NULL, 0);
    }
}
