/*
 * Imitate record/replay framework kernel module
 * exit_group system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"

void pre_exit_group(int error_code)
{
    process_t *process = processes[current->pid];
    monitor_t *monitor = process->monitor;
    syscall_log_entry_t *entry;

    if (recording(process))
    {
        write_syscall_log_entry(__NR_exit_group, error_code, NULL, 0);

        /* Last process */
        if (process->child_id == 1)
        {
            /* Force monitor to write system call data */
            down(&(monitor->data_write_complete_sem));
            monitor->ready_data.type = SYSCALL_DATA;
            monitor->ready_data.size = monitor->syscall_offset;
            up(&(monitor->data_available_sem));
        }
    }
    else if (replaying(process))
    {
        entry = get_next_syscall_log_entry(__NR_exit_group);
        *(&error_code) = entry->return_value;
    }

    /* Tell monitor that proc has exited */
    down(&(monitor->data_write_complete_sem));
    monitor->ready_data.type = APP_EXIT;
    up(&(monitor->data_available_sem));
}
