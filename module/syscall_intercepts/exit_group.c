/*
 * Imitate record/replay framework kernel module
 * exit_group system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"

void pre_exit_group(syscall_args_t *args)
{
    process_t *process = processes[current->pid];
    monitor_t *monitor = process->monitor;
    syscall_log_entry_t *entry;
    struct list_head *pos, *tmp;
    struct process_list *item;

    int error_code = (int) args->arg1;

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
        VDLOG("Replaying exit_group() for process %d (PID: %d)", process->child_id, process->pid);
        entry = get_next_syscall_log_entry(__NR_exit_group);

        /* error_code */ args->arg1 = (int) entry->return_value;

        /* Wake other threads to prevent D-state processes
        list_for_each_safe(pos, tmp, &(monitor->syscall_queue.list))
        {
            item = list_entry(pos, struct process_list, list);
            find_task_by_pid(item->process->pid)->state = TASK_INTERRUPTIBLE;
            list_del(pos);
            kfree(item);
        }
        */
    }

    /* Tell monitor that proc has exited */
    down(&(monitor->data_write_complete_sem));
    monitor->ready_data.type = APP_EXIT;
    up(&(monitor->data_available_sem));
}
