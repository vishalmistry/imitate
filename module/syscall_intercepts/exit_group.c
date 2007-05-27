/*
 * Imitate record/replay framework kernel module
 * exit_group system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"

extern long get_user_mode_instruction_pointer(struct task_struct *task);
void* slmalloc(monitor_t *monitor, unsigned int size);

void pre_exit_group(syscall_args_t *args)
{
    process_t *process = processes[current->pid];
    monitor_t *monitor = process->monitor;
    syscall_log_entry_t *entry;
    sched_log_entry_t *sched_entry;
/*    struct list_head *pos, *tmp;
    struct process_list *item; */

    int error_code = (int) args->arg1;

    if (recording(process))
    {
        write_syscall_log_entry(__NR_exit_group, error_code, NULL, 0);

        /* Write final log entry... to keep track of what last thread was */
        sched_entry = slmalloc(process->monitor, sizeof(*sched_entry));
        if (! sched_entry)
        {
            ERROR("Out of schedule memory for final schedule entry. Not writing.");
        }
        else
        {
            sched_entry->child_id = process->child_id;
            sched_entry->counter = *(process->sched_counter_addr);
            sched_entry->ip = get_user_mode_instruction_pointer(current);
        }

        /* Last process */
        if (process->child_id == 1)
        {
            /* Force monitor to write system call data */
            down(&(monitor->data_write_complete_sem));
            monitor->ready_data.type = SYSCALL_DATA;
            monitor->ready_data.size = monitor->syscall_offset;
            up(&(monitor->data_available_sem));

            /* Force monitor to write schedule data */
            down(&(monitor->data_write_complete_sem));
            monitor->ready_data.type = SCHED_DATA;
            monitor->ready_data.size = monitor->sched_offset;
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
