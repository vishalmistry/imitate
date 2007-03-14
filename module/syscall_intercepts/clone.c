/*
 * Imitate record/replay framework kernel module
 * clone system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"

void pre_clone(syscall_args_t *args)
{
    /* Immediately stop the process once it is cloned */
    /* clone_flags */ //args->arg1 |= CLONE_STOPPED;
}

void post_clone(long *return_value, syscall_args_t *args)
{
    process_t *process = processes[current->pid];
    monitor_t *monitor = process->monitor;
    syscall_log_entry_t *entry;
    struct process_list* pl_item;

    // unsigned long clone_flags = args->arg1;

    process_t *new_proc = (process_t*) kmalloc(sizeof(process_t), GFP_KERNEL);
    if (! new_proc)
    {
        ERROR("Could not allocate process data during clone() for process %d (PID %d)", process->child_id, process->pid);
        goto proc_malloc_fail;
    }

    new_proc->pid = *return_value;
    new_proc->mode = process->mode;
    new_proc->monitor = process->monitor;
    new_proc->child_id = ++(process->monitor->child_count);

    pl_item = (struct process_list*) kmalloc(sizeof(struct process_list), GFP_KERNEL);
    if (! pl_item)
    {
        ERROR("Could not allocate process list item during clone() for process %d (PID %d)", process->child_id, process->pid);
        goto plitem_malloc_fail;
    }
    pl_item->process = new_proc;
    list_add_tail(&(pl_item->list), &(monitor->app_processes.list));

    processes[*return_value] = new_proc;

    DLOG("clone() complete - child_id: %d, PID: %d", new_proc->child_id, new_proc->pid);

    if (recording(process))
    {
        /* Let it run */
        write_syscall_log_entry(__NR_clone, new_proc->child_id, NULL, 0);
    }
    else if (replaying(process))
    {
        VDLOG("Replaying clone() for process %d (PID: %d)", process->child_id, process->pid);
        entry = get_next_syscall_log_entry(__NR_clone);

        if (entry->return_value != new_proc->child_id)
            DLOG("clone() system call: log file indicates child %ld being created, but child %d was created instead.",
                entry->return_value, new_proc->child_id);

        replay_void(process);

        /* TODO */
    }

    return;

    plitem_malloc_fail:
        kfree(process);
    proc_malloc_fail:
        ERROR("Process will be killed.");

        /* Notify monitor of kill */
        down(&(monitor->data_write_complete_sem));
        monitor->ready_data.type = APP_KILLED;
        up(&(monitor->data_available_sem));

        /* Kill process */
        kill_proc(current->pid, SIGSYS, 1);
}
