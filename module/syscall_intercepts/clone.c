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
    syscall_log_entry_t *entry;
    process_t *new_proc = (process_t*) kmalloc(sizeof(process_t), GFP_KERNEL);

    // unsigned long clone_flags = args->arg1;

    new_proc->pid = *return_value;
    new_proc->mode = process->mode;
    new_proc->monitor = process->monitor;
    new_proc->child_id = ++(process->monitor->child_count);

    processes[*return_value] = new_proc;

    DLOG("clone() complete - child_id: %d, PID: %d", new_proc->child_id, new_proc->pid);

    if (recording(process))
    {
        /* Let it run */
        write_syscall_log_entry(__NR_clone, new_proc->child_id, NULL, 0);
    }
    else if (replaying(process))
    {
        entry = get_next_syscall_log_entry(__NR_clone);

        if (entry->return_value != new_proc->child_id)
            DLOG("clone() system call: log file indicates child %ld being created, but child %d was created instead.", entry->return_value, new_proc->child_id);

        replay_void(process);

        /* TODO */
    }
}
