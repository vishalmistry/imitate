/*
 * Imitate record/replay framework kernel module
 * read system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"

void pre_read(unsigned int fd, char __user *buf, size_t count)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;

    if (replaying(process))
    {
        entry = get_next_syscall_log_entry(__NR_read);
        
        if (entry->return_value > 0)
            if (copy_to_user(buf, &(entry->out_param), entry->return_value))
                goto copy_error;

        replay_value(process, entry);
    }

    return;

    copy_error:
        REPLAY_COPY_ERR(process, __NR_read);
}

void post_read(long return_value, unsigned int fd, char __user *buf, size_t count)
{
    process_t *process = processes[current->pid];

    if (recording(process))
        write_syscall_log_entry(__NR_read, return_value, buf, return_value);
}
