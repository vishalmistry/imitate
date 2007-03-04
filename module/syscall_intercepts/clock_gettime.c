/*
 * Imitate record/replay framework kernel module
 * clock_gettime system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"

void pre_clock_gettime(clockid_t clk_id, struct timespec __user *tp)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;

    if (process->mode == MODE_REPLAY)
    {
        entry = get_next_syscall_log_entry(__NR_clock_gettime);

        if (copy_to_user(tp, (struct timespec __user*) &(entry->out_param), sizeof(struct timespec)))
            goto copy_error;

        replay_value(process, entry);
    }

    return;

    copy_error:
        REPLAY_COPY_ERR(process, __NR_clock_gettime);
}

void post_clock_gettime(long return_value, clockid_t clk_id, struct timespec __user *tp)
{
    write_syscall_log_entry(__NR_clock_gettime, return_value, (char*) tp, sizeof(struct timespec));
}
