/*
 * Imitate record/replay framework kernel module
 * mmap2 system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"
#include <asm-generic/mman.h>

#define MAP_FAILED -1

void pre_mmap2(syscall_args_t *args)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;

    unsigned long fd = args->arg5;
    
    if (process && !process->mmap_counter) return;

    if ((replaying(process)) && (fd != -1))
    {
        entry = get_next_syscall_log_entry(__NR_mmap2);
        /* start */ args->arg1 = entry->return_value;
        /* prot */ args->arg3 |= PROT_WRITE;
        /* flags */ args->arg4 |= MAP_ANONYMOUS;
    }
}

void post_mmap2(long *return_value, syscall_args_t *args)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;
    unsigned long ncopycount;

    unsigned long len = args->arg2;
    unsigned long fd = args->arg5;

    if (process && !process->mmap_counter)
    {
        process->mmap_counter = 1;
        return;
    }

    if ((*return_value != MAP_FAILED) && (fd != -1))
    {
        if (recording(process))
        {
            write_syscall_log_entry(__NR_mmap2, *return_value, (char*) (*return_value), len);
        }
        else if (replaying(process))
        {
            VDLOG("Replaying mmap2() for process %d (PID: %d)", process->child_id, process->pid);
            entry = get_next_syscall_log_entry(__NR_mmap2);

            if ((ncopycount = copy_to_user((void*) (*return_value), &(entry->out_param), len > entry->out_param_len ? entry->out_param_len : len)))
                DLOG("Replaying mmap(): Failed to copy %ld of %ld bytes back to user space.", ncopycount, len > entry->out_param_len ? entry->out_param_len : len);
            
            replay_void(process);
        }
    }
}
