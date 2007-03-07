/*
 * Imitate record/replay framework kernel module
 * mmap2 system call intercept functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include "intercept.h"
#include <asm-generic/mman.h>

#define MAP_FAILED -1

void pre_mmap2(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
{
    process_t *process = processes[current->pid];

    if ((replaying(process)) && (fd != -1))
    {
        *(&prot) |= PROT_WRITE;
        *(&flags) |= MAP_ANONYMOUS;
    }
}

void post_mmap2(long return_value, unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;

    if ((return_value != MAP_FAILED) && (fd != -1))
    {
        if (recording(process))
        {
            write_syscall_log_entry(__NR_mmap2, 0, (void*) return_value, len);
        }
        else if (replaying(process))
        {
            entry = get_next_syscall_log_entry(__NR_mmap2);
            
            if (copy_to_user((void*) return_value, &(entry->out_param), len > entry->out_param_len ? entry->out_param_len : len))
                goto copy_error;
            
            replay_void(process);
        }
    }
    
    return;
    
    copy_error:
        REPLAY_COPY_ERR(process, __NR_mmap2);
}
