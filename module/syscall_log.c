/*
 * Imitate record/replay framework kernel module
 * System call log read/write functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include "syscall_log.h"

void *sclmalloc(unsigned int size)
{
    monitor_t *proc_mon = processes[current->pid]->monitor;
    void* alloced_mem = (void*) (proc_mon->syscall_data + proc_mon->syscall_offset);

    if (size > (SYSCALL_BUFFER_SIZE - proc_mon->syscall_offset))
    {
        DLOG("Log memory request: %d. Free: %d of %d bytes.", size, 
            (SYSCALL_BUFFER_SIZE - proc_mon->syscall_offset),
            SYSCALL_BUFFER_SIZE);
        LOG("Out of log memory!");
        return NULL;
    }
    
    /* Allocate */
    VVDLOG("Allocated %d bytes in system call buffer at offset %d", size, proc_mon->syscall_offset);
    proc_mon->syscall_offset += size;
    return alloced_mem;
}

void write_syscall_log_entry(unsigned short call_no, long ret_val, char *out_param, unsigned long out_param_len)
{
    process_t *process = processes[current->pid];
    monitor_t *monitor = process->monitor;
    struct semaphore *buffer_sem = &(monitor->syscall_sem);
    syscall_log_entry_t* current_data;

    /* Lock the buffer semaphore */
    VVDLOG("Attempting to acquire system call buffer semaphore");
    down(buffer_sem);
    VVDLOG("Acquired system call buffer semaphore");
    
    VVDLOG("Allocating %d bytes in system call buffer",
		(unsigned int) (sizeof(*current_data) - sizeof(current_data->out_param) + out_param_len));

    while (! (current_data = (syscall_log_entry_t*) sclmalloc(sizeof(*current_data) - sizeof(current_data->out_param) + out_param_len)))
    {
        /* If the offset was 0, then the buffer is too small */
        if (monitor->syscall_offset == 0)
        {
            ERROR("System call %d from PID %d generated more data than the size of the record buffer!", call_no, current->pid);
            ERROR("System call was _NOT_ recorded");
            goto no_mem_fail;
        }

        /* Data is not written */
        DLOG("Waiting for monitor of PID %d to complete writing to disk", current->pid);
        down(&(monitor->data_write_complete_sem));
        
        monitor->ready_data.type = SYSCALL_DATA;
        monitor->ready_data.size = monitor->syscall_offset;

        /* Data is available */
        DLOG("Sending system call data available message to monitor of PID %d", current->pid);
        up(&(monitor->data_available_sem));

        /* Wait for write to complete before trying again */
        down(&(monitor->data_write_complete_sem));
        monitor->ready_data.type = NO_DATA;
        up(&(monitor->data_available_sem));
    }

    current_data->child_id = process->child_id;
    current_data->call_no = call_no;
    current_data->return_value = ret_val;
    current_data->out_param_len = out_param_len;
    if (out_param_len != 0)
        if (copy_from_user(&(current_data->out_param), out_param, out_param_len))
        {
            ERROR("Failed to copy out parameter data for system call %d for process %d (PID: %d)",
                current_data->call_no,
                process->child_id,
                current->pid);
            ERROR("Out parameter data may be corrupted!");
        }

    VDLOG("Wrote record - child_id: %d, call_no: %d, return_value: %ld", 
        current_data->child_id, 
        current_data->call_no, 
        current_data->return_value);

    no_mem_fail:
        /* Unlock the buffer semaphore */
        VVDLOG("Releasing system call buffer semaphore");
        up(buffer_sem);
}

syscall_log_entry_t *get_next_syscall_log_entry(unsigned short call_no)
{
    process_t *process = processes[current->pid];
    monitor_t *monitor = process->monitor;
    struct semaphore *buffer_sem = &(monitor->syscall_sem);
    syscall_log_entry_t* log_entry = NULL;
    struct process_list *queue_item;

    /* Lock the buffer semaphore */
    VVDLOG("Attempting to acquire system call buffer semaphore");
    down(buffer_sem);
    VVDLOG("Acquired system call buffer semaphore");

    /* Current log entry */
    log_entry = (syscall_log_entry_t*) (monitor->syscall_data + monitor->syscall_offset);
    
    while (process->child_id != log_entry->child_id)
    {
        DLOG("System call log entry out of order. Current process: %d, expected: %d", process->child_id, log_entry->child_id);
        DLOG("Queuing and blocking process %d (PID %d)", process->child_id, process->pid);

        queue_item = (struct process_list*) kmalloc(sizeof(struct process_list), GFP_KERNEL);
        list_add_tail(&(queue_item->list), &(monitor->syscall_queue.list));

        set_current_state(TASK_UNINTERRUPTIBLE);
        VVDLOG("Releasing system call buffer semaphore");
        up(buffer_sem);
        schedule();
        
        DLOG("Blocked process %d (PID: %d) has been woken up.", process->child_id, process->pid);
        VVDLOG("Attempting to acquire system call buffer semaphore");
        down(buffer_sem);
        VVDLOG("Acquired system call buffer semaphore");
        log_entry = (syscall_log_entry_t*) (monitor->syscall_data + monitor->syscall_offset);
    }

    if (log_entry->call_no != call_no)
    {
        DLOG("Process %d (PID: %d) is expected to replay system call %d, but is actually trying to replay %d!", process->child_id, current->pid, log_entry->call_no, call_no);
        /* Kill process */
    }

    /* Unlock the buffer semaphore */
    VVDLOG("Releasing system call buffer semaphore");
    up(buffer_sem);

    return log_entry;
}

void seek_to_next_syscall_entry(void)
{
    monitor_t *monitor = processes[current->pid]->monitor;
    struct semaphore *buffer_sem = &(monitor->syscall_sem);
    syscall_log_entry_t* log_entry = NULL;
    struct list_head *pos, *tmp;
    struct process_list *item;
    unsigned long next_offset = 0;

    VVDLOG("Attempting to acquire system call buffer semaphore");
    down(buffer_sem);
    VVDLOG("Acquired system call buffer semaphore");

    /* Current log entry */
    log_entry = (syscall_log_entry_t*) (monitor->syscall_data + monitor->syscall_offset);

    /* Check limit */
    next_offset = monitor->syscall_offset +
                  sizeof(*log_entry) - 
                  sizeof(log_entry->out_param) + 
                  log_entry->out_param_len;
    if (next_offset >= monitor->syscall_size)
    {
        /* Request more data */
        DLOG("Waiting for monitor of PID %d to complete reading from disk", current->pid);

        /* Data is not read */
        down(&(monitor->data_write_complete_sem));
        
        monitor->ready_data.type = SYSCALL_DATA;
        monitor->ready_data.size = 0;

        /* Data is available */
        DLOG("Sending system call data unavailable message to monitor of PID %d", current->pid);
        up(&(monitor->data_available_sem));

        /* Wait for read to complete before trying again */
        down(&(monitor->data_write_complete_sem));
        monitor->ready_data.type = NO_DATA;
        up(&(monitor->data_available_sem));
 
        if (monitor->syscall_size == 0)
        {
            DLOG("System call log for PID %d is empty", current->pid);
            monitor->syscall_offset = 0;
            goto no_more_calls;
        }
        next_offset = 0;
    }

    /* Next log entry */
    monitor->syscall_offset = next_offset;
    log_entry = (syscall_log_entry_t*) (monitor->syscall_data + next_offset);

    VDLOG("Next system call entry - child_id: %d, call_no: %d, return_value: %ld", 
        log_entry->child_id, 
        log_entry->call_no, 
        log_entry->return_value);

    /* Wake next process on queue if ID matches */
    list_for_each_safe(pos, tmp, &(monitor->syscall_queue.list))
    {
        item = list_entry(pos, struct process_list, list);
        if (item->process->child_id == log_entry->child_id)
        {
            DLOG("Waking up previously blocked process %d (PID: %d)", item->process->child_id, item->process->pid);
            wake_up_process(find_task_by_pid(item->process->pid));
            list_del(pos);
            kfree(item);
            break;
        }
    }

    no_more_calls:
    /* Unlock the buffer semaphore */
    VVDLOG("Releasing system call buffer semaphore");
    up(buffer_sem);
}
