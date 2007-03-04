/*
 * Imitate record/replay framework kernel module
 * Copyright (c) 2007, Vishal Mistry
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include "main.h"

/*
 * Module information
 */
MODULE_AUTHOR("Vishal Mistry <vishal@digitalsilver.org>");
MODULE_DESCRIPTION("Kernel portion of the Imitate record/replay framework");
MODULE_LICENSE("GPL");

/*
 * System call intercept from architecture dependent function
 */
extern void syscall_intercept(void);

/*
 * System call table and the backup
 */
syscall_t original_sys_call_table[NR_syscalls];
static syscall_t *sys_call_table = (syscall_t*) SYS_CALL_TABLE_ADDR;
void* pre_syscall_callbacks[NR_syscalls];
void* post_syscall_callbacks[NR_syscalls];

/*
 * Process list
 */
static process_t *processes[PID_MAX_LIMIT];
static unsigned long syscall_return_addresses[PID_MAX_LIMIT];

/*
 * Character device
 */
static struct cdev cdev;

/*
 * Character device operations
 */
static int cdev_open(struct inode *inode, struct file *filp);
static int cdev_release(struct inode *inode, struct file *filp);
static ssize_t cdev_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset);
static int cdev_mmap(struct file *filp, struct vm_area_struct *vma);
static int cdev_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg);
static struct file_operations fops =
{
    .owner   = THIS_MODULE,
    .open    = cdev_open,
    .release = cdev_release,
    .read    = cdev_read,
    .mmap    = cdev_mmap,
    .ioctl   = cdev_ioctl
};

/*
 * Memory map operations
 */
static struct page *vma_syscall_nopage(struct vm_area_struct *vma, unsigned long address, int *type);
static struct vm_operations_struct vm_syscall_ops =
{
    .nopage  = vma_syscall_nopage
};

/*
 * Register module parameters
 */
static ushort dev_major = 0;
module_param(dev_major, ushort, 0000);
MODULE_PARM_DESC(dev_major, "Device major number for the " MODULE_NAME " character device");

/*
 * General Prototypes
 */
asmlinkage long *pre_syscall_callback(long syscall_no,
                                      unsigned long syscall_return_addr,
                                      syscall_args_t syscall_args);
asmlinkage unsigned long post_syscall_callback(long syscall_return_value, 
                                               unsigned long syscall_return_addr, 
                                               syscall_args_t syscall_args);
void write_syscall_log_entry(unsigned short call_no, 
                             long ret_val, 
                             char *out_param, 
                             unsigned long out_param_len);
syscall_log_entry_t *get_next_syscall_log_entry(unsigned short call_no);
void seek_to_next_syscall_entry(void);


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

void pre_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;

    if (process->mode == MODE_REPLAY)
    {
        entry = get_next_syscall_log_entry(__NR_getdents64);

        if (entry->return_value > 0)
            if (copy_to_user(dirent, (struct linux_dirent64 __user*) &(entry->out_param), entry->return_value))
                goto copy_error;

        replay_value(process, entry);
    }

    return;

    copy_error:
        REPLAY_COPY_ERR(process, __NR_getdents64);
}

void post_getdents64(long return_value, unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
    write_syscall_log_entry(__NR_getdents64, return_value, (char*) dirent, return_value > 0 ? return_value : 0);
}

void pre_fstat64(unsigned long fd, struct stat64 __user *statbuf)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;

    if (process->mode == MODE_REPLAY)
    {
        entry = get_next_syscall_log_entry(__NR_fstat64);

        if (entry->return_value == 0)
            if (copy_to_user(statbuf, (struct stat64 __user*) &(entry->out_param), sizeof(struct stat64)))
                goto copy_error;

        replay_value(process, entry);
    }
    
    return;

    copy_error:
        REPLAY_COPY_ERR(process, __NR_fstat64);
}

void post_fstat64(long return_value, unsigned long fd, struct stat64 __user *statbuf)
{
    write_syscall_log_entry(__NR_fstat64, return_value, (char*) statbuf, return_value == 0 ? sizeof(struct stat64) : 0);
}

void pre_lstat64(char __user *filename, struct stat64 __user *statbuf)
{
    process_t *process = processes[current->pid];
    syscall_log_entry_t *entry;

    if (process->mode == MODE_REPLAY)
    {
        entry = get_next_syscall_log_entry(__NR_lstat64);

        if (entry->return_value == 0)
            if (copy_to_user(statbuf, (struct stat64 __user*) &(entry->out_param), sizeof(struct stat64)))
                goto copy_error;

        replay_value(process, entry);
    }

    return;

    copy_error:
        REPLAY_COPY_ERR(process, __NR_lstat64);
}

void post_lstat64(long return_value, char __user *filename, struct stat64 __user *statbuf)
{
    write_syscall_log_entry(__NR_lstat64, return_value, (char*) statbuf, return_value == 0 ? sizeof(struct stat64) : 0);
}

void pre_exit_group(int error_code)
{
    process_t *process = processes[current->pid];
    monitor_t *monitor = process->monitor;
    syscall_log_entry_t *entry;

    if (process->mode == MODE_RECORD)
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
    else if (process->mode == MODE_REPLAY)
    {
        entry = get_next_syscall_log_entry(__NR_exit_group);
        *(&error_code) = entry->return_value;
    }

    /* Tell monitor that proc has exited */
    down(&(monitor->data_write_complete_sem));
    monitor->ready_data.type = APP_EXIT;
    up(&(monitor->data_available_sem));
}

asmlinkage void empty_callback(void)
{
}

/*
 * Module function prototypes
 */
static int  __init kmod_init(void);
static void __exit kmod_exit(void);

/*
 * Module initialisation function
 */
static int __init kmod_init(void)
{
    int result, i;
    dev_t dev;

    DLOG("Loading " MODULE_NAME " kernel module");

    DLOG("SYS_CALL_TABLE_ADDR = %x", SYS_CALL_TABLE_ADDR);
    DLOG("SYS_EXIT = %x", (int) sys_call_table[__NR_exit]);

    /* Register character device */
    if (dev_major)
    {
        dev = MKDEV(dev_major, DEVICE_MINOR);
        DLOG("Registering user supplied character device region with major number %d", dev_major);
        result = register_chrdev_region(dev, DEVICE_NR_DEVS, DEVICE_NAME);
    }
    else
    {
        DLOG("Dynamically allocating character device region");
        result = alloc_chrdev_region(&dev, DEVICE_MINOR, DEVICE_NR_DEVS, DEVICE_NAME);
        dev_major = MAJOR(dev);
    }
    if (result < 0)
    {
        ERROR("Error reserving major number for device");
        return result;
    }

    DLOG("Reserved major number %d for device", MAJOR(dev));

    /* Save current system call handlers */
    DLOG("Saving system call table");
    for (i = 0; i < NR_syscalls; i++)
    {
        original_sys_call_table[i] = sys_call_table[i];
        pre_syscall_callbacks[i] = empty_callback;
        post_syscall_callbacks[i] = empty_callback;
    }

    /* Hook the system call intercepts */
    DLOG("Attaching system call intercepts");
    sys_call_table[__NR_exit] = syscall_intercept;
    sys_call_table[__NR_exit_group] = syscall_intercept;
    sys_call_table[__NR_clock_gettime] = syscall_intercept;
    sys_call_table[__NR_getdents64] = syscall_intercept;
    sys_call_table[__NR_fstat64] = syscall_intercept;
    sys_call_table[__NR_lstat64] = syscall_intercept;

    pre_syscall_callbacks[__NR_exit_group] = pre_exit_group;
    pre_syscall_callbacks[__NR_clock_gettime] = pre_clock_gettime;
    pre_syscall_callbacks[__NR_getdents64] = pre_getdents64;
    pre_syscall_callbacks[__NR_fstat64] = pre_fstat64;
    pre_syscall_callbacks[__NR_lstat64] = pre_lstat64;
    
    post_syscall_callbacks[__NR_clock_gettime] = post_clock_gettime;
    post_syscall_callbacks[__NR_getdents64] = post_getdents64;
    post_syscall_callbacks[__NR_fstat64] = post_fstat64;
    post_syscall_callbacks[__NR_lstat64] = post_lstat64;


    /* Set up the character device */
    DLOG("Registering character device");
    cdev_init(&cdev, &fops);
    cdev.owner = THIS_MODULE;
    cdev.ops = &fops;
    result = cdev_add(&cdev, dev, 1);
    if (result < 0)
    {
        ERROR("Error registering character device");
        goto cdev_add_fail;
    }

    /* Reset processes */
    DLOG("Initialising process state array, PID_MAX_LIMIT = %lu", PID_MAX_LIMIT);
    for (i = 0; i < PID_MAX_LIMIT; i++)
    {
        processes[i] = NULL;
    }

    LOG("Loaded " MODULE_NAME " kernel module");

    return 0;

    /* Handle failures */
    cdev_add_fail:
        /* Free character device */
        DLOG("(error cleanup) Freeing character device region");
        kobject_put(&cdev.kobj);

        /* Restore original system call table */
        DLOG("(error cleanup) Restoring original system call table");
        for (i = 0; i < NR_syscalls; i++)
        {
            sys_call_table[i] = original_sys_call_table[i];
        }
        
        /* Unregister major number */
        DLOG("(error cleanup) Releasing character device region");
        unregister_chrdev_region(dev, DEVICE_NR_DEVS);

        return result;
}

/*
 * Module clean-up function
 */
static void __exit kmod_exit(void)
{
    int i;
    dev_t dev = MKDEV(dev_major, DEVICE_MINOR);

    DLOG("Unloading " MODULE_NAME " module");

    /* Clean up memory (just in case anything is left over) */
    for (i = 0; i < PID_MAX_LIMIT; i++)
    {
        if (processes[i] != NULL)
        {
            if (processes[i]->mode == MODE_MONITOR)
            {
                DLOG("Freeing monitor state for PID %d", i);
                if (processes[i]->monitor->syscall_data != NULL)
                {
                    DLOG("Freeing system call buffer data");
                    vfree(processes[i]->monitor->syscall_data);
                }
                kfree(processes[i]->monitor);
            }
            DLOG("Freeing process state for PID %d", i);
            kfree(processes[i]);
        }
    }

    /* Unregister character device */
    DLOG("Unregistering character device - major: %d, minor: %d", MAJOR(dev), MINOR(dev));
    cdev_del(&cdev);
    
    /* Restore original system call table */
    DLOG("Restoring original system call table");
    for (i = 0; i < NR_syscalls; i++)
    {
        sys_call_table[i] = original_sys_call_table[i];
    }

    /* Unregister major number */
    DLOG("Unregistering character device region");
    unregister_chrdev_region(dev, DEVICE_NR_DEVS);
    
    LOG("Unloaded " MODULE_NAME " module");
}

/*
 * Module function registrations
 */
module_init(kmod_init);
module_exit(kmod_exit);

/*
 * Device operations
 */
static int cdev_open(struct inode *inode, struct file *filp)
{
    DLOG("Device open");
    return 0;
}

static int cdev_release(struct inode *inode, struct file *filp)
{	
	process_t *process = processes[current->pid];
	monitor_t *monitor;

	DLOG("Device close");

	if (process != NULL && process->mode == MODE_MONITOR)
	{
		monitor = process->monitor;
		if (monitor->app_pid != 0 && processes[monitor->app_pid] != NULL)
		{
			DLOG("Freeing process state for application PID %d", monitor->app_pid);
			kfree(processes[monitor->app_pid]);
			processes[monitor->app_pid] = NULL;
		}

		DLOG("Freeing system call buffer data for monitor PID %d", current->pid);
		vfree(monitor->syscall_data);
		monitor->syscall_data = NULL;
		
    	DLOG("Freeing monitor state for PID %d", current->pid);
		kfree(monitor);
		process->monitor = NULL;
		
		DLOG("Freeing process state for monitor PID %d", current->pid);
		kfree(process);
		processes[current->pid] = NULL;
		
		return 0;
	}
	else
	{
	    return -EFAULT;
	}
}

static ssize_t cdev_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
    DLOG("Device read");
    return 0;
}

static int cdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
    process_t *process = processes[current->pid];
    if (process != NULL && process->mode == MODE_MONITOR)
    {
        DLOG("Memory mapping system call data buffer to user space");
        vma->vm_flags |= VM_RESERVED;
        vma->vm_ops = &vm_syscall_ops;
        return 0;
    }
    else
    {
        return -ENODEV;
    }
}

static int cdev_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
{
    int result = 0;
    process_t *process;
    monitor_t *monitor;
    prep_replay_t prepdata;
    
    /* Verify cmd is valid */
    if (_IOC_TYPE(cmd) != IMITATE_IOC_MAGIC) return -ENOTTY;
    if (_IOC_NR(cmd) > IMITATE_IOC_MAXNR) return -ENOTTY;

    /* Perform cmd */
    switch(cmd)
    {
        case IMITATE_RESET:
            DLOG("IMITATE_RESET received from PID %d", current->pid);
            break;

        case IMITATE_MONITOR:
            DLOG("Process %d assigned as a monitor. Waiting for application.", current->pid);

            process = (process_t*) kmalloc(sizeof(process_t), GFP_KERNEL);
			if (! process)
			{
				result = -ENOMEM;
				goto allocproc_fail; /* break; */
			}
			
            monitor = (monitor_t*) kmalloc(sizeof(monitor_t), GFP_KERNEL);
			if (! monitor)
			{
				result = -ENOMEM;
				goto allocmon_fail;
			}

            process->mode = MODE_MONITOR;
            process->pid  = current->pid;
            process->monitor = monitor;

            monitor->syscall_data = (char*) vmalloc(SYSCALL_BUFFER_SIZE);
			if (! (monitor->syscall_data))
			{
				result = -ENOMEM;
				goto allocsyscallbuf_fail;
			}

            /* TODO: Allocate schedule data */

			monitor->app_pid = 0;
            monitor->child_count = 0;
            monitor->syscall_size = 0;
            monitor->sched_size = 0;
            monitor->syscall_offset = 0;
            monitor->sched_offset = 0;
            monitor->ready_data.type = NO_DATA;

            INIT_LIST_HEAD(&(monitor->syscall_queue.list));

            sema_init(&(monitor->syscall_sem), 1);
            sema_init(&(monitor->data_available_sem), 0);
            sema_init(&(monitor->data_write_complete_sem), 0);

            processes[current->pid] = process;
            break;

        case IMITATE_APP_RECORD:
            DLOG("Process %d being recorded by monitor process %d", current->pid, (pid_t) arg);

            process = (process_t*) kmalloc(sizeof(process_t), GFP_KERNEL);
			if (! process)
			{
				result = -ENOMEM;
				goto allocproc_fail; /* break; */
			}
			
            process->pid = current->pid;
            process->mode = MODE_RECORD;
            process->monitor = processes[(pid_t) arg]->monitor;
            process->child_id = ++(process->monitor->child_count);
            process->monitor->app_pid = current->pid;
            processes[current->pid] = process;
            break;

        case IMITATE_APP_REPLAY:
            DLOG("Process %d being replayed by monitor %d", current->pid, (pid_t) arg);

            process = (process_t*) kmalloc(sizeof(process_t), GFP_KERNEL);
			if (! process)
			{
				result = -ENOMEM;
				goto allocproc_fail; /* break; */
			}

            process->pid = current->pid;
            process->mode = MODE_REPLAY;
            process->monitor = processes[(pid_t) arg]->monitor;
            process->child_id = ++(process->monitor->child_count);
            process->monitor->app_pid = current->pid;
            processes[current->pid] = process;
            break;

        case IMITATE_MONITOR_CB:
            process = processes[current->pid];
            if (process == NULL || process->mode != MODE_MONITOR)
            {
                return -EFAULT;
            }
            
            /*
             * Buffer was written/read, proceed with more logging/replaying
             */
            switch(process->monitor->ready_data.type)
            {
                case SYSCALL_DATA:
                    DLOG("Resetting system call buffer offset for monitor %d", current->pid);
                    if (copy_from_user(&(process->monitor->ready_data), (void __user*) arg, sizeof(process->monitor->ready_data)))
                    {
                        ERROR("CRITICAL: Failed to copy callback data from monitor with PID %d. Resetting", current->pid);
                        process->monitor->ready_data.size = 0;
                    }
                    process->monitor->syscall_size = process->monitor->ready_data.size;
                    process->monitor->syscall_offset = 0;
                    break;
                case SCHED_DATA:
                    DLOG("Resetting scheduler buffer offset for monitor %d", current->pid);
                    if (copy_from_user(&(process->monitor->ready_data), (void __user*) arg, sizeof(process->monitor->ready_data)))
                    {
                        ERROR("CRITICAL: Failed to copy callback data from monitor with PID %d. Resetting", current->pid);
                        process->monitor->ready_data.size = 0;
                    }
                    process->monitor->sched_size = process->monitor->ready_data.size;
                    process->monitor->sched_offset = 0;
                    break;
            }
            DLOG("Releasing data write complete lock for monitor %d", current->pid);
            up(&(process->monitor->data_write_complete_sem));

            /*
             * Block if there is not enough data.
             * The semaphore will be incremented by write_syscall_log_entry()
             * and write_thread_sched_log_entry() when enough data becomes
             * available
             */
            DLOG("Waiting for data to become available for monitor %d", current->pid);
            down(&(process->monitor->data_available_sem));

            if (copy_to_user((void __user*) arg, &(process->monitor->ready_data), sizeof(process->monitor->ready_data)))
            {
                ERROR("CRITICAL: Failed to copy callback data to monitor with PID %d. Cannot recover!", current->pid);
            }
            break;

        case IMITATE_PREP_REPLAY:
            process = processes[current->pid];
            if (copy_from_user(&prepdata, (void __user*) arg, sizeof(prepdata)))
            {
                ERROR("CRITICAL: Failed to copy replay preparation data from monitor with PID %d. Cannot recover!", current->pid);
                prepdata.syscall_size = 0;
                prepdata.sched_size = 0;
            }
            process->monitor->syscall_size = prepdata.syscall_size;
            process->monitor->sched_size = prepdata.sched_size;
            break;
    }

	allocproc_fail:
    return result;

	allocsyscallbuf_fail:
		kfree(monitor);
	allocmon_fail:
		kfree(process);
	return result;	
}

/*
 * System call map-on-page fault
 */
static struct page *vma_syscall_nopage(struct vm_area_struct *vma, unsigned long address, int *type)
{
    unsigned long offset;
    struct page *page = NOPAGE_SIGBUS;
    char *syscall_data = processes[current->pid]->monitor->syscall_data;
    
    offset = (address - vma->vm_start) + (vma->vm_pgoff << PAGE_SHIFT);
    DLOG("Mapping offset: %ld", offset);

    if (offset > SYSCALL_BUFFER_SIZE)
        goto out;

    page = vmalloc_to_page(syscall_data + offset);
    get_page(page);
    if (type)
        *type = VM_FAULT_MINOR;

    out:
        return page;
}

/*
 * System call pre-/post- callback handlers
 */
asmlinkage long *pre_syscall_callback(long syscall_no, unsigned long syscall_return_addr, syscall_args_t syscall_args)
{
    process_t *process = processes[current->pid];

    /* Store return address to be restored after post-syscall callback */
    syscall_return_addresses[current->pid] = syscall_return_addr;
    
    /* Process is not being monitored. */
    if (process == NULL)
    {
        return NULL;
    }
    
    /* Process is being monitored */
    if (process->mode >= MODE_RECORD)
    {
        process->replay_syscall = 0;
        ((pre_syscall_callback_t) pre_syscall_callbacks[syscall_no])(
            syscall_args.arg1,
            syscall_args.arg2,
            syscall_args.arg3,
            syscall_args.arg4,
            syscall_args.arg5,
            syscall_args.arg6);
    }

    switch (process->mode)
    {
        /* Application being recorded */
        case MODE_RECORD:
            process->last_syscall_no = (unsigned short) syscall_no;
            break;

        /* Application being replayed */
        case MODE_REPLAY:
            if (process->replay_syscall)
            {
                return &(process->syscall_replay_value);
            }
            break;
    }

    return NULL;
}

asmlinkage unsigned long post_syscall_callback(long syscall_return_value, unsigned long syscall_return_addr, syscall_args_t syscall_args)
{
    process_t *process = processes[current->pid];

    if(process != NULL && process->mode == MODE_RECORD)
    {
        ((post_syscall_callback_t) post_syscall_callbacks[process->last_syscall_no])(
            syscall_return_value,
            syscall_args.arg1,
            syscall_args.arg2,
            syscall_args.arg3,
            syscall_args.arg4,
            syscall_args.arg5,
            syscall_args.arg6);
    }

    return syscall_return_addresses[current->pid];
}

/*
 * Helper functions
 */
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
    DLOG("Allocated %d bytes at offset %d", size, proc_mon->syscall_offset);
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
    down(buffer_sem);
    
    DLOG("Allocating %d bytes in System call buffer",
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

    DLOG("Wrote record - child_id: %d, call_no: %d, return_value: %ld", 
        current_data->child_id, 
        current_data->call_no, 
        current_data->return_value);
    
    no_mem_fail:
        /* Unlock the buffer semaphore */
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
    down(buffer_sem);

    /* Current log entry */
    log_entry = (syscall_log_entry_t*) (monitor->syscall_data + monitor->syscall_offset);
    
    while (process->child_id != log_entry->child_id)
    {
        DLOG("System call log entry out of order. Current process: %d, expected: %d", process->child_id, log_entry->child_id);
        DLOG("Queuing and blocking process %d (PID %d)", process->child_id, process->pid);

        queue_item = (struct process_list*) kmalloc(sizeof(struct process_list), GFP_KERNEL);
        list_add_tail(&(queue_item->list), &(monitor->syscall_queue.list));

        set_current_state(TASK_UNINTERRUPTIBLE);
        up(buffer_sem);
        schedule();
        
        DLOG("Blocked process %d (PID: %d) has been woken up.", process->child_id, process->pid);
        down(buffer_sem);
        log_entry = (syscall_log_entry_t*) (monitor->syscall_data + monitor->syscall_offset);
    }

    if (log_entry->call_no != call_no)
    {
        /* Kill process */
    }

    /* Unlock the buffer semaphore */
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

    down(buffer_sem);

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
    DLOG("Next system call log entry - child_id: %d, call_no: %d, return_value: %ld", log_entry->child_id, log_entry->call_no, log_entry->return_value);

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
    up(buffer_sem);
}
