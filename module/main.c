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
#include <asm/uaccess.h>
#include <linux/mm.h>
#include <linux/io.h>
#include "syscall_intercepts/intercepts.h"
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
 * Architecture dependent instruction pointer
 */
extern long get_user_mode_instruction_pointer(struct task_struct *task);

/* 
 * Context switch hook function
 */
extern void set_context_switch_hook(void (*csh)(struct task_struct*, struct task_struct*));

/*
 * System call table and the backup
 */
syscall_t original_sys_call_table[NR_syscalls];
static syscall_t *sys_call_table;
void* pre_syscall_callbacks[NR_syscalls];
void* post_syscall_callbacks[NR_syscalls];

/*
 * Process list
 */
process_t *processes[PID_MAX_LIMIT];

/*
 * Stored return addresses
 */
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

static long sys_call_table_addr = 0;
module_param(sys_call_table_addr, long, 0000);
MODULE_PARM_DESC(sys_call_table_addr, "Address of system call table. Use /proc/kallsyms or System.map to obtain this value. THIS VALUE MUST BE CORRECT AS THIS MODULE WILL OVERWRITE MEMORY AT THIS ADDRESS! Supplying incorrect address will cause a system crash.");


/*
 * Pre-/Post- System call callback prototypes
 */
asmlinkage long *pre_syscall_callback(long syscall_no, unsigned long syscall_return_addr, syscall_args_t syscall_args);
asmlinkage unsigned long post_syscall_callback(long syscall_return_value, unsigned long syscall_return_addr, syscall_args_t syscall_args);


/*
 * Context-switch hook prototype
 */
void context_switch_hook(struct task_struct *prev, struct task_struct *next);

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

    if (!sys_call_table_addr)
    {
        ERROR("System call table address parameter (sys_call_table_addr) not specified. Aborting module load.");
        return -EINVAL;
    }

    sys_call_table = (syscall_t*) sys_call_table_addr;

    DLOG("sys_call_table_addr = %lx", sys_call_table_addr);
    DLOG("sys_exit = %lx", (long) sys_call_table[__NR_exit]);

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
    sys_call_table[__NR_open] = syscall_intercept;
    sys_call_table[__NR_read] = syscall_intercept;
    sys_call_table[__NR_close] = syscall_intercept;
    sys_call_table[__NR_mmap2] = syscall_intercept;
    sys_call_table[__NR_exit_group] = syscall_intercept;
    sys_call_table[__NR_clock_gettime] = syscall_intercept;
    sys_call_table[__NR_getdents64] = syscall_intercept;
    sys_call_table[__NR_fstat64] = syscall_intercept;
    sys_call_table[__NR_lstat64] = syscall_intercept;
    sys_call_table[__NR_getxattr] = syscall_intercept;
    sys_call_table[__NR_clone] = syscall_intercept;

    pre_syscall_callbacks[__NR_open] = pre_open;
    pre_syscall_callbacks[__NR_read] = pre_read;
    pre_syscall_callbacks[__NR_close] = pre_close;
    pre_syscall_callbacks[__NR_mmap2] = pre_mmap2;
    pre_syscall_callbacks[__NR_exit_group] = pre_exit_group;
    pre_syscall_callbacks[__NR_clock_gettime] = pre_clock_gettime;
    pre_syscall_callbacks[__NR_getdents64] = pre_getdents64;
    pre_syscall_callbacks[__NR_fstat64] = pre_fstat64;
    pre_syscall_callbacks[__NR_lstat64] = pre_lstat64;
    pre_syscall_callbacks[__NR_getxattr] = pre_getxattr;
    pre_syscall_callbacks[__NR_clone] = pre_clone;
    
    post_syscall_callbacks[__NR_open] = post_open;
    post_syscall_callbacks[__NR_read] = post_read;
    post_syscall_callbacks[__NR_close] = post_close;
    post_syscall_callbacks[__NR_mmap2] = post_mmap2;
    post_syscall_callbacks[__NR_clock_gettime] = post_clock_gettime;
    post_syscall_callbacks[__NR_getdents64] = post_getdents64;
    post_syscall_callbacks[__NR_fstat64] = post_fstat64;
    post_syscall_callbacks[__NR_lstat64] = post_lstat64;
    post_syscall_callbacks[__NR_getxattr] = post_getxattr;
    post_syscall_callbacks[__NR_clone] = post_clone;

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

    /* Set up context switch hook */
    DLOG("Installing context switch hook");
    set_context_switch_hook(context_switch_hook);

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

    set_context_switch_hook(NULL);

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
    struct list_head *pos, *tmp;
    struct process_list *item;
    struct task_struct *task;
    struct page *page, *pstart, *pend;

    DLOG("Device close");

    if (process != NULL && process->mode == MODE_MONITOR)
    {
        monitor = process->monitor;

        list_for_each_safe(pos, tmp, &(monitor->app_processes.list))
        {
            item = list_entry(pos, struct process_list, list);

            /* Delete from list */
            list_del(pos);

            if (item->process != NULL)
            {
                /* Mark processes[] entry as NULL */
                processes[item->process->pid] = NULL;

                /* Wake up process to avoid zombies and such */
                task = find_task_by_pid(item->process->pid);
                if (task) wake_up_process(task);

                /* Free process */
                DLOG("Freeing process state for application PID %d", item->process->pid);
                kfree(item->process);
                item->process = NULL;
            }

            /* Free list item struct */
            kfree(item);
            item = NULL;
        }

        DLOG("Freeing system call buffer data for monitor PID %d", current->pid);
        vfree(monitor->syscall_data);
        monitor->syscall_data = NULL;
        
        DLOG("Calling ClearPageReserved for schedule buffer data for monitor PID %d", current->pid);
        pstart = virt_to_page(monitor->sched_data);
        pend = virt_to_page(monitor->sched_data + SCHED_BUFFER_SIZE);

        /* Unreserve pages so they can be freed */
        for (page = pstart; page < pend; page++)
            ClearPageReserved(page);

        DLOG("Freeing schedule buffer data for monitor PID %d", current->pid);
        kfree(monitor->sched_data);
        monitor->sched_data = NULL;

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
    monitor_t *monitor = process->monitor;
    struct page *pstart, *pend, *page;

    if (process != NULL && process->mode == MODE_MONITOR)
    {
        if (monitor->mmap_select == MAP_SYSCALL_BUFFER)
        {
            DLOG("Memory mapping system call data buffer to user space");
            vma->vm_flags |= VM_RESERVED;
            vma->vm_ops = &vm_syscall_ops;

            monitor->mmap_select++;
            return 0;
        }
        else if (monitor->mmap_select == MAP_SCHED_BUFFER)
        {
            DLOG("Memory mapping schedule data buffer into user space");
            vma->vm_flags |= VM_RESERVED;
            
            pstart = virt_to_page(monitor->sched_data);
            pend = virt_to_page(monitor->sched_data + SCHED_BUFFER_SIZE);
            
            /* Reserve pages so they can be mapped by remap_pfn_range */
            for (page = pstart; page < pend; page++)
                SetPageReserved(page);

            if (remap_pfn_range(vma,
                    vma->vm_start,
                    virt_to_phys((void*)((unsigned long) monitor->sched_data)) >> PAGE_SHIFT,
                    SCHED_BUFFER_SIZE,
                    PAGE_SHARED))
                return -EAGAIN;

            monitor->mmap_select++;
            return 0;
        }
    }

    return -ENODEV;
}

static int cdev_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
{
    int result = 0;
    process_t *process;
    monitor_t *monitor;
    struct process_list* pl_item;
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

            monitor->sched_data = (char*) kmalloc(SCHED_BUFFER_SIZE, GFP_KERNEL);
            if (! (monitor->sched_data))
            {
                result = -ENOMEM;
                goto allocschedbuf_fail;
            }

            monitor->mmap_select = MAP_SYSCALL_BUFFER;
            monitor->child_count = 0;
            monitor->syscall_size = 0;
            monitor->sched_size = 0;
            monitor->syscall_offset = 0;
            monitor->sched_offset = 0;
            monitor->ready_data.type = NO_DATA;

            INIT_LIST_HEAD(&(monitor->syscall_queue.list));
            INIT_LIST_HEAD(&(monitor->app_processes.list));

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
            process->sched_counter = NULL;
            process->child_id = ++(process->monitor->child_count);

            pl_item = (struct process_list*) kmalloc(sizeof(struct process_list), GFP_KERNEL);
            if (! pl_item)
            {
                result = -ENOMEM;
                goto alloc_plitem_fail;
            }
            pl_item->process = process;
            list_add_tail(&(pl_item->list), &(process->monitor->app_processes.list));

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
            process->sched_counter = NULL;
            process->child_id = ++(process->monitor->child_count);

            pl_item = (struct process_list*) kmalloc(sizeof(struct process_list), GFP_KERNEL);
            if (! pl_item)
            {
                result = -ENOMEM;
                goto alloc_plitem_fail;
            }
            pl_item->process = process;
            list_add_tail(&(pl_item->list), &(process->monitor->app_processes.list));

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
                        result = -EFAULT;
                        goto allocproc_fail;
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
                        result = -EFAULT;
                        goto allocproc_fail;
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
            if (down_interruptible(&(process->monitor->data_available_sem)))
            {
                return -EINTR;
            }

            if (copy_to_user((void __user*) arg, &(process->monitor->ready_data), sizeof(process->monitor->ready_data)))
            {
                ERROR("CRITICAL: Failed to copy callback data to monitor with PID %d. Cannot recover!", current->pid);
                result = -EFAULT;
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

        case IMITATE_NOTIFY_SCHED_COUNTER:
            process = processes[current->pid];
            process->sched_counter = (unsigned long*) arg;
            break;
    }

    allocproc_fail:
    return result;
    
    alloc_plitem_fail:
        kfree(process);
    return result;
    
    allocschedbuf_fail:
        vfree(monitor->syscall_data);
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
    VDLOG("Mapping offset: %ld", offset);

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
        VVDLOG("Entered pre_syscall_callback() - syscall_no: %ld", syscall_no);

        VVDLOG("Dispatching pre_syscall_callback handler for call %ld", syscall_no);
        process->replay_syscall = 0;
        ((pre_syscall_callback_t) pre_syscall_callbacks[syscall_no])(
            &syscall_args);
        VVDLOG("Returned from pre_syscall_callback handler for call %ld", syscall_no);

        process->last_syscall_no = (unsigned short) syscall_no;

        if ((process->mode == MODE_REPLAY) && (process->replay_syscall))
        {
            VVDLOG("Replaying call return value for call %ld", syscall_no);
            return &(process->syscall_replay_value);
        }

        VVDLOG("Leaving pre_syscall_callback()");
    }

    return NULL;
}

asmlinkage unsigned long post_syscall_callback(long syscall_return_value, unsigned long syscall_return_addr, syscall_args_t syscall_args)
{
    process_t *process = processes[current->pid];

    if (process != NULL && process->mode >= MODE_RECORD)
    {
        VVDLOG("Dispatching post_syscall_callback handler for call %d", process->last_syscall_no);
        ((post_syscall_callback_t) post_syscall_callbacks[process->last_syscall_no])(
            &syscall_return_value,
            &syscall_args);
        VVDLOG("Returned from post_syscall_callback handler for call %d", process->last_syscall_no);
    }

    return syscall_return_addresses[current->pid];
}

void* slmalloc(unsigned int size)
{
    monitor_t *monitor = processes[current->pid]->monitor;
    void* alloced_mem = (void*) (monitor->sched_data + monitor->sched_offset);

    if (size > (SCHED_BUFFER_SIZE - monitor->sched_offset))
    {
        DLOG("Schedule log memory request: %d. Free: %d of %d bytes.", size,
            (SCHED_BUFFER_SIZE - monitor->sched_offset),
            SCHED_BUFFER_SIZE);
        DLOG("Out of schedule log memory!");
        return NULL;
    }

    /* Allocate */
    VVDLOG("Allocated %d bytes in schedule buffer at offset %d", size, monitor->sched_offset);
    monitor->sched_offset += size;
    return alloced_mem;
}

void context_switch_hook(struct task_struct *prev, struct task_struct *next)
{
    process_t *process = processes[prev->pid];
    sched_log_entry_t *entry;
    unsigned long counter_val;
    
    /* Process is being recorded and is being swapped out */
    if ((process != NULL) && (process->mode == MODE_RECORD))
    {
        entry = slmalloc(sizeof(sched_log_entry_t));
        if (! entry)
        {
            /* Out of schedule memory */
            return;
        }

        entry->child_id = process->child_id;
        entry->counter = 0;
        if (process->sched_counter)
        {
            if (get_user(counter_val, (unsigned long __user*) process->sched_counter))
            {
                /* Copy failed */
            }
        }
        entry->ip = get_user_mode_instruction_pointer(prev);
    }
}
