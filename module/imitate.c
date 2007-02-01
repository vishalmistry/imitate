/*
 * Imitate record/replay framework kernel module
 * Copyright (c) 2007, Vishal Mistry
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include "syscall_types.h"
#include "imitate.h"

/*
 * Module name for logging
 */
#define MODULE_NAME "imitate"

/*
 * Character device parameters
 */
#define DEVICE_NAME    "imitate"
#define DEVICE_MINOR   0
#define DEVICE_NR_DEVS 1

/*
 * Monitored process modes
 */
#define MODE_NULL       0
#define MODE_RECORD     1
#define MODE_REPLAY     2
#define MODE_MONITOR    3

/*
 * Temporary!!! Buffer size of syscall storage (20 MB)
 */
#define SYSCALL_BUFFER_SIZE 20971520

/*
 * Debug message macros
 */
#ifdef DEBUG
#define DLOG(msg, args...) (printk(KERN_DEBUG MODULE_NAME " (debug): " msg "\n", ##args))
#else
#define DLOG(msg, args...) /* No Message */
#endif

#define LOG(msg, args...) (printk(KERN_INFO MODULE_NAME ": " msg "\n", ##args))
#define ERROR(msg, args...) (printk(KERN_ERR MODULE_NAME ": " msg "\n", ##args))

/*
 * Module information
 */
MODULE_AUTHOR("Vishal Mistry <vishal@digitalsilver.org>");
MODULE_DESCRIPTION("Kernel portion of the Imitate record/replay framework");
MODULE_LICENSE("GPLv2");

/*
 * Type definition of a system call
 */
typedef void *syscall_t;

/*
 * Monitor process struct
 */
typedef struct
{
    unsigned long syscall_offset;
    unsigned long sched_offset;
    char *syscall_data;
    char *sched_data;
    struct semaphore syscall_sem;
} monitor_t;

/*
 * Process struct
 */
typedef struct
{
    pid_t pid;
    char mode;
    monitor_t *monitor;
} process_t;

/*
 * System call log entry
 */
typedef struct
{
    unsigned short call_no;
    int return_value;
    unsigned long out_param_len;
    char out_param;
} syscall_log_entry_t;

/*
 * System call table and the backup
 */
static syscall_t *sys_call_table = (syscall_t*) SYS_CALL_TABLE_ADDR;
static syscall_t original_sys_call_table[NR_syscalls];

/*
 * Process list
 */
static process_t *processes[PID_MAX_LIMIT];

/*
 * Character device
 */
static struct cdev cdev;

/*
 * Character device operations
 */
static int cdev_open(struct inode *inode, struct file *filp);
static ssize_t cdev_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset);
static int cdev_mmap(struct file *filp, struct vm_area_struct *vma);
static int cdev_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg);
static struct file_operations fops =
{
    .owner   = THIS_MODULE,
    .open    = cdev_open,
    .read    = cdev_read,
    .mmap    = cdev_mmap,
    .ioctl   = cdev_ioctl
};

/*
 * Memory map operations
 */
static struct page *vma_syscall_nopage(struct vm_area_struct *area, unsigned long address, int *type);
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
static void write_syscall_log_entry(unsigned short call_no, int ret_val, char *out_param, unsigned long out_param_len);


asmlinkage long handle_sys_exit(int error_code)
{
    if (processes[current->pid] != NULL && processes[current->pid]->mode == MODE_RECORD)
    {
        LOG("%d: sys_exit called", current->pid);
    }
    return ((sys_exit_t) original_sys_call_table[__NR_exit])(error_code);
}

asmlinkage void handle_sys_exit_group(int error_code)
{
    if (processes[current->pid] != NULL && processes[current->pid]->mode == MODE_RECORD)
    {
        LOG("%d: sys_exit_group called", current->pid);
        write_syscall_log_entry(__NR_exit_group, 0, NULL, 0);
    }
    return ((sys_exit_group_t) original_sys_call_table[__NR_exit_group])(error_code);
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
    }

    /* Hook the system call intercepts */
    DLOG("Attaching system call intercepts");
    sys_call_table[__NR_exit] = handle_sys_exit;
    sys_call_table[__NR_exit_group] = handle_sys_exit_group;

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
            kfree(processes[i]);
            DLOG("Freeing process state for PID %d", i);
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
        vma->vm_flags |= (VM_LOCKED | VM_RESERVED);
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
            monitor = (monitor_t*) kmalloc(sizeof(monitor_t), GFP_KERNEL);
            process->mode = MODE_MONITOR;
            process->pid  = current->pid;
            process->monitor = monitor;
            monitor->syscall_data = (char*) vmalloc(SYSCALL_BUFFER_SIZE);
            monitor->syscall_offset = 0;

            sema_init(&(monitor->syscall_sem), 1);

            processes[current->pid] = process;
            break;

        case IMITATE_APP_RECORD:
            DLOG("Process %d being recorded by monitor process %d", current->pid, (pid_t) arg);

            process = (process_t*) kmalloc(sizeof(process_t), GFP_KERNEL);
            process->mode = MODE_RECORD;
            process->pid = current->pid;
            process->monitor = processes[(pid_t) arg]->monitor;
            processes[current->pid] = process;
            break;

        case IMITATE_APP_REPLAY:
            DLOG("Process %d being replayed by monitor %d", current->pid, (pid_t) arg);

            process = (process_t*) kmalloc(sizeof(process_t), GFP_KERNEL);
            process->mode = MODE_REPLAY;
            process->pid = current->pid;
            process->monitor = processes[(pid_t) arg]->monitor;
            break;

        case IMITATE_MONITOR_CB:
            DLOG("Monitor %d registered callbacks", current->pid);
            break;
    }
    return result;
}

/*
 * System call map-on-page fault
 */
static struct page *vma_syscall_nopage(struct vm_area_struct *vma, unsigned long address, int *type)
{
    char *syscall_data = processes[current->pid]->monitor->syscall_data;

    struct page *page = vmalloc_to_page(&(syscall_data[address - vma->vm_start]));
    get_page(page);
    return page;
}

/*
 * Helper functions
 */
static void write_syscall_log_entry(unsigned short call_no, int ret_val, char *out_param, unsigned long out_param_len)
{
    monitor_t *proc_mon = processes[current->pid]->monitor;
    syscall_log_entry_t* current_data;

    down(&(proc_mon->syscall_sem));

    current_data = (syscall_log_entry_t*)(proc_mon->syscall_data + proc_mon->syscall_offset);
    proc_mon->syscall_offset += sizeof(*current_data) - sizeof(current_data->out_param) + out_param_len;

    current_data->call_no = call_no;
    current_data->return_value = ret_val;
    current_data->out_param_len = out_param_len;
    if (out_param_len != 0)
    {
        copy_from_user(&(current_data->out_param), out_param, out_param_len);
    }

    DLOG("Wrote record - call_no: %d, return_value: %d", current_data->call_no, current_data->return_value);

    up(&(proc_mon->syscall_sem));
}

