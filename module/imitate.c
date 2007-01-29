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
#include "syscall_types.h"
#include "imitate.h"

/*
 * Module name for logging
 */
#define MODULE_NAME "imitate"

/*
 * Character device parameters
 */
#define DEVICE_NAME "imitate"
#define DEVICE_MINOR 0
#define DEVICE_NR_DEVS 1

/*
 * Monitored process modes
 */
#define MODE_NULL       0
#define MODE_RECORD     1
#define MODE_REPLAY     2
#define MODE_MONITOR    3

/*
 * Debug message macros
 */
#ifdef DEBUG
#define DLOG(msg, args...) (printk(KERN_DEBUG MODULE_NAME ": " msg "\n", ##args))
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
typedef void* syscall_t;

/*
 * Monitor process struct
 */
typedef struct
{
    unsigned long data_offset;
    unsigned long sched_offset;
    char* syscall_data;
    char* sched_data;
} monitor_t;

/*
 * Process struct
 */
typedef struct
{
    pid_t pid;
    char mode;
    monitor_t* monitor;
} process_t;

/*
 * System call table and the backup
 */
static syscall_t* sys_call_table = (syscall_t*) SYS_CALL_TABLE_ADDR;
static syscall_t original_sys_call_table[NR_syscalls];

/*
 * Process list
 */
static process_t* processes[PID_MAX_LIMIT];

/*
 * Character device
 */
static struct cdev cdev;

/*
 * Character device operations
 */
static int cdev_open(struct inode* inode, struct file* filp);
static ssize_t cdev_read(struct file* filp, char __user* buffer, size_t length, loff_t* offset);
static int cdev_mmap(struct file* filp, struct vm_area_struct* vma);
static int cdev_ioctl(struct inode* inode, struct file* filp, unsigned int cmd, unsigned long arg);
static struct file_operations fops =
{
    .owner   = THIS_MODULE,
    .open    = cdev_open,
    .read    = cdev_read,
    .mmap    = cdev_mmap,
    .ioctl   = cdev_ioctl
};

/*
 * Register module parameters
 */
static ushort dev_major = 0;
module_param(dev_major, ushort, 0000);
MODULE_PARM_DESC(dev_major, "Device major number for the " MODULE_NAME " character device");

asmlinkage long handle_sys_exit(int error_code)
{
    if (processes[current->pid] != NULL)
    {
        LOG("%d: sys_exit called", current->pid);
    }
    return ((sys_exit_t) original_sys_call_table[__NR_exit])(error_code);
}

/*
 * Module function prototypes
 */
static int __init kmod_init(void);
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
        result = register_chrdev_region(dev, DEVICE_NR_DEVS, DEVICE_NAME);
    }
    else
    {
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
    for (i = 0; i < NR_syscalls; i++)
    {
        original_sys_call_table[i] = sys_call_table[i];
    }

    /* Hook the system call intercepts */
    sys_call_table[__NR_exit] = handle_sys_exit;

    /* Set up the character device */
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
    for (i = 0; i < PID_MAX_LIMIT; i++)
    {
        processes[i] = NULL;
    }

    LOG("Loaded " MODULE_NAME " kernel module");

    return 0;

    /* Handle failures */
    cdev_add_fail:
        /* Free character device */
        kobject_put(&cdev.kobj);

        /* Restore original system call table */
        for (i = 0; i < NR_syscalls; i++)
        {
            sys_call_table[i] = original_sys_call_table[i];
        }
        
        /* Unregister major number */
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

    /* Unregister character device */
    cdev_del(&cdev);
    
    /* Restore original system call table */
    for (i = 0; i < NR_syscalls; i++)
    {
        sys_call_table[i] = original_sys_call_table[i];
    }

    /* Unregister major number */
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
static int cdev_open(struct inode* inode, struct file* filp)
{
    LOG("Device open");
    return 0;
}

static ssize_t cdev_read(struct file* filp, char __user* buffer, size_t length, loff_t* offset)
{
    LOG("Device read");
    return 0;
}

static int cdev_mmap(struct file* filp, struct vm_area_struct* vma)
{
    return -ENODEV;
}

static int cdev_ioctl(struct inode* inode, struct file* filp, unsigned int cmd, unsigned long arg)
{
    int result = 0;
    process_t* process;
    monitor_t* monitor;
    
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
            processes[current->pid] = process;
            break;

        case IMITATE_APP_RECORD:
            DLOG("Process %d being recorded by monitor process %d", current->pid, (pid_t) arg);

            process = (process_t*) kmalloc(sizeof(process_t), GFP_KERNEL);
            process->mode = MODE_RECORD;
            process->pid = current->pid;
            process->monitor = processes[(pid_t) arg]->monitor;
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
