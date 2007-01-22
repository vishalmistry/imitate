/*
 * Imitate record/replay framework kernel module
 * Copyright (c) 2007, Vishal Mistry
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>

/*
 * Debug message macros
 */
#ifdef DEBUG
#define LOG(msg, args...) (printk(KERN_DEBUG "imitate: " msg "\n", ##args))
#else
#define LOG(msg, args...) /* No Message */
#endif

static void** sys_call_table = (void**) SYS_CALL_TABLE_ADDR;

/*
 * Module information
 */
MODULE_AUTHOR("Vishal Mistry <vishal@digitalsilver.org>");
MODULE_DESCRIPTION("Kernel portion of the Imitate record/replay framework");
MODULE_LICENSE("GPL");

asmlinkage long (*orig_exit) (int);
asmlinkage long handle_sys_exit(int error_code)
{
	LOG("sys_exit called");
	return orig_exit(error_code);
}

/*
 * Module initialisation function
 */
static int __init kmod_init(void)
{
	LOG("Loaded Imitate kernel module");
	LOG("SYS_CALL_TABLE_ADDR = %x", SYS_CALL_TABLE_ADDR);
	LOG("SYS_EXIT = %x", (int) sys_call_table[__NR_exit]);

	orig_exit = sys_call_table[__NR_exit];
	sys_call_table[__NR_exit] = handle_sys_exit;

	return 0;
}

/*
 * Module clean-up function
 */
static void __exit kmod_exit(void)
{
	sys_call_table[__NR_exit] = orig_exit;
	LOG("Unloaded Imitate kernel module");
}

/*
 * Module function registrations
 */
module_init(kmod_init);
module_exit(kmod_exit);
