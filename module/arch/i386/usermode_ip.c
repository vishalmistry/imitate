/*
 * Imitate record/replay framework kernel module
 * Copyright (c) 2007, Vishal Mistry
 */

#include <linux/module.h>
#include <linux/kernel.h>

inline long get_user_mode_instruction_pointer(struct task_struct *task)
{
    void *stack_top = (void *) task->thread.esp0;
    struct pt_regs *regs = (struct pt_regs*) (stack_top - sizeof(struct pt_regs));
    return regs->eip;
}
