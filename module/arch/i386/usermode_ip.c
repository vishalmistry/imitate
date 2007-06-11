/*
 * Imitate record/replay framework kernel module
 * Copyright (c) 2007, Vishal Mistry
 */

#include <linux/module.h>
#include <linux/kernel.h>

inline struct pt_regs *get_user_mode_regs(struct task_struct *task)
{
    void *stack_top = (void *) task->thread.esp0;
    return (struct pt_regs*) (stack_top - sizeof(struct pt_regs));
}

inline long get_user_mode_instruction_pointer(struct task_struct *task)
{
    struct pt_regs *regs = get_user_mode_regs(task);
    return regs->eip;
}
