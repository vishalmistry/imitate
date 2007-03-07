/*
 * Imitate record/replay framework kernel module
 * Standard intercept include
 * Copyright (c) 2007, Vishal Mistry
 */

#ifndef SYSCALL_INTERCEPT_H
#define SYSCALL_INTERCEPT_H

#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include "../syscall_log.h"
#include "../main.h"
#include "intercepts.h"

/*
 * Macros to increase readability
 */
#define replaying(P)    (P)->mode == MODE_REPLAY
#define recording(P)    (P)->mode == MODE_RECORD

/*
 * Replay result macros
 */
#define replay_void(P)    seek_to_next_syscall_entry(); \
                          (P)->replay_syscall = 1
#define replay_value(P,X) seek_to_next_syscall_entry(); \
                          (P)->replay_syscall = 1; \
                          (P)->syscall_replay_value = (X)->return_value

/*
 * Copy to user-space standard error
 */
#define REPLAY_COPY_ERR(P,X) ERROR("Unable to copy replay data for process %d (PID %d). Call %d not replayed.", (P)->child_id, current->pid, (X))

#endif
