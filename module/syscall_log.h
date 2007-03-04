/*
 * Imitate record/replay framework kernel module
 * System call log read/write functions
 * Copyright (c) 2007, Vishal Mistry
 */

#ifndef SYSCALL_LOG_H
#define SYSCALL_LOG_H

#include "main.h"

void write_syscall_log_entry(unsigned short call_no, long ret_val, char *out_param, unsigned long out_param_len);
syscall_log_entry_t *get_next_syscall_log_entry(unsigned short call_no);
void seek_to_next_syscall_entry(void);

#endif
