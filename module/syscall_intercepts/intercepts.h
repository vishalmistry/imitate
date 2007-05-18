/*
 * Imitate record/replay framework kernel module
 * Intercept prototypes
 * Copyright (c) 2007, Vishal Mistry
 */

#ifndef SYSCALL_INTERCEPTS_H
#define SYSCALL_INTERCEPTS_H

#include "../main.h"

void pre_open(syscall_args_t *args);
void post_open(long *return_value, syscall_args_t *args);

void pre_read(syscall_args_t *args);
void post_read(long *return_value, syscall_args_t *args);

void pre_close(syscall_args_t *args);
void post_close(long *return_value, syscall_args_t *args);

void pre_mmap2(syscall_args_t *args);
void post_mmap2(long *return_value, syscall_args_t *args);

void pre_exit_group(syscall_args_t *args);

void pre_clock_gettime(syscall_args_t *args);
void post_clock_gettime(long *return_value, syscall_args_t *args);

void pre_getdents64(syscall_args_t *args);
void post_getdents64(long *return_value, syscall_args_t *args);

void pre_fstat64(syscall_args_t *args);
void post_fstat64(long *return_value, syscall_args_t *args);

void pre_lstat64(syscall_args_t *args);
void post_lstat64(long *return_value, syscall_args_t *args);

void pre_getxattr(syscall_args_t *args);
void post_getxattr(long *return_value, syscall_args_t *args);

void pre_clone(syscall_args_t *args);
void post_clone(long *return_value, syscall_args_t *args);

void pre_execve(syscall_args_t *args);
void post_execve(long *return_value, syscall_args_t *args);

#endif
