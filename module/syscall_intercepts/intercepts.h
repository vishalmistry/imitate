/*
 * Imitate record/replay framework kernel module
 * Intercept prototypes
 * Copyright (c) 2007, Vishal Mistry
 */

#ifndef SYSCALL_INTERCEPTS_H
#define SYSCALL_INTERCEPTS_H

void pre_open(const char __user *filename, int flags, int mode);
void post_open(long return_value, const char __user *filename, int flags, int mode);

void pre_read(unsigned int fd, char __user *buf, size_t count);
void post_read(long return_value, unsigned int fd, char __user *buf, size_t count);

void pre_close(unsigned int fd);
void post_close(long return_value, unsigned int fd);

void pre_mmap2(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff);
void post_mmap2(long return_value, unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff);

void pre_exit_group(int error_code);

void pre_clock_gettime(clockid_t clk_id, struct timespec __user *tp);
void post_clock_gettime(long return_value, clockid_t clk_id, struct timespec __user *tp);

void pre_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
void post_getdents64(long return_value, unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);

void pre_fstat64(unsigned long fd, struct stat64 __user *statbuf);
void post_fstat64(long return_value, unsigned long fd, struct stat64 __user *statbuf);

void pre_lstat64(char __user *filename, struct stat64 __user *statbuf);
void post_lstat64(long return_value, char __user *filename, struct stat64 __user *statbuf);

#endif
