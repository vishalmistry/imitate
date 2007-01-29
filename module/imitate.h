#ifndef _IMITATE_H
#define _IMITATE_H

#include <linux/ioctl.h>

/* Magic number for ioct() command code generation */
#define IMITATE_IOC_MAGIC 0xE0

/* Maximum command number */
#define IMITATE_IOC_MAXNR 4

/*
 * ioctl() commands
 */

/* Notify driver to reset data structures for calling monitor
   and associated child */
#define IMITATE_RESET _IO(IMITATE_IOC_MAGIC, 0)
/* Notify driver that the caller is the application monitor */
#define IMITATE_MONITOR _IO(IMITATE_IOC_MAGIC, 1)
/* Notify driver that the caller is child that is being recorded 
   with monitor in _arg_ */
#define IMITATE_APP_RECORD _IOW(IMITATE_IOC_MAGIC, 2, pid_t)
/* Notify driver that the caller is child that is being replayed
   with monitor in _arg_ */
#define IMITATE_APP_REPLAY _IOW(IMITATE_IOC_MAGIC, 3, pid_t)
/* Notify driver of callback on monitor to request/remove data
   from mmap'ed buffer */
#define IMITATE_MONITOR_CB _IOR(IMITATE_IOC_MAGIC, 4, callback_t)

typedef struct
{
    int type;
    int data;
} callback_t;

#endif
