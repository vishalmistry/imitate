#ifndef _DYNINST_RT_EXPORT_H_
#define _DYNINST_RT_EXPORT_H_
#ifndef ASSEMBLER
  /*  This file contains function prototypes that may be useful for 
      dyninst users to directly have access to from their own runtime
      libraries.
  */

#if !defined(DLLEXPORT)
#if defined (_MSC_VER)
/* If we're on Windows, we need to explicetely export these functions: */
#define DLLEXPORT __declspec(dllexport) 
#else
#define DLLEXPORT
#endif
#endif
  /*
    DYNINSTuserMessage(void *msg, unsigned int msg_size) may be used 
    in conjunction with the dyninstAPI method 
    BPatch_process::registerUserMessageCallback(), to implement a generic
    user-defined, asynchronous communications protocol from the mutatee
    (via this runtime library) to the mutator.

    Calls to DYNINSTuserMessage() will result in <msg> (of <msg_size> bytes)
    being sent to the mutator, and then passed to the callback function
    provided by the API user via registerUserMessageCallback().

    Returns zero on success, nonzero on failure.
  */
DLLEXPORT int DYNINSTuserMessage(void *msg, unsigned int msg_size);

/* Returns the number of threads DYNINST currently knows about.  (Which
   may differ at certain times from the number of threads actually present.) */
DLLEXPORT int DYNINSTthreadCount();

/**
 * These function implement a locking mechanism that can be used by 
 * a user's runtime library.
 * 
 * Be sure to always check for DYNINST_LIVE_LOCK and DYNINST_DEAD_LOCK.
 * When instrumenting multithread or signal-based application as these error
 * conditions can trigger even on simple synchronization mechanisms.
 **/

/* The contents of this structure are subject to change between
   dyninst versions.  Don't rely on it. */
typedef void * dyntid_t;
#define DYNINST_INITIAL_LOCK_PID ((void *)-129)

typedef struct {
   volatile int mutex;
   dyntid_t tid;
} dyninst_lock_t;

/* Return values for 'dyninst_lock' */
#define DYNINST_LIVE_LOCK      -1
#define DYNINST_DEAD_LOCK      -2

/* Declare a lock already initialized */
#define DECLARE_DYNINST_LOCK(lck) dyninst_lock_t lck = {0, DYNINST_INITIAL_LOCK_PID}

DLLEXPORT void dyninst_init_lock(dyninst_lock_t *lock);
DLLEXPORT void dyninst_free_lock(dyninst_lock_t *lock);
DLLEXPORT int dyninst_lock(dyninst_lock_t *lock);
DLLEXPORT void dyninst_unlock(dyninst_lock_t *lock);

/**
 * Functions for retrieving information about threads
 **/
DLLEXPORT unsigned dyninst_maxNumOfThreads();
DLLEXPORT unsigned dyninst_threadIndex();

DLLEXPORT void setNewthrCB(void (*rt_newthr_cb)(int));

#endif
#endif
