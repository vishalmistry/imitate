/*
 * Copyright (c) 1996-2004 Barton P. Miller
 * 
 * We provide the Paradyn Parallel Performance Tools (below
 * described as "Paradyn") on an AS IS basis, and do not warrant its
 * validity or performance.  We reserve the right to update, modify,
 * or discontinue this software at any time.  We shall have no
 * obligation to supply such updates or modifications or any other
 * form of support to you.
 * 
 * This license is for research uses.  For such uses, there is no
 * charge. We define "research use" to mean you may freely use it
 * inside your organization for whatever purposes you see fit. But you
 * may not re-distribute Paradyn or parts of Paradyn, in any form
 * source or binary (including derivatives), electronic or otherwise,
 * to any other organization or entity without our permission.
 * 
 * (for other uses, please contact us at paradyn@cs.wisc.edu)
 * 
 * All warranties, including without limitation, any warranty of
 * merchantability or fitness for a particular purpose, are hereby
 * excluded.
 * 
 * By your use of Paradyn, you understand and agree that we (or any
 * other person or entity with proprietary rights in Paradyn) are
 * under no obligation to provide either maintenance services,
 * update services, notices of latent defects, or correction of
 * defects for Paradyn.
 * 
 * Even if advised of the possibility of such damages, under no
 * circumstances shall we (or any other person or entity with
 * proprietary rights in the software licensed hereunder) be liable
 * to you or any third party for direct, indirect, or consequential
 * damages of any character regardless of type of action, including,
 * without limitation, loss of profits, loss of use, loss of good
 * will, or computer failure or malfunction.  You agree to indemnify
 * us (and any other person or entity with proprietary rights in the
 * software licensed hereunder) for any and all liability it may
 * incur to third parties resulting from your use of Paradyn.
 */

#ifndef _RTTHREAD_H_
#define _RTTHREAD_H_

#include "dyninstAPI_RT/h/dyninstAPI_RT.h"
#include "dyninstAPI_RT/h/dyninstRTExport.h"

dyntid_t dyn_pthread_self();    //Thread library identifier
int dyn_lwp_self();        //LWP used by the kernel identifier
int dyn_pid_self();        //PID identifier representing the containing process

unsigned DYNINSTthreadIndexFAST();
unsigned DYNINSTthreadIndexSLOW();
int DYNINSTthreadInfo(BPatch_newThreadEventRecord *ev);

dyntid_t DYNINST_getThreadFromIndex(unsigned index);
unsigned DYNINST_alloc_index(dyntid_t tid);
int DYNINST_free_index(dyntid_t tid);
void DYNINST_initialize_index_list();


extern int DYNINST_multithread_capable;
extern unsigned DYNINST_max_num_threads;

typedef dyninst_lock_t tc_lock_t;

#define DECLARE_TC_LOCK(l)         tc_lock_t l={0 ,(dyntid_t)-1}

int tc_lock_init(tc_lock_t*);
int tc_lock_lock(tc_lock_t*);
int tc_lock_unlock(tc_lock_t*);
int tc_lock_destroy(tc_lock_t*);


int DYNINST_am_initial_thread(dyntid_t tid);

#endif
