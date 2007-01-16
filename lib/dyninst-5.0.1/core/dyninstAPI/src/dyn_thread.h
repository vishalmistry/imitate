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

// $Id: dyn_thread.h,v 1.29 2006/06/14 19:06:57 legendre Exp $

#ifndef _DYNTHREAD_H_
#define _DYNTHREAD_H_

#include "dyninstAPI/src/process.h"
#include "dyninstAPI/src/dyn_lwp.h"

typedef long dynthread_t;

class Frame;
class dyn_lwp;

class dyn_thread {
 private:
   Frame getActiveFrameMT();  // called by getActiveFrame

 public:
  //
  dyn_thread(process *pproc);
  dyn_thread(process *proc_, unsigned index_, dyn_lwp *lwp_);
  dyn_thread(dyn_thread *src, process *child, dyn_lwp *lwp_ = NULL);
  ~dyn_thread();
  
  // Get the active frame (PC, SP, FP) of the thread
  // calls dyn_lwp::getActiveFrame if necessary
  // Note: OS specific, defined in <OS>MT.C files
  Frame getActiveFrame();

  // Walk the stack of the thread
  bool walkStack(pdvector<Frame> &stackWalk);

  bool updateLWP();
  
  dynthread_t    get_tid()           const { return(tid); }
  int            get_index()           const { return(index); }
  dyn_lwp *      get_lwp();
  unsigned       get_stack_addr()    const { return(stack_addr); }
  int            get_ppid()          const { return(ppid); }
  process*       get_proc()                { return(proc); }
  int_function*  get_start_func()          { return(start_func); }
  unsigned       get_start_pc()      const { return(start_pc); }
  void*          get_resumestate_p()       { return resumestate_p; }
  Address        get_indirect_start_addr() const { return indirect_start_func; }

  void update_tid          (dynthread_t tid_)        { tid = tid_; }
  void update_index        (unsigned index_);
  void update_lwp          (dyn_lwp *lwp_)        { lwp = lwp_; }
  void update_stack_addr   (unsigned stack_addr_) { stack_addr=stack_addr_; }
  void update_start_pc     (unsigned start_pc_)   { start_pc=start_pc_; }
  void update_start_func   (int_function *pdf)   { start_func=pdf; }
  void update_sfunc_indir  (Address addr)        {indirect_start_func = addr; }
  void update_resumestate_p(void* resumestate_p_) { resumestate_p=resumestate_p_; }
  
  Address get_pending_tramp_addr( void ) const	{ return pending_tramp_addr; }
  void set_pending_tramp_addr( Address a )	{ pending_tramp_addr = a; }
  bool is_exited()                         { return lwp->status() == exited; }
  int_function *map_initial_func(int_function *ifunc);

  ///
 private:
  int ppid;

  dynthread_t tid;
  int index;
  dyn_lwp *lwp;
  unsigned stack_addr;
  unsigned start_pc ;
  void*    resumestate_p; //platform specific
  int_function *start_func ;
  process *proc;
  Address pending_tramp_addr;	// address of pending instrumentation
  Address indirect_start_func;
  // currently used on NT only  
};

#endif
