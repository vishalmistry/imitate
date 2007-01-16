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

#include "dyninstAPI_RT/src/RTthread.h"

/**
 * atomic_set will do the following atomically:
 *    if (*val == 0) {
 *       *val = 1;
 *       return 1;
 *    }
 *    return 0;
 *
 * We need two versions since windows uses a different assembly syntax
 * (AT&T syntax on Linux and Intel on Windows)
 **/
#if defined(os_windows)
int atomic_set(volatile int *val)
{
   int result;
   __asm
   {
      mov eax, 0 ;
      mov ebx, 1 ;
      mov ecx, val ;      
      lock cmpxchg [ecx],ebx ;
      setz al ;
      mov result, eax ;
   }   
   return result;
}
#else
int atomic_set(volatile int *val)
{
   int result;
   __asm(
      "movl $0,%%eax\n"
      "movl $1,%%edx\n"
      "movl %1,%%ecx\n"
      "lock\n"
      "cmpxchgl %%edx,(%%ecx)\n"
      "setz %%al\n"
      "movl %%eax,%0\n"
      : "=r" (result)
      : "r" (val)
      : "%eax", "%edx", "%ecx");
   return result;
}
#endif

int tc_lock_lock(tc_lock_t *tc)
{
   dyntid_t me;

   me = dyn_pthread_self();
   if (me == tc->tid)
      return DYNINST_DEAD_LOCK;

   while (1) {
      if (tc->mutex == 0 && atomic_set(&tc->mutex))
      {
         tc->tid = me;
         break;
      }
   }
   return 0;
}

unsigned DYNINSTthreadIndexFAST() {
   return 0;
}
