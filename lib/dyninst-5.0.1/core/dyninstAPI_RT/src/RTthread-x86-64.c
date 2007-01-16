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

long atomic_set(volatile int *val)
{
  static long result = 0;
#if defined(MUTATEE_32)
   __asm("movl $1,%%eax\n"
         "movl %1,%%ecx\n"
         "lock\n"
         "xchgl %%eax, (%%ecx)\n"
         "movl %%eax, %0\n"
         : "=r" (result)
         : "r" (val)
         : "%eax",
           "%ecx");
#else
   __asm("mov $1,%%rax\n"
         "mov %1,%%rcx\n"
         "lock\n"
         "xchg %%rax, (%%rcx)\n"
         "mov %%rax, %0\n"
         : "=r" (result)
         : "r" (val)
         : "%rax",
           "%rcx");
#endif
   return !result;
}
/*
#if 1
   __asm(
         "movl $0,%%eax\n"
         "movl $1,%%ebx\n"
         "movl %1,%%ecx\n"
         "lock\n"
         "cmpxchgl %%ebx,(%%ecx)\n"
         "setz %%al\n"
         "movl %%eax,%0\n"
         : "=r" (result)
         : "r" (val)
         : "%eax", "%ebx", "%ecx");
#else
      __asm(
            "mov $0,%%rax\n"
            "mov $1,%%rbx\n"
            "mov %1,%%rcx\n"
            "lock\n"
            "cmpxchg %%rbx,(%%rcx)\n"
            "setz %%al\n"
            "mov %%rax,%0\n"
            : "=r" (result)
            : "r" (val)
            : "%rax", "%rbx", "%rcx");
#endif
      return result;
*/

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
