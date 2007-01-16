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

/* $Id: RTheap.h,v 1.9 2006/03/12 23:32:44 legendre Exp $ */

#ifndef _RT_HEAP_H
#define _RT_HEAP_H

#include "dyninstAPI_RT/h/dyninstAPI_RT.h" /* RT_Boolean, Address */

#if defined(sparc_sun_solaris2_4)    \
 || defined(i386_unknown_solaris2_5) \
 || defined(mips_sgi_irix6_4)        \
 || defined(alpha_dec_osf4_0)

/* SVR4 */
#include <sys/procfs.h>
typedef prmap_t dyninstmm_t;

#elif defined(os_linux)

/* LINUX */
typedef struct {
     Address pr_vaddr;
     unsigned long pr_size;
} dyninstmm_t;

#elif defined(os_aix)

/* No actual /proc on AIX, we fake it with pre-built data */
typedef struct {
  Address pr_vaddr;
  unsigned long pr_size;
} dyninstmm_t;

#elif defined(os_windows)
typedef struct {
  Address pr_vaddr;
  unsigned long pr_size;
} dyninstmm_t;
#else
#error Dynamic heaps are not implemented on this platform
#endif

/* 
 * platform-specific variables
 */

extern int     DYNINSTheap_align;
extern Address DYNINSTheap_loAddr;
extern Address DYNINSTheap_hiAddr;
extern int     DYNINSTheap_mmapFlags;


/* 
 * platform-specific functions
 */

RT_Boolean DYNINSTheap_useMalloc(void *lo, void *hi);
int        DYNINSTheap_mmapFdOpen();
void       DYNINSTheap_mmapFdClose(int fd);
int        DYNINSTheap_getMemoryMap(unsigned *, dyninstmm_t **mmap);

int DYNINSTgetMemoryMap(unsigned *nump, dyninstmm_t **mapp);

#endif /* _RT_HEAP_H */
