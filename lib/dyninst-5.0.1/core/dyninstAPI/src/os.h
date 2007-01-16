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

// $Id: os.h,v 1.33 2006/04/20 22:45:00 bernat Exp $

#ifndef _OS_HDR
#define _OS_HDR

/*
 * This is an initial attempt at providing an OS abstraction for paradynd
 * I am doing this so I can compile paradynd on solaris
 *
 * This should enforce the abstract OS operations
 */ 

#if defined(sparc_sun_sunos4_1_3)
#include "dyninstAPI/src/sunos.h"

#elif defined(sparc_sun_solaris2_4) \
   || defined(i386_unknown_solaris2_5)
#include "dyninstAPI/src/solaris.h"

#elif defined(rs6000_ibm_aix3_2) \
   || defined(rs6000_ibm_aix4_1)
#include "dyninstAPI/src/aix.h"

#elif defined(alpha_dec_osf4_0)
#include "dyninstAPI/src/alpha.h"

#elif defined(hppa1_1_hp_hpux)
#include "dyninstAPI/src/hpux.h"

#elif defined(i386_unknown_nt4_0) \
   || defined(mips_unknown_ce2_11) //ccw 20 july 2000 : 29 mar 2001
#include "dyninstAPI/src/pdwinnt.h"

#elif defined(i386_unknown_linux2_0) \
   || defined(x86_64_unknown_linux2_4) \
   || defined(ia64_unknown_linux2_4)
#include "dyninstAPI/src/linux.h"

#elif defined(mips_sgi_irix6_4)
#include "dyninstAPI/src/irix.h"
#endif

#include "common/h/String.h"
#include "common/h/Types.h"

typedef enum { neonatal, running, stopped, detached, exited, deleted, unknown_ps } processState;
char *processStateAsString(processState state); // Defined in process.C

class OS {
public:
  static void osTraceMe(void);
  static void osDisconnect(void);
  static bool osKill(int);
  static void make_tempfile(char *);
  static bool execute_file(char *);
  static void unlink(char *);
  static bool executableExists(pdstring &file);
};

#endif
