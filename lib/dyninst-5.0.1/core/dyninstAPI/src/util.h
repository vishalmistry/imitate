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

// $Id: util.h,v 1.35 2006/05/10 02:31:02 jaw Exp $

#ifndef UTIL_H
#define UTIL_H

#define FILE__ strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__
#include "common/h/headers.h"
#include "common/h/Time.h"
#include "common/h/Types.h"
#include "common/h/String.h"

bool waitForFileToExist(char *fname, int timeout_seconds);
int openFileWhenNotBusy(char *fname, int flags, int mode, int timeout_seconds);

#ifndef BPATCH_LIBRARY
// DON'T access through this global variable
extern timeStamp *pFirstRecordTime;

// ACCESS through these functions
void setFirstRecordTime(const timeStamp &ts);
bool isInitFirstRecordTime();
const timeStamp &getFirstRecordTime();
#endif

#define BPFATAL(x) bpfatal_lf(__FILE__, __LINE__, x)
extern void logLine(const char *line);
extern void statusLine(const char *line, bool force = false);
extern char errorLine[];
extern int bpfatal(const char *format, ...);
extern int bperr(const char *format, ...);
extern int bpwarn(const char *format, ...);
extern int bpinfo(const char *format, ...);

extern int bpfatal_lf(const char *__file__, unsigned int __line__, const char *format, ...);
inline unsigned uiHash(const unsigned &val) {
  return val;
}

inline unsigned CThash(const unsigned &val) {
  return val % 1048573;
}

unsigned addrHash4(const Address &addr);
   // use when you know the address is divisible by 4 (lo 2 bits 0)
unsigned addrHash16(const Address &addr);
   // use when you know the address is divisible by 16 (lo 4 bits 0)
unsigned addrHash(const Address &addr);
   // use when you cannot assume anything about the address

unsigned ptrHash4(void *ptr);
unsigned ptrHash16(void *ptr);

inline unsigned intHash(const int &val) {
  return val;
}

void
pd_log_perror(const char* msg);

#endif /* UTIL_H */
