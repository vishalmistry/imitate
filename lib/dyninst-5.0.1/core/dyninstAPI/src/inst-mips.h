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

// $Id: inst-mips.h,v 1.11 2004/03/23 01:12:03 eli Exp $

#ifndef INST_MIPS_H
#define INST_MIPS_H


#include <stdio.h>
#include "dyninstAPI/src/ast.h"
#ifdef BPATCH_LIBRARY
#include "BPatch_point.h"
#endif

#define REG_MT_POS 0 /* register saved to keep the address */
                 /* of the current vector of           */
                 /* counter/timers for each thread     */

extern registerSpace *regSpace;
extern Register Dead[];
extern const unsigned int nDead;

typedef Register reg;
void genRtype(instruction *insn, int ops, reg rs, reg rt, reg rd, int sa = 0); 
void genItype(instruction *insn, int op, reg rs, reg rt, signed short imm);
void genJtype(instruction *insn, int op, unsigned imm);
void genBranch(instruction *insn, Address branch, Address target);
bool genJump(instruction *insn, Address jump, Address target);
void genNop(instruction *insn);
void genMove(instruction *insn, reg rs, reg rd);
void genTrap(instruction *insn);
void genIll(instruction *insn);

Address readAddressInMemory(process *p, Address ptr, bool is_elf64);
Address lookup_fn(process *p, const pdstring &f);
void dis(void *actual, void *addr = NULL, int ninsns = 1, 
	 const char *pre = NULL, FILE *stream = stderr);
void disDataSpace(process *p, void *addr, int ninsns = 1, 
		  const char *pre = NULL, FILE *stream = stderr);

#ifdef BPATCH_LIBRARY
BPatch_point *createInstructionInstPoint(process *proc, void *address,
                                         BPatch_point** alternative,
					 BPatch_function* bpf);
#endif

#endif /* INST_MIPS_H */
