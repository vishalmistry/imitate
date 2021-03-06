/*
 * Copyright (c) 1996 Barton P. Miller
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

/* $Id: RTtext-power.S,v 1.5 2006/06/05 22:30:20 bernat Exp $
 * create an array to use as a heap for new instructions.
 *
 *    This file is required since AIX has instructions and data are in
 *       different segments that are not reachable with a PC relative
 *       branch.  On other systems this would not be a good idea since it
 *       means that the dyninst code would have to be inserted at the first 
 *       link (since the data and text segments are next to each other).
 *       However, AIX permits incremental re-linking and can insert new
 *       code into a existing text segment.
 */

.csect .text[PR]
	.globl DYNINSTstaticHeap_16M_textHeap_1
	.globl .DYNINSTstaticHeap_16M_textHeap_1
DYNINSTstaticHeap_16M_textHeap_1:
.DYNINSTstaticHeap_16M_textHeap_1:
	.space	16777216
