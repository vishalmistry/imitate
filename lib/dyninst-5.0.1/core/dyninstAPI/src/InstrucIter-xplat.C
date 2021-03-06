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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "common/h/Types.h"
#include "common/h/Vector.h"
#include "common/h/Dictionary.h"

#include "arch.h"
#include "util.h"
#include "process.h"
#include "symtab.h"
#include "instPoint.h"
#include "InstrucIter.h"

#include "BPatch_Set.h"

#if !defined(arch_ia64)
// IA64 has a bundle-oriented version defined in InstrucIter-ia64.C

void InstrucIter::initializeInsn() {
    if (proc_) {
        instPtr = proc_->getPtrToInstruction(current);
    }
    else {
        assert(img_); 
        if (!img_->isValidAddress(current)) {
            fprintf(stderr, "Error: addr 0x%lx is not valid!\n",
                    current);
            assert(0);
        }
        else instPtr = img_->getPtrToInstruction(current);
    }            

    // ARGH 64-bit/32-bit...
#if defined(arch_x86_64)
    if (proc_) {
      ia32_set_mode_64(proc_->getAddressWidth() == 8);
    }
    else {
      assert(img_);
      ia32_set_mode_64(img_->getAddressWidth() == 8);
    }
#endif

    if (instPtr) 
        insn.setInstruction((codeBuf_t *)instPtr, current);

    // If there's no pointer we have an invalid instrucIter... however,
    // this can happen if you're using logic like "while hasMore()... iter++"
    // so we allow it. If the value gets used then choke.
}
#endif

// FIXME: should do an in-order iteration over basic blocks or something
InstrucIter::InstrucIter(int_function* func) :
    proc_(func->proc()),
    img_(NULL),
    base(func->getAddress()),
    range(func->getSize_NP()),
    current(base) {
    assert(current >= base);
    assert(current < base+range);
    initializeInsn();
}

InstrucIter::InstrucIter(Address addr, int_function* func) :
    proc_(func->proc()),
    img_(NULL),
    base(addr),
    range(func->getSize_NP()),
    current(base) {
    assert(current >= base);
    assert(current < base+range);
    initializeInsn();
}


InstrucIter::InstrucIter(bblInstance* b) :
    proc_(b->proc()),
    img_(NULL),
    base(b->firstInsnAddr()),
    range(b->getSize()),
    current(base) {
    assert(current >= base);
    assert(current < base+range);
    initializeInsn();
}

InstrucIter::InstrucIter(image_basicBlock *b) :
    proc_(NULL),
    base(b->firstInsnOffset()),
    range(b->getSize()),
    current(base) {
    assert(current >= base);
    // The range might be 0.
    if (range) {
        if (current >= (base+range)) {
            fprintf(stderr, "Error: current 0x%p >= 0x%p (0x%p + 0x%x)\n",
                    (void *)current, (void*)(base+range), (void *)base, range);
        assert(current < base+range);
        }
    }

    // image will be the same for any function containing this block
    image_func *f = b->getFirstFunc();
    if(f)
        img_ = f->img();
    else
        img_ = NULL;

    initializeInsn();
}


InstrucIter::InstrucIter( CONST_EXPORT BPatch_basicBlock* bpBasicBlock) :
    proc_(bpBasicBlock->flowGraph->getBProcess()->lowlevel_process()),
    img_(NULL),
    base(bpBasicBlock->getStartAddress()),
    range(bpBasicBlock->size()),
    current(base) {
    assert(current >= base);
    assert(current < base+range);
    initializeInsn();
}

InstrucIter::InstrucIter( int_basicBlock *ibb) :
    proc_(ibb->proc()),
    img_(NULL),
    base( ((BPatch_basicBlock *)ibb->getHighLevelBlock())->getStartAddress()),
    range( ((BPatch_basicBlock *)ibb->getHighLevelBlock())->size()),
    current(base) {
    assert(current >= base);
    assert(current < base+range);
    initializeInsn();
}


/** copy constructor
 * @param ii InstrucIter to copy
 */
InstrucIter::InstrucIter(const InstrucIter& ii) :
    proc_(ii.proc_),
    img_(ii.img_),
    base(ii.base),
    range(ii.range),
    current(ii.current),
    prevInsns(ii.prevInsns)
{
    assert(current >= base);
    initializeInsn();
}

// For somewhere in a process (maybe)
InstrucIter::InstrucIter( Address addr, process *proc) :
    proc_(proc),
    img_(NULL),
    current(addr)
{
    // There's all sorts of reasons to iterate over the middle of nowhere;
    // we may be grabbing the PLT or new code. On the other hand, nobody knows
    // what the range is.
    // Did I mention this is dangerous?
    base = addr;
    range = 0;

    initializeInsn();
}

// And truly generic
InstrucIter::InstrucIter( Address addr, unsigned size, process *proc) :
    proc_(proc),
    img_(NULL),
    base(addr),
    range(size),
    current(addr)
{
    assert(current >= base);
    assert(current < base+range);
    initializeInsn();
}

// Used in parsing -- relative addrs
InstrucIter::InstrucIter(Address current, image_func *func) :
    proc_(NULL),
    img_(func->img()),
    base(func->getOffset()),
    range(func->get_size_cr()), // Probably in the middle of
    // parsing, so calling getSize is
    // a bad idea as it may
    // trigger... parsing.
    current(current) {
    assert(current >= base);
    initializeInsn();
}

bool InstrucIter::hasMore()
{
    if (instPtr == NULL) return false;

    if ((range == 0) ||
        (range ==-1)) return true; // Unsafe iteration, but there is more

    if((current < (base + range )) &&
       (current >= base))
        return true;
    return false;
}

bool InstrucIter::hasPrev()
{
    if (instPtr == NULL) return false;
    //cerr << "hasprev" << std::hex << current 
    //   << " "  << baseAddress << " "  << range << endl;
#if defined(arch_x86) || defined(arch_x86_64) // arch_has_variable_length_insns...
    if (prevInsns.size() == 0) 
        // There is more, but we can't access...
        return false;
#endif
    
    if( current > base )
    //if((current < (baseAddress + range )) &&
    // (current > baseAddress))
	return true;

    return false;
}
