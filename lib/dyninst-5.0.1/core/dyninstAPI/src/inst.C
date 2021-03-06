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

// $Id: inst.C,v 1.154 2006/05/30 20:48:59 bernat Exp $
// Code to install and remove instrumentation from a running process.
// Misc constructs.

#include <assert.h>
//#include <sys/signal.h>
//#include <sys/param.h>
#include "dyninstAPI/src/symtab.h"
#include "dyninstAPI/src/process.h"
#include "dyninstAPI/src/inst.h"
#include "dyninstAPI/src/instP.h"
#include "dyninstAPI/src/ast.h"
#include "dyninstAPI/src/util.h"
#include "dyninstAPI/src/stats.h"
#include "dyninstAPI/src/showerror.h"
#include "dyninstAPI/src/instPoint.h"
#include "dyninstAPI/src/miniTramp.h"
#include "dyninstAPI/src/baseTramp.h"
#include "dyninstAPI/src/InstrucIter.h"
#include "dyninstAPI/src/function.h"
#include "dyninstAPI/src/image-func.h"
#include "dyninstAPI/src/arch.h"


/*
 * return the time required to execute the passed primitive.
 *
 */
unsigned getPrimitiveCost(const pdstring &name)
{

    static bool init=false;

    if (!init) { init = 1; initPrimitiveCost(); }

    if (!primitiveCosts.defines(name)) {
      return 1;
    } else
      return (primitiveCosts[name]);
}


// find any tags to associate semantic meaning to function
unsigned findTags(const pdstring ) {
  return 0;
#ifdef notdef
  if (tagDict.defines(funcName))
    return (tagDict[funcName]);
  else
    return 0;
#endif
}

// IA64 has its own version; dunno if this would work there, so skipping for now
unsigned generateAndWriteBranch(process *proc, 
                                Address fromAddr, 
                                Address newAddr,
                                unsigned fillSize)
{
    assert(fillSize != 0);

    codeGen gen(fillSize);

#if defined(os_aix)
    instruction::generateInterFunctionBranch(gen, fromAddr, newAddr);
#else
    instruction::generateBranch(gen, fromAddr, newAddr);
#endif
    gen.fillRemaining(codeGen::cgNOP);
    
    proc->writeTextSpace((caddr_t)fromAddr, gen.used(), gen.start_ptr());
    return gen.used();
}

unsigned trampEnd::maxSizeRequired() {
#if defined(arch_x86) || defined(arch_x86_64)
    unsigned illegalSize = 2;
#else
    unsigned illegalSize = instruction::size();
#endif
    // Return branch, illegal.
    return (instruction::maxJumpSize() + illegalSize);
}


trampEnd::trampEnd(multiTramp *multi, Address target) :
    multi_(multi), target_(target) 
{}

Address relocatedInstruction::originalTarget() const {
#if defined(cap_relocation)
    if (targetAddr_) return targetAddr_;
#else
    assert(targetAddr_ == 0);
#endif
  return insn->getTarget(origAddr_);
}

void relocatedInstruction::overrideTarget(Address newTarget) {
    targetOverride_ = newTarget;
}

#if defined (cap_unwind)
bool trampEnd::generateCode(codeGen &gen,
                            Address baseInMutatee,
                            UNW_INFO_TYPE ** unwindRegion ) 
#else
bool trampEnd::generateCode(codeGen &gen,
                            Address baseInMutatee,
                            UNW_INFO_TYPE ** /*unwindRegion*/ )
#endif
{
    generateSetup(gen, baseInMutatee);
    
    if (target_) {
        instruction::generateBranch(gen,
                                    gen.currAddr(baseInMutatee),
                                    target_);
    }
    // And a sigill insn
    instruction::generateIllegal(gen);
    
    size_ = gen.currAddr(baseInMutatee) - addrInMutatee_;
    generated_ = true;
    hasChanged_ = false;

#if defined( cap_unwind )
    /* The jump back is an zero-length ALIAS to the original location, followed
       by a no-op region covering the jump bundle. */
    dyn_unw_printf( "%s[%d]: aliasing tramp end to 0x%lx\n", __FILE__, __LINE__, multi_->instAddr() );
    unw_dyn_region_info_t * aliasRegion = (unw_dyn_region_info_t *)malloc( _U_dyn_region_info_size( 2 ) );
    assert( aliasRegion != NULL );
    aliasRegion->insn_count = 0;
    aliasRegion->op_count = 2;
    
    _U_dyn_op_alias( & aliasRegion->op[0], _U_QP_TRUE, -1, multi_->instAddr() );
    _U_dyn_op_stop( & aliasRegion->op[1] );
    
    unw_dyn_region_info_t * jumpRegion = (unw_dyn_region_info_t *)malloc( _U_dyn_region_info_size( 1 ) );
    assert( jumpRegion != NULL );
#if defined( arch_ia64 )    
    jumpRegion->insn_count = (size_ / 16) * 3;
#else
#error How do I know how many instructions are in the jump region?
#endif /* defined( arch_ia64 ) */
    jumpRegion->op_count = 1;
    
    _U_dyn_op_stop( & jumpRegion->op[0] );
    
    /* The care and feeding of pointers. */
    assert( unwindRegion != NULL );
    unw_dyn_region_info_t * prevRegion = * unwindRegion;
    prevRegion->next = aliasRegion;
    aliasRegion->next = jumpRegion;
    jumpRegion->next = NULL;
    * unwindRegion = jumpRegion;
#endif /* defined( cap_unwind ) */
        
    return true;
}

instMapping::instMapping(const instMapping *parIM,
                         process *child) :
    func(parIM->func),
    inst(parIM->inst),
    where(parIM->where),
    when(parIM->when),
    order(parIM->order),
    useTrampGuard(parIM->useTrampGuard),
    mt_only(parIM->mt_only),
    allow_trap(parIM->allow_trap)
{
    for (unsigned i = 0; i < parIM->args.size(); i++) {
        args.push_back(assignAst(parIM->args[i]));
    }
    for (unsigned j = 0; j < parIM->miniTramps.size(); j++) {
        miniTramp *cMT = NULL;
        getInheritedMiniTramp(parIM->miniTramps[j],
                              cMT,
                              child);
        assert(cMT);
        miniTramps.push_back(cMT);
    }
}

Address relocatedInstruction::relocAddr() const {
    return addrInMutatee_;
}

void *relocatedInstruction::getPtrToInstruction(Address) const {
    assert(0); // FIXME if we do out-of-line baseTramps
    return NULL;
}

void *trampEnd::getPtrToInstruction(Address) const {
    assert(0); // FIXME if we do out-of-line baseTramps
    return NULL;
}

