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
 
// $Id: reloc-func.C,v 1.25 2006/06/16 16:13:36 bernat Exp $



#include "common/h/Types.h"
#include "function.h"
#include "process.h"
#include "showerror.h"
#include "codeRange.h"
#include "instPoint.h"
#include "multiTramp.h"
#include "InstrucIter.h"
#include "mapped_object.h"

class int_basicBlock;
class instruction;

// We'll also try to limit this to relocation-capable platforms
// in the Makefile. Just in case, though....
#if defined(cap_relocation)
#include "reloc-func.h"



// And happy fun time. Relocate a function: make a physical copy somewhere else
// in the address space that will execute as the original function did. 
// This creates a somewhat inefficient new version; relocation is done
// for correctness, not efficiency.

// Input: a list of things to change when we relocate the function.

// TODO: which version do we relocate? ;)

// 29.Nov.05 Okay, so things just got a little trickier. When relocating
// a function, co-owner functions (those that share blocks with this function)
// must also be relocated if we will overwrite any of the shared blocks.

bool int_function::relocationGenerate(pdvector<funcMod *> &mods,
                                      int sourceVersion /* = 0 */,
                                      pdvector< int_function *> &needReloc)
{
    bool ret;

#if defined(os_aix)
    // Once we've relocated once, we're good... there's a new function version
    // near the heap. The code will blithely relocate a bazillion times, too. 
    if (version() > 0)
        return true;
#endif

    // process this function (with mods)
    ret = relocationGenerateInt(mods,sourceVersion,needReloc);

    // process all functions in needReloc list -- functions that have
    // been previously processed or actually relocated (installed and
    // linked) must be skipped!

    for(unsigned i = 0; i < needReloc.size(); i++)
    {
        // if the function has previously been relocated (any stage,
        // not just installed and linked), skip.
        if(needReloc[i]->generatedVersion_ > 0)
        {
            reloc_printf("Skipping dependant relocation of %s: function already relocated\n",
                         needReloc[i]->prettyName().c_str());
            needReloc[i] = needReloc.back();
            needReloc.pop_back();
            i--; // reprocess  
        }
        else
        {
            reloc_printf("Forcing dependant relocation of %p\n",
                         needReloc[i]);
            // always version 0?
            ret &= needReloc[i]->relocationGenerateInt(
                                            needReloc[i]->enlargeMods(),
                                            0,needReloc);
        }
    }

    return ret;
}

bool int_function::relocationGenerateInt(pdvector<funcMod *> &mods, 
                                      int sourceVersion,
                                      pdvector<int_function *> &needReloc) {
    unsigned i;

    if(!canBeRelocated()) {
        return false;
    }
   
    // If we call this function, we *probably* want to relocate whether
    // or not we need to actually modify anything. 
    //if (mods.size() == 0)
    //    return true;

    assert(sourceVersion <= version_);
    if (generatedVersion_ > version_) {
        // Odd case... we generated, but never installed or
        // linked. Nuke the "dangling" version.
        relocationInvalidate();
    }

    generatedVersion_++;


    reloc_printf("Relocating function %s, version %d, 0x%lx, size: 0x%lx\n",
                 symTabName().c_str(), sourceVersion,
                 getAddress(), getSize_NP());

    // Make sure the blocklist is created.
    blocks(); 

    // Make the basic block instances; they're placeholders for now.
    pdvector<bblInstance *> newInstances;
    for (i = 0; i < blockList.size(); i++) {
        reloc_printf("Block %d, creating instance...", i);
        bblInstance *newInstance = new bblInstance(blockList[i], generatedVersion_);
        assert(newInstance);
        newInstances.push_back(newInstance);
        blockList[i]->instances_.push_back(newInstance);
        reloc_printf("and added to basic block\n");
    }
    assert(newInstances.size() == blockList.size());

    // Whip through them and let people play with the sizes.
    // We can also keep a tally of how much space we'll need while
    // we're at it...
    unsigned size_required = 0;
    for (i = 0; i < newInstances.size(); i++) {
        reloc_printf("Calling relocationSetup on block %d...\n",
                     i);
        reloc_printf("Calling newInst:relocationSetup(%d)\n",
                     sourceVersion);
        newInstances[i]->relocationSetup(blockList[i]->instVer(sourceVersion),
                                         mods);
        size_required += newInstances[i]->sizeRequired();
        reloc_printf("After block %d, %d bytes required\n",
                     i, size_required);
    }

    // AIX: we try to target the data heap, since it's near instrumentation; 
    // we can do big branches at the start of a function, but not within. 
    // So amusingly, function relocation probably won't _enlarge_ the function,
    // just pick it up and move it nearer instrumentation. Bring the mountain 
    // to Mohammed, I guess.
#if defined(os_aix)
    // Also, fork() instrumentation needs to go in data.
    Address baseInMutatee = proc()->inferiorMalloc(size_required, dataHeap);
#elif defined(arch_x86_64)
    Address baseInMutatee = proc()->inferiorMalloc(size_required, anyHeap, getAddress());
#else
    // We're expandin'
    Address baseInMutatee = proc()->inferiorMalloc(size_required);
#endif

    if (!baseInMutatee) return false;
    reloc_printf("... new version at 0x%lx in mutatee\n", baseInMutatee);

    Address currAddr = baseInMutatee;
    // Inefficiency, part 1: we pin each block at a particular address
    // so that we can one-pass generate and get jumps done correctly.
    for (i = 0; i < newInstances.size(); i++) {
        reloc_printf("Pinning block %d to 0x%lx\n", i, currAddr);
        newInstances[i]->setStartAddr(currAddr);
        currAddr += newInstances[i]->sizeRequired();
    }

    // Okay, so we have a set of "new" basicBlocks. Now go through and
    // generate code for each; we can do branches appropriately, since
    // we know where the targets will be.
    // This builds the codeGen member of the bblInstance
    bool success = true;
    for (i = 0; i < newInstances.size(); i++) {
        reloc_printf("... relocating block %d\n", blockList[i]->id());
        success &= newInstances[i]->generate();
        if (!success) break;
    }

    if (!success) {
        relocationInvalidate();
        return false;
    }

    // We use basicBlocks as labels.
    // TODO Since there is only one entry block to any function and the
    // image_function knows what it is, maybe it should be available at
    // this level so we didn't have to do all this.
    for (i = 0; i < blockList.size(); i++) {
        if (!blockList[i]->needsJumpToNewVersion()) continue;
        functionReplacement *funcRep = new functionReplacement(blockList[i], 
                                                             blockList[i],
                                                             sourceVersion,
                                                             generatedVersion_);
        if (funcRep->generateFuncRep(needReloc))
            blockList[i]->instVer(generatedVersion_)->jumpToBlock() = funcRep;
        else
            success = false;
    }

    return success;
}

bool int_function::relocationInstall() {

    // Okay, we now have a new copy of the function. Go through 
    // the version to be replaced, and replace each basic block
    // with a "jump to new basic block" combo.
    // If we overlap a bbl (which we probably will), oops.
    unsigned i;

    if (installedVersion_ == generatedVersion_)
        return true; // Nothing to do here...

    bool success = true;
    for (i = 0; i < blockList.size(); i++) {
        success &= blockList[i]->instVer(generatedVersion_)->install();
        if (!success) break;
        
        // Add all the basicBlocks to the process data range...
        proc()->addCodeRange(blockList[i]->instVer(generatedVersion_));
        addBBLInstance(blockList[i]->instVer(generatedVersion_));
    }
    if (!success) {
        fprintf(stderr, "Warning: installation of relocated function failed\n");
        return false;
    }

    installedVersion_ = generatedVersion_;
    version_ = installedVersion_;

    // Fix up all of our instPoints....
    // This will cause multiTramps, etc. to be built in the new
    // version of the function.  
    for (i = 0; i < entryPoints_.size(); i++)
        entryPoints_[i]->updateInstances();
    for (i = 0; i < exitPoints_.size(); i++)
        exitPoints_[i]->updateInstances();
    for (i = 0; i < callPoints_.size(); i++)
        callPoints_[i]->updateInstances();
    for (i = 0; i < arbitraryPoints_.size(); i++)
        arbitraryPoints_[i]->updateInstances();

    return success;
}

bool int_function::relocationCheck(pdvector<Address> &checkPCs) {
    unsigned i;

    assert(generatedVersion_ == installedVersion_);
    if (installedVersion_ == installedVersion_)
        return true;
    for (i = 0; i < blockList.size(); i++) {
        if (!blockList[i]->instVer(installedVersion_)->check(checkPCs))
            return false;
    }
    return true;
}
        

bool int_function::relocationLink(pdvector<codeRange *> &overwritten_objs) {

    unsigned i;

    if (linkedVersion_ == installedVersion_) {
        assert(linkedVersion_ == version_);
        return true; // We're already done...
    }

    // If the assert fails, then we linked but did not
    // update the global function version. That's _BAD_.

    bool success = true;
    for (i = 0; i < blockList.size(); i++) {
        success &= blockList[i]->instVer(installedVersion_)->link(overwritten_objs);
        if (!success)
            break;
    }
    if (!success) {
        // Uh oh...
        fprintf(stderr, "ERROR: linking relocated function failed!\n");
        assert(0);
    }

    linkedVersion_ = installedVersion_;
    assert(linkedVersion_ == version_);

    return true;
}

bool int_function::relocationInvalidate() {
    unsigned i;
    // The increase pattern goes like so:
    // generatedVersion_++;
    // installedVersion_++;
    // version_++; -- so that instpoints will be updated
    // linkedVersion_++;
    reloc_printf("%s[%d]: relocationInvalidate for %s: linkedVersion %d, installedVersion %d, generatedVersion %d, version %d\n",
                 FILE__, __LINE__, symTabName().c_str(), 
                 linkedVersion_,
                 installedVersion_,
                 generatedVersion_,
                 version_);

    assert(generatedVersion_ >= installedVersion_);
    assert(installedVersion_ >= version_);
    assert(version_ >= linkedVersion_);

    if (generatedVersion_ == linkedVersion_) {
        reloc_printf("%s[%d]: nothing to do, returning\n",
                     FILE__, __LINE__);
        return true;
    }

    while (installedVersion_ > linkedVersion_) {
        reloc_printf("******* Removing installed version %d\n",
                     installedVersion_);
        for (i = 0; i < blockList.size(); i++) {
            reloc_printf("%s[%d]: Removing installed version %d of block %d\n",
                         FILE__, __LINE__, installedVersion_, i);
            bblInstance *instance = blockList[i]->instVer(installedVersion_);
            assert(instance);
            proc()->deleteCodeRange(instance->firstInsnAddr());
            deleteBBLInstance(instance);
            // Nuke any attached multiTramps...
            multiTramp *multi = proc()->findMultiTramp(instance->firstInsnAddr());
            if (multi)
                delete multi;
        }
        installedVersion_--;
    }
    
    while (generatedVersion_ > installedVersion_) {
        reloc_printf("******* Removing generated version %d\n",
                     generatedVersion_);
        proc()->inferiorFree(blockList[0]->instVer(generatedVersion_)->firstInsnAddr());
        for (i = 0; i < blockList.size(); i++) {
            reloc_printf("%s[%d]: Removing generated version %d of block %d\n",
                         FILE__, __LINE__, generatedVersion_, i);
            blockList[i]->removeVersion(generatedVersion_);
        }
        generatedVersion_--;
    }
    version_ = linkedVersion_;

    reloc_printf("%s[%d]: version %d, linked %d, installed %d, generated %d\n",
                 FILE__, __LINE__, version_, linkedVersion_, installedVersion_, generatedVersion_);
    for (i = 0; i < blockList.size(); i++) {
        reloc_printf("%s[%d]: block %d has %d versions\n",
                     FILE__, __LINE__, i, blockList[i]->instances().size());
    }

    for (i = 0; i < entryPoints_.size(); i++)
        entryPoints_[i]->updateInstances();
    for (i = 0; i < exitPoints_.size(); i++)
        exitPoints_[i]->updateInstances();
    for (i = 0; i < callPoints_.size(); i++)
        callPoints_[i]->updateInstances();
    for (i = 0; i < arbitraryPoints_.size(); i++)
        arbitraryPoints_[i]->updateInstances();

    return true;
}

bool int_function::expandForInstrumentation() {
    unsigned i;
    // Take the most recent version of the function, check the instPoints
    // registered. If one needs more room, create an expansion record.
    // When we're done, relocate the function (most recent version only).

    // Oh, only do that if there's instrumentation added at the point?
    reloc_printf("Function expandForInstrumentation, version %d\n",
                 version_);
    // Right now I'm basing everything off version 0; that is, if we
    // relocate multiple times, we will have discarded versions instead
    // of a long chain. 

    if (!canBeRelocated()) {
        return false;
    }

    for (i = 0; i < blockList.size(); i++) {
        bblInstance *bblI = blockList[i]->origInstance();
        assert(bblI->block() == blockList[i]);
        // Simplification: check if there's a multiTramp at the block.
        // If there isn't, then we don't care.
        multiTramp *multi = proc()->findMultiTramp(bblI->firstInsnAddr());
        if (!multi) continue;
        if (bblI->getSize() < multi->sizeDesired()) {
            reloc_printf("Enlarging basic block %d\n",
                         i);
            pdvector<bblInstance::reloc_info_t::relocInsn *> whocares;
            bool found = false;
            // Check to see if there's already a request for it...
            for (unsigned j = 0; j < enlargeMods_.size(); j++) {
                if (enlargeMods_[j]->update(bblI->block(), 
                                            whocares,
                                            multi->sizeDesired())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                // Didn't find it...
                enlargeBlock *mod = new enlargeBlock(bblI->block(), multi->maxSizeRequired());
                enlargeMods_.push_back(mod);
            }
        }
    }
    return true;
}

// Return the absolute maximum size required to relocate this
// block somewhere else. If this looks very familiar, well, 
// _it is_. We should unify the instruction and relocatedInstruction
// classes.
// This is a bit inefficient, since we rapidly use and delete
// relocatedInstructions... ah, well :)
unsigned bblInstance::sizeRequired() {
    assert(getMaxSize());
    return getMaxSize();
}


// Make a copy of the basic block (from the original provided),
// applying the modifications stated in the vector of funcMod
// objects.

bool bblInstance::relocationSetup(bblInstance *orig, pdvector<funcMod *> &mods) {
   unsigned i;
   origInstance() = orig;
   assert(origInstance());
   // First, build the insns vector

   for (i = 0; i < relocs().size(); i++) {
     delete relocs()[i];
   }

   relocs().clear();

   // Keep a running count of how big things are...
   maxSize() = 0;
   InstrucIter insnIter(orig);
   while (insnIter.hasMore()) {
     instruction *insnPtr = insnIter.getInsnPtr();
     assert(insnPtr);
     reloc_info_t::relocInsn *reloc = new reloc_info_t::relocInsn;

     reloc->origAddr = *insnIter;
     reloc->relocAddr = 0;
     reloc->origInsn = insnPtr;
     reloc->origPtr = insnPtr->ptr();
     reloc->relocTarget = 0;
     reloc->relocSize = 0;

     relocs().push_back(reloc);

     maxSize() += insnPtr->spaceToRelocate();
     insnIter++;
   }

   // Apply any hanging-around relocations from our previous instance
    for (i = 0; i < orig->appliedMods().size(); i++) {
      if (orig->appliedMods()[i]->modifyBBL(block_, relocs(), maxSize())) {
	appliedMods().push_back(orig->appliedMods()[i]);
      }
    }

    // So now we have a rough size and a list of insns. See if any of
    // those mods want to play.
    for (i = 0; i < mods.size(); i++) {
        if (mods[i]->modifyBBL(block_, relocs(), maxSize())) {
            // Store for possible further relocations.
            appliedMods().push_back(mods[i]);
        }
    }

    return true;
}

void bblInstance::setStartAddr(Address addr) {
    if (addr) {
        // No implicit overriding - set it to 0 first.
        assert(firstInsnAddr_ == 0);
        firstInsnAddr_ = addr;
    }
    else {
        firstInsnAddr_ = 0;
    }
}

bool bblInstance::generate() {
    assert(firstInsnAddr_);
    assert(relocs().size());
    assert(maxSize());
    assert(block_);
    assert(origInstance());
    unsigned i;

    generatedBlock().allocate(maxSize());

    Address origAddr = origInstance()->firstInsnAddr();
    for (i = 0; i < relocs().size(); i++) {
      Address currAddr = generatedBlock().currAddr(firstInsnAddr_);
      relocs()[i]->relocAddr = currAddr;
      Address fallthroughOverride = 0;
      Address targetOverride = 0;
      if (i == (relocs().size()-1)) {
	// Check to see if we need to fix up the target....
	pdvector<int_basicBlock *> targets;
	block_->getTargets(targets);
	if (targets.size() > 2) {
	  // Multiple jump... we can't handle this yet
            // Actually, I believe we can....
            reloc_printf("WARNING: attempt to relocate function %s with indirect jump!\n",
                         block_->func()->symTabName().c_str());
            //return false;
	}
	// We have edge types on the internal data, so we drop down and get that. 
	// We want to find the "branch taken" edge and override the destination
	// address for that guy.
	pdvector<image_edge *> out_edges;
	block_->llb()->getTargets(out_edges);
	
	// May be greater; we add "extra" edges for things like function calls, etc.
	assert (out_edges.size() >= targets.size());
	
	int_basicBlock *hlTarget = NULL;
	
	for (unsigned edge_iter = 0; edge_iter < out_edges.size(); edge_iter++) {
	  EdgeTypeEnum edgeType = out_edges[edge_iter]->getType();
	  // Update to Nate's commit...
	  if ((edgeType == ET_COND_TAKEN) ||
	      (edgeType == ET_DIRECT)) {
	    // Got the right edge... now find the matching high-level
	    // basic block
	    image_basicBlock *llTarget = out_edges[edge_iter]->getTarget();
	    for (unsigned t_iter = 0; t_iter < targets.size(); t_iter++) {
	      // Should be the same index, but this is a small set...
	      if (targets[t_iter]->llb() == llTarget)
		hlTarget = targets[t_iter];
	    }
	    assert(hlTarget != NULL);
	    break;
	  }
	}
	if (hlTarget != NULL) {
	  // Remap its destination
	  // This is a jump target; get the start addr for the
	  // new block.
	  assert(targetOverride == 0);
	  targetOverride = hlTarget->instVer(version_)->firstInsnAddr();
	  reloc_printf("... found jmp target 0x%lx->0x%lx, now to 0x%lx\n",
		       origInstance()->endAddr(),
		       hlTarget->origInstance()->firstInsnAddr(),
		       targetOverride);
	}
      }
      reloc_printf("... generating insn %d, orig addr 0x%lx, new addr 0x%lx, " 
		   "fallthrough 0x%lx, target 0x%lx\n",
		   i, origAddr, currAddr, fallthroughOverride, targetOverride);
      unsigned usedBefore = generatedBlock().used();
      relocs()[i]->origInsn->generate(generatedBlock(),
				      proc(),
				      origAddr,
				      currAddr,
				      fallthroughOverride,
				      targetOverride); // targetOverride

      relocs()[i]->relocTarget = targetOverride;
      
      // And set the remaining bbl variables correctly
      // This may be overwritten multiple times, but will end
      // correct.
      lastInsnAddr_ = currAddr;

      relocs()[i]->relocSize = generatedBlock().used() - usedBefore;
      
      origAddr += relocs()[i]->origInsn->size();
    }


    generatedBlock().fillRemaining(codeGen::cgNOP);


    blockEndAddr_ = firstInsnAddr_ + maxSize();

    relocs().back()->relocSize = blockEndAddr_ - lastInsnAddr_;
    
    // Post conditions
    assert(firstInsnAddr_);
    assert(lastInsnAddr_);
    assert(blockEndAddr_);
    
    return true;
}

bool bblInstance::install() {
    assert(firstInsnAddr_);
    assert(generatedBlock() != NULL);
    assert(maxSize());
    if (maxSize() != generatedBlock().used()) {
        fprintf(stderr, "ERROR: max size of block is %d, but %d used!\n",
                maxSize(), generatedBlock().used());
    }
    assert(generatedBlock().used() == maxSize());

    reloc_printf("(%d) Writing from 0x%lx 0x%lx to 0x%lx 0x%lx\n",
                 proc()->getPid(),
                 generatedBlock().start_ptr(), 
                 (long) generatedBlock().start_ptr() + generatedBlock().used(),
                 firstInsnAddr_,
                 firstInsnAddr_ + generatedBlock().used());
    
    bool success = proc()->writeTextSpace((void *)firstInsnAddr_,
                                          generatedBlock().used(),
                                          generatedBlock().start_ptr());
    if (success) {
        return true;
    }
    else 
        return false;
}

bool bblInstance::check(pdvector<Address> &checkPCs) {
    if (!getJumpToBlock()) return true;
    return jumpToBlock()->checkFuncRep(checkPCs);
}

bool bblInstance::link(pdvector<codeRange *> &overwrittenObjs) {
    if (!getJumpToBlock()) return true;
    return jumpToBlock()->linkFuncRep(overwrittenObjs);
}

bool enlargeBlock::modifyBBL(int_basicBlock *block,
                             pdvector<bblInstance::reloc_info_t::relocInsn *> &,
                             unsigned &size)
{
    if (block == targetBlock_) {
        if (targetSize_ == (unsigned) -1) {
            return true;
        }

        if (size < targetSize_) {
            size = targetSize_;
        }

        return true;
    }
    return false;
}

bool enlargeBlock::update(int_basicBlock *block,
                          pdvector<bblInstance::reloc_info_t::relocInsn *> &,
                          unsigned size) {
    if (block == targetBlock_) {
        if (size == (unsigned) -1) {
            // Nothing we can do about it, we're just fudging...
            return true;
        }
        targetSize_ = (targetSize_ > size) ? targetSize_ : size;
        return true;
    }
    return false;
}


#endif // cap_relocation

functionReplacement::functionReplacement(int_basicBlock *sourceBlock,
                                         int_basicBlock *targetBlock,
                                         unsigned sourceVersion /* =0 */,
                                         unsigned targetVersion /* =0 */) :
    sourceBlock_(sourceBlock),
    targetBlock_(targetBlock),
    sourceVersion_(sourceVersion),
    targetVersion_(targetVersion),
    overwritesMultipleBlocks_(false) 
{}
    
Address functionReplacement::get_address_cr() const {
    assert(sourceBlock_);
    return sourceBlock_->instVer(sourceVersion_)->firstInsnAddr();
}

unsigned functionReplacement::get_size_cr() const {
    if (jumpToRelocated != NULL)
        return jumpToRelocated.used();
    else
        return 0;
}

// Dig down to the low-level block of b, find the low-level functions
// that share it, and map up to int-level functions and add them
// to the funcs list.
void int_function::getSharingFuncs(int_basicBlock *b,
                                   pdvector< int_function *> & funcs)
{
    if(!b->hasSharedBase())
        return;

    pdvector<image_func *> lfuncs;

    b->llb()->getFuncs(lfuncs);
    for(unsigned i=0;i<lfuncs.size();i++) {
        image_func *ll_func = lfuncs[i];
        int_function *hl_func = obj()->findFunction(ll_func);
        assert(hl_func);

        if (hl_func == this) continue;

        // Let's see if we've already got it...
        bool found = false;
        for (unsigned j = 0; j < funcs.size(); j++) {
            if (funcs[j] == hl_func) {
                found = true;
                break;
            }
        }
        if (!found)
            funcs.push_back(hl_func);
    }
}

// Will potentially append to needReloc (indicating that
// other functions must be relocated)
bool functionReplacement::generateFuncRep(pdvector<int_function *> &needReloc)
{
    assert(sourceBlock_);
    assert(targetBlock_);
    assert(jumpToRelocated == NULL);

#if !defined(cap_relocation)
    assert(sourceVersion_ == 0);
    assert(targetVersion_ == 0);
#endif

    // TODO: if check modules and do ToC if not the same one.

    bblInstance *sourceInst = sourceBlock_->instVer(sourceVersion_);
    assert(sourceInst);
    bblInstance *targetInst = targetBlock_->instVer(targetVersion_);
    assert(targetInst);

    jumpToRelocated.allocate(instruction::maxInterFunctionJumpSize());
    reloc_printf("******* generating interFunctionJump from 0x%lx (%d) to 0x%lx (%d)\n",
		 sourceInst->firstInsnAddr(),
		 sourceVersion_,
		 targetInst->firstInsnAddr(),
		 targetVersion_);

    instruction::generateInterFunctionBranch(jumpToRelocated,
                                             sourceInst->firstInsnAddr(),
                                             targetInst->firstInsnAddr());

    // Determine whether relocation of this function will force relocation
    // of any other functions:
    // If the inter-function jump will overwrite any shared blocks,
    // the "co-owner" functions that are associated with those blocks
    // must be relocated before the jump can be written.
    //

    if(sourceBlock_->hasSharedBase() && 0)
    {
        // if this entry block is shared...
        sourceBlock_->func()->getSharingFuncs(sourceBlock_,
                                              needReloc);
    }

    if (jumpToRelocated.used() > sourceInst->getSize()) {
        // Okay, things are going to get ugly. There are two things we
        // can't do:
        // 1) Overwrite another entry point
        // 2) Overwrite a different function
        // So start seeing where this jump is going to run into...
        
        // FIXME there seems to be something fundamentally unsound about
        // going ahead and installing instrumentation over the top of
        // other functions! 
	//
	// And so, now, we don't.  Return false in this case, and in the
	// case where we would normally write into unclaimed space.
	//
        unsigned overflow = jumpToRelocated.used() - sourceInst->getSize();
        Address currAddr = sourceInst->endAddr();

        while (overflow > 0) {
            bblInstance *curInst = sourceBlock_->func()->findBlockInstanceByAddr(currAddr);
            if (curInst) {
                // Okay, we've got another block in this function. Check
                // to see if it's shared.
                if (curInst->block()->hasSharedBase()) {
		  // This can get painful. If we're the entry block for another
		  // function (e.g., __write_nocancel on Linux), we _really_ don't
		  // want to be writing a jump here. So, check to see if the
		  // internal block is an entry for a function that is _not_ us.
		  image_func *possibleEntry = curInst->block()->llb()->getEntryFunc();
		  if (possibleEntry != sourceBlock_->func()->ifunc()) {
		    // Yeah, this ain't gonna work
		    return false;
		  }

		  // add functions to needReloc list
		  curInst->block()->func()->getSharingFuncs(curInst->block(),
							    needReloc);
                } 

                if (curInst->block()->needsJumpToNewVersion()) {
                    // Ooopsie... we're going to stop on another block
                    // that jumps over. This we cannot do.
                    return false;
                }

                // Otherwise keep going
                // Inefficient...
                currAddr = curInst->endAddr();
                if (curInst->getSize() > overflow)
                    overflow = 0;
                else
                    overflow -= curInst->getSize();
            }
            else {
                // Ummm... see if anyone else claimed this space.

                // NTS: we want any basic block that matches this address range
                // as part of any image in the proc(). hmmmm.... this means
                // that the process needs to have knowledge of all
                // int_basicBlocks.
                int_basicBlock *block =
                        sourceBlock_->proc()->findBasicBlockByAddr(currAddr);

                if(block)
                {
                    // Consistency check...
                    assert(block->func() != sourceBlock_->func());
		    return false;
                }
                else {
                    // Ummm... empty space.  Let's not try to write here.
		    return false;
                }
            }
        }
        overwritesMultipleBlocks_ = true;
    }
    return true;
}

bool functionReplacement::installFuncRep() {
  // Nothing to do here unless we go to a springboard model.
return true;
}

// TODO: jumps that overwrite multiple basic blocks...
bool functionReplacement::checkFuncRep(pdvector<Address> &checkPCs) {
    unsigned i;

    Address start = get_address_cr();
    Address end = get_address_cr() + get_size_cr();
    for (i = 0; i < checkPCs.size(); i++) {
        if ((checkPCs[i] > start) &&
            (checkPCs[i] < end))
            return false;
    }
    return true;
}

bool functionReplacement::linkFuncRep(pdvector<codeRange *> &overwrittenObjs) {
    if (sourceBlock_->proc()->writeTextSpace((void *)get_address_cr(),
                                             jumpToRelocated.used(),
                                             jumpToRelocated.start_ptr())) {
        sourceBlock_->proc()->addFunctionReplacement(this,
                                       overwrittenObjs);
        return true;
    }
    else
        return false;
}


// If we're an entry block, we need a jump (to catch the
// entry point). Also true if we are the target of an indirect jump.

bool int_basicBlock::needsJumpToNewVersion() {
    if (isEntryBlock())
        return true;
    
    assert(ib_);
    pdvector<int_basicBlock *> sources;
    getSources(sources);
    for (unsigned i = 0; i < sources.size(); i++) {
        if (getSourceEdgeType(sources[i]) == ET_INDIR)
            return true;
    }
    return false;
}
    

