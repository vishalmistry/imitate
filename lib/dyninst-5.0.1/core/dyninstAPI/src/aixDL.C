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

// $Id: aixDL.C,v 1.72 2006/05/16 21:14:34 jaw Exp $

#include "dyninstAPI/src/mapped_object.h"
#include "dyninstAPI/src/dynamiclinking.h"
#include "dyninstAPI/src/process.h"
#include "dyninstAPI/src/dyn_lwp.h"
#include "dyninstAPI/src/instPoint.h"
#include "dyninstAPI/src/symtab.h"
#include "dyninstAPI/src/arch.h"
#include "dyninstAPI/src/inst-power.h"
#include "dyninstAPI/src/InstrucIter.h"
#include "dyninstAPI/src/miniTramp.h"
#include "common/h/debugOstream.h"
#include <sys/ptrace.h>
#include <sys/ldr.h>


bool dynamic_linking::initialize() {
    // Since we read out of /proc/.../map, there is nothing to do here

    dynlinked = true;
    return true;
}

bool dynamic_linking::installTracing() {
    // We capture dlopen/dlclose by overwriting the return address
    // of their worker functions (load1 for dlopen, dlclose is TODO).
    // We get this from the (already-parsed) listing of libc.

  // Should check only libc.a...

  AstNode *retval = new AstNode(AstNode::ReturnVal, (void *)0);
  instMapping *loadInst = new instMapping("load1", "DYNINST_instLoadLibrary",
					  FUNC_EXIT | FUNC_ARG,
					  retval);
  instMapping *unloadInst = new instMapping("unload", "DYNINST_instLoadLibrary",
                                            FUNC_EXIT | FUNC_ARG,
                                            retval);
  
  loadInst->dontUseTrampGuard();
  unloadInst->dontUseTrampGuard();

  removeAst(retval);
  pdvector<instMapping *>instReqs;
  instReqs.push_back(loadInst);
  instReqs.push_back(unloadInst);
  proc->installInstrRequests(instReqs);
  if (loadInst->miniTramps.size()) {
      sharedLibHook *sharedHook = new sharedLibHook(proc, SLH_UNKNOWN,
                                                    loadInst);
      sharedLibHooks_.push_back(sharedHook);
      instru_based = true;
  }
  if (unloadInst->miniTramps.size()) {
      sharedLibHook *sharedHook = new sharedLibHook(proc, SLH_UNKNOWN,
                                                    unloadInst);
      sharedLibHooks_.push_back(sharedHook);
      instru_based = true;
  }

  if (sharedLibHooks_.size())
      return true;
  else
      return false;


#if 0
      // Seriously deprecated
      const pdvector<mapped_object *> &objs = proc->mappedObjects();
      
      // Get libc
      mapped_object *libc = NULL;
      for (unsigned i = 0; i < objs.size(); i++) {
          const fileDescriptor &desc = objs[i]->getFileDesc();
          if ((objs[i]->fileName().suffixed_by("libc.a")) &&
              (desc.member() == "shr.o")) {
              libc = (objs[i]);
          }
      }
      assert(libc);
    
      // Now, libc may have been parsed... in which case we pull the function vector
      // from it. If not, we parse it manually.
      
      const pdvector<int_function *> *loadFuncs = libc->findFuncVectorByPretty(pdstring("load1"));
      assert(loadFuncs);
      assert(loadFuncs->size() > 0);
      
      int_function *loadFunc = (*loadFuncs)[0];
      assert(loadFunc);
      
    // There is no explicit place to put a trap, so we'll replace
    // the final instruction (brl) with a trap, and emulate the branch
    // mutator-side
    //
    //  JAW-- Alas this only works on AIX < 5.2.  The AIX 5.2 version of 
    //  load1 has 2 'blr' exit points, and we really want the first one.
    //  the last one is (apparently) the return that is used when there is
    //  is a failure.
    //
    // We used to find multiple exit points in findInstPoints. Now that
    // Laune's got a new version, we don't hack that any more. Instead, we
    // read in the function image, find the blr instructions, and overwrite
    // them by hand. This should be replaced with either a) instrumentation
    // or b) a better hook (aka r_debug in Linux/Solaris)

    InstrucIter funcIter(loadFunc);

    while (*funcIter) {
        instruction insn = funcIter.getInstruction();

        if (insn.raw() == BRraw) {
            sharedLibHook *sharedHook = new sharedLibHook(proc, SLH_UNKNOWN, 
                                                          *funcIter);
            sharedLibHooks_.push_back(sharedHook);
        }
        funcIter++;
    }
  }
#endif
}

// If result has entries, use them as a base (don't double-create)
bool dynamic_linking::processLinkMaps(pdvector<fileDescriptor> &result)
{
    // First things first, get a list of all loader info structures.
    int pid;

    pid = proc->getPid();
    
    prmap_t mapEntry;
    int iter = 0; // Starting with the a.out is _just fine_.

    bool is_aout = true;
    
    // We want to fill in this vector.

    int mapfd = proc->getRepresentativeLWP()->map_fd();
    do {
        pread(mapfd, &mapEntry, sizeof(prmap_t), iter*sizeof(prmap_t));
        if (mapEntry.pr_size != 0) {
            prmap_t next;
            pread(mapfd, &next, sizeof(prmap_t), (iter+1)*sizeof(prmap_t));
            if (strcmp(mapEntry.pr_mapname, next.pr_mapname)) {
                // Must only have a text segment (?)
                next.pr_vaddr = 0;
                iter++;
            }
            else {
                iter += 2;
            }
            
            char objname[256];
            if (mapEntry.pr_pathoff) {
                pread(mapfd, objname, 256,
                      mapEntry.pr_pathoff);
            }
            else {
                objname[0] = objname[1] = objname[2] = 0;
            }
 
            Address textOrg = (Address) mapEntry.pr_vaddr;
            Address dataOrg = (Address) next.pr_vaddr;
            
            // Round up to next multiple of wordsize;
            
            if (textOrg % sizeof(unsigned))
                textOrg += sizeof(unsigned) - (textOrg % sizeof(unsigned));
            if (dataOrg % sizeof(unsigned))
                dataOrg += sizeof(unsigned) - (dataOrg % sizeof(unsigned));
            
			fileDescriptor fda;

			if (is_aout) {
				char buf[256];
				sprintf(buf, "/proc/%d/object/a.out", proc->getPid());
				fda = fileDescriptor(buf, textOrg, dataOrg, false);
				fda.setMember(objname);
			}
			else {
           		fda = fileDescriptor(objname, 
                                     textOrg, dataOrg,
                                     true);
                fda.setMember(objname+strlen(objname)+1);
            }
            //fda.setPid(pid);

            result.push_back(fda);

            is_aout = false;
        }
        
    } while (mapEntry.pr_size != 0);    
    return true;
}

bool dynamic_linking::decodeIfDueToSharedObjectMapping(EventRecord &ev,
                                                       u_int & /* change_type */) 
{
    assert(ev.lwp);
    dyn_lwp *brk_lwp = ev.lwp;
    sharedLibHook *hook = NULL;
    
    Frame brk_frame = brk_lwp->getActiveFrame();
    hook = reachedLibHook(brk_frame.getPC());
   
    if (!hook) {
      return false;
    }

    pdvector<fileDescriptor> newfds;
    if (! didLinkMapsChange((u_int &)ev.what, newfds)) {
      fprintf(stderr, "%s[%d]:  link maps not changed\n", FILE__, __LINE__);
      return false;
    }

   return true;
}

// handleIfDueToSharedObjectMapping: returns true if the trap was caused
// by a change to the link maps
// p - process we're dealing with
// changed_objects -- set to list of new objects
// change_type -- set to 1 if added, 2 if removed
// error_occurred -- duh
// return value: true if there was a change to the link map,
// false otherwise
bool dynamic_linking::handleIfDueToSharedObjectMapping(EventRecord &ev,
                                                      pdvector<mapped_object *> &changed_objects)
{
    // We discover it by comparing sizes
    dyn_lwp *brk_lwp = instru_based ? NULL : ev.lwp;
    sharedLibHook *hook = NULL;

    if (!instru_based && brk_lwp) {
       Frame brk_frame = brk_lwp->getActiveFrame();
       hook = reachedLibHook(brk_frame.getPC());
    }

    if (force_library_load || hook || instru_based) {
        
        if (!findChangeToLinkMaps((u_int &) ev.what, 
                                  changed_objects))
            return false;
	if (brk_lwp) {
	  // Now we need to fix the PC. We overwrote the return instruction,
	  // so grab the value in the link register and set the PC to it.
	  dyn_saved_regs regs;
	  bool status = brk_lwp->getRegisters(&regs);
	  assert(status == true);
	  brk_lwp->changePC(regs.theIntRegs.__lr, NULL);
	  return true;
   }
	else
      return true;
    }
    return false;
}

sharedLibHook::sharedLibHook(process *p, sharedLibHookType t, Address b) 
        : proc_(p), type_(t), breakAddr_(b), loadinst_(NULL) {

    // Before putting in the breakpoint, save what is currently at the
    // location that will be overwritten.
    proc_->readDataSpace((void *)breakAddr_, SLH_SAVE_BUFFER_SIZE,
                         (void *)saved_, true);

    codeGen gen(instruction::size());
    instruction::generateTrap(gen);
    
    if (!proc_->writeDataSpace((caddr_t)breakAddr_,
                          gen.used(),
                          gen.start_ptr()))
        fprintf(stderr, "%s[%d]:  writeDataSpace failed\n", FILE__, __LINE__);
    
}

sharedLibHook::sharedLibHook(process *p, sharedLibHookType t, instMapping *inst) 
        : proc_(p), type_(t), breakAddr_(0), loadinst_(inst) {
}

sharedLibHook::~sharedLibHook() {
    if (!proc_->isAttached() || proc_->execing())
        return;
    
    if (breakAddr_)
        if (!proc_->writeDataSpace((void *)breakAddr_, SLH_SAVE_BUFFER_SIZE, saved_))
          fprintf(stderr, "%s[%d]:  writeDataSpace failed\n", FILE__, __LINE__);
    else if (loadinst_) {
        miniTramp *handle;
        for (unsigned i = 0; i < loadinst_->miniTramps.size(); i++) {
            handle = loadinst_->miniTramps[i];
            handle->uninstrument();
        }
        delete loadinst_;
    }
}

