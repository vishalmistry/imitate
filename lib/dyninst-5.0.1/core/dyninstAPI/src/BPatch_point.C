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
#ifdef rs6000_ibm_aix4_1
#include <memory.h>
#endif

#include "common/h/headers.h"

#define BPATCH_FILE

#include "BPatch_point.h"
#include "BPatch_snippet.h"
#include "BPatch_type.h"
#include "BPatch_image.h"
#include "BPatch_function.h"
#include "BPatch_collections.h"
#include "BPatch_asyncEventHandler.h"
#include "BPatch.h"
#include "BPatch_process.h"
#include "BPatch_libInfo.h"
#include "process.h"
#include "symtab.h"
#include "instPoint.h"
#include "instP.h"
#include "baseTramp.h"
#include "miniTramp.h"
#include "InstrucIter.h"
#include "BPatch_edge.h"

/*
 * Private constructor, insn
 */
BPatch_point::BPatch_point(BPatch_process *_proc, BPatch_function *_func, instPoint *_point,
                           BPatch_procedureLocation _pointType) :
    // Note: MIPSPro compiler complains about redefinition of default argument
    proc(_proc), func(_func), point(_point), pointType(_pointType), memacc(NULL),
    dynamic_point_monitor_func(NULL),edge_(NULL)
{
    if (_pointType == BPatch_subroutine)
        dynamic_call_site_flag = 2; // dynamic status unknown
    else
        dynamic_call_site_flag = 0; // not a call site, so not a dynamic call site.
    // I'd love to have a "loop" constructor, but the code structure
    // doesn't work right. We create an entry point as a set of edge points,
    // but not all edge points are loop points.
    loop = NULL;
    
    // And check to see if there's already instrumentation there (from a fork, say)
    
    pdvector<miniTramp *> mts;
    
    // Preinsn
    // TODO: this will grab _everything_, including internal instrumentation.
    // We need a "type" flag on the miniTramp that specifies whether instru is
    // internal, BPatch-internal (dynamic monitoring), or user-added.

    baseTramp *bt = point->getBaseTramp(callPreInsn);
    miniTramp *mt = NULL;

    if (bt) mt = bt->firstMini;

    while (mt) {
        if (mt->instP() == point)
            mts.push_back(mt);
        mt = mt->next;
    }

    for(unsigned i=0; i<mts.size(); i++) {
        BPatchSnippetHandle *handle = new BPatchSnippetHandle(proc);
        handle->addMiniTramp(mts[i]);
        preSnippets.push_back(handle);
    }
    // And now post.
    mts.clear();
    mt = NULL;
    
    bt = point->getBaseTramp(callPostInsn);
    if (bt) mt = bt->firstMini;
    
    while (mt) {
        if (mt->instP() == point)
            mts.push_back(mt);
        mt = mt->next;
    }
    for(unsigned ii=0; ii<mts.size(); ii++) {
        BPatchSnippetHandle *handle = new BPatchSnippetHandle(proc);
        handle->addMiniTramp(mts[ii]);
        postSnippets.push_back(handle);
    }
}

/*
 * Private constructor, edge
 */
BPatch_point::BPatch_point(BPatch_process *_proc, BPatch_function *_func, 
                           BPatch_edge *_edge, instPoint *_point) :
    // Note: MIPSPro compiler complains about redefinition of default argument
    proc(_proc), func(_func), point(_point), pointType(BPatch_locInstruction), memacc(NULL),
    dynamic_call_site_flag(0), dynamic_point_monitor_func(NULL),edge_(_edge)
{
  // I'd love to have a "loop" constructor, but the code structure
  // doesn't work right. We create an entry point as a set of edge points,
  // but not all edge points are loop points.
  loop = NULL;
  // We override that later... also, a single edge could be multiple loops. We need
  // "virtual" points.   

  // And check to see if there's already instrumentation there (from a fork, say)

  pdvector<miniTramp *> mts;

  // Preinsn
  
  baseTramp *bt = point->getBaseTramp(callPreInsn);
  miniTramp *mt = NULL;
  if (bt) mt = bt->firstMini;

  while (mt) {
      if (mt->instP() == point)
          mts.push_back(mt);
      mt = mt->next;
  }
  
  for(unsigned i=0; i<mts.size(); i++) {
      BPatchSnippetHandle *handle = new BPatchSnippetHandle(proc);
      handle->addMiniTramp(mts[i]);
      preSnippets.push_back(handle);
  }
  // No post-insn

}

/*
 * BPatch_point::setLoop
 *
 * For a BPatch_point representing a loop instrumentation site,
 * set the loop that it represents.
 */

void BPatch_point::setLoop(BPatch_basicBlockLoop *l) {
  // We currently can use a single BPatch_point to represent
  // multiple loops. This is a problem, since we would really
  // like the points to label a unique loop. On the other hand,
  // then multiple points would share the same physical address..
  // not good.


  // Point must be for a loop.
  assert(pointType == BPatch_locLoopEntry ||
	 pointType == BPatch_locLoopExit ||
	 pointType == BPatch_locLoopStartIter ||
	 pointType == BPatch_locLoopEndIter);

  loop = l;
}

/*
 * BPatch_point::getPointType
 *
 * Returns type of BPatch_point
 */

const BPatch_procedureLocation BPatch_point::getPointTypeInt() 
{ 
   return pointType; 
}

/*
 * BPatch_point::getLoop
 *
 * Returns loop if of appropriate type
 */

BPatch_basicBlockLoop *BPatch_point::getLoopInt() 
{ 
   return loop; 
}

/*
 * BPatch_point::getFunction
 *
 * Returns function to which this BPatch_point belongs
 */

BPatch_function *BPatch_point::getFunctionInt()
{
   return func;
}

/*
 * BPatch_point::getCalledFunction
 *
 * For a BPatch_point representing a call site, returns a pointer to a
 * BPatch_function that represents the function being called.  If the point
 * isn't a call site, returns NULL.
 */
BPatch_function *BPatch_point::getCalledFunctionInt()
{
   assert(point);

   if (func->getModule()->hasBeenRemoved()) return NULL;
   
   if (point->getPointType() != callSite)
      return NULL;
   
   int_function *_func;
   
   _func = point->findCallee();
   if (!_func) {
       parsing_printf("findCallee failed in getCalledFunction\n");
       return NULL;
   }
   return proc->findOrCreateBPFunc(_func, NULL);
}

void BPatch_point::attachMemAcc(BPatch_memoryAccess *newMemAcc) {
    if (memacc) {
        // Change if we ever want to override these...
        assert(newMemAcc == memacc);
    }
    else
        memacc = newMemAcc;
}

const BPatch_memoryAccess *BPatch_point::getMemoryAccessInt()
{
   if (func->getModule()->hasBeenRemoved()) return NULL;

    if (memacc) { 
        return memacc;
    }
    fprintf(stderr, "No memory access recorded for 0x%lx, grabbing now...\n",
            point->addr());
    assert(point);
    // Try to find it... we do so through an InstrucIter
    InstrucIter ii(point->addr(), point->proc());
    BPatch_memoryAccess *ma = ii.isLoadOrStore();

    attachMemAcc(ma);
    return ma;
}

const BPatch_Vector<BPatchSnippetHandle *> BPatch_point::getCurrentSnippetsInt() 
{
    allSnippets.clear();

    if (func->getModule()->hasBeenRemoved()) return allSnippets;


    for (unsigned pre = 0; pre < preSnippets.size(); pre++) 
        allSnippets.push_back(preSnippets[pre]);
    for (unsigned post = 0; post < postSnippets.size(); post++) 
        allSnippets.push_back(postSnippets[post]);
    
    return allSnippets;
}

const BPatch_Vector<BPatchSnippetHandle *> 
BPatch_point::getCurrentSnippetsByWhen(BPatch_callWhen when) 
{
    if (when == BPatch_callBefore)
        return preSnippets;
    else {
        assert(when == BPatch_callAfter);
        return postSnippets;
    }
}

const int *
BPatch_point::getLiveRegistersInt(int & size)
{
  instPoint * ip = getPoint();
  int * liveR = ip->liveRegisters;
  size = instPoint::liveRegSize();
  return liveR;
}


/*
 * BPatch_point::getAddress
 *
 * Returns the original address of the first instruction at this point.
 */
void *BPatch_point::getAddressInt()
{
    return (void *)point->addr();
}


/*
 * BPatch_point::usesTrap_NP
 *
 * Returns true if this point is or would be instrumented with a trap, rather
 * than a jump to the base tramp, false otherwise.  On platforms that do not
 * use traps (everything other than x86), it always returns false;
 *
 */
bool BPatch_point::usesTrap_NPInt()
{
  assert(point);
  return false;
  //return point->usesTrap();
}

/*
 * BPatch_point::isDynamic
 *
 * Returns true if this point is a dynamic call site.
 *
 */
bool BPatch_point::isDynamicInt()
{
   if (func->getModule()->hasBeenRemoved()) return false;

    if (!dynamic_call_site_flag) return false;
    if (dynamic_call_site_flag == 1) return true;
    
    assert(proc);
    assert(proc->llproc);
    assert(point);

    bool is_dyn = point->isDynamicCall();
    dynamic_call_site_flag = is_dyn ? 1 : 0;
    return is_dyn;
}

/*
 * BPatch_point::monitorCalls(BPatch_function *userCBFunc)
 *
 * Insert function call to user-defined callback function
 * at dynamic call site.
 *
 * Returns false if BPatch_point is not a dynamic call site.
 *
 */

void *BPatch_point::monitorCallsInt( BPatch_function * user_cb ) 
{
  BPatch_function *func_to_use = user_cb;

   if (func->getModule()->hasBeenRemoved()) return NULL;

  if ( !isDynamic() ) {
    fprintf(stderr, "%s[%d]:  call site is not dynamic, cannot monitor\n", 
            __FILE__, __LINE__ );
    return NULL;
  }

  if ( dynamic_point_monitor_func ) {
    fprintf(stderr, "%s[%d]:  call site is already monitored\n", 
            __FILE__, __LINE__ );
    return NULL;
  }

  if (!func_to_use) {
    BPatch_image *bpi = proc->getImage();
    assert(bpi);
    //  if no user cb is provided, use the one in the rt lib
    BPatch_Vector<BPatch_function *> funcs;
    bpi->findFunction("DYNINSTasyncDynFuncCall", funcs);
    if (!funcs.size()) {
      fprintf(stderr, "%s[%d]:  cannot find function DYNINSTasyncDynFuncCall\n", FILE__, __LINE__);
      return NULL;
    }
    func_to_use = funcs[0];
  }
  // The callback takes two arguments: the first is the (address of the) callee,
  // the second the (address of the) callsite. 

  pdvector<AstNode *> args;
  if ( (!proc->llproc->getDynamicCallSiteArgs( point,args )) || 
       (args.size() != 2) ) {
     return NULL;
  }

  // construct function call and insert
  int_function * fb = func_to_use->lowlevel_func();

  // Monitoring function
  AstNode * ast = new AstNode( fb, args );
  miniTramp *res = point->instrument(ast,
				     callPreInsn,
				     orderLastAtPoint,
				     true,
				     false);
  
  if ( ! res ) {
     fprintf( stderr,"%s[%d]:  insertSnippet failed, cannot monitor call site\n",
               __FILE__, __LINE__ );
     return NULL;
  }

  //  Let asyncEventHandler know that we are being monitored
  getAsync()->registerMonitoredPoint(this);

  dynamic_point_monitor_func = res;

  //  Return pointer to handle as unique id, user does not need to know its a
  //  miniTramp.

  return (void*) res;
} /* end monitorCalls() */

bool BPatch_point::stopMonitoringInt()
{
  if (!dynamic_point_monitor_func) {
    bperr("%s[%d]:  call site not currently monitored", __FILE__, __LINE__);
    return false;
  }
  bool ret;
  ret = dynamic_point_monitor_func->uninstrument();

  dynamic_point_monitor_func = NULL;
  return ret;
}

/*
 * BPatch_point::getDisplacedInstructions
 *
 * Returns the instructions to be relocated when instrumentation is inserted
 * at this point.  Returns the number of bytes taken up by these instructions.
 *
 * maxSize      The maximum number of bytes of instructions to return.
 * insns        A pointer to a buffer in which to return the instructions.
 */

int BPatch_point::getDisplacedInstructionsInt(int maxSize, void* insns)
{
    // This is a stupid idea... but there's a test case, so make it happy.
    // We overwrite the entire basic block... 

    // So, we return the instruction "overwritten". Wrong, but what the heck...
    const instruction &insn = point->insn();
    unsigned size = (maxSize < (int)insn.size()) ? maxSize : insn.size();
    memcpy(insns, (const void *)insn.ptr(), size);
    return insn.size();
}

// This isn't a point member because it relies on instPoint.h, which
// we don't want to include in BPatch_point.h. If we had a public "enumerated types"
// header file this could move.
bool BPatchToInternalArgs(BPatch_point *point,
                          BPatch_callWhen when,
                          BPatch_snippetOrder order,
                          callWhen &ipWhen,
                          callOrder &ipOrder) {
    // Edge instrumentation: overrides inputs
    if (point->edge()) {
        if (when == BPatch_callAfter) {
            // Can't do this... there is no "before" or 
            // "after" for an edge
            return false;
        }
        switch(point->edge()->type) {
        case CondJumpTaken:
        case UncondJump:
            ipWhen = callBranchTargetInsn;
            break;
        case CondJumpNottaken:
        case NonJump:
            ipWhen = callPostInsn;
            break;
        default:
            fprintf(stderr, "Unknown edge type %d\n", point->edge()->type);
            assert(0);
        }
    }
    else {
        // Instruction level
        if (when == BPatch_callBefore)
            ipWhen = callPreInsn;
        else if (when == BPatch_callAfter)
            ipWhen = callPostInsn;
        else if (when == BPatch_callUnset)
            ipWhen = callPreInsn;
    }
    
    if (order == BPatch_firstSnippet)
        ipOrder = orderFirstAtPoint;
    else if (order == BPatch_lastSnippet)
        ipOrder = orderLastAtPoint;
    else
        return false;
    
    //
    // Check for valid combinations of BPatch_procedureLocation & call*
    // 	Right now we don't allow
    //		BPatch_callBefore + BPatch_exit
    //		BPatch_callAfter + BPatch_entry
    //
    //	These combinations are intended to be used to mark the point that
    //      is the last, first valid point where the local variables are
    //      valid.  This is different than the first/last instruction of
    //      a subroutine which is what the other combinations of BPatch_entry
    //	    and BPatch_exit refer to.
    //
    if (when == BPatch_callBefore && point->getPointType() == BPatch_exit) {
        BPatch_reportError(BPatchSerious, 113,
                           "BPatch_callBefore at BPatch_exit not supported yet");
        return false;
    }
    if (when == BPatch_callAfter && point->getPointType() == BPatch_entry) {
        BPatch_reportError(BPatchSerious, 113,
                           "BPatch_callAfter at BPatch_entry not supported yet");
        return false;
    }
    
    if ((point->getPointType() == BPatch_exit)) {
        //  XXX - Hack! 
        //  The semantics of pre/post insn at exit are setup for the new
        //  defintion of using this to control before/after stack creation,
        //  but the lower levels of dyninst don't know about this yet.
        ipWhen = callPreInsn;
    }
    
    return true;
}

void BPatch_point::recordSnippet(BPatch_callWhen when,
                                 BPatch_snippetOrder order,
                                 BPatchSnippetHandle *handle) {
    if (when == BPatch_callUnset) {
        if (getPointType() == BPatch_exit)
            when = BPatch_callAfter;
        else
            when = BPatch_callBefore;
    }

    if (when == BPatch_callBefore)
        if (order == BPatch_firstSnippet) {
#if !defined(USE_DEPRECATED_BPATCH_VECTOR)
            preSnippets.insert(preSnippets.begin(), handle);
#else
            preSnippets.push_front(handle);
#endif
        }
        else {
            preSnippets.push_back(handle);
        }
    else {
        if (order == BPatch_firstSnippet) {
#if !defined(USE_DEPRECATED_BPATCH_VECTOR)
            postSnippets.insert(postSnippets.begin(), handle);
#else
            postSnippets.push_front(handle);
#endif
        }
        else {
            postSnippets.push_back(handle);
        }
    }        

}

// Create an arbitrary BPatch point
BPatch_point *BPatch_point::createInstructionInstPoint(BPatch_process *proc,
                                                       void *address,
                                                       BPatch_function *bpf) {

   if (bpf->getModule()->hasBeenRemoved()) return NULL;

    // The useful prototype for instPoints:
    // createArbitraryInstPoint(addr, proc);
    
    Address internalAddr = (Address) address;
    process *internalProc = proc->lowlevel_process();

    instPoint *iPoint = instPoint::createArbitraryInstPoint(internalAddr,
                                                            internalProc);

    if (!iPoint)
        return NULL;

    return proc->findOrCreateBPPoint(bpf, iPoint, BPatch_arbitrary);
}

// findPoint refactoring
BPatch_Vector<BPatch_point*> *BPatch_point::getPoints(const BPatch_Set<BPatch_opCode>& ops,
                                        InstrucIter &ii, 
                                        BPatch_function *bpf) {
    BPatch_Vector<BPatch_point*> *result = new BPatch_Vector<BPatch_point *>;
    
    int osize = ops.size();
    BPatch_opCode* opa = new BPatch_opCode[osize];
    ops.elements(opa);
    
    bool findLoads = false, findStores = false, findPrefetch = false;
    
    for(int i=0; i<osize; ++i) {
        switch(opa[i]) {
        case BPatch_opLoad: findLoads = true; break;
        case BPatch_opStore: findStores = true; break;	
        case BPatch_opPrefetch: findPrefetch = true; break;	
        }
    }
    delete[] opa;
    
    while(ii.hasMore()) {
        
        //inst = ii.getInstruction();
        Address addr = *ii;     // XXX this gives the address *stored* by ii...
        
        BPatch_memoryAccess* ma = ii.isLoadOrStore();
        ii++;
        
        if(!ma)
            continue;
        
        //BPatch_addrSpec_NP start = ma.getStartAddr();
        //BPatch_countSpec_NP count = ma.getByteCount();
        //int imm = start.getImm();
        //int ra  = start.getReg(0);
        //int rb  = start.getReg(1);
        //int cnt = count.getImm();
        //short int fcn = ma.prefetchType();
        bool add = false;
        
        if(findLoads && ma->hasALoad()) {
            add = true;
        }
        else if (findStores && ma->hasAStore()) {
            add = true;
        }
        else if (findPrefetch && ma->hasAPrefetch_NP()) {
            add = true;
        }
        
        if (add) {
            BPatch_point *p = BPatch_point::createInstructionInstPoint(bpf->getProc(),
                                                                       (void *)addr,
                                                                       bpf);
            if (p) {
                if (p->memacc == NULL)
                    p->attachMemAcc(ma);
                else
                    delete ma;
                result->push_back(p);
            }
        }
    }
    return result;
}
                                                          
