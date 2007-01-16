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

#ifndef _RPC_MGR_
#define _RPC_MGR_

/*
 * TODO:
 * RPC manager level (collate running IRPCs and handle removing them when completed)
 * LWP RPCs
 * Check callback logic
 */

#include "common/h/Dictionary.h"
#include "dyninstAPI/src/dyn_lwp.h"
#include "common/h/Types.h"

class AstNode;
class dyn_lwp;
class dyn_thread;
class process;
struct dyn_saved_regs;

class rpcLWP;
class rpcThr;
class rpcMgr;
class baseTramp;
class EventRecord;
class codeGen;

// RPC state enumerated type
typedef enum { irpcNotValid, irpcNotRunning, irpcRunning, irpcWaitingForSignal,
               irpcNotReadyForIRPC } irpcState_t;

char *irpcStateAsString(irpcState_t state);

// RPC launch return type
typedef enum { irpcNoIRPC, irpcStarted, irpcAgain, irpcBreakpointSet, 
               irpcError } irpcLaunchState_t;

char *irpcLaunchStateAsString(irpcLaunchState_t state);

// inferior RPC callback function type
typedef void(*inferiorRPCcallbackFunc)(process *p, unsigned rpcid, void *data, void *result);


struct inferiorRPCtoDo {  
    AstNode *action;
    bool noCost; // if true, cost model isn't updated by generated code.
    inferiorRPCcallbackFunc callbackFunc;
    void *userData; /* Good 'ol callback/void * pair */
    bool lowmem; /* Steers allocation of memory for the RPC to run in */
    unsigned id;
    bool runProcessWhenDone; 
    bool saveFPState;
    dyn_thread *thr;
    dyn_lwp *lwp;
};

#include "codeRange.h"
class inferiorRPCinProgress : public codeRange {
	public:
		virtual Address get_address_cr() const { return rpcStartAddr; }
		virtual unsigned get_size_cr() const { return (rpcCompletionAddr - rpcStartAddr) + 1; }
		virtual	void * getPtrToInstruction( Address /*addr*/ ) const { assert( 0 ); return NULL; }
		        
    struct inferiorRPCtoDo *rpc;
    // Saved state about the RPC
    struct dyn_saved_regs *savedRegs;
    Address origPC;
    bool runProcWhenDone;
  
    Address rpcStartAddr;
    Address rpcResultAddr;
    Address rpcContPostResultAddr;
    Address rpcCompletionAddr;
    
    // Register the return value is in
    Register resultRegister;
    void *resultValue; // Get the result at rpcResultAddr, use it in
    // the callback (made after the RPC completes)
    
    rpcThr *rpcthr; /* Particular thread to run on */
    rpcLWP *rpclwp; /* Or a particular LWP */

    bool isProcessRPC;
    
    irpcState_t state;
};

// RPC component of the thread class. Contains various bits and pieces of state
// information

class rpcThr {
    friend class rpcMgr;
  private:
    // Handle to the 'parent' rpcMgr
    rpcMgr *mgr_;

    // Handle to the original thread
    dyn_thread *thr_;

    pdvector<inferiorRPCtoDo *> postedRPCs_;
    // RPC waiting on a system call to exit
    inferiorRPCinProgress        *pendingRPC_;
    inferiorRPCinProgress        *runningRPC_;
    
    // Internal launch function
    irpcLaunchState_t runPendingIRPC();

    
  public:
    rpcThr(rpcMgr *mgr, dyn_thread *thr) : mgr_(mgr), thr_(thr), pendingRPC_(NULL), runningRPC_(NULL) {};
    rpcThr(rpcThr *parThr, rpcMgr *cMgr, dyn_thread *cthr);
    
    dyn_thread *get_thr() const { return thr_; }

    // Returns ID of the RPC posted
    int postIRPC(inferiorRPCtoDo *todo);

    // Returns true iff:
    // 1) we're running an iRPC
    // 2) we're waiting for a set breakpoint
    bool isProcessingIRPC() const;
    // First half of the above
    bool isRunningIRPC() const;
    // Second half
    bool isWaitingForBreakpoint() const;
    
    // Returns true if there is an available
    // RPC and we're not already doing one
    bool isReadyForIRPC() const;

    // Launch an IRPC
    irpcLaunchState_t launchThrIRPC(bool runProcWhenDone);
    irpcLaunchState_t launchProcIRPC(bool runProcWhenDone);

    // Handle the syscall callback
    static bool launchThrIRPCCallbackDispatch(dyn_lwp *lwp, void *data);
    
    // Remove a pending IRPC
    bool deleteThrIRPC(unsigned id);

    // Cancel a running IRPC
    bool cancelThrIRPC(unsigned id);
    
    // Handle completion states
    bool handleCompletedIRPC();
    bool getReturnValueIRPC();

    // Status vrbles
    inferiorRPCinProgress *getRunningRPC() const {
        return runningRPC_;
    }
};

// In certain cases we need to be able to run an inferior RPC
// on a particular LWP. This is dangerous for a number of reasons
// (particularly because a thread of control can migrate LWPs)
// but is used when we need to run code but do not know the thread
// information.

class rpcLWP {
    friend class rpcMgr;
  private:
    // Handle to the 'parent' rpcMgr
    rpcMgr *mgr_;

    // Handle to the original thread
    dyn_lwp *lwp_;

    pdvector<inferiorRPCtoDo *> postedRPCs_;
    // RPC waiting on a system call to exit
    inferiorRPCinProgress        *pendingRPC_;
    inferiorRPCinProgress        *runningRPC_;
    
    // Internal launch function
    irpcLaunchState_t runPendingIRPC();

  public:
    rpcLWP(rpcMgr *mgr, dyn_lwp *lwp) : mgr_(mgr), lwp_(lwp), pendingRPC_(NULL), runningRPC_(NULL) {} ;
    rpcLWP(rpcLWP *parThr, rpcMgr *cMgr, dyn_lwp *clwp);


    dyn_lwp *get_lwp() const { return lwp_; }

    // Returns ID of the RPC posted
    int postIRPC(inferiorRPCtoDo *todo);

    // Returns true iff:
    // 1) we're running an iRPC
    // 2) we're waiting for a set breakpoint
    bool isProcessingIRPC() const;
    // First half of the above
    bool isRunningIRPC() const;
    // Second half
    bool isWaitingForBreakpoint() const;
    
    // Returns true if there is an available
    // RPC and we're not already doing one
    bool isReadyForIRPC() const;

    // Launch an IRPC
    irpcLaunchState_t launchLWPIRPC(bool runProcWhenDone);

    // Handle the syscall callback
    static bool launchLWPIRPCCallbackDispatch(dyn_lwp *lwp, void *data);
    
    // Remove a pending IRPC
    bool deleteLWPIRPC(unsigned id);

    // Cancel a running IRPC
    bool cancelLWPIRPC(unsigned id);
    
    // Handle completion states
    bool handleCompletedIRPC();
    bool getReturnValueIRPC();

    // Status vrbles
    inferiorRPCinProgress *getRunningRPC() const {
        return runningRPC_;
    }
};

static inline unsigned rpcLwpHash(unsigned const &index)
{
  // assume all addresses are 4-byte aligned
  unsigned result = (unsigned)(Address)index;
  result >>= 2;
  return result;
  // how about %'ing by a huge prime number?  Nah, x % y == x when x < y 
  // so we don't want the number to be huge.
}

#define  MAX_IRPC_SIZE 0x100000

class rpcMgr {
    friend class rpcThr;
    friend class rpcLWP;
    
  private:

    bool processingProcessRPC;

    process *proc_;
    pdvector<rpcThr *> thrs_;
    dictionary_hash<unsigned, rpcLWP *> lwps_;

    // Every posted RPC (for administration)
    pdvector<inferiorRPCtoDo *> allPostedRPCs_;
    
    // posted process-wide RPCs
    pdvector<inferiorRPCtoDo *> postedProcessRPCs_;

    // And all currently running RPCs
    pdvector<inferiorRPCinProgress *> allRunningRPCs_;
    // Oh, and pending ones -- why not
    pdvector<inferiorRPCinProgress *> allPendingRPCs_;

    bool deleteProcessRPC(unsigned id);
    
    // Used by thread and LWP
    bool removePostedRPC(inferiorRPCtoDo *rpc);
    
    // Implicitly removes from the posted list
    bool addPendingRPC(inferiorRPCinProgress *rpc);
    bool removePendingRPC(inferiorRPCinProgress *rpc);
    
    // Implicitly removes from pending list
    bool addRunningRPC(inferiorRPCinProgress *rpc);
    bool removeRunningRPC(inferiorRPCinProgress *rpc);

    // Prevent launchRPCs from being entered recursively
    bool recursionGuard;

    baseTramp *irpcTramp;
    
  public:
   rpcMgr(process *proc);
   rpcMgr(rpcMgr *parRpcMgr, process *child);
   ~rpcMgr();

   void addThread(dyn_thread *thr);
   void deleteThread(dyn_thread *thr);
   void addLWP(dyn_lwp *lwp);
   void deleteLWP(dyn_lwp *lwp);
   process *proc() { return proc_; }

   // Find an IRPC and return it's state (queued, running, etc.)
   irpcState_t getRPCState(unsigned id);
   bool cancelRPC(unsigned id);
   
   inferiorRPCtoDo *getProcessRPC();
   
   // The big function: launch RPCs everywhere possible
   // runProcessNow: the RPC mechanism requires the process
   // to be run; set by launchRPCs
   // runProcessWhenDone: when the RPC finishes, recommend that
   // the process be run (set by the caller).
   // Note: can also be set on a per-RPC basis...
   bool launchRPCs(bool &runProcessNow,
                   bool runProcessWhenDone);

   // Search allRunningRPCs_ for a RPC with specified result address
   // Returns pointer to RPC, or NULL if not found;
   inferiorRPCinProgress *findRunningRPCWithResultAddress(Address where);

   // Search allRunningRPCs_ for a RPC with specified completion address
   // Returns pointer to RPC, or NULL if not found;
   inferiorRPCinProgress *findRunningRPCWithCompletionAddress(Address where);

   bool decodeEventIfDueToIRPC(EventRecord &ev);
   bool handleRPCEvent(EventRecord &ev, bool &continueHint);

   // State query functions
   // Note: since we're multithreaded, there might be multiple
   // overlapping states. These functions return true if any thread
   // fulfills the requirement (hence 'exists')

   // True if there is any thread/LWP running an IRPC
   bool existsActiveIRPC() const;
   // True if there is any thread/LWP waiting on a system call
   bool existsPendingIRPC() const;
   // True if there is any thread/LWP with a pending (unscheduled) IRPC (e.g.,
   // if we cannot add the trap)
   bool existsWaitingIRPC() const;

   void showState() const;
   
   // posting RPC on a process
   unsigned postRPCtoDo(AstNode *action, bool noCost,
                        inferiorRPCcallbackFunc callbackFunc,
                        void *userData, 
                        bool runProcessWhenDone,
                        bool lowmem, dyn_thread *thr,
                        dyn_lwp *lwp);

   // Create the body of the IRPC
   Address createRPCImage(AstNode *action, bool noCost,
                          bool shouldStopForResult, Address &breakAddr,
                          Address &stopForResultAddr,
                          Address &justAfter_stopForResultAddr,
                          Register &resultReg, bool lowmem, 
                          dyn_thread *thr,
                          dyn_lwp *lwp);

   
   bool emitInferiorRPCheader(codeGen &gen);
   
   bool emitInferiorRPCtrailer(codeGen &gen,
                               unsigned &breakOffset,
                               bool stopForResult,
                               unsigned &stopForResultOffset,
                               unsigned &justAfter_stopForResultOffset);
};




#endif /* _RPC_MGR_ */


