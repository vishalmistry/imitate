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

// $Id: signalhandler.C,v 

#include "signalhandler.h"
#include "signalgenerator.h"
#include "process.h"
#include "eventgate.h"
#include "stats.h"
#include "dyn_thread.h"
#include "dyn_lwp.h"
#include "Object.h"
#include "function.h" // instPointTrap debugging
#include "rpcMgr.h"

extern void dyninst_yield();

void SignalHandler::main() {
    // As with the SignalGenerator, we use a custom main to avoid
    // unlocking in the middle of things; this can screw up our synchronization.

    addToThreadMap();
    
    startupLock->_Lock(FILE__, __LINE__);
    signal_printf("%s[%d]:  about to do init for %s\n", FILE__, __LINE__, idstr);
    if (!initialize_event_handler()) {
        signal_printf("%s[%d]: initialize event handler failed, %s returning\n", FILE__, __LINE__, idstr);
        _isRunning = false;
        init_ok = false; 

        removeFromThreadMap();

        startupLock->_Broadcast(FILE__, __LINE__);
        startupLock->_Unlock(FILE__, __LINE__);
        return;
    }
    
    init_ok = true;
    signal_printf("%s[%d]:  init success for %s\n", FILE__, __LINE__, idstr);
    
    _isRunning = true;
    startupLock->_Broadcast(FILE__, __LINE__);
    startupLock->_Unlock(FILE__, __LINE__);
    
    signal_printf("%s[%d]:  before main loop for %s\n", __FILE__, __LINE__, idstr);

    eventlock->_Lock(FILE__, __LINE__);
    pdvector<EventRecord> events;
    while (1) {
        // TOP
        signal_printf("%s[%d]: signal handler at top of loop\n", FILE__, __LINE__);
        assert(eventlock->depth() == 1);
        
        if (stop_request) {
            signal_printf("%s[%d]: exit request (loop top)\n", FILE__, __LINE__);
            break;
        }

        while (!events_to_handle.size()) {
            waitForEvent(events_to_handle);
            if (stop_request) {
                signal_printf("%s[%d]: exit request (post wait)\n", FILE__, __LINE__);
                break;
            }
        }

        while (events_to_handle.size()) {
            handleEvent(events_to_handle[0]);
            if (stop_request) {
                signal_printf("%s[%d]: exit request (post handle)\n", FILE__, __LINE__);
                break;
            }
            events_to_handle.erase(0,0);
        }
    }        

    thread_printf("%s[%d]: removing from thread map\n", FILE__, __LINE__);
    removeFromThreadMap();
    
    _isRunning = false;
    if (eventlock->depth() != 1) {
        fprintf(stderr, "%s[%d]:  WARNING:  eventlock->depth() is %d, leaving thread %s\n",
                FILE__, __LINE__, eventlock->depth(),idstr);
        eventlock->printLockStack();
    }
    eventlock->_Broadcast(FILE__, __LINE__);
    eventlock->_Unlock(FILE__, __LINE__);
    
    thread_printf("%s[%d][%s]:  SignalHandler::main exiting\n", FILE__, __LINE__, idstr);
}


SignalHandler::~SignalHandler()
{
    signal_printf("%s[%d]:  welcome to ~SignalHandler\n", FILE__, __LINE__);

    stopThreadNextIter();
    if (waitingForWakeup_) {
        waitLock->_Lock(FILE__, __LINE__);
        waitLock->_Broadcast(FILE__, __LINE__);
    }

    while (isRunning()) {
        _Unlock(FILE__, __LINE__);
        dyninst_yield();
        _Lock(FILE__, __LINE__);
    }

    assert(waitLock);
    delete waitLock;
}


bool SignalHandler::handleSingleStep(EventRecord &ev, bool &continueHint) 
{
   if (!ev.lwp->isSingleStepping()) {
     fprintf(stderr, "%s[%d]:  unexpected step event\n", FILE__, __LINE__);
   }
   ev.lwp->setSingleStepping(false);
   sg->signalEvent(evtDebugStep);
   continueHint = false;
   return true;
}

bool SignalHandler::handleProcessStop(EventRecord &ev, bool &continueHint)
{
   process *proc = ev.proc;

   // Unlike other signals, don't forward this to the process. It's stopped
   // already, and forwarding a "stop" does odd things on platforms
   // which use ptrace. PT_CONTINUE and SIGSTOP don't mix
   continueHint = false;

   // We can get an extra SIGSTOP during process startup if it was paused
   // when we attached. So... nuke it.
   if (!ev.proc->reachedBootstrapState(bootstrapped_bs)) {
       continueHint = true;
       return true;
   }

#if defined(os_linux)
      // Linux uses SIGSTOPs for process control.  If the SIGSTOP
      // came during a process::pause (which we would know because
      // suppressEventConts() is set) then we'll handle the signal.
      // If it comes at another time we'll assume it came from something
      // like a Dyninst Breakpoint and not handle it.      
      if (!ev.lwp) {
         fprintf(stderr, "%s[%d]:  no lwp for SIGSTOP handling (needed)\n", FILE__, __LINE__);
         return false;
      }
      bool done =  ev.lwp->isWaitingForStop() || sg->waitingForStop();

      signal_printf("%s[%d]: result of isWaitingForStop on lwp %d: %d\n",
                    FILE__, __LINE__, ev.lwp->get_lwp_id(), done);
      proc->set_lwp_status(ev.lwp, stopped);
      if (done) return true;

#else
      signal_printf("%s[%d]:  unhandled SIGSTOP for pid %d, process will stay paused\n",
             FILE__, __LINE__, proc->getPid());
#endif

      // If we're still here, notify BPatch
      
      return notifyBPatchOfStop(ev, continueHint);
}

bool SignalHandler::notifyBPatchOfStop(EventRecord &ev, bool & /*contHint*/) {
    bool exists = false;
    BPatch_process *bproc = BPatch::bpatch->getProcessByPid(ev.proc->getPid(), &exists);
    if (bproc) {
        setBPatchProcessSignal(bproc, ev.what);
        bproc->isVisiblyStopped = true;
        sg->overrideSyncContinueState(stopRequest);
    }

    return true;
}

bool SignalHandler::handleProcessExit(EventRecord &ev, bool &continueHint) 
{
  bool ret = false;
  process *proc = ev.proc;


  if (ev.status == statusNormal) {
      sprintf(errorLine, "Process %d has terminated with code 0x%x\n",
              proc->getPid(), (int) ev.what);
      statusLine(errorLine);
#if defined(os_windows)
      //  on the unixes we do this at syscall exit()
      proc->triggerNormalExitCallback(ev.what);
#endif
      ret = proc->handleProcessExit();
   } else if (ev.status == statusSignalled) {
      sprintf(errorLine, "process %d has terminated on signal %d\n",
              proc->getPid(), (int) ev.what);
      logLine(errorLine);
      statusLine(errorLine);
      printDyninstStats();
      // The process is gone at this point; we just have a return code.
      // So handle the exit _before_ we do the user-level callback, as
      // it sets state appropriately.
      ret = proc->handleProcessExit();
      proc->triggerSignalExitCallback(ev.what);
    } else {
      sprintf(errorLine, "process %d has terminated for unknown reason\n",
              proc->getPid());
      logLine(errorLine);
      ret = proc->handleProcessExit();
      //ret = true; //  maybe this should be false?  (this case is an error)
    }
  handleProcessExitPlat(ev, continueHint);
  flagBPatchStatusChange();

  continueHint = false;

  return ret;
}

bool SignalHandler::handleCritical(EventRecord &ev, bool &continueHint) 
{
   process *proc = ev.proc;
   assert(proc);

   dyn_debug_signal = 1;
   if (dyn_debug_signal) {
       pdvector<pdvector<Frame> > stackWalks;
       proc->walkStacks(stackWalks);
       for (unsigned walk_iter = 0; walk_iter < stackWalks.size(); walk_iter++) {
           fprintf(stderr, "%s[%d]:  Stack for pid %d, lwpid %d\n", FILE__, __LINE__,
                   stackWalks[walk_iter][0].getLWP()->proc()->getPid(), 
                   stackWalks[walk_iter][0].getLWP()->get_lwp_id());
           for( unsigned i = 0; i < stackWalks[walk_iter].size(); i++ )
               {
                   //int_function* f = proc->findFuncByAddr( stackWalks[walk_iter][i].getPC() );
                   //const char* szFuncName = (f != NULL) ? f->prettyName().c_str() : "<unknown>";
                   //fprintf( stderr, "%08x: %s\n", stackWalks[walk_iter][i].getPC(), szFuncName );
                   cerr << stackWalks[walk_iter][i] << endl;
                   //int_function *f = stackWalks[walk_iter][i].getFunc();
               }
       }
       
       int sleep_counter = SLEEP_ON_MUTATEE_CRASH;
       while (dyn_debug_signal && (sleep_counter > 0)) {
           signal_printf("Critical signal received, spinning to allow debugger to attach\n");
           sleep(10);
           sleep_counter -= 10;
       }
   }

   return forwardSigToProcess(ev, continueHint);
}

bool SignalHandler::handleForkEntry(EventRecord &ev, bool &continueHint)
{
     signal_printf("Welcome to FORK ENTRY for process %d\n",
                   ev.proc->getPid());
     continueHint = true;
     for (unsigned i=0; i<ev.proc->threads.size(); i++)
        if (ev.proc->threads[i]->get_lwp() == ev.lwp) {
           ev.proc->lastForkingThread = ev.proc->threads[i];
           
        }
     return ev.proc->handleForkEntry();
}

bool SignalHandler::handleLwpAttach(EventRecord &ev, bool &continueHint)
{
   assert(ev.lwp);
   ev.lwp->setIsAttached(true);
   continueHint = false;
   return true;
}

bool SignalHandler::handleLwpExit(EventRecord &ev, bool &continueHint)
{
   thread_printf("%s[%d]:  welcome to handleLwpExit\n", FILE__, __LINE__);
   signal_printf("%s[%d]:  welcome to handleLwpExit\n", FILE__, __LINE__);
   process *proc = ev.proc;
   dyn_lwp *lwp = ev.lwp;
   dyn_thread *thr = NULL;

   //Find the exiting thread
   for (unsigned i=0; i<proc->threads.size(); i++) {
       if (proc->threads[i]->get_lwp()->get_lwp_id() == lwp->get_lwp_id()) {
           thr = proc->threads[i];
           break;
       }
   }

   if (proc->IndependentLwpControl()) {
     proc->set_lwp_status(ev.lwp, exited);
   }
   ev.lwp->set_dead();

   if (!thr) {
     // DOA thread...
     continueHint = true;
     return true;
   }

   BPatch::bpatch->registerThreadExit(proc, thr->get_tid(), false);

   flagBPatchStatusChange();

#if defined(os_windows)
   if (getExecThreadID() != sg->getThreadID()) {
      signal_printf("%s[%d][%s]:  signalling active process\n", 
                    FILE__, __LINE__, getThreadStr(getExecThreadID()));
      sg->requested_wait_until_active = false;
      sg->signalActiveProcess();
   }
#endif
#if defined(os_linux)
   sg->unregisterLWP(lwp->get_lwp_id());
#endif
   continueHint = true;

   return true;
}

bool SignalHandler::handleSyscallEntry(EventRecord &ev, bool &continueHint)
{
    signal_printf("%s[%d]:  welcome to handleSyscallEntry\n", FILE__, __LINE__);
    process *proc = ev.proc;
    bool ret = false;
    switch ((procSyscall_t)ev.what) {
      case procSysFork:
          ret = handleForkEntry(ev, continueHint);
          break;
      case procSysExec:
          ret = handleExecEntry(ev, continueHint);
          break;
      case procSysExit:
          signal_printf("%s[%d]:  handleSyscallEntry exit(%d)\n", FILE__, __LINE__, ev.what);
          proc->triggerNormalExitCallback(INFO_TO_EXIT_CODE(ev.info));
          continueHint = true;
          ret = true;
          break;
      case procLwpExit:
         assert(0);
         //  this case should be hijacked during event decoding and mapped onto
         //  the evtThreadExit event type.

         break;
      default:
         // Check process for any other syscall
         // we may have trapped on entry to?
         continueHint = true;
         ret = false;
         break;
    }
    return ret;
}

bool SignalHandler::handleForkExit(EventRecord &ev, bool &continueHint)
{
     signal_printf("%s[%d]: Welcome to FORK EXIT for process %d\n",
                   FILE__, __LINE__, ev.proc->getPid());

     process *proc = ev.proc;
     // Fork handler time
     extern pdvector<process*> processVec;
     int childPid = INFO_TO_PID(ev.info);

     if (childPid == getpid()) {
         // this is a special case where the normal createProcess code
         // has created this process, but the attach routine runs soon
         // enough that the child (of the mutator) gets a fork exit
         // event.  We don't care about this event, so we just continue
         // the process - jkh 1/31/00
         signal_printf("%s[%d]: received FORK on self pid\n",
                       FILE__, __LINE__);
         continueHint = true;
         return true;
     } else if (childPid > 0) {

         unsigned int i;
         for (i=0; i < processVec.size(); i++) {
             if (processVec[i] &&
                 (processVec[i]->getPid() == childPid)) break;
         }
         if (i== processVec.size()) {
             // this is a new child, register it with dyninst
             // Note: we need to wait for the child process to be created.

             sleep(1);

             // For now, we sleep (apparently), but the better solution is to
             // loop waiting for the child to be created and then attach to it.
             // We have seen the following order:
             // Parent exits fork
             // We get notification -- but no child yet.
             // Child is created
             // This seems to be OS dependent on who goes first - parent or child.

             // We leave the parent paused until the child is finished,
             // so that we can be sure to copy everything correctly.

             process *theChild = ev.proc->sh->newProcess(proc, (int) childPid, -1);
             if (!theChild)
               return false;
   
             proc->handleForkExit(theChild);

             // This may have been mucked with during the fork callback
	     // If we're still paused, then hit run. It'd be nice if there was a 
	     // way to let the user say "stay paused!" -- bernat
	     if (proc->sh->syncRunWhenFinished_ != runRequest) {
	       signal_printf("%s[%d]: running parent post-FORK: overriding syncContinueState\n",
			     FILE__, __LINE__);
	       proc->sh->overrideSyncContinueState(runRequest);
	     }
             continueHint = true;
             // Unlike normal, we want to start this guy up running (the user can pause if desired in
             // the callback)
	     if (theChild->sh->syncRunWhenFinished_ != runRequest) {
	       signal_printf("%s[%d]: running child post-FORK: overriding syncContinueState\n",
			     FILE__, __LINE__);
	       theChild->sh->overrideSyncContinueState(runRequest);
	     }
             theChild->continueProc();
        }
     }
     else {
         // Child signalGenerator may execute this guy ; leave it untouched.

         // If we've already received the stop (AKA childForkStopAlreadyReceived
         // is true), then we're getting double-signalled due to odd Linux behavior.
         // Continue the process.
         // If not, then set to true and leave paused.

         signal_printf("%s[%d]: child case in fork handling; stopAlreadyReceived = %d\n",
                       FILE__, __LINE__, proc->sh->childForkStopAlreadyReceived_);

         // Might be a different signal generator from us...
         if (proc->sh->childForkStopAlreadyReceived_) {
	   continueHint = true;
         }
     }
    return true;
}
// the alwaysdosomething argument is to maintain some strange old code
bool SignalHandler::handleExecExit(EventRecord &ev, bool &continueHint)
{
    process *proc = ev.proc;
    proc->nextTrapIsExec = false;
    if ( (int) INFO_TO_PID(ev.info) == -1) {
        // Failed exec, do nothing
      continueHint=true;
    }

    proc->execFilePath = proc->tryToFindExecutable(proc->execPathArg, proc->getPid());
    // As of Solaris 2.8, we get multiple exec signals per exec.
    // My best guess is that the daemon reads the trap into the
    // kernel as an exec call, since the process is paused
    // and PR_SYSEXIT is set. We want to ignore all traps 
    // but the last one.

    // We also see an exec as the first signal in a process we create. 
    // That's because it... wait for it... execed!
    if (!proc->reachedBootstrapState(begun_bs)) {
      return handleProcessCreate(ev, continueHint);
    }


   int status = 0;
   // False: not waitin' for a signal (theoretically, we already got
    // it when we attached)
    fileDescriptor desc;
    if (!proc->sh->getExecFileDescriptor(proc->execFilePath,
                                   proc->getPid(),
                                   false,
                                   status,
                                   desc)) {
        cerr << "Failed to find exec descriptor" << endl;
	continueHint = true;
    }

    // Unlike fork, handleExecExit doesn't do all processing required.
    // We finish up when the trap at main() is reached.
    proc->handleExecExit(desc);
    
    continueHint = true;
    
    return true;
}


bool SignalHandler::handleSyscallExit(EventRecord &ev, bool &continueHint)
{
    // We need to multiplex "run" between the generic trap decoding and
    // and the specific handlers.
    bool runProcess = false;
    bool retval = false;

    signal_printf( "%s[%d]:  welcome to handleSyscallExit\n", FILE__, __LINE__);

    retval = ev.lwp->handleSyscallTrap(ev, continueHint);

    // Fall through no matter what since some syscalls have their
    // own handlers.
    switch((procSyscall_t) ev.what) {
    case procSysFork:
        signal_printf("%s[%d]:  Fork Exit\n", FILE__, __LINE__);
        handleForkExit(ev, runProcess);
        break;
    case procSysExec:
        signal_printf("%s[%d]:  Exec Exit\n", FILE__, __LINE__);
        handleExecExit(ev, runProcess);
        break;
    case procSysLoad:
        signal_printf("%s[%d]:  Load Exit\n", FILE__, __LINE__);
        handleLoadLibrary(ev, runProcess);
        break;
    default:
        // We stopped on a system call and didn't particularly care,
        // or handled it above but left ourselves paused. 
      runProcess = true;
        break;
    }

    continueHint |= runProcess;

    return true;
}

bool SignalHandler::handleEvent(EventRecord &ev)
{
    signal_printf("%s[%d]:  got event: %s\n", FILE__, __LINE__, eventType2str(ev.type));
    
    if (ev.type == evtShutDown) {
        stop_request = true;
        return true;
    }

    process *proc = ev.proc;
    // Do we run the process or not? Well, that's a tricky question...
    // user control can override anything we do here (frex, a "run when
    // done" iRPC conflicting with a user "pause"). So we have the lowlevel
    // code suggest whether to continue or not, and we have logic here
    // to see if we do it or not.
    
    bool continueHint = false;
    bool ret = false;
    Frame activeFrame;
    assert(proc);
    
    // One big switch statement
    switch(ev.type) {
        // First the platform-independent stuff
        // (/proc and waitpid)
    case evtProcessExit:
        ret = handleProcessExit(ev, continueHint);
        break;
    case evtProcessCreate:
        ret = handleProcessCreate(ev, continueHint);
        break;
    case evtThreadCreate:
        ret = handleThreadCreate(ev, continueHint);
        break;
    case evtThreadExit:
        ret = handleLwpExit(ev, continueHint);
        break;
     case evtLwpAttach:
        ret = handleLwpAttach(ev, continueHint);
        break;
    case evtProcessAttach:
        ret = handleProcessAttach(ev, continueHint);
        break;
     case evtProcessInit:
        proc->handleTrapAtEntryPointOfMain(ev.lwp);
        proc->setBootstrapState(initialized_bs);
        // If we were execing, we now know we finished
        if (proc->execing()) {
           proc->finishExec();
        }
        continueHint = false;
        ret = true;
        break;
     case evtProcessLoadedRT:
     {
        pdstring buffer = pdstring("PID=") + pdstring(proc->getPid());
        buffer += pdstring(", loaded dyninst library");
        statusLine(buffer.c_str());
        startup_printf("%s[%]:  trapDueToDyninstLib returned tru, trying to handle\n", 
                       FILE__, __LINE__);
        startup_cerr << "trapDueToDyninstLib returned true, trying to handle\n";
        proc->loadDYNINSTlibCleanup(ev.lwp);
        proc->setBootstrapState(loadedRT_bs);
        ret = true;
        continueHint = false;
        break;
     }
     case evtInstPointTrap: {
         // Linux inst via traps
         // First, we scream... this is undesired behavior.
         signal_printf("%s[%d]: WARNING: inst point trap detected at 0x%lx, trap to 0x%lx\n",
                       FILE__, __LINE__, ev.address, proc->trampTrapMapping[ev.address]);
         ev.lwp->changePC(proc->trampTrapMapping[ev.address], NULL);
         continueHint = true;
         ret = true;
         break;
     }
     case evtLoadLibrary:
     case evtUnloadLibrary:
       ret = handleLoadLibrary(ev, continueHint);
       continueHint = true;
       break;
     case evtPreFork:
         // If we ever want to callback this guy, put it here.
        ret = true;
        continueHint = true;
        break;
     case evtSignalled:
     {
        ret = forwardSigToProcess(ev, continueHint);
        break;
     }
    case evtProcessStop:
       ret = handleProcessStop(ev, continueHint);
       if (!ret) {
           fprintf(stderr, "%s[%d]:  handleProcessStop failed\n", FILE__, __LINE__);
       }
       break;
     // Now the /proc only
     // AIX clones some of these (because of fork/exec/load notification)
     case evtRPCSignal:
         ret = proc->getRpcMgr()->handleRPCEvent(ev, continueHint);
         signal_printf("%s[%d]: handled RPC event, continueHint %d\n",
                       FILE__, __LINE__, continueHint);
         break;
     case evtSyscallEntry:
         ret = handleSyscallEntry(ev, continueHint);
         if (!ret)
             cerr << "handleSyscallEntry failed!" << endl;
         break;
     case evtSyscallExit:
         ret = handleSyscallExit(ev, continueHint);
         if (!ret)
            fprintf(stderr, "%s[%d]: handlesyscallExit failed! ", __FILE__, __LINE__); ;
         break;
     case evtSuspended:
         continueHint = true;
         ret = true;
         flagBPatchStatusChange();
         break;
     case evtDebugStep:
         handleSingleStep(ev, continueHint);
         ret = 1;
         break;
     case evtUndefined:
        // Do nothing
        cerr << "Undefined event!" << endl;
        continueHint = true;
        break;
     case evtCritical:
       ret = handleCritical(ev, continueHint);
         break;
     case evtRequestedStop:
         // /proc-age. We asked for a stop and the process did, and the signalGenerator
         // saw it.
         continueHint = false;
         ret = true;
         break;
     case evtTimeout:
     case evtThreadDetect:
         continueHint = true;
         ret = true;
         break;
     case evtNullEvent:
         ret = true;
         continueHint = true;
         break;
     default:
        fprintf(stderr, "%s[%d]:  cannot handle signal %s\n", FILE__, __LINE__, eventType2str(ev.type));
        assert(0 && "Undefined");
   }

  if (stop_request) {
    // Someone deleted us in place. 
    return true;
  }

   if (ret == false) {
      //  if ret is false, complain, but return true anyways, since the handler threads
      //  should be shut down by the SignalGenerator.
      char buf[128];
      fprintf(stderr, "%s[%d]:  failed to handle event %s\n", FILE__, __LINE__,
              ev.sprint_event(buf));
      ret = true;
   }

   // Process continue hint...
   if (continueHint) {
       signal_printf("%s[%d]: requesting continue\n",
                     FILE__, __LINE__);
       wait_flag = true;
       sg->continueProcessAsync(-1, // No signal...
                                ev.lwp); // But give the LWP
       wait_flag = false;
   }

   // Should always be the last thing we do...
   sg->signalEvent(ev);

   return ret;
}

bool SignalHandler::idle() {
    return (events_to_handle.size() == 0);
}

bool SignalHandler::waitingForCallback() {
    // Processing... well, if we're waiting on a callback, then we're not processing. 
    // Previously we set wait_flag inside the call to waitForEvent, but that was called
    // after this was checked. Whoopsie.

    return (wait_cb != NULL);
#if 0

    CallbackBase *cb = getMailbox()->runningInsideCallback();

    signal_printf("%s[%d]: running inside callback: %p... \n",
                  FILE__, __LINE__, cb);
    if (cb == NULL) return false;

    if (wait_cb == cb) {
        signal_printf("%s[%d]: signal handler %s waiting on callback\n",
                      FILE__, __LINE__, getThreadStr(getThreadID()));
        return true;
    }
    else {
        signal_printf("%s[%d]: running inside callback %p different from stored %p, odd case\n",
                      FILE__, __LINE__, cb, wait_cb);
    }

    return false;
#endif
}

bool SignalHandler::processing() {
    signal_printf("%s[%d]: checking whether processing for SH %s: idle_flag %d, waiting for callback %d, wait_flag %d\n", 
                  FILE__, __LINE__, getThreadStr(getThreadID()), idle(), waitingForCallback(), wait_flag);

    if (idle()) return false;
    if (waitingForCallback()) return false;
    if (wait_flag) return false;

    return true;
}

bool SignalHandler::assignEvent(EventRecord &ev) 
{
  assert(eventlock->depth());

  bool can_assign = false;

  //  after we get the lock, the handler thread should be either idle, or waiting
  //  for some event.  
  
  if (idle()) {
      can_assign = true;
  }
  else if (waitingForCallback() && ev.type == evtShutDown) {
      can_assign = true;
  }
  
  if (can_assign) {
      signal_printf("%s[%d]: assigning event to handler %s\n",
                    FILE__, __LINE__, getThreadStr(getThreadID()));
      events_to_handle.push_back(ev);
      waitLock->_Lock(FILE__, __LINE__);
      if (waitingForWakeup_) {
          waitLock->_Broadcast(FILE__, __LINE__);
      }
      waitLock->_Unlock(FILE__, __LINE__);
      return true;
  }

  // Otherwise we already assigned an event but the SH hasn't run yet.

  return false;
}

bool SignalHandler::waitForEvent(pdvector<EventRecord> &events_to_handle)
{
    assert(waitLock);

    signal_printf("%s[%d]: waitForEvent, events_to_handle(%d), idle_flag %d\n",
                  FILE__, __LINE__, events_to_handle.size(), idle());

    while (idle()) {
        // Our eventlocks are paired mutexes and condition variables; this
        // is actually _not_ what we want because we want to be able to
        // wait on different things but have the same global mutex. So we fake it
        // by carefully unlocking and relocking things. 
        
        // We now wait until _we_ are signalled by the generator; so we grab
        // our signal lock, give up the global mutex lock, and then wait; after
        // we're signalled we take the global mutex before giving up our own 
        // waitLock.
        
        waitingForWakeup_ = true;
        signal_printf("%s[%d]: acquiring waitLock lock...\n", FILE__, __LINE__);
        waitLock->_Lock(FILE__, __LINE__);
        signal_printf("%s[%d]: releasing global mutex...\n", FILE__, __LINE__);
        assert(eventlock->depth() == 1);
        eventlock->_Unlock(FILE__, __LINE__);
        
        signal_printf("%s[%d]: sleeping for activation\n", FILE__, __LINE__);
        waitLock->_WaitForSignal(FILE__, __LINE__);
        
        signal_printf("%s[%d]: woken, reacquiring global lock...\n", FILE__, __LINE__);
        eventlock->_Lock(FILE__, __LINE__);
        signal_printf("%s[%d]: woken, releasing waitLock...\n", FILE__, __LINE__);
        waitLock->_Unlock(FILE__, __LINE__);
        waitingForWakeup_ = false;        
    }
    
    return true;
}

signal_handler_location::signal_handler_location(Address addr, unsigned size) :
    addr_(addr),
    size_(size) {}

// Unimplemented
bool SignalHandler::waitNextEvent(EventRecord &) {
    assert(0);
    return false;
}
