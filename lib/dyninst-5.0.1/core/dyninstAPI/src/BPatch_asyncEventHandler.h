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


#ifndef __BPATCH_ASYNC_EVENT_HANDLER_H__
#define __BPATCH_ASYNC_EVENT_HANDLER_H__

#if defined (os_osf)
#include <standards.h>
#endif

#include <errno.h>
#include <BPatch_eventLock.h>
#include <BPatch.h>
#include <BPatch_process.h>
#include <BPatch_image.h>
#include <BPatch_Vector.h>

#include "os.h"
#include "EventHandler.h"
#include "dyninstAPI_RT/h/dyninstAPI_RT.h" // for BPatch_asyncEventType
                                           //  and BPatch_asyncEventRecord
#include "common/h/Pair.h"
#include "common/h/Vector.h"

typedef enum {
    REsuccess,
    REnoData,
    REinsufficientData,
    REreadError,
    REillegalProcess,
    REerror
} asyncReadReturnValue_t;

typedef struct {
    pdvector<BPatch_function *> *mutatee_side_cbs;
    pdvector<BPatchSnippetHandle *> *handles;
} thread_event_cb_record;

typedef struct {
  BPatch_process *process;
  int fd;
} process_record;

const char *asyncEventType2Str(BPatch_asyncEventType evtype); 

#ifdef DYNINST_CLASS_NAME
#undef DYNINST_CLASS_NAME
#endif
#define DYNINST_CLASS_NAME BPatch_asyncEventHandler

class BPatch_asyncEventHandler : public EventHandler<EventRecord> {
  friend THREAD_RETURN asyncHandlerWrapper(void *);
  friend class BPatch;  // only BPatch constructs & does init
  friend class BPatch_eventMailbox;
  public:
    //  BPatch_asyncEventHandler::connectToProcess()
    //  Tells the async event handler that there is a new process
    //  to listen for.
    bool connectToProcess(BPatch_process *p);

    //  BPatch_asyncEventHandler::detachFromProcess()
    //  stop paying attention to events from specified process
    bool detachFromProcess(BPatch_process *p);

    bool startupThread();

    bool registerMonitoredPoint(BPatch_point *);
  private: 
    BPatch_asyncEventHandler();
    pdvector<EventRecord> event_queue;
    bool initialize();  //  want to catch init errors, so we do most init here
    virtual ~BPatch_asyncEventHandler();

    //  BPatch_asyncEventHandler::shutDown()
    //  Sets a flag that the async thread will check during its next iteration.
    //  When set, the handler thread will shut itself down.
    bool shutDown();


    //  BPatch_asyncEventHandler::waitNextEvent()
    //  Wait for the next event to come from a mutatee.  Essentially 
    //  a big call to select().
   virtual bool waitNextEvent(EventRecord &ev);

    //  BPatch_asyncEventHandler::handleEvent()
    //  called after waitNextEvent, obtains global lock and handles event.
    //  Since event handling needs to be a locked operation (esp. if it 
    //  requires accessing lower level dyninst data structures), this is
    //  where it should be done.
    virtual bool handleEvent(EventRecord &ev)
         { LOCK_FUNCTION(bool, handleEventLocked, (ev)); }
    bool handleEventLocked(EventRecord &ev);

    //  BPatch_asyncEventHandler::readEvent()
    //  Reads from the async fd connection to the mutatee
    static asyncReadReturnValue_t readEvent(PDSOCKET fd, void *ev, ssize_t sz);
    static asyncReadReturnValue_t readEvent(PDSOCKET fd, EventRecord &ev);

    //  BPatch_asyncEventHandler::mutateeDetach()
    //  use oneTimeCode to call a function in the mutatee to handle
    //  closing of the comms socket.

    bool mutateeDetach(BPatch_process *p);

    //  BPatch_asyncEventHandler::cleanUpTerminatedProcs()
    //  clean up any references to terminated processes in our lists
    //  (including any user specified callbacks).
    bool cleanUpTerminatedProcs();

    //  BPatch_asyncEventHandler::cleanupProc(BPatch_process *p)
    //  remove a particular process without detaching. Used in 
    //  exec.
    bool cleanupProc(BPatch_process *p);

    //  BPatch_asyncEventHandler::instrumentThreadEvent
    //  Associates a function in the thread library with a eventType
    BPatchSnippetHandle *instrumentThreadEvent(BPatch_process *process,
                                               BPatch_asyncEventType t,
                                               BPatch_function *f);

    //  These vars are only modified as part of init (before/while threads are
    //  created) so we do not need to worry about locking them:
    PDSOCKET sock;
    bool shutDownFlag;

#if defined (os_windows)
    unsigned int listen_port;
#endif

    //  The rest:  Data in this class that is not exclusively set during init
    //   will have to be locked.  
    pdvector<process_record> process_fds;

    dictionary_hash<Address, BPatch_point *> monitored_points;
};

BPatch_asyncEventHandler *getAsync();

#endif // __BPATCH_EVENT_HANDLER_H__
