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

#ifndef _BPatch_h_
#define _BPatch_h_

#include <stdio.h>
#include "BPatch_dll.h"
#include "BPatch_Vector.h"
#include "BPatch_thread.h"
#include "BPatch_type.h"
#include "BPatch_eventLock.h"

class BPatch_typeCollection;
class BPatch_libInfo;
class BPatch_module;
class int_function;
class process;

typedef void (*BPatchAsyncThreadEventCallback)(BPatch_process *proc, BPatch_thread *thr);
typedef void (*BPatchUserEventCallback)(BPatch_process *proc, void *buf, 
                                        unsigned int bufsize);
typedef enum {
    BPatchFatal, BPatchSerious, BPatchWarning, BPatchInfo
} BPatchErrorLevel;

typedef void (*BPatchErrorCallback)(BPatchErrorLevel severity,
				    int number,
				    const char * const *params);

typedef void (*BPatchDynLibraryCallback)(BPatch_thread *proc,
					 BPatch_module *mod,
					 bool load);

typedef void (*BPatchForkCallback)(BPatch_thread *parent, 
                                   BPatch_thread *child);

typedef void (*BPatchExecCallback)(BPatch_thread *proc);

typedef void (*BPatchExitCallback)(BPatch_thread *proc,
                                   BPatch_exitType exit_type);

typedef void (*BPatchSignalCallback)(BPatch_thread *proc, int sigNum);

typedef void (*BPatchOneTimeCodeCallback)(BPatch_thread *proc, 
                                          void *userData, void *returnValue);

typedef void (*BPatchDynamicCallSiteCallback)(BPatch_point *at_point,
                                              BPatch_function *called_function);
#ifdef IBM_BPATCH_COMPAT
typedef void *BPatch_Address;
typedef void (*BPatchLoggingCallback)(char *msg, int);
extern void setLogging_NP(BPatchLoggingCallback func, int);

typedef void (*BPatchThreadEventCallback)(BPatch_thread *thr, void *arg1, void *arg2);
typedef void (*BPatchProcessEventCallback)(BPatch_process *proc, void *arg1, void *arg2);

#define BP_OK			0
#define BP_Pending		1
#define BP_Delayed		2
#define BP_child		3
#define BP_state		4
#define BP_pthdbBadContext	5
#define BP_lastCode		6

extern int eCodes[BP_lastCode];

#endif

//  BPatch_stats is a collection of instrumentation statistics.
//  Introduced to export this information to paradyn, which 
//  produces a summary of these numbers upon application exit.
//  It probably makes more sense to maintain such numbers on a
//  per-process basis.  But is set up globally due to historical
//  precendent.   

typedef struct {
  unsigned int pointsUsed;
  unsigned int totalMiniTramps;
  unsigned int trampBytes;
  unsigned int ptraceOtherOps;
  unsigned int ptraceOps;
  unsigned int ptraceBytes;
  unsigned int insnGenerated;
} BPatch_stats;


class EventRecord;

#ifdef DYNINST_CLASS_NAME
#undef DYNINST_CLASS_NAME
#endif
#define DYNINST_CLASS_NAME BPatch
class BPATCH_DLL_EXPORT BPatch : public BPatch_eventLock {
    friend class BPatch_thread;
    friend class BPatch_process;
    friend class BPatch_point;
    friend class process;
    friend class int_function;
    friend class SignalHandler;
    friend class BPatch_asyncEventHandler;
    friend bool handleSigStopNInt(EventRecord &ev);

    BPatch_libInfo *info; 

#ifdef NOTDEF // PDSEP
    BPatchErrorCallback      	errorHandler;
    BPatchDynLibraryCallback 	dynLibraryCallback;
    BPatchForkCallback   	postForkCallback;
    BPatchForkCallback    	preForkCallback;
    BPatchExecCallback		execCallback;
    BPatchExitCallback		exitCallback;
    BPatchOneTimeCodeCallback   oneTimeCodeCallback;
#endif
    bool	typeCheckOn;
    int		lastError;
    bool	debugParseOn;
    bool	baseTrampDeletionOn;

#ifdef NOTDEF // PDSEP
    bool	getThreadEvent(bool block);
    bool	getThreadEventOnly(bool block);
    bool	havePendingEvent();
#endif

    /* If true, trampolines can recurse to their heart's content.
       Defaults to false */
    bool        trampRecursiveOn;

    bool        forceRelocation_NP;
    /* If true, allows automatic relocation of functions if dyninst
       deems it necessary.  Defaults to true */
    bool        autoRelocation_NP;

    /* If true, ignore all liveness calculations. Will seriously impact performance
       but is necessary if the user has information we don't about optimized code. */
    bool        disregardLiveness_NP_;

    /* If true, base tramps and mini tramps are merged 
       Defaults to false */
    bool        trampMergeOn;

    /* If true, we save FPRs in situations we normally would 
       Defaults to true */
    bool saveFloatingPointsOn;

    /* If true, override requests to block while waiting for events,
       polling instead */
    bool asyncActive;

    /* If true, deep parsing (anything beyond symtab info) is delayed until
       accessed */
    /* Note: several bpatch constructs have "access everything" behavior, 
       which will trigger full parsing. This should be looked into. */
    bool delayedParsing_;

    BPatch_stats stats;
    void updateStats();

	/* this is used to denote the fully qualified name of the prelink command on linux */
	char *systemPrelinkCommand;

        // Wrapper - start process running if it was not deleted. 
        // We use this at the end of callbacks to user code, since those
        // callbacks may delete BPatch objects. 
        void continueIfExists(int pid);

    /* flag that is set when a mutatee's runnning status changes,
       for use with pollForStatusChange */
   bool mutateeStatusChange;
   bool waitingForStatusChange;

   /* Internal notification file descriptor - a pipe */
   int notificationFDOutput_;
   int notificationFDInput_;
   // Easier than non-blocking reads... there is either 1 byte in the pipe or 0.
   bool FDneedsPolling_;
   /* And auxiliary functions for the above */
   void signalNotificationFD();
   void clearNotificationFD();
   
public:
    static BPatch		 *bpatch;

    BPatch_builtInTypeCollection *builtInTypes;
    BPatch_typeCollection	 *stdTypes;
    BPatch_typeCollection        *APITypes; //API/User defined types
    BPatch_type			 *type_Error;
    BPatch_type			 *type_Untyped;

    // The following are only to be called by the library:
    //  These functions are not locked.
    void registerProvisionalThread(int pid);
    void registerForkedProcess(process *parentProc, process *childProc);
    void registerForkingProcess(int forkingPid, process *proc);

    void registerExecExit(process *proc);
    void registerExecEntry(process *proc, char *arg0);

    void registerNormalExit(process *proc, int exitcode);
    void registerSignalExit(process *proc, int signalnum);

    void registerThreadExit(process *proc, long tid, bool exiting);

    void registerProcess(BPatch_process *process, int pid=0);
    void unRegisterProcess(int pid);

    void launchDeferredOneTimeCode();

    void registerLoadedModule(process *process, mapped_module *mod);
    void registerUnloadedModule(process *process, mapped_module *mod);

    BPatch_thread *getThreadByPid(int pid, bool *exists = NULL);
    BPatch_process *getProcessByPid(int pid, bool *exists = NULL);

    static void reportError(BPatchErrorLevel severity, int number, const char *str);

    void clearError() { lastError = 0; }
    int getLastError() { return lastError; }
    // End of functions that are for internal use only

    public:

    BPatch();

    //  BPatch::~BPatch
    //  destructor
    API_EXPORT_DTOR(_dtor, (),

    ~,BPatch,());

    static const char *getEnglishErrorString(int number);
    static void formatErrorString(char *dst, int size,
				  const char *fmt, const char * const *params);

    // BPatch::isTypeChecked:
    // returns whether type checking is on.
    API_EXPORT(Int, (),

    bool,isTypeChecked,());

    // BPatch::parseDebugInfo:
    // returns whether debugging information is set to be parsed
    API_EXPORT(Int, (),

    bool,parseDebugInfo,());

    // BPatch::baseTrampDeletion:
    // returns whether base trampolines are set to be deleted
    API_EXPORT(Int, (),

    bool,baseTrampDeletion,());

    // BPatch::setPrelinkCommand
    // sets the fully qualified path name of the prelink command
    API_EXPORT_V(Int, (command),

 	void,setPrelinkCommand,(char *command));

    // BPatch::getPrelinkCommand
    // gets the fully qualified path name of the prelink command
    API_EXPORT(Int, (),

 	char*,getPrelinkCommand,());

    // BPatch::isTrampRecursive:
    // returns whether trampolines are set to handle recursive instrumentation
    API_EXPORT(Int, (),

    bool,isTrampRecursive,());

    API_EXPORT(Int, (),
    bool, disregardLiveness_NP, ());

    // BPatch::isMergeTramp:
    // returns whether base tramp and mini-tramp is merged
    API_EXPORT(Int, (),

    bool,isMergeTramp,());        

    // BPatch::saveFPROn:
    // returns whether base tramp and mini-tramp is merged
    API_EXPORT(Int, (),

    bool,isSaveFPROn,());        

    // BPatch::hasForcedRelocation_NP:
    // returns whether all instrumented functions will be relocated
    API_EXPORT(Int, (),

    bool,hasForcedRelocation_NP,());

    // BPatch::autoRelocationsOn:
    // returns whether functions will be relocated when appropriate
    API_EXPORT(Int, (),

    bool,autoRelocationOn,());


    // BPatch::delayedParsingOn:
    // returns whether inst info is parsed a priori, or on demand
    API_EXPORT(Int, (),

    bool,delayedParsingOn,());


    //  User-specified callback functions...

    //  BPatch::registerErrorCallback:
    //  Register error handling/reporting callback
    API_EXPORT(Int, (function),

    BPatchErrorCallback, registerErrorCallback,(BPatchErrorCallback function));

    //  BPatch::registerDynLibraryCallback:
    //  Register callback for new library events (eg. load)
    API_EXPORT(Int, (func),

    BPatchDynLibraryCallback, registerDynLibraryCallback,(BPatchDynLibraryCallback func));

    //  BPatch::registerPostForkCallback:
    //  Register callback to handle mutatee fork events (before fork)
    API_EXPORT(Int, (func),

    BPatchForkCallback, registerPostForkCallback,(BPatchForkCallback func));

    //  BPatch::registerPreForkCallback:
    //  Register callback to handle mutatee fork events (before fork)
    API_EXPORT(Int, (func),

    BPatchForkCallback, registerPreForkCallback,(BPatchForkCallback func));

    //  BPatch::registerExecCallback:
    //  Register callback to handle mutatee exec events 
    API_EXPORT(Int, (func),
    BPatchExecCallback, registerExecCallback,(BPatchExecCallback func));

    //  BPatch::registerExitCallback:
    //  Register callback to handle mutatee exit events 
    API_EXPORT(Int, (func),

    BPatchExitCallback, registerExitCallback,(BPatchExitCallback func));

    //  BPatch::registerOneTimeCodeCallback:
    //  Register callback to run at completion of oneTimeCode 
    API_EXPORT(Int, (func),
    BPatchOneTimeCodeCallback, registerOneTimeCodeCallback,(BPatchOneTimeCodeCallback func));

    //  BPatch::registerThreadEventCallback
    //  Registers a callback to run when a thread is created
    API_EXPORT(Int, (type,cb),
    bool,registerThreadEventCallback,(BPatch_asyncEventType type, 
                                      BPatchAsyncThreadEventCallback cb));

    //  BPatch::removeThreadEventCallback
    //  Registers a callback to run when a thread is destroyed
    API_EXPORT(Int, (type,cb),
    bool,removeThreadEventCallback,(BPatch_asyncEventType type,
                                    BPatchAsyncThreadEventCallback cb));

    //  BPatch::registerDynamicCallCallback
    //  Specifies a user-supplied function to be called when a dynamic call is
    //  executed.

    API_EXPORT(Int, (cb),
    bool,registerDynamicCallCallback,(BPatchDynamicCallSiteCallback cb));

    API_EXPORT(Int, (cb),
    bool,removeDynamicCallCallback,(BPatchDynamicCallSiteCallback cb));


    //  BPatch::registerUserEventCallback
    //  
    //  Specifies a user defined function to call when a "user event" 
    //  occurs, user events are trigger by calls to the function 
    //  DYNINSTuserMessage(void *, int) in the runtime library.
    //  
    //  BPatchUserEventCallback is:
    //  void (*BPatchUserEventCallback)(void *msg, unsigned int msg_size);

    API_EXPORT(Int, (cb),
    bool,registerUserEventCallback,(BPatchUserEventCallback cb)); 

    API_EXPORT(Int, (cb),
    bool,removeUserEventCallback,(BPatchUserEventCallback cb));

    //  BPatch::getThreads:
    //  Get a vector of all threads
    API_EXPORT(Int, (),
    BPatch_Vector<BPatch_thread*> *,getThreads,());

    //  BPatch::getThreads:
    //  Get a vector of all processes 
    API_EXPORT(Int, (),
    BPatch_Vector<BPatch_process*> *,getProcesses,());

    //
    //  General BPatch parameter settings:
    //
    
    //  BPatch::setDebugParsing:
    //  Turn on/off parsing of debug section(s)
    API_EXPORT_V(Int, (x),

    void,setDebugParsing,(bool x));

    //  BPatch::setBaseTrampDeletion:
    //  Turn on/off deletion of base tramp
    API_EXPORT_V(Int, (x),

    void,setBaseTrampDeletion,(bool x));

    //  BPatch::setTypeChecking:
    //  Turn on/off type checking
    API_EXPORT_V(Int, (x),

    void,setTypeChecking,(bool x));

    //  BPatch::setTrampRecursive:
    //  Turn on/off recursive trampolines
    API_EXPORT_V(Int, (x),

    void,setTrampRecursive,(bool x));

    API_EXPORT_V(Int, (x),
    void, setDisregardLiveness_NP, (bool x));

    //  BPatch::setMergeTramp:
    //  Turn on/off merged base & mini-tramps
    API_EXPORT_V(Int, (x),

    void,setMergeTramp,(bool x));

    //  BPatch::setSaveFPR:
    //  Turn on/off merged base & mini-tramps
    API_EXPORT_V(Int, (x),

    void,setSaveFPR,(bool x));

    //  BPatch::setForcedRelocation_NP:
    //  Turn on/off forced relocation of instrumted functions
    API_EXPORT_V(Int, (x),

    void,setForcedRelocation_NP,(bool x));

    //  BPatch::setAutoRelocation_NP:
    //  Turn on/off function relocations, performed when necessary
    API_EXPORT_V(Int, (x),

    void,setAutoRelocation_NP,(bool x));

    //  BPatch::setDelayedParsing:
    //  Turn on/off delayed parsing
    API_EXPORT_V(Int, (x),

    void,setDelayedParsing,(bool x));

    // BPatch::processCreate:
    // Create a new mutatee process
    API_EXPORT(Int, (path, argv, envp, stdin_fd, stdout_fd, stderr_fd),
    BPatch_process *,processCreate,(const char *path,
                                    const char *argv[],
                                    const char **envp = NULL,
                                    int stdin_fd=0,
                                    int stdout_fd=1,
                                    int stderr_fd=2));

    // BPatch::processAttach
    // Attach to mutatee process
    API_EXPORT(Int, (path, pid),
    BPatch_process *,processAttach,(const char *path, int pid));

    // BPatch::createProcess:
    // Create a new mutatee process
    API_EXPORT(Int, (path, argv, envp, stdin_fd, stdout_fd, stderr_fd),
    BPatch_thread *,createProcess,(const char *path,
                                   const char *argv[],
                                   const char **envp = NULL,
                                   int stdin_fd=0,
                                   int stdout_fd=1,
                                   int stderr_fd=2));

    // BPatch::attachProcess:
    // Attach to mutatee process
    API_EXPORT(Int, (path, pid),
    BPatch_thread *,attachProcess,(const char *path, int pid));

    // BPatch::createEnum:
    // Create Enum types. 
    API_EXPORT(Int, (name, elementNames, elementIds),

    BPatch_type *,createEnum,(const char * name, BPatch_Vector<char *> &elementNames,
                              BPatch_Vector<int> &elementIds));

    // BPatch::createEnum:
    // API selects elementIds
    API_EXPORT(AutoId, (name, elementNames),

    BPatch_type *,createEnum,(const char * name, BPatch_Vector<char *> &elementNames));

    // BPatch::createStruct:
    // Create Struct types. 
    API_EXPORT(Int, (name, fieldNames, fieldTypes),

    BPatch_type *,createStruct,(const char * name, BPatch_Vector<char *> &fieldNames,
                                BPatch_Vector<BPatch_type *> &fieldTypes));

    // BPatch::createUnion:
    // Create Union types. 
    API_EXPORT(Int, (name, fieldNames, fieldTypes),

    BPatch_type *,createUnion,(const char * name, BPatch_Vector<char *> &fieldNames,
                               BPatch_Vector<BPatch_type *> &fieldTypes));

    // BPatch::createArray:
    // Creates BPatch_array type or symtyperanges ( scalars with upper and
    //lower bound).
    API_EXPORT(Int, (name, ptr, low, hi),

    BPatch_type *,createArray,(const char * name, BPatch_type * ptr,
                               unsigned int low, unsigned int hi));

    // BPatch::createPointer:
    // Creates BPatch_pointer types	 
    API_EXPORT(Int, (name, ptr, size),

    BPatch_type *,createPointer,(const char * name, BPatch_type * ptr,
                                 int size = sizeof(void *)));

    // BPatch::createScalar:
    // Creates BPatch_scalar types
    API_EXPORT(Int, (name, size),

    BPatch_type *,createScalar,(const char * name, int size));
    
    // BPatch::createTypedef:
    // Creates typedefs.
    API_EXPORT(Int, (name, ptr),

    BPatch_type *,createTypedef,(const char * name, BPatch_type * ptr));
	 
    // User programs are required to call pollForStatusChange or
    // waitForStatusChange before user-level callback functions
    // are executed (for example, fork, exit, or a library load). 

    // Non-blocking form; returns immediately if no callback is
    // ready, or executes callback(s) then returns.
    API_EXPORT(Int, (),
    bool,pollForStatusChange,());

    // Blocks until a callback is ready.
    API_EXPORT(Int, (),
    bool,waitForStatusChange,());

    // For user programs that block on other things as well,
    // we provide a (simulated) file descriptor that can be added
    // to a poll or select fdset. When a callback is prepared the BPatch
    // layer writes to this fd, thus making poll/select return. The user
    // program should then call pollForStatusChange. The BPatch layer
    // will handle clearing the file descriptor; all the program must do 
    // is call pollForStatusChange or waitForStatusChange.
    API_EXPORT(Int, (),
    int, getNotificationFD, ());

    //  BPatch:: waitUntilStopped:
    //  Block until specified process has stopped.
    API_EXPORT(Int, (appThread),

    bool,waitUntilStopped,(BPatch_thread *appThread));

    //  BPatch::getBPatchStatistics:
    //  Get Instrumentation statistics
    API_EXPORT(Int, (),

    BPatch_stats &,getBPatchStatistics,());

#ifdef IBM_BPATCH_COMPAT

    API_EXPORT(Int, (),
    int,getLastErrorCode,());

    // New-style, BPatch_process versions. Use these.

    API_EXPORT(Int, (cb),
    BPatchProcessEventCallback,registerDetachDoneCallback,(BPatchProcessEventCallback cb)); 

    API_EXPORT(Int, (cb),
    BPatchProcessEventCallback,registerSnippetRemovedCallback,(BPatchProcessEventCallback cb));

    API_EXPORT(Int, (func, sigNum),
    BPatchProcessEventCallback,registerSignalCallback,(BPatchProcessEventCallback func, int sigNum)); 

    API_EXPORT(DPCL, (func),
    BPatchProcessEventCallback,registerExitCallback,(BPatchProcessEventCallback func));

    API_EXPORT(Int, (cb),
    BPatchProcessEventCallback,registerRPCTerminationCallback,(BPatchProcessEventCallback cb));

    // DEPRECATED!!!

    API_EXPORT(Int, (cb),
    BPatchThreadEventCallback,registerDetachDoneCallback,(BPatchThreadEventCallback cb)); 

    API_EXPORT(Int, (cb),
    BPatchThreadEventCallback,registerSnippetRemovedCallback,(BPatchThreadEventCallback cb));

    API_EXPORT(Int, (func, sigNum),
    BPatchThreadEventCallback,registerSignalCallback,(BPatchThreadEventCallback func, int sigNum)); 

    API_EXPORT(DPCL, (func),
    BPatchThreadEventCallback,registerExitCallback,(BPatchThreadEventCallback func));

    API_EXPORT(Int, (cb),
    BPatchThreadEventCallback,registerRPCTerminationCallback,(BPatchThreadEventCallback cb));

#endif

};

#endif /* _BPatch_h_ */
