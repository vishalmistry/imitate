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

/* $Id: process.h,v 1.387.2.1 2006/09/19 16:07:16 legendre Exp $
 * process.h - interface to manage a process in execution. A process is a kernel
 *   visible unit with a seperate code and data space.  It might not be
 *   the only unit running the code, but it is only one changed when
 *   ptrace updates are applied to the text space.
 */

#ifndef PROCESS_H
#define PROCESS_H

#include <stdio.h>
#include <assert.h>

#include "dyninstAPI_RT/h/dyninstAPI_RT.h"

#include "common/h/String.h"
#include "common/h/vectorSet.h"
#include "common/h/Dictionary.h"
#include "common/h/Types.h"
#include "common/h/Timer.h"
#include "dyninstAPI/src/os.h"
#include "dyninstAPI/src/inst.h" // callWhen
#include "dyninstAPI/src/frame.h"
#include "dyninstAPI/src/showerror.h"
#include "dyninstAPI/src/libState.h"
#include "dyninstAPI/src/syscalltrap.h"
#include "dyninstAPI/src/codeRange.h"

//#include "dyninstAPI/src/symtab.h"
#include "dyninstAPI/src/imageUpdate.h"

#include "dyninstAPI/src/infHeap.h"
//#include "dyninstAPI/src/signalgenerator.h"

#if (! defined( BPATCH_LIBRARY )) && defined( PAPI )
#include "paradynd/src/papiMgr.h"
#endif

// Annoying... Solaris has two /proc header files, one for the
// multiple-FD /proc and one for an ioctl-based compatibility /proc.
// /usr/include/procfs.h is the one we want, and /usr/include/sys/procfs.h
// is the ioctl one. This makes it impossible to have a single include
// line. 
#if defined(os_solaris)
#include <procfs.h>
#elif defined(os_aix) || defined(os_osf) || defined(os_irix)
#include <sys/procfs.h>
#endif


#if defined( cap_unwind )
#include <libunwind.h>
#include <libunwind-ptrace.h>
#endif /* defined( cap_unwind ) */

#if defined(SHM_SAMPLING)
extern unsigned SHARED_SEGMENT_SIZE;
#endif

#define MAX_THREADS 32
extern unsigned activeProcesses; // number of active processes
   // how about just processVec.size() instead?  At least, this should be made
   // a (static) member vrble of class process

typedef enum { undefined_bs,
               unstarted_bs, 
               attached_bs, 
               begun_bs, 
               initialized_bs, 
               loadingRT_bs, 
               loadedRT_bs, 
               bootstrapped_bs} bootstrapState_t;

typedef enum { terminateFailed, terminateSucceeded, alreadyTerminated } terminateProcStatus_t;

typedef enum { vsys_unknown, vsys_unused, vsys_notfound, vsys_found } syscallStatus_t;

const int LOAD_DYNINST_BUF_SIZE = 256;

class instPoint;
class multiTramp;
class baseTramp;
class miniTramp;
class generatedCodeObject;
class replacedFunctionCall;
class functionReplacement;

class dyn_thread;
class dyn_lwp;

class Object;
class relocationEntry;
class fileDescriptor;
class Symbol;
class image;
class mapped_object;
class mapped_module;
class dynamic_linking;
class int_variable;
class int_function;

class rpcMgr;
class syscallNotification;

class SignalGenerator;

#ifdef BPATCH_LIBRARY
class BPatch_thread;
class BPatch_function;
#endif

#if 0
static inline unsigned ipHash(const instPoint * const &ip)
{
  // assume all addresses are 4-byte aligned
  unsigned result = (unsigned)(Address)ip;
  result >>= 2;
  return result;
  // how about %'ing by a huge prime number?  Nah, x % y == x when x < y 
  // so we don't want the number to be huge.
}
#endif

typedef void (*continueCallback)(timeStamp timeOfCont);

class process {
    friend class ptraceKludge;
    friend class dyn_thread;
    friend class dyn_lwp;
    friend Address loadDyninstDll(process *, char Buffer[]);
    friend class multiTramp;
    friend class SignalGenerator;
    friend class SignalGeneratorCommon;

    //  
    //  PUBLIC MEMBERS FUNCTIONS
    //  
    
 public:
    
    // Default constructor
    process(SignalGenerator *sh_);

    // Fork constructor
    process(process *parentProc, SignalGenerator *sg_, int iTrace_fd);

    SignalGenerator *getSG() {return sh;}
    // Creation work
    bool setupCreated(int iTraceLink);
    bool setupAttached();
    // Similar case... process execs, we need to clean everything out
    // and reload the runtime library. This is basically creation,
    // just without someone calling us to make sure it happens...
    bool prepareExec(fileDescriptor &desc);
    // Once we're sure an exec is finishing, there's all sorts of work to do.
    bool finishExec();

    // And fork...
    bool setupFork();

    // Shared creation tasks
    bool setupGeneral();

    // And parse/get the a.out
    // Doing this post-attach allows us to one-pass parse things that need it (e.g., AIX)
    bool setAOut(fileDescriptor &desc);
    bool setMainFunction();

  protected:  
  bool walkStackFromFrame(Frame currentFrame, // Where to start walking from
			  pdvector<Frame> &stackWalk); // return parameter
  Frame preStackWalkInit(Frame startFrame); //Let's the OS do any needed initialization
  public:
  // Preferred function: returns a stack walk (vector of frames)
  // for each thread in the program
  bool walkStacks(pdvector<pdvector<Frame> > &stackWalks);

  // Get a vector of the active frames of all threads in the process
  bool getAllActiveFrames(pdvector<Frame> &activeFrames);


  // Is the current address "after" the given instPoint?
  bool triggeredInStackFrame(Frame &frame,
                             instPoint *point,
                             callWhen when,
                             callOrder order);

  bool isInSignalHandler(Address addr);

  void deleteThread(dynthread_t tid);
  void deleteThread_(dyn_thread *thr);
  bool removeThreadIndexMapping(dynthread_t tid, unsigned index);

  // Thread index functions
  // Current implementations _cannot_ be correct; also, unused
#if 0
  unsigned getIndexToThread(unsigned index);
  void setIndexToThread(unsigned index, unsigned value);
  void updateThreadIndexAddr(Address addr);
#endif
 public:

  // Current process state
  processState status() const { return status_;}

  // State when we attached;
  bool wasRunningWhenAttached() const { return stateWhenAttached_ == running; }

  // Are we in the middle of an exec?
  bool execing() const { return inExec_; }

  // update the status on the whole process (ie. process state and all lwp
  // states)
  void set_status(processState st, bool global_st = true, bool overrideState = false);

  // update the status of the process and one particular lwp in the process
  void set_lwp_status(dyn_lwp *whichLWP, processState st);

  // should only be called by dyn_lwp::continueLWP
  void clearCachedRegister();

  Address previousSignalAddr() const { return previousSignalAddr_; }
  void setPreviousSignalAddr(Address a) { previousSignalAddr_ = a; }
  pdstring getStatusAsString() const; // useful for debug printing etc.

  bool checkContinueAfterStop() {
          if( continueAfterNextStop_ ) {
                  continueAfterNextStop_ = false;
                  return true;
          }
          return false;
  }

  void continueAfterNextStop() { continueAfterNextStop_ = true; }
  static process *findProcess(int pid);

#if defined(sparc_sun_solaris2_4) \
 || defined(i386_unknown_linux2_0) \
 || defined(x86_64_unknown_linux2_4) /* Blind duplication - Ray */ \
 || defined(rs6000_ibm_aix4_1)
  char* dumpPatchedImage(pdstring outFile);//ccw 28 oct 2001

#if defined(i386_unknown_linux2_0) \
 || defined(x86_64_unknown_linux2_4)
	bool prelinkSharedLibrary(pdstring originalLibNameFullPath, char* dirName, Address baseAddr);
#endif

#if defined(sparc_sun_solaris2_4)  //ccw 10 mar 2004
	bool dldumpSharedLibrary(pdstring dyninstRT_name, char* directoryname);
#endif

#if defined(i386_unknown_linux2_0) \
 || defined(x86_64_unknown_linux2_4) \
 || defined(sparc_sun_solaris2_4)
	char *saveWorldFindNewSharedLibraryName(pdstring originalLibNameFullPath, char* dirName);
	void setPrelinkCommand(char *command);
#endif

#else
  char* dumpPatchedImage(pdstring /*outFile*/) { return NULL; } 
#endif
	bool applyMutationsToTextSection(char *textSection, unsigned textAddr, unsigned textSize);
	

  bool dumpImage(pdstring outFile);

  //  SignalHandler::dumpMemory()
  //
  //  Dumps memory +/- nbytes around target addr, to stderr
  //  Used in place of dumpImage() on platforms that cannot dump core
  //  (windows, notably)
  //  Useful for debug output?  (belongs in process class?)
  bool dumpMemory(void *addr, unsigned nbytes);

  
  // This will find the named symbol in the image or in a shared object
  // Necessary since some things don't show up as a function or variable.
  bool getSymbolInfo( const pdstring &name, Symbol &ret );

  // Not at all sure we want to use this anymore...
  void overwriteImage( image* /*img */) {
    assert(0);
  }

  // Appears to be the system pointer size. 
  unsigned getAddressWidth(); 

  // The process keeps maps of valid (i.e. allocated) address ranges
  bool isValidAddress(Address);

  // And "get me a local pointer to XX" -- before we modified it.
  void *getPtrToInstruction(Address);

  // this is only used on aix so far - naim
  // And should really be defined in a arch-dependent place, not process.h - bernat
  Address getTOCoffsetInfo(Address);

  bool dyninstLibAlreadyLoaded() { return runtime_lib != 0; }

  rpcMgr *getRpcMgr() const { return theRpcMgr; }

  bool getCurrPCVector(pdvector <Address> &currPCs);

#if defined(os_solaris) && (defined(arch_x86) || defined(arch_x86_64))
  bool changeIntReg(int reg, Address addr);
#endif

  void installInstrRequests(const pdvector<instMapping*> &requests);
  void recognize_threads(process *parent = NULL);
  // Get LWP handles from /proc (or as appropriate)

  bool determineLWPs(pdvector<unsigned> &lwp_ids);

  int getPid() const;

  /***************************************************************************
   **** Runtime library initialization code (Dyninst)                     ****
   ***************************************************************************/

  bool loadDyninstLib();
  bool setDyninstLibPtr(mapped_object *libobj);
  bool setDyninstLibInitParams();
  bool finalizeDyninstLib();
  
  bool iRPCDyninstInit();
  static void DYNINSTinitCompletionCallback(process *, unsigned /* rpc_id */,
                                            void *data, void *ret);
  bool initMT();

  // Get the list of inferior heaps from:

  bool getInfHeapList(pdvector<heapDescriptor> &infHeaps); // Whole process
  bool getInfHeapList(const mapped_object *theObj,
                      pdvector<heapDescriptor> &infHeaps); // Single mapped object

  void addInferiorHeap(const mapped_object *obj);

  void initInferiorHeap();

  /* Find the tramp guard addr and set it */
  bool initTrampGuard();
  void saveWorldData(Address address, int size, const void* src);

#if defined(cap_save_the_world)

  char* saveWorldFindDirectory();

  unsigned int saveWorldSaveSharedLibs(int &mutatedSharedObjectsSize,
                                   unsigned int &dyninst_SharedLibrariesSize,
                                   char* directoryName, unsigned int &count);
  char* saveWorldCreateSharedLibrariesSection(int dyninst_SharedLibrariesSize);

  void saveWorldCreateHighMemSections(pdvector<imageUpdate*> &compactedHighmemUpdates, 
                                      pdvector<imageUpdate*> &highmemUpdates,
                                      void *newElf);
  void saveWorldCreateDataSections(void* ptr);
  void saveWorldAddSharedLibs(void *ptr);//ccw 14 may 2002
  void saveWorldloadLibrary(pdstring tmp, void *brk_ptr) {
     loadLibraryUpdates.push_back(tmp);
     loadLibraryBRKs.push_back(brk_ptr);
  };
  
#if defined(os_aix)
  void addLib(char *lname);//ccw 30 jul 2002
#endif // os_aix

#endif // cap_save_the_world


  bool writeDataSpace(void *inTracedProcess,
                      u_int amount, const void *inSelf);
  bool readDataSpace(const void *inTracedProcess, u_int amount,
                     void *inSelf, bool displayErrMsg);

  bool writeTextSpace(void *inTracedProcess, u_int amount, const void *inSelf);
  bool writeTextWord(caddr_t inTracedProcess, int data);

  bool readTextSpace(const void *inTracedProcess, u_int amount,
                     const void *inSelf);

  static bool IndependentLwpControl() { return INDEPENDENT_LWP_CONTROL; }
  void independentLwpControlInit();

  // Internal calls only; this is an asynchronous call that says "run when everyone
  // is finished". BPatch should use the equivalent SignalGeneratorCommon call.
  bool continueProc(int signalToContinueWith = -1);

  bool terminateProc();

  // Detach from a process, deleting data to prep for reattaching
  // NOTE: external callers should use this function, not ::detach
  bool detachProcess(const bool leaveRunning);

  private:
    bool detach(const bool leaveRunning);
  public:
  
  // Clear out all dynamically allocated process data
  void deleteProcess();
  ~process();
  bool pause();

  // instPoint isn't const; it may get an updated list of
  // instances since we generate them lazily.
  bool replaceFunctionCall(instPoint *point,const int_function *newFunc);

  bool dumpCore(const pdstring coreFile);
  bool attach();
  // Set whatever OS-level process flags are needed
  bool setProcessFlags();
  bool unsetProcessFlags(); // Counterpart to above
  
  bool getDynamicCallSiteArgs(instPoint *callSite, 
                              pdvector<AstNode *> &args);
                              
  // Trampoline guard get/set functions
  Address trampGuardBase(void) { return trampGuardBase_; }
  //  
  //  PUBLIC DATA MEMBERS
  //  


  // Need a code range of multiTramps
  // Look up to see if a multiTramp already covers this address.
  multiTramp *findMultiTramp(Address addr);
  // Add...
  void addMultiTramp(multiTramp *multi);
  // And remove.
  void removeMultiTramp(multiTramp *multi);

  // Replaced function calls...
  void addModifiedCallsite(replacedFunctionCall *RFC);

  // And replaced functions
  void addFunctionReplacement(functionReplacement *,
                              pdvector<codeRange *> &overwrittenObjs);

  codeRange *findModifiedPointByAddr(Address addr);
  void removeModifiedPoint(Address addr);

  // Did we override the address of this call?
  Address getReplacedCallAddr(Address origAddr) const;
  bool wasCallReplaced(Address origAddr) const;

  ////////////////////////////////////////////////
  // Address to <X> mappings
  ////////////////////////////////////////////////

 public:
  //interface call to Dyninst pass-through debugging
  Address stepi(bool verbose, int lwp);  
  void stepi(int lwp);  
  void stepi();  

 private:
  void print_instrucs(unsigned char *buffer, unsigned size, 
                 bool leave_files);
 public:
  void disass(Address start, Address end);
  void disass(Address start, Address end, bool leave_files);

#if defined( os_linux )
 public:
  Address getVsyscallStart() { return vsyscall_start_; }
  Address getVsyscallEnd() { return vsyscall_end_; }
  Address getVsyscallText() { return vsyscall_text_; } 
  syscallStatus_t getVsyscallStatus() { return vsys_status_; }
  void setVsyscallStatus(syscallStatus_t s) { vsys_status_ = s; }
  void setVsyscallRange(Address start, Address end) 
    { vsyscall_start_ = start; vsyscall_end_ = end; }
  void *getVsyscallData() { return vsyscall_data_; }
  void setVsyscallData(void *data) { vsyscall_data_ = data; }
  void setVsyscallText(Address addr) { vsyscall_text_ = addr; }
  bool readAuxvInfo(); 
#endif

#if defined(os_windows)
  bool instrumentThreadInitialFunc(int_function *f);
  pdvector<int_function *> initial_thread_functions;
#endif

  public:
  // True if we've reached or past a certain state
  bool reachedBootstrapState(bootstrapState_t state) const { return bootstrapState >= state; }

  pdstring getBootstrapStateAsString(bootstrapState_t state = undefined_bs) const;
  bootstrapState_t getBootstrapState() {return bootstrapState;}

  // Strictly increments (we never drop back down)
  void setBootstrapState(bootstrapState_t state);

  void resetBootstrapState(bootstrapState_t state) {
      // Every so often we need to force this to a particular value
      bootstrapState = state;
  }

  void suppressBPatchCallbacks(bool state) { 
      suppress_bpatch_callbacks_ = state; 
  }

 // Callbacks for higher level code (like BPatch) to learn about new 
 //  functions and InstPoints.
 private:
  BPatch_function *(*new_func_cb)(process *p, int_function *f);
  BPatch_point *(*new_instp_cb)(process *p, int_function *f, instPoint *ip, 
                                int type);
 public:
  //Trigger the callbacks from a lower level
  BPatch_function *newFunctionCB(int_function *f) 
     { assert(new_func_cb); return new_func_cb(this, f); }
  BPatch_point *newInstPointCB(int_function *f, instPoint *pt, int type)
     { assert(new_instp_cb); return new_instp_cb(this, f, pt, type); }

  //Register callbacks from the higher level
  void registerFunctionCallback(BPatch_function *(*f)(process *p, 
                                                      int_function *f))
     { new_func_cb = f; };
  void registerInstPointCallback(BPatch_point *(*f)(process *p, int_function *f,
                                                    instPoint *ip, int type))
     { new_instp_cb = f; }
  
  void warnOfThreadDelete(dyn_thread *thr);
 
  //Anonymous up pointer to the containing process.  This is BPatch_process
  // in Dyninst.  Currently stored as an void pointer in case we do
  // anything with this during the library split.
  void *container_proc;
 public:

 //Run the mutatee until exit in single-step mode, printing each instruction
 //as it executes.  
 void debugSuicide();
 private:


/////////////////////////////////////////////////////////////////
//  System call trap tracking
/////////////////////////////////////////////////////////////////

  public:
  // Overloaded: Address for linux-style, syscall # for /proc
  syscallTrap *trapSyscallExitInternal(Address syscall);
  bool clearSyscallTrapInternal(syscallTrap *trappedSyscall);
  
  // Check all traps entered for a match to the syscall
  bool checkTrappedSyscallsInternal(Address syscall);
    
  private:
  
  // Trampoline guard location -- actually an addr in the runtime library.

  
  //
  //  PRIVATE MEMBER FUNCTIONS
  // 

 public:


  bool getDyninstRTLibName();
  bool loadDYNINSTlib();
#if defined(os_linux)
  // If dlopen is present, use it. Otherwise, call a libc-internal function
  bool loadDYNINSTlib_exported();
  bool loadDYNINSTlib_hidden();

  // Unprotect stack if necessary for runtime library loading
  Address tryUnprotectStack(codeGen &buf, Address codeBase);
#endif
  bool loadDYNINSTlibCleanup(dyn_lwp *trappingLWP);
  bool trapDueToDyninstLib(dyn_lwp *trappingLWP);

  // trapAddress is not set on non-NT, we discover it inline
  bool trapAtEntryPointOfMain(dyn_lwp *checkLWP, Address trapAddress = 0);
  bool wasCreatedViaAttach() { return creationMechanism_ == attached_cm; }
  bool wasCreatedViaAttachToCreated() { return creationMechanism_ == attachedToCreated_cm; }

  // This is special, since it's orthogonal to the others. We're forked if
  // the "parent process" is non-null
  bool wasCreatedViaFork() { return parent != NULL; }


  bool insertTrapAtEntryPointOfMain();
  bool handleTrapAtEntryPointOfMain(dyn_lwp *trappingLWP);

  bool shouldSaveFPState();

  static pdstring tryToFindExecutable(const pdstring &progpath, int pid);
      // os-specific implementation.  Returns empty string on failure.
      // Otherwise, returns a full-path-name for the file.  Tries every
      // trick to determine the full-path-name, even though "progpath" may
      // be unspecified (empty string)

  bool isDynamicallyLinked() const { return mapped_objects.size() > 1; }

  bool decodeIfDueToSharedObjectMapping(EventRecord &);
  bool handleChangeInSharedObjectMapping(EventRecord &);

  private:

  public:

  // getSharedObjects: This routine is called before main() to get and
  // process all shared objects that have been mapped into the process's
  // address space
  bool processSharedObjects();

  // addASharedObject: This routine is called whenever a new shared object
  // has been loaded by the run-time linker after the process starts running
  // It processes the image, creates new resources
  bool addASharedObject(mapped_object *);

  // removeASharedObject: get rid of a shared object; e.g., dlclose
  bool removeASharedObject(mapped_object *);

  // return the list of dynamically linked libs
  const pdvector<mapped_object *> &mappedObjects() { return mapped_objects;  } 

  // getMainFunction: returns the main function for this process
  int_function *getMainFunction() const { return main_function; }

#if !defined(BPATCH_LIBRARY)
  // findOneFunction: returns the function associated with function "func"
  // and module "mod".  This routine checks both the a.out image and any
  // shared object images for this function.  
  // mcheyney - should return NULL if function is excluded!!!!
  class resource;
  int_function *findOnlyOneFunction(resource *func,resource *mod);

  //this routine searches for a function in a module.  Note that res is a vector
  // due to gcc emitting duplicate constructors/destructors
  bool findAllFuncsByName(resource *func, resource *mod, pdvector<int_function *> &res);
#endif

 private:
  enum mt_cache_result { not_cached, cached_mt_true, cached_mt_false };
  enum mt_cache_result cached_result;

 public:

  // If true is passed for ignore_if_mt_not_set, then an error won't be
  // initiated if we're unable to determine if the program is multi-threaded.
  // We are unable to determine this if the daemon hasn't yet figured out
  // what libraries are linked against the application.  Currently, we
  // identify an application as being multi-threaded if it is linked against
  // a thread library (eg. libpthreads.a on AIX).  There are cases where we
  // are querying whether the app is multi-threaded, but it can't be
  // determined yet but it also isn't necessary to know.
  bool multithread_capable(bool ignore_if_mt_not_set = false);

  // Do we have the RT-side multithread functions available
  bool multithread_ready(bool ignore_if_mt_not_set = false);
    
  dyn_thread *STdyn_thread();

  // findFuncByName: returns function associated with "func_name"
  // This routine checks both the a.out image and any shared object images 
  // for this function
  //int_function *findFuncByName(const pdstring &func_name);

  bool findFuncsByAll(const pdstring &funcname,
                      pdvector<int_function *> &res,
                      const pdstring &libname = "");

  // Specific versions...
  bool findFuncsByPretty(const pdstring &funcname,
                         pdvector<int_function *> &res,
                         const pdstring &libname = "");
  bool findFuncsByMangled(const pdstring &funcname, 
                          pdvector<int_function *> &res,
                          const pdstring &libname = "");

  bool findVarsByAll(const pdstring &varname,
                     pdvector<int_variable *> &res,
                     const pdstring &libname = "");

  void getLibAndFunc(const pdstring &name,
                     pdstring &func,
                     pdstring &lib);

  // And we often internally want to wrap the above to return one
  // and only one func...
  int_function *findOnlyOneFunction(const pdstring &name,
                                    const pdstring &libname = "");

  // Find the code sequence containing an address
  // Note: fix the name....
  codeRange *findCodeRangeByAddress(Address addr);
  int_function *findFuncByAddr(Address addr);
  int_basicBlock *findBasicBlockByAddr(Address addr);

  // And a lookup by "internal" function to find clones during fork...
  int_function *findFuncByInternalFunc(image_func *ifunc);

  //findJumpTargetFuncByAddr Acts like findFunc, but if it fails,
  // checks if 'addr' is a jump to a function.
  int_function *findJumpTargetFuncByAddr(Address addr);
  
  // We no longer do instPoints process-wide, as a codesharing function
  // may cause multiple instPoints at the same address. Lovely...
  // Instead, call int_function::findInstPByAddr(...)
  //  instPoint *findInstPByAddr(Address addr);
  // Should be called once per address an instPoint points to
  // (multiples for relocated functions)
  // void registerInstPointAddr(Address addr, instPoint *inst);
  // void unregisterInstPointAddr(Address addr, instPoint *inst);

  bool addCodeRange(codeRange *codeobj);
  bool deleteCodeRange(Address addr);
    
  // No function is pushed onto return vector if address can't be resolved
  // to a function
  pdvector<int_function *>pcsToFuncs(pdvector<Frame> stackWalk);

  // findModule: returns the module associated with "mod_name" 
  // this routine checks both the a.out image and any shared object 
  // images for this module
  // if check_excluded is true it checks to see if the module is excluded
  // and if it is it returns 0.  If check_excluded is false it doesn't check
  //  if substring_match is true, the first module whose name contains
  //  the provided string is returned.
  // Wildcard: handles "*" and "?"
  mapped_module *findModule(const pdstring &mod_name, bool wildcard = false);
  // And the same for objects
  // Wildcard: handles "*" and "?"
  mapped_object *findObject(const pdstring &obj_name, bool wildcard = false);
  mapped_object *findObject(Address addr);
  // getAllFunctions: returns a vector of all functions defined in the
  // a.out and in the shared objects
  void getAllFunctions(pdvector<int_function *> &);

  // getAllModules: returns a vector of all modules defined in the
  // a.out and in the shared objects
  void getAllModules(pdvector<mapped_module *> &);

  void triggerNormalExitCallback(int exitCode);
  void triggerSignalExitCallback(int signalnum);  
  
  // triggering normal exit callback and cleanup process happen at different
  // times.  if triggerSignalExitCallback is called, this function should
  // also be called at the same time.

  // this function makes no callback to dyninst but only does cleanup work
  bool handleProcessExit();

#ifndef BPATCH_LIBRARY
  bool SearchRelocationEntries(const image *owner, instPoint &instr,
                               int_function *&target,
                               Address target_addr, Address base_addr);
#endif

  // Checks the mapped object for signal handlers
  void findSignalHandler(mapped_object *obj);

#if defined(os_aix)
  // Manually copy inferior heaps past the end of text segments
  void copyDanglingMemory(process *parent);
#endif
  bool handleForkEntry();
  bool handleForkExit(process *child);
  bool handleExecEntry(char *arg0);
  bool handleExecExit(fileDescriptor &desc);

  public:

  dyn_thread *getThread(dynthread_t tid);
  dyn_lwp *getLWP(unsigned lwp_id);

  // return NULL if not found
  dyn_lwp *lookupLWP(unsigned lwp_id);

  // This is an lwp which controls the entire process.  This lwp is a
  // fictional lwp in the sense that it isn't associated with a specific lwp
  // in the system.  For both single-threaded and multi-threaded processes,
  // this lwp represents the process as a whole (ie. all of the individual
  // lwps combined).  This lwp will be NULL if no such lwp exists which is
  // the case for multi-threaded linux processes.
  dyn_lwp *getRepresentativeLWP() const {
     return representativeLWP;
  }

  dyn_lwp *getInitialLwp() const;
  dyn_thread *getInitialThread() const {
     if(threads.size() == 0)
        return NULL;

     return threads[0];
  }

  void updateThreadIndex(dyn_thread *thread, int index);
  dyn_thread *createInitialThread();
  void addThread(dyn_thread *thread);
  dyn_lwp *createRepresentativeLWP();

  // fictional lwps aren't saved in the real_lwps vector
  dyn_lwp *createFictionalLWP(unsigned lwp_id);
  dyn_lwp *createRealLWP(unsigned lwp_id, int lwp_index);

  void deleteLWP(dyn_lwp *lwp_to_delete);

  int maxNumberOfThreads();
#if defined(os_osf)
  int waitforRPC(int *status,bool block = false);
#endif
  const process *getParent() const {return parent;}

 public:

  void processCost(unsigned obsCostLow, timeStamp wallTime, 
                   timeStamp processTime);

   bool extractBootstrapStruct(DYNINST_bootstrapStruct *);
   bool isBootstrappedYet() const;
  
private:
  // Since we don't define these, 'private' makes sure they're not used:
  process &operator=(const process &); // assign oper

public:

  dynamic_linking *getDyn() { return dyn; }

  Address getObservedCostAddr() const { return costAddr_; }
  void updateObservedCostAddr(Address addr) { costAddr_ = addr;}


  // Add a signal handler that was detected
  void addSignalHandler(Address addr, unsigned size);
  
  // Used to be ifdefed, now not because of rework
  // Goes right to the multitramp and installs/uninstalls
  // jumps.
   bool uninstallMutations();
   bool reinstallMutations();

private:

  bool flushInstructionCache_(void *baseAddr, size_t size); //ccw 25 june 2001

  bool continueProc_(int sig);
  
  // terminateProcStatus_t is defined at the top of this file.
  terminateProcStatus_t terminateProc_();
  bool dumpCore_(const pdstring coreFile);
  bool osDumpImage(const pdstring &imageFileName,  pid_t pid, Address codeOff);

  dyn_lwp *query_for_stopped_lwp();
  dyn_lwp *stop_an_lwp(bool *wasRunning);

  // stops a process
  bool stop_(bool waitForStop = true);
  // wait until the process stops
  bool waitUntilStopped();
#if defined (os_linux)
  bool waitUntilLWPStops();
#endif
  
 public:

  dyn_lwp *query_for_running_lwp();

  // returns true iff ok to operate on the process (attached)
  bool isAttached() const;

  // returns true if the process is stopped (AKA we can operate on it)
  bool isStopped() const;

  // if the process has exited
  bool hasExited() const;


  // Prolly shouldn't be public... but then we need a stack of 
  // access methods. 
  // This is an lwp which controls the entire process.  This lwp is a
  // fictional lwp in the sense that it isn't associated with a specific lwp
  // in the system.  For both single-threaded and multi-threaded processes,
  // this lwp represents the process as a whole (ie. all of the individual
  // lwps combined).  This lwp will be NULL if no such lwp exists which is
  // the case for multi-threaded linux processes.

  // /proc platforms
#if defined(cap_proc)
  bool get_entry_syscalls(sysset_t *entry);
  bool get_exit_syscalls(sysset_t *exit);
  bool set_entry_syscalls(sysset_t *entry);
  bool set_exit_syscalls(sysset_t *exit);
#endif  //cap_proc

#if defined(cap_proc_fd)
    bool get_status(pstatus_t *) const;
#endif // cap_proc_fd


  public:
    mapped_object *getAOut() { assert(mapped_objects.size()); return mapped_objects[0];}
    
 public:
    // Needed by instPoint
    // hasBeenBound: returns true if the runtime linker has bound the
    // function symbol corresponding to the relocation entry in at the address 
    // specified by entry and base_addr.  If it has been bound, then the callee 
    // function is returned in "target_pdf", else it returns false. 
    bool hasBeenBound(const relocationEntry &entry, int_function *&target_pdf, 
                      Address base_addr) ;
 private:

  bool isRunning_() const;
     // needed to initialize the 'wasRunningWhenAttached' member vrble. 
     // Determines whether the process is running by doing a low-level OS
     // check, not by checking member vrbles like status_.  May assume that
     // process::attach() has already run, but can't assume anything else.
     // May barf with a not-yet-implemented error on a given platform if the
     // platform doesn't yet support attaching to a running process. But
     // there's no reason why we shouldn't be able to implement this on any
     // platform; after all, the output from the "ps" command can be used
     // (T --> return false, S or R --> return true, other --> return ?)

 private:
   static void inferiorMallocCallback(process *proc, unsigned /* rpc_id */,
                                      void *data, void *result);

   void inferiorMallocDynamic(int size, Address lo, Address hi);
   void inferiorFreeCompact(inferiorHeap *hp);
   int findFreeIndex(unsigned size, int type, Address lo, Address hi);

 public:
   // Handling of inferior memory management
#if defined(cap_dynamic_heap)
   // platform-specific definition of "near" (i.e. close enough for one-insn jump)
   void inferiorMallocConstraints(Address near_, Address &lo, Address &hi, inferiorHeapType type);
   // platform-specific buffer size alignment
   void inferiorMallocAlign(unsigned &size);
#endif

   
   Address inferiorMalloc(unsigned size, inferiorHeapType type=anyHeap,
			  Address near_=0, bool *err=NULL);
   void inferiorFree(Address item);
   bool inferiorRealloc(Address item, unsigned newSize);


/*Address inferiorMalloc(process *p, unsigned size, inferiorHeapType type=anyHeap,
                       Address near_=0, bool *err=NULL);
void inferiorFree(process *p, Address item, const pdvector<addrVecType> &);
*/
// garbage collect instrumentation

   void deleteGeneratedCode(generatedCodeObject *del);
   void gcInstrumentation();
   void gcInstrumentation(pdvector<pdvector<Frame> >&stackWalks);

  ///////////////////////////////////////////////////
  // Process class members
  ///////////////////////////////////////////////////
  int tmp;
  

  ///////////////////////////////
  // Core process data
  ///////////////////////////////
  process *parent;
  SignalGenerator *sh;
  pdvector<mapped_object *> mapped_objects;
  // And deleted...
  pdvector<mapped_object *> deleted_objects;
  // And a shortcut pointer
  mapped_object *runtime_lib;
  // ... and keep the name around
  pdstring dyninstRT_name;

  // We have to perform particular steps based on how we were started.
  typedef enum { unknown_cm, 
                 created_cm, 
                 attached_cm, 
                 attachedToCreated_cm } creationMechanism_t;

  // Use accessor method that checks before returning...
  creationMechanism_t creationMechanism_; 
  // Users may want to leave a process in the same state as it was;
  // for example, if attached.
  processState stateWhenAttached_;

  int_function *main_function; // Usually, but not always, "main"
  int_function *thread_index_function;
  dyn_thread *lastForkingThread;

  ///////////////////////////////
  // Shared library handling
  ///////////////////////////////
  dynamic_linking *dyn;

  
  ///////////////////////////////
  // Process control
  ///////////////////////////////
  dyn_lwp *representativeLWP;
  // LWPs are index by their id
  dictionary_hash<unsigned, dyn_lwp *> real_lwps;
  pdvector<dyn_lwp *> lwps_to_delete;

  // Threads are accessed by index.
  int max_number_of_threads;
  pdvector<dyn_thread *> threads;
  Address thread_structs_base;


  dynthread_t mapIndexToTid(int index);
  bool deferredContinueProc;
  Address previousSignalAddr_;
  bool continueAfterNextStop_;
  // Defined in os.h
  processState status_;         /* running, stopped, etc. */
  // And so we don't run into a _lot_ of problems in process control...
  bool exiting_; // Post-exit callback; "we don't care any more"

  //// Exec
  // For platforms where we have to guess what the next signal is caused by.
  // Currently: Linux/ptrace
  bool nextTrapIsExec;
  // More sure then looking at /proc/pid
  pdstring execPathArg;		// Argument given to exec
  pdstring execFilePath;	// Full path info
  bool inExec_; // Used to be a status vrble, but is orthogonal to running/stopped

  ///////////////////////////////
  // RPCs
  ///////////////////////////////
  rpcMgr *theRpcMgr;


  ///////////////////////////////
  // Save The World
  ///////////////////////////////
  bool collectSaveWorldData;//this is set to collect data for
				//save the world

  pdvector<imageUpdate*> imageUpdates;//ccw 28 oct 2001
  pdvector<imageUpdate*> highmemUpdates;//ccw 20 nov 2001
  pdvector<dataUpdate*>  dataUpdates;//ccw 26 nov 2001
  pdvector<pdstring> loadLibraryCalls;//ccw 14 may 2002 
  pdvector<pdstring> loadLibraryUpdates;//ccw 14 may 2002
  pdvector<void*> loadLibraryBRKs;
  int requestTextMiniTramp; //ccw 20 jul 2002
	void setRequestTextMiniTramp(int flag){requestTextMiniTramp=flag;};


  // Pipe between mutator and mutatee
  int traceLink;                /* pipe to transfer traces data over */

  // the following 3 are used in perfStream.C
  // Should migrate to process level when we get the LL tracePipe
  char buffer[2048];
  unsigned bufStart;
  unsigned bufEnd;


  ///////////////////////////////
  // Address lookup members
  ///////////////////////////////
  // Trap address to base tramp address (for trap instrumentation)
  dictionary_hash<Address, Address> trampTrapMapping;

  // Address to executable code pieces (functions, miniTramps, baseTramps, ...) mapping
  codeRangeTree codeRangesByAddr_;
  // Get a mutator-side pointer to mutatee-side data without readDataSpace...
  // codeRangeTree readableSections_;
  // codeSections_ and dataSections_ instead...
  // Address -> multiTramp mapping...
  codeRangeTree modifiedAreas_;
  // And an integer->multiTramp so we can replace multis easily
  dictionary_hash<int, multiTramp *> multiTrampDict;

  // Keep track of function replacements so that we can fix them
  // up later
  dictionary_hash<Address, replacedFunctionCall *> replacedFunctionCalls_;

  // Address -> instruction pointer (with sanity checking)
  codeRangeTree codeSections_;
  codeRangeTree dataSections_;

  // Signal handling!
  codeRangeTree signalHandlerLocations_;

  //////////////////
  // Startup and initialization
  //////////////////
  bootstrapState_t bootstrapState;
  bool suppress_bpatch_callbacks_;
  unsigned char savedCodeBuffer[BYTES_TO_SAVE];
  Address loadDyninstLibAddr;
  dyn_saved_regs *savedRegs;

  Address dyninstlib_brk_addr;
  Address main_brk_addr;

  char * systemPrelinkCommand;

#if defined(os_windows)
  dictionary_hash<Address, unsigned char> main_breaks;
  pdvector<unsigned> cached_lwps;

  // On windows we need to temporarily keep details of process creation in
  // order to handle their debug mechanism. We create the process, then get a message
  // about it (instead of our "pull" mechanism on other platforms). This gives us
  // space to stash the info.
  // Instead of tracking what we need to peel out, we keep the whole thing for later.

  handleT processHandle_;
  handleT mainFileHandle_;
  Address mainFileBase_;

  pdvector<int> continueHandles;
  pdvector<int> continueTypes;
#endif

  ////////////////////
  // Inferior heap
  ////////////////////
  bool splitHeaps;              /* are there separate code/data heaps? */
  bool heapInitialized_;
  inferiorHeap heap;            /* the heap */
  bool inInferiorMallocDynamic; // The oddest recursion problem...

  /////////////////////
  // System call and signal handling
  /////////////////////
  // Tracing for whatever mechanism we use to notify us of syscalls made
  // by the process (fork/exec/exit)
  syscallNotification *tracedSyscalls_;

  // A list of traps inserted at system calls
  pdvector<syscallTrap *> syscallTraps_;

  /////////////////////
  // Instrumentation
  /////////////////////
  pdvector<instMapping *> tracingRequests;
  pdvector<generatedCodeObject *> pendingGCInstrumentation;

  // Total observed cost. To avoid 64-bit math in the base tramps, we
  // use a 32-bit temporary accumulator and periodically dump it to
  // this variable.
  uint64_t cumulativeObsCost;
  unsigned lastObsCostLow; // Value of counter last time we checked it
  Address costAddr_; // Address of global cost in the mutatee

  Address threadIndexAddr; // Thread ID->index mapping
  Address trampGuardBase_; // Tramp recursion index mapping

  ///////////////////////////////
  // Platform-specific
  ///////////////////////////////

#if defined( arch_ia64 )
  unw_addr_space * unwindAddressSpace;
  dictionary_hash< Address, void * > unwindProcessArgs;
  typedef dictionary_hash< Address, void * >::iterator upaIterator;
  
  bool insertAndRegisterDynamicUnwindInformation( unw_dyn_info_t * unwindInformation );
#endif

#if defined(os_linux)
  //////////////////
  // Linux vsyscall stuff
  //////////////////
  syscallStatus_t vsys_status_; 
  Address vsyscall_start_;
  Address vsyscall_end_;
  Address vsyscall_text_;
  void *vsyscall_data_;
#endif

  ///////////////////
  // 64-32 bit mapping functions
  //////////////////
  bool readThreadStruct(Address baseAddr, dyninst_thread_t &struc);
};


process *ll_createProcess(const pdstring file, pdvector<pdstring> *argv, 
                          pdvector<pdstring> *envp,
                          const pdstring dir, int stdin_fd, int stdout_fd,
                          int stderr_fd);

process *ll_attachProcess(const pdstring &progpath, int pid, void *container_proc_);


bool isInferiorAllocated(process *p, Address block);

#if !defined(os_linux)
inline void process::independentLwpControlInit() { }
#endif

extern pdvector<process *> processVec;

#define NUMBER_OF_MAIN_POSSIBILITIES 7
extern char main_function_names[NUMBER_OF_MAIN_POSSIBILITIES][20];

#endif
