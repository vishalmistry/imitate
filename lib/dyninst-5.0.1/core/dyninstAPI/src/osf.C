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

// $Id: osf.C,v 1.97 2006/05/16 21:14:35 jaw Exp $

#include "common/h/headers.h"
#include "os.h"
#include "process.h"
#include "dyn_lwp.h"
#include "stats.h"
#include "common/h/Types.h"
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <filehdr.h>
#include <scnhdr.h>
#include <fcntl.h>
#include <ldfcn.h>
#include "showerror.h"
#include "instPoint.h"

#include <sys/procfs.h>
#include <sys/poll.h>
#include <sys/fault.h>
#include <dlfcn.h>

#include "common/h/osfKludges.h"
#include "common/h/pathName.h"
#include "dyninstAPI/src/rpcMgr.h"
#include "dyninstAPI/src/signalhandler.h"
#include "dyninstAPI/src/signalgenerator.h"
#include "dyninstAPI/src/dyn_thread.h"

#include "mapped_object.h"
#include "function.h"

#define V0_REGNUM 0	/* retval from integer funcs */
#define PC_REGNUM 31
#define SP_REGNUM 30
#define FP_REGNUM 15
#define RA_REGNUM 26

int getNumberOfCPUs()
{
  return(1);
}

Address dyn_lwp::readRegister(Register /*reg*/)
{  
  gregset_t theIntRegs;
  if (-1 == ioctl(fd_, PIOCGREG, &theIntRegs)) {
    perror("process::readRegister PIOCGREG");
    if (errno == EBUSY) {
      cerr << "It appears that the process was not stopped in the eyes of /proc" << endl;
      assert(false);
    }
    return 0; // assert(false)?
  }
  return theIntRegs.regs[0];
}

//void OS::osTraceMe(void) { P_ptrace(PT_TRACE_ME, 0, 0, 0); }


// getActiveFrame(): populate Frame object using toplevel frame
Frame dyn_lwp::getActiveFrame()
{
  Address pc, fp;
  Frame theFrame;
  gregset_t theIntRegs;
//  int proc_fd = p->getProcFileDescriptor();
  if (ioctl(fd_, PIOCGREG, &theIntRegs) != -1) {
    fp = theIntRegs.regs[SP_REGNUM];  
    pc = theIntRegs.regs[PC_REGNUM]-4; /* -4 because the PC is updated */
    theFrame = Frame(pc, fp, 0, proc_->getPid(), proc_, NULL, this, true);
  }
  return theFrame;
}

/* 
 * Syscall tracing wrappers
 */
bool process::get_entry_syscalls(sysset_t *entries) {
    dyn_lwp *replwp = getRepresentativeLWP();    
    if (ioctl(replwp->get_fd(), PIOCGENTRY, entries) < 0) {
        perror("get_entry_syscalls");
        return false;
    }
    return true;
}

bool process::set_entry_syscalls(sysset_t *entries) {
    dyn_lwp *replwp = getRepresentativeLWP();    
    if (ioctl(replwp->get_fd(), PIOCSENTRY, entries) < 0) {
        perror("set_entry_syscalls");
        return false;
    }
    return true;
}

bool process::get_exit_syscalls(sysset_t *exits) {
    dyn_lwp *replwp = getRepresentativeLWP();    
    if (ioctl(replwp->get_fd(), PIOCGEXIT, exits) < 0) {
        perror("get_exit_syscalls");
        return false;
    }
    return true;
}

bool process::set_exit_syscalls(sysset_t *exits) {
    dyn_lwp *replwp = getRepresentativeLWP();    
    if (ioctl(replwp->get_fd(), PIOCSEXIT, exits) < 0) {
        perror("set_exit_syscalls");
        return false;
    }
    return true;
}


/*
 * Use by dyninst to set events we care about from procfs
 *
 */
bool process::setProcessFlags()
{

  long flags = 0;
  // cause the child to inherit trap-on-exit from exec and other traps
  // so we can learn of the child (if the user cares)
  flags = PR_FORK | PR_ASYNC;

  dyn_lwp *replwp = getRepresentativeLWP();
  if (ioctl(replwp->get_fd(), PIOCSET, &flags) < 0) {
    bperr( "attach: PIOCSET failed: %s\n", sys_errlist[errno]);
    return false;
  }

   /* we don't catch any child signals, except SIGSTOP */
   sigset_t sigs;
   fltset_t faults;
   premptyset(&sigs);
   praddset(&sigs, SIGSTOP);
   praddset(&sigs, SIGTRAP);
   praddset(&sigs, SIGSEGV);
   praddset(&sigs, DYNINST_BREAKPOINT_SIGNUM);
   
   if (ioctl(replwp->get_fd(), PIOCSTRACE, &sigs) < 0) {
       perror("setProcessFlags: PIOCSTRACE");
      return false;
   }
   
   premptyset(&faults);
   praddset(&faults,FLTBPT);
   if (ioctl(replwp->get_fd(), PIOCSFAULT, &faults) <0) {
       perror("setProcessFlags: PIOCSFAULT");
      return false;
  }

   // Clear the list of traced syscalls 
   sysset_t sysset;
   premptyset(&sysset);
   if (!set_entry_syscalls(&sysset)) return false;
   if (!set_exit_syscalls(&sysset)) return false;
    

  return true;
}

bool process::unsetProcessFlags()
{

  long flags = 0;
  // cause the child to inherit trap-on-exit from exec and other traps
  // so we can learn of the child (if the user cares)
  flags = PR_FORK | PR_ASYNC;

  if (!isAttached()) return false;

  dyn_lwp *replwp = getRepresentativeLWP();
  if (!replwp) {
     fprintf(stderr, "%s[%d]:  no representative lwp, cannot unset process flags\n", FILE__, __LINE__);
     return false;
  }
  if (ioctl(replwp->get_fd(), PIOCRESET, &flags) < 0) {
      perror("unsetProcessFlags: PIOCRESET");
      return false;
  }
  
   sigset_t sigs;
   premptyset(&sigs);

   if (ioctl(replwp->get_fd(), PIOCSTRACE, &sigs) < 0) {
       perror("unsetProcessFlags: PIOCSTRACE");
       return false;
   }
  return true;
}


static inline bool execResult(prstatus_t stat) 
{
  return (stat.pr_reg.regs[V0_REGNUM] == 0);
}


bool checkForAnyProcessExit(EventRecord &/*ev*/)
{
  extern pdvector<process*> processVec;
  bool ret = false;
  EventRecord temp;
  for (unsigned u = 0; u < processVec.size(); u++) {
    temp.proc = processVec[u];
    if (ret = temp.proc->sh->checkForExit(temp, false /*block ? */)) 
       break;
  }
  return ret;
}

bool SignalGenerator::decodeEvents(pdvector<EventRecord> &evts)
{
  // There can be only one...
  assert(evts.size() == 1);
  EventRecord &ev = evts[0];

   procProcStatus_t procstatus;

   //  read process status, and translate into internal event representation
   if (!ev.proc->getRepresentativeLWP()->get_status(&procstatus)) {
     if (ev.type == evtUndefined) {
       ev.type = evtProcessExit;
       ev.status = statusSignalled; // signifies unusual exit.
       if (checkForExit(ev, false)) {
	 return true;
       }
       fprintf(stderr, "%s[%d]:  file desc for process exit not available\n",
	       FILE__, __LINE__);
       return true;
     }
     fprintf(stderr, "%s[%d]:  file desc for %s not available\n",
	     FILE__, __LINE__, eventType2str(ev.type));
     return false;
   }
   
   if (!decodeProcStatus(procstatus, ev)) {
     fprintf(stderr, "%s[%d]:  decodeProcStatus failed\n", FILE__, __LINE__);
     return false;
   }
   
   signal_printf("%s[%d]:  new event: %s\n",
		 FILE__, __LINE__, eventType2str(ev.type));
   
   return true;
}

Frame dyn_thread::getActiveFrameMT() 
{
	return Frame();
}

Frame Frame::getCallerFrame()
{
  Address values[2];
  gregset_t theIntRegs;
  int_function *currFunc;
  if (fp_ == 0) return Frame();

  Address newPC=0;
  Address newFP=0;
  Address newSP=0;
  //Address newpcAddr=0;

  if (uppermost_) {
      int proc_fd = getProc()->getRepresentativeLWP()->get_fd();
      if (ioctl(proc_fd, PIOCGREG, &theIntRegs) != -1) {
	newPC = theIntRegs.regs[PC_REGNUM];  
	if (newPC) {
          currFunc = getProc()->findFuncByAddr(newPC);
          if (currFunc && currFunc->frame_size()) {
	    newFP = theIntRegs.regs[SP_REGNUM] + currFunc->frame_size();
	    newSP = theIntRegs.regs[SP_REGNUM];
	    //bperr(" %s fp=%lx\n",currFunc->prettyName().c_str(), newFP);
          } else {
	    sprintf(errorLine, "%s[%d]: pc %lx, not in a known function\n", 
		    __FILE__, __LINE__, newPC);
	    logLine(errorLine);
          }
	}
      } else {
          return Frame(); // zero frame
      }
  } else {
      if (!getProc()->readDataSpace((void *)sp_, sizeof(Address), values, false)){
          bperr("error reading frame at %lx\n", fp_);
          return Frame(); // zero frame
      } else {
          // (*sp_) = RA
          // fp_ + frame_size = saved fp
          newPC = values[0];
          
          currFunc = getProc()->findFuncByAddr(newPC);
          if (currFunc && currFunc->frame_size()) {
              newSP = fp_;		/* current stack pointer is old fp */
              newFP = fp_ + currFunc->frame_size();  
              //bperr(" %s fp=%lx\n",currFunc->prettyName().c_str(), newFP);
          } else {
              sprintf(errorLine, "%s[%d]: pc %lx, not in a known function\n", 
                                  __FILE__, __LINE__, newPC);
              logLine(errorLine);
              newFP = 0;
          }
      }
  }
  return Frame(newPC, newFP, newSP, 0, this);
}

bool Frame::setPC(Address newpc) {
  fprintf(stderr, "Implement me! Changing frame PC from %x to %x\n",
	  pc_, newpc);
  return false;
}

bool process::dumpCore_(const pdstring coreFile) 
{
  //bperr( ">>> process::dumpCore_()\n");
  bool ret;
#ifdef BPATCH_LIBRARY
  ret = dumpImage(coreFile);
#else
  ret = dumpImage();
#endif
  return ret;

}

pdstring process::tryToFindExecutable(const pdstring &progpath, int pid) 
{
   // returns empty string on failure

   if (exists_executable(progpath)) // util lib
      return progpath;

   char buffer[128];
   sprintf(buffer, "/proc/%05d", pid);
   int procfd = open(buffer, O_RDONLY, 0);
   if (procfd == -1) {
      startup_cerr << "tryToFindExecutable failed since open of /proc failed" << endl;
      return "";
   }
   startup_cerr << "tryToFindExecutable: opened /proc okay" << endl;

   struct prpsinfo the_psinfo;

   if (ioctl(procfd, PIOCPSINFO, &the_psinfo) == -1) {
       P_close(procfd);
       return "";
   }

   char commandName[256];
   strcpy(commandName, the_psinfo.pr_psargs);
   if (strchr(commandName, ' ')) *(strchr(commandName, ' ')) = '\0';

   if (!access(commandName, X_OK)) {
       // found the file, return the results
       (void) P_close(procfd);
       return commandName;
   }

   bperr("access to  %s failed \n", commandName);
   startup_cerr << "tryToFindExecutable: giving up" << endl;

   (void) P_close(procfd);

   return ""; // failure
}


//
// Write out the current contents of the text segment to disk.  This is useful
//    for debugging dyninst.
//
#ifdef BPATCH_LIBRARY
bool process::dumpImage(pdstring outFile)
#else
bool process::dumpImage()
#endif
{
#if !defined(BPATCH_LIBRARY)
  pdstring outFile = getImage()->file() + ".real";
#endif
  int i;
  int rd;
  int ifd;
  int ofd;
  int total;
  int length;
  Address baseAddr;
    //extern int errno;
    const int COPY_BUF_SIZE = 4*4096;
    char buffer[COPY_BUF_SIZE];
    struct filehdr hdr;
    struct stat statBuf;
    SCNHDR sectHdr;
    LDFILE      *ldptr = NULL;
    //image       *im;
    long text_size , text_start,file_ofs;

    pdstring origFile = getAOut()->fileName();

    ifd = open(origFile.c_str(), O_RDONLY, 0);
    if (ifd < 0) {
      sprintf(errorLine, "Unable to open %s\n", origFile.c_str());
      logLine(errorLine);
      showErrorCallback(41, (const char *) errorLine);
      perror("open");
      return true;
    }

    rd = fstat(ifd, &statBuf);
    if (rd != 0) {
      perror("fstat");
      sprintf(errorLine, "Unable to stat %s\n", origFile.c_str());
      logLine(errorLine);
      showErrorCallback(72, (const char *) errorLine);
      return true;
    }
    length = statBuf.st_size;

    sprintf(errorLine, "saving program to %s\n", outFile.c_str());
    logLine(errorLine);

    ofd = open(outFile.c_str(), O_WRONLY|O_CREAT, 0777);
    if (ofd < 0) {
      perror("open");
      exit(-1);
    }

    /* read header and section headers */
    /* Uses ldopen to parse the section headers */
    /* try */ 
    if (!(ldptr = ldopen(const_cast<char *>( origFile.c_str()), ldptr))) {
       perror("Error in Open");
       exit(-1);
     }
     
     if (TYPE(ldptr) != ALPHAMAGIC) {
       bperr("%s is not an alpha executable\n", outFile.c_str());
       exit(-1);
     }
     // Read the text and data sections
     hdr = HEADER(ldptr);
     /* Find text segment and then */
     /* compute text segment length and start offset */
     for (int k=0;k<hdr.f_nscns;k++) {
	 if (ldshread(ldptr, k , &sectHdr) == SUCCESS) {
	   // sprintf(errorLine,"Section: %s  Start: %ld ",sectHdr.s_name,
	   //  sectHdr.s_vaddr); 
	   // logLine(errorLine);
	   // cout << "Section: " << sectHdr.s_name << "\tStart: " << sectHdr.s_vaddr 
	   // << "\tEnd: " << sectHdr.s_vaddr + sectHdr.s_size << endl;
	   // cout.flush();
	 } else {
	     perror("Error reading section header");
	     exit(-1);
	 }

	 if (!P_strcmp(sectHdr.s_name, ".text")) {
	   text_size = sectHdr.s_size;
	   text_start = sectHdr.s_vaddr;
	   file_ofs = sectHdr.s_scnptr;
	 }
       }
     ldclose(ldptr);
    /* ---------end section header read ------------*/

    /* now copy the entire file */
    lseek(ofd, 0, SEEK_SET);
    lseek(ifd, 0, SEEK_SET);
    for (i=0; i < length; i += COPY_BUF_SIZE) {
        rd = read(ifd, buffer, COPY_BUF_SIZE);
        write(ofd, buffer, rd);
        total += rd;
    }

    baseAddr = (Address) text_start;
    sprintf(errorLine, "seeking to %ld as the offset of the text segment \n",
            file_ofs);
    logLine(errorLine);
    sprintf(errorLine, " code offset= %ld\n", baseAddr);
    logLine(errorLine);

    /* seek to the text segment */
    lseek(ofd,(off_t)file_ofs, SEEK_SET);
    for (i=0; i < text_size; i+= 1024) {
       errno = 0;
       length = ((i + 1024) < text_size) ? 1024 : text_size -i;
       dyn_lwp *replwp = getRepresentativeLWP();
       if (lseek(replwp->get_fd(),(off_t)(baseAddr + i), SEEK_SET) !=
           (long)(baseAddr + i))
       {
          bperr("Error_:%s\n",sys_errlist[errno]);
          bperr("[%d] Couldn't lseek to the designated point\n",i);
       }
       read(replwp->get_fd(),buffer,length);
       write(ofd, buffer, length);
    }

    P_close(ofd);
    P_close(ifd);

    return true;
}

/*
   terminate execution of a process
 */
terminateProcStatus_t process::terminateProc_()
{
  long flags = PRFS_KOLC;
  if (getRepresentativeLWP())
    if (ioctl (getRepresentativeLWP()->get_fd(), PIOCSSPCACT, &flags) < 0)
      return terminateFailed;
  
  // just to make sure it is dead
  if (kill(getPid(), 9)) {
    if (errno == ESRCH)
      return alreadyTerminated;
    else
      return terminateFailed;
  }
  return terminateSucceeded;
}

dyn_lwp *process::createRepresentativeLWP() {
   // don't register the representativeLWP in real_lwps since it's not a true
   // lwp
   representativeLWP = createFictionalLWP(0);
   return representativeLWP;
}

#if !defined(BPATCH_LIBRARY)
rawTime64 dyn_lwp::getRawCpuTime_hw()
{
  return 0;
}

/* return unit: nsecs */
rawTime64 dyn_lwp::getRawCpuTime_sw() 
{
  // returns user+sys time from the u or proc area of the inferior process,
  // which in turn is presumably obtained by mmapping it (sunos)
  // or by using a /proc ioctl to obtain it (solaris).
  // It must not stop the inferior process in order to obtain the result,
  // nor can it assue that the inferior has been stopped.
  // The result MUST be "in sync" with rtinst's DYNINSTgetCPUtime().
  
  // We use the PIOCUSAGE /proc ioctl
  
  // Other /proc ioctls that should work too: PIOCPSINFO and the
  // lower-level PIOCGETPR and PIOCGETU which return copies of the proc
  // and u areas, respectively.
  // PIOCSTATUS does _not_ work because its results are not in sync
  // with DYNINSTgetCPUtime
  
  rawTime64 now;
  
  prpsinfo_t procinfo;
  
  if (ioctl(fd_, PIOCPSINFO, &procinfo) == -1) {
    perror("process::getInferiorProcessCPUtime - PIOCPSINFO");
    abort();
  }
  
  /* Put secs and nsecs into usecs */
  now = procinfo.pr_time.tv_sec;
  now *= I64_C(1000000000);
  now += procinfo.pr_time.tv_nsec;
  
  if (now<sw_previous_) {
    // time shouldn't go backwards, but we have seen this happening
    // before, so we better check it just in case - naim 5/30/97
    logLine("********* time going backwards in paradynd **********\n");
    now=sw_previous_;
  }
  else {
    sw_previous_=now;
  }
  
  return now;
}
#endif

bool SignalGeneratorCommon::getExecFileDescriptor(pdstring filename,
                                    int /*pid*/,
                                    bool /*whocares*/,
                                    int &,
                                    fileDescriptor &desc)
{
    desc = fileDescriptor(filename, 0, 0, false);
    return true;
}

bool dyn_lwp::get_status(procProcStatus_t *status) const
{
    if (ioctl(get_fd(), 
            PIOCSTATUS, status) == -1) {
       return false;
    }
    return true;
}

bool dyn_lwp::realLWP_attach_() {
   assert( false && "threads not yet supported on OSF");
   return false;
}

// in procfs.C
bool lwp_isRunning_(int);

bool dyn_lwp::representativeLWP_attach_() 
{
   /*
     Open the /proc file correspoding to process pid, 
     set the signals to be caught to be only SIGSTOP,
     and set the kill-on-last-close and inherit-on-fork flags.
   */

   char procName[128];    
   sprintf(procName, "/proc/%d", (int)getPid());
   fd_ = P_open(procName, O_RDWR, 0);
   if (fd_ == -1) {
      perror("Error opening process file descriptor");
      return false;
   }

   is_attached_ = true;

   // If we attached to a running process, then stop
   // (If we created the process, we know its stopped already, so don't do anything)
   if (proc()->wasCreatedViaAttach()) {
     if (lwp_isRunning_(fd_)) {
       stop_();
     }
   }

   return true;
}

void dyn_lwp::realLWP_detach_()
{
   assert(is_attached());  // dyn_lwp::detach() shouldn't call us otherwise
}

void dyn_lwp::representativeLWP_detach_()
{
   assert(is_attached());  // dyn_lwp::detach() shouldn't call us otherwise
   if (fd_) P_close(fd_);
}


void loadNativeDemangler() {}




bool process::trapDueToDyninstLib(dyn_lwp *)
{
  Address pc;
  prstatus_t stat;

  if (dyninstlib_brk_addr == 0) return false;

  if (ioctl(getRepresentativeLWP()->get_fd(), PIOCSTATUS, &stat) < 0) {
      perror("ioctl");
  }

  //pc = Frame(this).getPC();
  pc = getRepresentativeLWP()->getActiveFrame().getPC();

  // bperr("testing for trap at entry to DyninstLib, current pc = 0x%lx\n",pc);
  // bperr("    breakpoint addr = 0x%lx\n", dyninstlib_brk_addr);

  bool ret = (pc == dyninstlib_brk_addr);

  // XXXX - Hack, Tru64 is giving back an invalid pc here, we check for a pc == 0 and
  //   conclude if we are waiting for a trap for dlopen, then this must be it.
  //   Need to figure out why this happens. - jkh 1/30/02
  if (!ret && (stat.pr_reg.regs[31] == 0)) ret = true;

  return ret;
}

bool process::loadDYNINSTlibCleanup(dyn_lwp *)
{
    dyninstlib_brk_addr = 0x0;
    
  // restore code and registers
    //bool err;

  int_function *_startfn;

    pdvector<int_function *> funcs;
    bool res = findFuncsByMangled("_start", funcs);
    if (!res) {
        // we can't instrument main - naim
      if (!findFuncsByMangled("__start", funcs)) {
        showErrorCallback(108,"process::loadDYNINSTlibCleanup: _start() unfound");
        return false;
      }
    }
    if( funcs.size() > 1 ) {
      cerr << __FILE__ << __LINE__ 
             << ": found more than one main! using the first" << endl;
    }
    _startfn = funcs[0];

    Address code = _startfn->getAddress();

  assert(code);
  writeDataSpace((void *)code, sizeof(savedCodeBuffer), savedCodeBuffer);

  getRepresentativeLWP()->restoreRegisters(*savedRegs);

  delete savedRegs;
  savedRegs = NULL;
  dyninstlib_brk_addr = 0;

  return true;
}





bool osfTestProc(int proc_fd, const void *mainLoc)
// This function is used to test if the child program is
// ready to be read or written to.  mainLoc should be the
// address of main() in the mutatee.
//
// See process::insertTrapAtEntryPointOfMain() below for a
// detailed explination of why this function is needed.
//
// Ray Chen 6/18/2002
{
    return (lseek(proc_fd, reinterpret_cast<off_t>(mainLoc), SEEK_SET) == (off_t)mainLoc);
}

void osfWaitProc(int fd)
{
    int ret;
    struct pollfd pollFD;
    struct prstatus status;

    // now wait for the signal
    memset(&pollFD, '\0', sizeof(pollFD));
    pollFD.fd = fd;
    pollFD.events = POLLPRI | POLLNORM;
    pollFD.revents = 0;
    ret = poll(&pollFD, 1, -1);
    if (ret < 0) {
	 pdstring msg("poll failed");
	 showErrorCallback(101, msg);
	 return;
    }

    if (ioctl(fd, PIOCSTATUS, &status) < 0) {
	 pdstring msg("PIOCSTATUS failed");
	 showErrorCallback(101, msg);
	 return;
    }
#ifdef DEBUG
    bperr("status = %d\n", status.pr_why);
    if (status.pr_flags & PR_STOPPED) {
        if (status.pr_why == PR_SIGNALLED) {
            bperr("stopped for signal %d\n", status.pr_what);
        } else if (status.pr_why == PR_FAULTED) {
            bperr("stopped for fault %d\n", status.pr_what);
        } else if (status.pr_why == PR_SYSEXIT) {
            bperr("stopped for exist system call %d\n", status.pr_what);
        } else {
            bperr("stopped for pr+why = %d\n", status.pr_why);
        }
    } else {
        bperr("process is *not* stopped\n");
    }
#endif
}

/*
 * Place a trap at the entry point to main.  We need to prod the program
 *    along a bit since at the entry to this function, the program is in
 *    the dynamic loader and has not yet loaded the segment that contains
 *    main.  All we need to do is wait for a SIGTRAP that the loader gives
 *    us just after it completes loading.
 */
bool process::insertTrapAtEntryPointOfMain()
{
  // XXX - Should check if it's statically linked and skip the prod. - jkh
  // continueProc_();
  // waitProc(proc_fd, SIGTRAP);

  // continueProc_();
  // waitProc(proc_fd, SIGTRAP);

  // save trap address: start of main()
  // TODO: use start of "_main" if exists?
  //bool err;
  int countdown = 10;

    int_function *f_main = NULL;
    pdvector<int_function *> funcs;
    bool res = findFuncsByPretty("main", funcs);
    if (!res) {
        // we can't instrument main - naim
        showErrorCallback(108,"main() uninstrumentable");
        return false;
    }

    if( funcs.size() > 1 ) {
        cerr << __FILE__ << __LINE__ 
             << ": found more than one main! using the first" << endl;
    }
    f_main = funcs[0];
    assert(f_main);

    main_brk_addr = f_main->getAddress();
    if (!main_brk_addr) {
      // failed to locate main
      showErrorCallback(108,"Failed to locate main().\n");
      return false;
    }
    assert(main_brk_addr);
    
    // dumpMap(proc_fd);
    
    while (!osfTestProc(getRepresentativeLWP()->get_fd(), (void *)main_brk_addr))
      {
	// POSSIBLE BUG:  We expect the first SIGTRAP to occur after a
	// successful exec call, but we seem to get an early signal.
	// At the time of the first SIGTRAP, attempts to read or write the
	// child data space fail.
	//
	// If the child is instructed to continue, it will eventually stop
	// in a useable state (before the first instruction of main).  However,
	// a SIGTRAP will *NOT* be generated on the second stop.  PROCFS also
	// stops in a strange state (prstatus_t.pr_info.si_code == 0).
	//
	// Looks like this code was in place before.  I don't know why it was
	// removed. (I renamed waitProc() to osfWaitProc() to avoid confusion
	// with process' waitProcs() class method)
	//
	// Ray Chen 03/22/02
	if (--countdown < 0) {
	  // looped too many times.
	  showErrorCallback(108, "Could not access mutatee (even after 10 tries).\n");
	  return false;
	}
	
	getRepresentativeLWP()->continueLWP_(dyn_lwp::NoSignal);
	osfWaitProc(getRepresentativeLWP()->get_fd());
      }
    readDataSpace((void *)main_brk_addr, instruction::size(), savedCodeBuffer, true);

    codeGen gen(instruction::size());
    instruction::generateTrap(gen);
    
    writeDataSpace((void *)main_brk_addr, gen.used(), gen.start_ptr());
    return true;
}

bool process::trapAtEntryPointOfMain(dyn_lwp *, Address)
{
  Address pc;

  if (main_brk_addr == 0) return false;

  //pc = Frame(this).getPC();
  pc = getRepresentativeLWP()->getActiveFrame().getPC();

  // bperr("testing for trap at enttry to main, current pc = %lx\n", pc);

  bool ret = (pc == main_brk_addr);
  // if (ret) bperr( ">>> process::trapAtEntryPointOfMain()\n");
  return ret;
}

bool process::handleTrapAtEntryPointOfMain(dyn_lwp *)
{
  // restore original instruction to entry point of main()
  writeDataSpace((void *)main_brk_addr, instruction::size(), savedCodeBuffer);
  
    // set PC to be value at the address.
   gregset_t theIntRegs;
   dyn_lwp *replwp = getRepresentativeLWP();
   if (ioctl(replwp->get_fd(), PIOCGREG, &theIntRegs) == -1) {
      perror("dyn_lwp::getRegisters PIOCGREG");
      if (errno == EBUSY) {
         cerr << "It appears that the process was not stopped in the eyes of /proc" << endl;
         assert(false);
      }
      return false;
   }
   theIntRegs.regs[PC_REGNUM] -= 4;
   replwp->changePC(theIntRegs.regs[PC_REGNUM], NULL);
   
   prstatus info;
   ioctl(replwp->get_fd(), PIOCSTATUS,  &info);
   while (!prismember(&info.pr_flags, PR_STOPPED))
   {
       sleep(1);
       ioctl(replwp->get_fd(), PIOCSTATUS,  &info);
   }
   if (ioctl(replwp->get_fd(), PIOCSREG, &theIntRegs) == -1) {
       perror("dyn_lwp::getRegisters PIOCGREG");
       if (errno == EBUSY) {
           cerr << "It appears that the process was not stopped in the eyes of /proc" << endl;
           assert(false);
       }
       return false;
   }
   return true;
}


bool process::getDyninstRTLibName() {
   if (dyninstRT_name.length() == 0) {
      // Get env variable
      if (getenv("DYNINSTAPI_RT_LIB") != NULL) {
         dyninstRT_name = getenv("DYNINSTAPI_RT_LIB");
      }
      else {
         pdstring msg = pdstring("Environment variable ") +
                        pdstring("DYNINSTAPI_RT_LIB") +
                        pdstring(" has not been defined for process ") +
                        pdstring(getPid());
         showErrorCallback(101, msg);
         return false;
      }
   }
   // Check to see if the library given exists.
   if (access(dyninstRT_name.c_str(), R_OK)) {
      pdstring msg = pdstring("Runtime library ") + dyninstRT_name +
                     pdstring(" does not exist or cannot be accessed!");
      showErrorCallback(101, msg);
      return false;
   }
   return true;
}



bool process::loadDYNINSTlib()
{
    //bperr( ">>> process::loadDYNINSTlib()\n");

  // use "_start" as scratch buffer to invoke dlopen() on DYNINST
  //bool err;
  extern bool skipSaveCalls;
  
  int_function *_startfn;
  
  pdvector<int_function *> funcs;
  if (!findFuncsByMangled("_start", funcs) &&
      !findFuncsByMangled("__start", funcs)) {
    // we can't instrument main - naim
    showErrorCallback(108,"process::loadDYNINSTlib: _start() unfound");
    return false;
  }
  
  if( funcs.size() > 1 ) {
    cerr << __FILE__ << __LINE__ 
	 << ": found more than one _start! using the first" << endl;
  }
  _startfn = funcs[0];
  
  Address baseAddr = _startfn->getAddress();
  assert(baseAddr);

  codeGen gen(BYTES_TO_SAVE);

  // step 0: illegal instruction (code)
  instruction::generateIllegal(gen);
  
  // step 1: DYNINST library string (data)
  Address libAddr = baseAddr + gen.used();
#ifdef BPATCH_LIBRARY
  char *libVar = "DYNINSTAPI_RT_LIB";
#else
  char *libVar = "PARADYN_LIB";
#endif
  char *libName = getenv(libVar);
  if (!libName) {
    pdstring msg = pdstring("Environment variable DYNINSTAPI_RT_LIB is not defined,"
        " should be set to the pathname of the dyninstAPI_RT runtime library.");
    showErrorCallback(101, msg);
    return false;
  }

  int libSize = strlen(libName) + 1;
  gen.copy(libName, libSize);

  // step 2: inferior dlopen() call (code)
  Address dlopenAddr = gen.currAddr(baseAddr);

  extern registerSpace *createRegisterSpace();
  registerSpace *regs = createRegisterSpace();
  
  pdvector<AstNode*> args(2);
  AstNode *call;
  pdstring callee = "dlopen";
  // inferior dlopen(): build AstNodes
  args[0] = new AstNode(AstNode::Constant, (void *)libAddr);
  args[1] = new AstNode(AstNode::Constant, (void *)RTLD_NOW);
  call = new AstNode(callee, args);
  removeAst(args[0]);
  removeAst(args[1]);
  
  // inferior dlopen(): generate code
  regs->resetSpace();
  
  skipSaveCalls = true;		// don't save register, we've done it!
  call->generateCode(this, regs, gen, true, true);
  skipSaveCalls = false;

  removeAst(call);

  Address trapAddr = gen.currAddr(baseAddr);
  instruction::generateTrap(gen);
  
  // save registers and "_start" code
  readDataSpace((void *)baseAddr, BYTES_TO_SAVE, (void *) savedCodeBuffer,true);
  savedRegs = new dyn_saved_regs;
  bool status = getRepresentativeLWP()->getRegisters(savedRegs);
  assert(status == true);
  
  
  // bperr( "writing %ld bytes to <0x%08lx:_start>, $pc = 0x%lx\n",
  // bufSize, baseAddr, codeAddr);
  // bperr( ">>> loadDYNINSTlib <0x%lx(_start): %ld insns>\n",
  // baseAddr, bufSize/instruction::size());

  writeDataSpace((void *)baseAddr, gen.used(), gen.start_ptr());
  bool ret = getRepresentativeLWP()->changePC(dlopenAddr, savedRegs);
  assert(ret);

  dyninstlib_brk_addr = trapAddr;
  setBootstrapState(loadingRT_bs);
  
  return true;
}

bool process::determineLWPs(pdvector<unsigned> & /*all_lwps*/)
{
  return true;
}

// findCallee: returns false unless callee is already set in instPoint
// dynamic linking not implemented on this platform
int_function *instPoint::findCallee() {
  if (callee_) {
    return callee_;
  }
  
  if (ipType_ != callSite) {
    return NULL;
  }
  
  if (isDynamicCall()) { 
    return NULL;
  }
  
  // Check if we parsed an intra-module static call
  assert(img_p_);
  image_func *icallee = img_p_->getCallee();
  if (icallee) {
    // Now we have to look up our specialized version
    // Can't do module lookup because of DEFAULT_MODULE...
    const pdvector<int_function *> *possibles = func()->obj()->findFuncVectorByMangled(icallee->symTabName());
    if (!possibles) {
      return NULL;
    }
    for (unsigned i = 0; i < possibles->size(); i++) {
      if ((*possibles)[i]->ifunc() == icallee) {
	callee_ = (*possibles)[i];
	return callee_;
      }
    }
    // No match... very odd
    assert(0);
    return NULL;
  }
  
#if 0
  // Not sure what this was supposed to do... instr.getCallee() would
  // always be false if callIndirect is true.

  // Ahh... there's an AIX-similar "load and jump" combo. We determined this
  // via parsing in an unsafe way; this should be updated if this causes
  // a problem.

  if((target = instr.getCallee())) {
    return true;
  }
  if (instr.callIndirect && instr.getCallee()) {
    // callee contains the address in the mutatee
    // read the contents of the address
    Address dest;
    if (!readDataSpace((caddr_t)(instr.getCallee()), sizeof(Address),
		       (caddr_t)&(dest),true)) {
      return false;
    }
    // now lookup the funcation
    target = findFuncByAddr(dest);
    if (target) return true;
  }
#endif
  return NULL;
}

void dyninst_yield()
{
}
