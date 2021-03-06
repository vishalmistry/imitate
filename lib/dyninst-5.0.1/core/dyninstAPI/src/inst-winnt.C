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

// $Id: inst-winnt.C,v 1.26 2006/05/04 01:41:21 legendre Exp $

#include "dyninstAPI/src/os.h"
#include "dyninstAPI/src/dyninst.h"
#include "dyninstAPI/src/symtab.h"
#include "dyninstAPI/src/process.h"
#include "dyninstAPI/src/inst.h"
#include "dyninstAPI/src/instP.h"
#include "dyninstAPI/src/ast.h"
#include "dyninstAPI/src/ptrace_emul.h"
#include "dyninstAPI/src/util.h"
#include "dyninstAPI/src/stats.h"
#include "dyninstAPI/src/instPoint.h"

#ifdef NOTDEF // PDSEP
#ifndef BPATCH_LIBRARY
#include "rtinst/h/trace.h"
#include "paradynd/src/main.h"
#include "paradynd/src/perfStream.h"
#include "dyninstAPI/src/showerror.h"

#ifndef mips_unknown_ce2_11 //ccw 27 july 2000 : 29 mar 2001
//defined in inst-mips.C

pdstring process::getProcessStatus() const {
   char ret[80];

   switch (status()) {
	case running:
	    sprintf(ret, "%d running", pid);
	    break;
	case neonatal:
	    sprintf(ret, "%d neonatal", pid);
	    break;
	case stopped:
	    sprintf(ret, "%d stopped", pid);
	    break;
	case exited:
	    sprintf(ret, "%d exited", pid);
	    break;
	default:
	    sprintf(ret, "%d UNKNOWN State", pid);
	    break;
    }
    return(ret);
}
#endif

#endif
#endif
#ifndef mips_unknown_ce2_11 //ccw 27 july 2000 : 29 mar 2001
//defined in inst-mips.C

//
// All costs are based on Measurements on a SPARC station 10/40.
//
void initPrimitiveCost()
{
    /* Need to add code here to collect values for other machines */

    // this doesn't really take any time
    primitiveCosts["DYNINSTbreakPoint"] = 1;

    // this happens before we start keeping time.
    primitiveCosts["DYNINSTinit"] = 1;

    primitiveCosts["DYNINSTprintCost"] = 1;

    //
    // I can't find DYNINSTincrementCounter or DYNINSTdecrementCounter
    // I think they are not being used anywhere - naim
    //
    // isthmus acutal numbers from 7/3/94 -- jkh
    // 240 ns
    primitiveCosts["DYNINSTincrementCounter"] = 16;
    // 240 ns
    primitiveCosts["DYNINSTdecrementCounter"] = 16;

    // Updated calculation of the cost for the following procedures.
    // cost in cycles
    // Values (in cycles) benchmarked on a Pentium II 450MHz
    // Level 1 - Hardware Level
    primitiveCosts["DYNINSTstartWallTimer"] = 151;
    primitiveCosts["DYNINSTstopWallTimer"] = 165;

    // Implementation still needs to be added to handle start/stop
    // timer costs for multiple levels
    /* Level 2 - Software Level
    primitiveCosts["DYNINSTstartWallTimer"] = 797;
    primitiveCosts["DYNINSTstopWallTimer"] = 807;
    */
    primitiveCosts["DYNINSTstartProcessTimer"] = 990;
    primitiveCosts["DYNINSTstopProcessTimer"] = 1017;

    // These happen async of the rest of the system.
    primitiveCosts["DYNINSTalarmExpire"] = 3724;
    primitiveCosts["DYNINSTsampleValues"] = 13;
    primitiveCosts["DYNINSTreportTimer"] = 1380;
    primitiveCosts["DYNINSTreportCounter"] = 1270;
    primitiveCosts["DYNINSTreportCost"] = 1350;
    primitiveCosts["DYNINSTreportNewTags"] = 837;
}
#endif

/*
 * Define the various classes of library functions to inst. 
 *
 */
void initLibraryFunctions()
{
}
 

// hasBeenBound: returns false
// dynamic linking not implemented on this platform
bool process::hasBeenBound(const relocationEntry &,int_function *&, Address ) {
    return false;
}

// findCallee: returns false unless callee is already set in instPoint
// dynamic linking not implemented on this platform
int_function *instPoint::findCallee() 
{
   // Already been bound
   if (callee_) {
      return callee_;
   }  
   if (ipType_ != callSite) {
       return NULL;
   }
  
   if (!isDynamicCall()) {
      // We have a direct call but don't yet know the callee.
      // This may be because we didn't see a symbol for a
      // thunk in the ILT.
      // (I.e., the call is 'call @ILT+<smallconstant>'
      // and at @ILT+<smallconstant> there is a 'jmp <realfuncaddr>'
      // instruction.
      //
      // We consider the callee to be the real function that
      // is eventually called.
      
      // get the target address of the call
      Address callTarget = insn().getTarget(addr());
      
      // find code range that contains the target address
      // TODO: optimize by checking callsite image first?
      codeRange* cr = proc()->findCodeRangeByAddress(callTarget);
      if (cr == NULL) 
         return NULL;
      // if target address is a known function, return it
      int_function* func = cr->is_function();
      if (func != NULL) {
         callee_ = func;
         return func;
      }
      mapped_object *obj = cr->is_mapped_object();
      if (obj == NULL)
         return NULL;
      
      // get a "local" pointer to the call target instruction
      const void *insnLocalAddr = proc()->getPtrToInstruction(callTarget);
      instruction callTargetInst(insnLocalAddr);
      
      if( callTargetInst.isJumpDir() ||
          callTargetInst.isJumpIndir() )
      {
         // the instruction is a jmp
         // get the target address of the jmp
         Address jmpTargetAddr = callTargetInst.getTarget(callTarget);
              
         // see if we know about that target address
         int_function *target = proc()->findFuncByAddr( jmpTargetAddr );
         if (target) {
            callee_ = target;
            return target;
         }
      }
   }
   else
   {
      // An call that uses an indirect call instruction could be one
      // of three things:
      //
      // 1. A call to a function within the same executable or DLL.  In 
      //    this case, it could be a call through a function pointer in
      //    memory or a register, or some other type of call.
      //   
      // 2. A call to a function in an implicitly-loaded DLL.  These are
      //    indirect calls through an entry in the object's Import Address 
      //    Table (IAT). An IAT entry is set to the address of the target 
      //    when the DLL is loaded at process creation.
      //
      // 3. A call to a function in a delay-loaded DLL.  Like calls to 
      //    implicitly-loaded DLLs, these are calls through an entry in the 
      //    IAT.  However, for delay-loaded DLLs the IAT entry initially 
      //    holds the address of a short code sequence that loads the DLL,
      //    looks up the target function, patches the IAT entry with the 
      //    address of the target function, and finally executes the target 
      //    function.  After the first call, the IAT entry has been patched
      //    and subsequent calls look the same as calls into an
      //    implicitly-loaded DLL.
      //
      // Figure out what type of indirect call instruction this is
      //
      Register base_reg;
      Register index_reg;
      int displacement;
      unsigned int scale;
      unsigned int mod;
      int instMode = get_instruction_operand( insn().ptr(),
                                              base_reg,
                                              index_reg,
                                              displacement,
                                              scale,
                                              mod );
          
      if( instMode == DISPLACED )
      {
          // it is a call through a function pointer in memory
         Address funcPtrAddress = (Address)displacement;
         assert( funcPtrAddress != ADDR_NULL );
                  
         // obtain the target address from memory if it is available
         Address targetAddr = ADDR_NULL;
         proc()->readDataSpace( (const void*)funcPtrAddress, sizeof(Address),
                                &targetAddr, true );
         if( targetAddr != ADDR_NULL )
         {
            
            // see whether we already know anything about the target
            // this may be the case with implicitly-loaded and delay-loaded
            // DLLs, and it is possible with other types of indirect calls
            int_function *target = proc()->findFuncByAddr( targetAddr );
                          
            // we need to handle the delay-loaded function case specially,
            // since we want the actual target function, not the temporary
            // code sequence that handles delay loading
            if( (target != NULL) &&
                (!strncmp( target->prettyName().c_str(), "_imp_load_", 10 )) )
            {
               // The target is named like a linker-generated
               // code sequence for a call into a delay-loaded DLL.
               //
               // Try to look up the function based on its name
               // without the 
                                  
#if READY
               // check if the target is in the same module as the function
               // containing the instPoint
               // check whether the function pointer is in the IAT
               if((funcPtrAddress >= something.iatBase) &&
                  (funcPtrAddress <= (something.iatBase+something.iatLength)))
               {
                  // it is a call through the IAT, to a function in our
                  // own module, so it is a call into a delay-loaded DLL
                  // ??? how to handle this case
               }
#else
               // until we can detect the actual callee for delay-loaded
               // DLLs, make sure that we don't report the linker-
               // generated code sequence as the target
               target = NULL;
#endif // READY
            }
            else {
               callee_ = target;
               return target;
            }
         }   
      }
   }
   return NULL;
}
