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

#ifndef _IRIX_DL_H_
#define _IRIX_DL_H_

#include <libelf.h>                        /* ElfXX_Sym */
#include "common/h/Types.h"
#include "common/h/Vector.h"
#include "dyninstAPI/src/sharedobject.h"
class process;


//
// All platform specific dynamic linking info is in this class.
// Each version of this class must have the following functions:
// getSharedObjects, isDynamic, handleIfDueToSharedObjectMapping
//
enum pdDsoEventType {
  DSO_INSERT_PRE,
  DSO_INSERT_VERSION_PRE,
  DSO_INSERT_POST,
  DSO_REMOVE_PRE,
  DSO_REMOVE_POST,
  DSO_UNKNOWN
};

class pdDsoEvent {
 public:
  pdDsoEvent(process *p, pdDsoEventType t, Address b);
  ~pdDsoEvent();

  pdDsoEventType type;
  Address        brk;
  instruction    buf[2];
  process       *proc;
};

// ABI-generic wrapper class for "ElfXX_Obj_Info"
class pdElfObjInfo {
 public:
  Address pd_self;
  Address pd_next;
  Address pd_prev;
  Address pd_ehdr;
  Address pd_orig_ehdr;
  pdstring  pd_pathname;

  pdElfObjInfo(process *p, Address addr, bool is_elf64);
  bool operator==(const pdElfObjInfo &) const;
  bool operator!=(const pdElfObjInfo &) const;
};

// ABI-generic wrapper class for "ElfXX_Sym"
class pdElfSym {
 public:
  
  unsigned pd_name;
  unsigned pd_type;
  unsigned pd_shndx;
  Address  pd_value;

  // 32-bit constructor
  pdElfSym(Elf32_Sym *symp)
  {
    assert(symp);
    pd_name = symp->st_name;
    pd_type = ELF32_ST_TYPE(symp->st_info);
    pd_shndx = symp->st_shndx;
    pd_value = symp->st_value;
  } 

  // 64-bit constructor
  pdElfSym(Elf64_Sym *symp)
  {
    assert(symp);
    pd_name = symp->st_name;
    pd_type = ELF64_ST_TYPE(symp->st_info);
    pd_shndx = symp->st_shndx;
    pd_value = symp->st_value;
  } 
};


// ABI-generic wrapper class for "ElfXX_Sym" vector
class pdElfSymVector {
 private:

  pdvector<pdElfSym *> elf_syms_;

 public:

  pdElfSymVector(Elf_Data *symdatap, bool is_elf64) 
    {
      assert(symdatap);
     
      if (is_elf64) {
	
	unsigned nsyms = symdatap->d_size / sizeof(Elf64_Sym);
	Elf64_Sym *syms = (Elf64_Sym *)symdatap->d_buf;
	for (unsigned i = 0; i < nsyms; i++) {
	  elf_syms_.push_back(new pdElfSym(&syms[i]));
	}

      } else { // 32-bit ELF
	
	unsigned nsyms = symdatap->d_size / sizeof(Elf32_Sym);
	Elf32_Sym *syms = (Elf32_Sym *)symdatap->d_buf;
	for (unsigned i = 0; i < nsyms; i++) {
	  elf_syms_.push_back(new pdElfSym(&syms[i]));
	}

      }
    }

  ~pdElfSymVector() 
    {
      for (unsigned i = 0; i < elf_syms_.size(); i++) {
	delete elf_syms_[i];
      }
    }

  int size() { return elf_syms_.size(); }

  pdElfSym &operator[](unsigned i) { return *elf_syms_[i]; }
};


#endif /* _IRIX_DL_H_ */


