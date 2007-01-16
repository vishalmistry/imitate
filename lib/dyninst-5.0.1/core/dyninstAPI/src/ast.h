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

// $Id: ast.h,v 1.89 2006/06/16 16:13:30 bernat Exp $

#ifndef AST_HDR
#define AST_HDR

//
// Define a AST class for use in generating primitive and pred calls
//

#include <stdio.h>
#include "common/h/Vector.h"
#include "common/h/Dictionary.h"
#include "common/h/String.h"
#include "common/h/Types.h"
#include "dyninstAPI/h/BPatch_type.h"

class process;
class instPoint;
class int_function;
class codeGen;

// a register number, e.g. [0,31]
// typedef int reg; // see new Register type in "common/h/Types.h"

typedef enum { 
               invalidOp,
               plusOp,
               minusOp,
               timesOp,
               divOp,
               lessOp,
               leOp,
               greaterOp,
               geOp,
               eqOp,
               neOp,
               loadOp,           
               loadConstOp,
	       loadFrameRelativeOp,
	       loadFrameAddr,
	       loadRegRelativeOp,	// More general form of loadFrameRelativeOp
	       loadRegRelativeAddr,	// More general form of loadFrameAddr
               storeOp,
	       storeFrameRelativeOp,
               ifOp,
	       whileOp,  // Simple control structures will be useful
	       doOp,     // Zhichen
	       callOp,
	       trampPreamble,
	       trampTrailer,
	       noOp,
	       orOp,
	       andOp,
	       getRetValOp,
	       getSysRetValOp,
	       getParamOp,
	       getSysParamOp,	   
	       getAddrOp,	// return the address of the operand
	       loadIndirOp,
	       storeIndirOp,
	       saveRegOp,
	       updateCostOp,
	       funcJumpOp,        // Jump to function without linkage
	       branchOp,
               ifMCOp,
	       undefOp
} opCode;

class registerSlot {
 public:
    Register number;    // what register is it
    int refCount;      	// == 0 if free
    bool needsSaving;	// been used since last restore
    bool mustRestore;   // need to restore it before we are done.		
    bool startsLive;	// starts life as a live register.
    bool beenClobbered; // registers clobbered
};

#if defined(ia64_unknown_linux2_4)
#include "inst-ia64.h"
#endif

class registerSpace {
 public:
	registerSpace(const unsigned int dCount, Register *deads,
                 const unsigned int lCount, Register *lives,
                 bool multithreaded = false);
   ~registerSpace();
	Register allocateRegister(codeGen &gen, bool noCost);
    bool allocateSpecificRegister(codeGen &gen, Register r, bool noCost);
	// Free the specified register (decrement its refCount)
	void freeRegister(Register k);
	// Free the register even if its refCount is greater that 1
	void forceFreeRegister(Register k);
	void resetSpace();
	void resetClobbers();
	void setAllLive();
	void saveClobberInfo(const instPoint * location);
	void resetLiveDeadInfo(const int* liveRegs,
			       const int *, const int *, bool);


	// Check to see if the register is free
	bool isFreeRegister(Register k);
	//bool getDisregardLiveness() {return disregardLiveness;}
	bool getDisregardLiveness();
	void setDisregardLiveness(bool dl) {disregardLiveness = dl;}
	
	// Inits the values for the clobbered variables for the floating point registers
	void initFloatingPointRegisters(const unsigned int count, Register *fp);

	
	//Makes register unClobbered
	void unClobberRegister(Register reg);
	void unClobberFPRegister(Register reg);

	// Checks to see if register has been clobbered and clobbers it 
	// if it hasn't been clobbered yet, returns true if we clobber it
	// false if it has already been clobbered
	bool clobberRegister(Register reg);
	bool clobberFPRegister(Register reg);

	// Checks to see if given register has been clobbered, true if it has
	bool beenSaved(Register reg);
	bool beenSavedFP(Register reg);

	// Checks to see if register starts live
	bool isRegStartsLive(Register reg);
	int fillDeadRegs(Register * deadRegs, int num);
	
	// Manually set the reference count of the specified register
	// we need to do so when reusing an already-allocated register
	void fixRefCount(Register k, int iRefCount);
	
	// Bump up the reference count. Occasionally, we underestimate it
	// and call this routine to correct this.
	void incRefCount(Register k);

	u_int getRegisterCount() { return numRegisters; }
	u_int getFPRegisterCount() { return numFPRegisters; }

	registerSlot *getRegSlot(Register k) { return (&registers[k]); }
	registerSlot *getFPRegSlot(Register k) { return (&fpRegisters[k]); }

	int getSPFlag() {return spFlag;}
	
	void copyInfo(registerSpace *rs) const;


	bool readOnlyRegister(Register k);
	// Make sure that no registers remain allocated, except "to_exclude"
	// Used for assertion checking.
	void checkLeaks(Register to_exclude);
   bool for_multithreaded() { return is_multithreaded; }

   registerSpace &operator=(const registerSpace &src);
 private:
	u_int numRegisters;
	u_int numFPRegisters;
	Register highWaterRegister;
	registerSlot *registers;
	registerSlot *fpRegisters;
	int spFlag;
	bool disregardLiveness; // for RPC base tramps
	bool is_multithreaded;
 public:
	bool hasXMM;  // for Intel architectures, XMM registers
 

#if defined(ia64_unknown_linux2_4)

public:
	int originalLocals;
	int originalOutputs;
	int originalRotates;
	int sizeOfStack;

	// storageMap[] needs to be of type 'int' as opposed to
	// 'Register' becuase negative values may be used.
	int storageMap[ BP_R_MAX ];
#endif

};

class dataReqNode;
class AstNode {
    public:
        enum nodeType { sequenceNode, opCodeNode, operandNode, callNode };
        enum operandType { Constant, ConstantPtr, ConstantString,
			   OffsetConstant,      // add a OffsetConstant type for offset
			                        // generated for level or index:
			                        //   it is  MAX#THREADS * level * tSize  for level
			                        //     or                 index * tSize  for index
			   DataValue, DataPtr,  // restore AstNode::DataValue and AstNode::DataPtr
                           DataId, DataIndir, DataReg,
			   Param, ReturnVal, DataAddr, FrameAddr, RegOffset,
			   SharedData, PreviousStackFrameDataReg,
			   EffectiveAddr, BytesAccessed };
        AstNode(); // mdl.C
	AstNode(const pdstring &func, AstNode *l, AstNode *r);
        AstNode(const pdstring &func, AstNode *l); // needed by inst.C
	AstNode(operandType ot, void *arg);
	AstNode(AstNode *l, AstNode *r);

        AstNode(opCode, AstNode *left); 
        // assumes "NULL" for right child ptr
        // needed by inst.C and stuff in ast.C

        AstNode(operandType ot, AstNode *l);
	AstNode(opCode ot, AstNode *l, AstNode *r, AstNode *e = NULL);
        AstNode(const pdstring &func, pdvector<AstNode *> &ast_args);
        AstNode(int_function *func, pdvector<AstNode *> &ast_args);
        // And for a blind jump to a known address
        AstNode(Address funcAddr, pdvector<AstNode *> &ast_args);
	AstNode(int_function *func); // FuncJump (for replaceFunction)

        AstNode(AstNode *src);
        AstNode &operator=(const AstNode &src);

       ~AstNode();

        Address generateTramp(process *proc, const instPoint *location, codeGen &gen, 
                              int *trampCost, bool noCost);
	Address generateCode(process *proc, registerSpace *rs, codeGen &gen, 
                             bool noCost, bool root,
			     const instPoint *location = NULL);
	Address generateCode_phase2(process *proc, registerSpace *rs, codeGen &gen,
                                    bool noCost,
				    const pdvector<AstNode*> &ifForks,
				    const instPoint *location = NULL);
        
	

	enum CostStyleType { Min, Avg, Max };
	int minCost() const {  return costHelper(Min);  }
	int avgCost() const {  return costHelper(Avg);  }
	int maxCost() const {  return costHelper(Max);  }

	// return the # of instruction times in the ast.
	int costHelper(enum CostStyleType costStyle) const;	
	void print() const;
        int referenceCount;     // Reference count for freeing memory
        int useCount;           // Reference count for generating code
        void setUseCount(registerSpace *rs); // Set values for useCount
        int getSize() { return size; };
        void cleanUseCount(void);
        bool checkUseCount(registerSpace*, bool&);
        void printUseCount(void);
	
	// Occasionally, we do not call .generateCode_phase2 for the
	// referenced node, but generate code by hand. This routine decrements
	// its use count properly
	void decUseCount(registerSpace *rs);

        Register kept_register; // Use when generating code for shared nodes

	// Path from the root to this node which resulted in computing the
	// kept_register. It contains only the nodes where the control flow
	// forks (e.g., "then" or "else" clauses of an if statement)
	pdvector<AstNode*> kept_path;

	// Record the register to share as well as the path that lead
	// to its computation
	void keepRegister(Register r, pdvector<AstNode*> path);

	// Do not keep the register anymore
	void unkeepRegister();

	// Do not keep the register and force-free it
	void forceUnkeepAndFree(registerSpace *rs);

	// Our children may have incorrect useCounts (most likely they 
	// assume that we will not bother them again, which is wrong)
	void fixChildrenCounts(registerSpace *rs);

	// Check to see if the value had been computed earlier
	bool hasKeptRegister() const;

	// Check if the node can be kept at all. Some nodes (e.g., storeOp)
	// can not be cached
	bool canBeKept() const;

	// Allocate a register and make it available for sharing if our
        // node is shared
	Register allocateAndKeep(registerSpace *rs, 
				 const pdvector<AstNode*> &ifForks,
				 codeGen &gen, bool noCost);

	// Check to see if path1 is a subpath of path2
	bool subpath(const pdvector<AstNode*> &path1, 
		     const pdvector<AstNode*> &path2) const;

	// Return all children of this node ([lre]operand, ..., operands[])
	void getChildren(pdvector<AstNode*> *children);

        void updateOperandsRC(bool flag); // Update operand's referenceCount
                                          // if "flag" is true, increments the
                                          // counter, otherwise it decrements 
                                          // the counter.
        void printRC(void);
	bool accessesParam(void);         // Does this AST access "Param"

	void setOValue(void *arg) { oValue = (void *) arg; }
	const void *getOValue() { return oValue; }
	// only function that's defined in metric.C (only used in metri.C)
	bool condMatch(AstNode* a,
		       pdvector<dataReqNode*> &data_tuple1,
		       pdvector<dataReqNode*> &data_tuple2,
		       pdvector<dataReqNode*> datareqs1,
		       pdvector<dataReqNode*> datareqs2);


	// DEBUG
	operandType getoType() const { return oType; };
    private:
        AstNode(opCode); // like AstNode(opCode, const AstNode &, 
                         //              const AstNode &)
                         // but assumes "NULL" for both child ptrs
	nodeType type;
	opCode op;		    // only for opCode nodes
	pdstring callee;		    // only for call nodes
	int_function *calleefunc;  // only for call nodes
        Address calleefuncAddr;
	pdvector<AstNode *> operands; // only for call nodes
	operandType oType;	    // for operand nodes
	void *oValue;	            // operand value for operand nodes
        unsigned int whichMA;       // only for memory access nodes
	BPatch_type *bptype;  // type of corresponding BPatch_snippet
	bool doTypeCheck;	    // should operands be type checked
	int size;		    // size of the operations (in bytes)

        // These 2 vrbles must be pointers; otherwise, we'd have a recursive
        // data structure with an infinite size.
        // The only other option is to go with references, which would have
        // to be initialized in the constructor and can't use NULL as a
        // sentinel value...
	AstNode *loperand;
	AstNode *roperand;
	AstNode *eoperand;

    public:
	// Functions for getting and setting type decoration used by the
	// dyninst API library
	AstNode(operandType ot, int which); // for memory access
	BPatch_type *getType() { return bptype; };
	void		  setType(BPatch_type *t) { 
				bptype = t; 
				if( t != NULL ) { size = t->getSize(); } }
	void		  setTypeChecking(bool x) { doTypeCheck = x; }
	BPatch_type	  *checkType();
};

AstNode *assignAst(AstNode *src);
void removeAst(AstNode *&ast);
void terminateAst(AstNode *&ast);

void emitLoadPreviousStackFrameRegister(Address register_num,
					Register dest,
                                        codeGen &gen,
					int size,
					bool noCost);
void emitFuncJump(opCode op, codeGen &gen,
		  const int_function *func, process *proc,
		  const instPoint *loc, bool noCost);

#endif /* AST_HDR */
