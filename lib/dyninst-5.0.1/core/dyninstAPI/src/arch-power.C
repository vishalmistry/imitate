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

/*
 * inst-power.C - Identify instrumentation points for a RS6000/PowerPCs
 * $Id: arch-power.C,v 1.10 2006/05/03 00:31:19 jodom Exp $
 */

#include "common/h/Types.h"
#include "arch.h"
#include "util.h"
#include "showerror.h"

instruction *instruction::copy() const {
    return new instruction(*this);
}

void instruction::generateIllegal(codeGen &gen) { // instP.h
    instruction insn;
    insn.generate(gen);
}

void instruction::generateTrap(codeGen &gen) {
    instruction insn(BREAK_POINT_INSN);
    insn.generate(gen);
}

void instruction::generateBranch(codeGen &gen, int disp, bool link)
{
    if (ABS(disp) > MAX_BRANCH) {
        fprintf(stderr, "ABS OFF: 0x%x, MAX: 0x%x\n",
                ABS(disp), MAX_BRANCH);
        bperr( "Error: attempted a branch of 0x%x\n", disp);
	logLine("a branch too far\n");
	showErrorCallback(52, "Internal error: branch too far");
	bperr( "Attempted to make a branch of offset %x\n", disp);
        assert(0);
	return;	
    }

    instruction insn;
    insn.insn_.iform.op = Bop;
    insn.insn_.iform.li = disp >> 2;
    insn.insn_.iform.aa = 0;
    if (link)
        insn.insn_.iform.lk = 1;
    else
        insn.insn_.iform.lk = 0;

    insn.generate(gen);

}

void instruction::generateBranch(codeGen &gen, Address from, Address to, bool link) {
    int disp = (to - from);
    generateBranch(gen, disp, link);
}

void instruction::generateCall(codeGen &gen, Address from, Address to) {
    generateBranch(gen, from, to, true);
}

void instruction::generateInterFunctionBranch(codeGen &gen,
                                              Address from,
                                              Address to) {
    int disp = from - to;
    if (ABS(disp) <= MAX_BRANCH) {
        // We got lucky...
        return generateBranch(gen, from, to);
    }

    // Code sequence:
    // push hi -> R0
    // or lo -> R0
    // move R0 -> CTR
    // branch -> CTR

    unsigned int top_half = ((to & 0xffff0000) >> 16);
    unsigned int bottom_half = (to & 0x0000ffff);
    assert (to == ((top_half << 16) + bottom_half));
    // AIX sign-extends. So if top_half is 0, and the top bit of
    // bottom_half is 0, then we can use a single instruction. Otherwise
    // do it the hard way.
    if (!top_half && !(bottom_half & 0x8000)) {
        // single instruction (CALop)
        instruction::generateImm(gen, 
                                 CALop, 0, 0, bottom_half);
    }
    else {
        instruction::generateImm(gen, CAUop, 
                                 0, 0, top_half);
        // ori dest,dest,LOW(src1)
        instruction::generateImm(gen, ORILop, 
                                 0, 0, bottom_half);
    }

    instruction insn;

    (*insn).raw = 0;                    //mtspr:  mtctr scratchReg
    (*insn).xform.op = 31;
    (*insn).xform.rt = 0;
    (*insn).xform.ra = SPR_CTR & 0x1f;
    (*insn).xform.rb = (SPR_CTR >> 5) & 0x1f;
    (*insn).xform.xo = 467;
    insn.generate(gen);

    // And branch to CTR
    instruction btctr(BCTRraw);
    btctr.generate(gen);
}

    
void instruction::generateImm(codeGen &gen, int op, Register rt, Register ra, int immd)
 {
  // something should be here to make sure immd is within bounds
  // bound check really depends on op since we have both signed and unsigned
  //   opcodes.
  // We basically check if the top bits are 0 (unsigned, or positive signed)
  // or 0xffff (negative signed)
  // This is because we don't enforce calling us with LOW(immd), and
  // signed ints come in with 0xffff set. C'est la vie.
  // TODO: This should be a check that the high 16 bits are equal to bit 15,
  // really.
  assert (((immd & 0xffff0000) == (0xffff0000)) ||
          ((immd & 0xffff0000) == (0x00000000)));

  instruction insn;
  
  (*insn).raw = 0;
  (*insn).dform.op = op;
  (*insn).dform.rt = rt;
  (*insn).dform.ra = ra;
  if (op==SIop) immd = -immd;
  (*insn).dform.d_or_si = immd;

  insn.generate(gen);
}

// rlwinm ra,rs,n,0,31-n
void instruction::generateLShift(codeGen &gen, Register rs, int shift, Register ra)
{
    instruction insn;
  
    assert(shift<32);
    (*insn).raw = 0;
    (*insn).mform.op = RLINMxop;
    (*insn).mform.rs = rs;
    (*insn).mform.ra = ra;
    (*insn).mform.sh = shift;
    (*insn).mform.mb = 0;
    (*insn).mform.me = 31-shift;
    (*insn).mform.rc = 0;

    insn.generate(gen);
}

// rlwinm ra,rs,32-n,n,31
void instruction::generateRShift(codeGen &gen, Register rs, int shift, Register ra)
{
    instruction insn;

    assert(shift<32);
    (*insn).raw = 0;
    (*insn).mform.op = RLINMxop;
    (*insn).mform.rs = rs;
    (*insn).mform.ra = ra;
    (*insn).mform.sh = 32-shift;
    (*insn).mform.mb = shift;
    (*insn).mform.me = 31;
    (*insn).mform.rc = 0;
    insn.generate(gen);
}

//
// generate an instruction that does nothing and has to side affect except to
//   advance the program counter.
//
void instruction::generateNOOP(codeGen &gen, unsigned size)
{
    assert ((size % instruction::size()) == 0);
    while (size) {
        instruction insn(NOOPraw);
        insn.generate(gen);
        size -= instruction::size();
    }
}

void instruction::generateSimple(codeGen &gen, int op, 
                                 Register src1, Register src2, 
                                 Register dest)
{
  instruction insn;

  int xop=-1;
  (*insn).raw = 0;
  (*insn).xform.op = op;
  (*insn).xform.rt = src1;
  (*insn).xform.ra = dest;
  (*insn).xform.rb = src2;
  if (op==ANDop) {
      xop=ANDxop;
  } else if (op==ORop) {
      xop=ORxop;
  } else {
      // only AND and OR are currently designed to use genSimpleInsn
      assert(0);
  }
  (*insn).xform.xo = xop;
  insn.generate(gen);
}

void instruction::generateRelOp(codeGen &gen, int cond, int mode, Register rs1,
                                Register rs2, Register rd)
{
    instruction insn;

    // cmp rs1, rs2
    (*insn).raw = 0;
    (*insn).xform.op = CMPop;
    (*insn).xform.rt = 0;    // really bf & l sub fields of rt we care about
    (*insn).xform.ra = rs1;
    (*insn).xform.rb = rs2;
    (*insn).xform.xo = CMPxop;

    insn.generate(gen);

    // li rd, 1
    instruction::generateImm(gen, CALop, rd, 0, 1);

    // b??,a +2
    (*insn).raw = 0;
    (*insn).bform.op = BCop;
    (*insn).bform.bi = cond;
    (*insn).bform.bo = mode;
    (*insn).bform.bd = 2;		// + two instructions */
    (*insn).bform.aa = 0;
    (*insn).bform.lk = 0;
    insn.generate(gen);

    // clr rd
    instruction::generateImm(gen, CALop, rd, 0, 0);
}

// Given a value, load it into a register (two operations, CAU and ORIL)

void instruction::loadImmIntoReg(codeGen &gen, Register rt, 
                                 unsigned value)
{
    unsigned high16 = (value & 0xffff0000) >> 16;
    unsigned low16 = (value & 0x0000ffff);
    assert((high16+low16)==value);
    
    if (high16 == 0x0) { // We can save an instruction by not using CAU
        instruction::generateImm(gen, CALop, rt, 0, low16);
        return;
    }
    else if (low16 == 0x0) { // we don't have to ORIL the low bits
        instruction::generateImm(gen, CAUop, rt, 0, high16);
        return;
    }
    else {
        instruction::generateImm(gen, CAUop, rt, 0, high16);
        instruction::generateImm(gen, ORILop, rt, rt, low16);
        return;
    }
}

Address instruction::getBranchOffset() const {
    if (isUncondBranch()) {
        return (insn_.iform.li << 2);
    }
    else if (isCondBranch()) {
        return (insn_.bform.bd << 2);
    }
    return 0;

}

Address instruction::getTarget(Address addr) const {
    if (isUncondBranch() || isCondBranch()) {
        return getBranchOffset() + addr;
    }
    else if (isInsnType(Bmask, BAAmatch)) // Absolute
        return (insn_.iform.li << 2);
    else if (isInsnType(Bmask, BCAAmatch)) // Absolute
        return (insn_.bform.bd << 2);

    return 0;
}

// TODO: argument _needs_ to be an int, or ABS() doesn't work.
void instruction::setBranchOffset(Address newOffset) {
    if (isUncondBranch()) {
        assert(ABS((int) newOffset) < MAX_BRANCH);
        insn_.iform.li = (newOffset >> 2);
    }
    else if (isCondBranch()) {
        assert(ABS(newOffset) < MAX_CBRANCH);
        insn_.bform.bd = (newOffset >> 2);
    }
    else {
        assert(0);
    }
}


bool instruction::isCall() const
{
#define CALLmatch 0x48000001 /* bl */
    
    // Only look for 'bl' instructions for now, although a branch
    // could be a call function, and it doesn't need to set the link
    // register if it is the last function call
    return(isInsnType(OPmask | AALKmask, CALLmatch));
}

// "Casting" methods. We use a "base + offset" model, but often need to 
// turn that into "current instruction pointer".
codeBuf_t *instruction::insnPtr(codeGen &gen) {
    return (instructUnion *)gen.cur_ptr();
}

// Same as above, but increment offset to point at the next insn.
codeBuf_t *instruction::ptrAndInc(codeGen &gen) {
    instructUnion *ret = insnPtr(gen);
    gen.moveIndex(instruction::size());
    return ret;
}

void instruction::setInstruction(codeBuf_t *ptr, Address) {
    // We don't need the addr on this platform
    instructUnion *insnPtr = (instructUnion *)ptr;
    insn_ = *insnPtr;
}

void instruction::generate(codeGen &gen) {
    instructUnion *ptr = ptrAndInc(gen);
    *ptr = insn_;
}

void instruction::write(codeGen &gen) {
    instructUnion *ptr = insnPtr(gen);
    *ptr = insn_;
}

bool instruction::isUncondBranch() const {
    return isInsnType(Bmask, Bmatch);
}

bool instruction::isCondBranch() const {
    return isInsnType(Bmask, BCmatch);
}

unsigned instruction::jumpSize(Address from, Address to) {
    int disp = (to - from);
    return jumpSize(disp);
}

// -1 is infinite, don't ya know.
unsigned instruction::jumpSize(int disp) {
    if (ABS(disp) >= MAX_BRANCH) {
        return (unsigned) -1;
    }
    return instruction::size();
}

unsigned instruction::maxJumpSize() {
    // TODO: some way to do a full-range branch
    // For now, a BRL-jump'll do.
    // plus two - store r0 and restore afterwards
    return 4*instruction::size();
}

unsigned instruction::maxInterFunctionJumpSize() {
    // 4...
    // move <high>, r0
    // move <low>, r0
    // move r0 -> ctr
    // branch to ctr
    return 4*instruction::size();
}

unsigned instruction::spaceToRelocate() const {

    // We currently assert instead of fixing out-of-range
    // branches. In the spirit of "one thing at a time",
    // we'll handle that _later_.

    // Actually, since conditional branches have such an abysmally
    // short range, we _do_ handle moving them through a complicated
    // "jump past an unconditional branch" combo.
    
    if (isCondBranch()) {
        // Maybe... so worst-case
        if ((insn_.bform.bo & BALWAYSmask) != BALWAYScond) {
            return 3*instruction::size();
        }
    }
    if (isUncondBranch()) {
        // Worst case... branch to LR
        // and save/restore r0
        return 6*instruction::size();
    }
    return instruction::size();
}

bool instruction::generate(codeGen &gen,
                           process * /* proc */,
                           Address origAddr,
                           Address relocAddr,
                           Address /* fallthroughOverride */,
                           Address targetOverride) {

    int newOffset = 0;
    Address to;

    if (isUncondBranch()) {
        // unconditional pc relative branch.

        // If it's absolute, no change
        if (isInsnType(Bmask, BAAmatch) && !targetOverride) {
            generate(gen);
            return true;
        }
        if (isInsnType(Bmask, BCAAmatch) && !targetOverride) {
            generate(gen);
            return true;
        }
        
        if (!targetOverride) {
            newOffset = origAddr - relocAddr + (int)getBranchOffset(); 
            to = getTarget(origAddr);
        }
        else {
            // We need to pin the jump
            newOffset = targetOverride - relocAddr;
            to = targetOverride;
        }

        if (ABS(newOffset) >= MAX_BRANCH) {
            // If we're doing a branch-n-link we can pull this off by making
            // several assumptions...
            if (insn_.bform.lk == 1) {
                // The native compiler can be really aggravating. In this
                // case, see the following sequence:
                // mflr    r0
                // bl      0x100098d8 <_savef14>
                // mtlr    r0
                // ... which looks like a call, but has a live r0. So we cannot
                // assume that r0 is dead at the point of a call. 
                // Fortunately, there's the extra stack slots... grab one to 
                // stash r0 in. I'm open to other suggestions, but I don't think 
                // there are any.

                // st r0, 16 (r1)

                instruction::generateImm(gen, STop, 
                                         0, // source: r0
                                         1, // ra: r1
                                         16); // offset

                // Whee. Stomp that link register.
                unsigned int top_half = ((to & 0xffff0000) >> 16);
                unsigned int bottom_half = (to & 0x0000ffff);
                assert (to == ((top_half << 16) + bottom_half));

                // AIX sign-extends. So if top_half is 0, and the top bit of
                // bottom_half is 0, then we can use a single instruction. Otherwise
                // do it the hard way.
                
                // Honestly, why do we bother? An address of 0x00008000 is in the
                // _kernel_. This will never happen. Someone was overly clever.

                if (!top_half && !(bottom_half & 0x8000)) {
                    // single instruction (CALop)
                    instruction::generateImm(gen, 
                                             CALop, 0, 0, bottom_half);
                }
                else {
                    instruction::generateImm(gen, CAUop, 
                                             0, 0, top_half);
                    // ori dest,dest,LOW(src1)
                    instruction::generateImm(gen, ORILop, 
                                             0, 0, bottom_half);
                }
                
                instruction mtlr(MTLR0raw);
                mtlr.generate(gen);
                
                // And branch to LR
                instruction btlr(BRLraw);
                btlr.generate(gen);

                // lw r0, 16 (r1)

                instruction::generateImm(gen, Lop, 
                                         0, // target: r0
                                         1, // ra: r1
                                         16); // offset

            }
            else {
                // Crud.
                fprintf(stderr, "Fatal error: relocating branch, orig at 0x%lx, now 0x%lx, target 0x%lx, orig offset 0x%lx\n",
                        origAddr, relocAddr, targetOverride, getBranchOffset());
                assert(0);
            }
        } else {
            instruction newInsn(insn_);
            newInsn.setBranchOffset(newOffset);
            newInsn.generate(gen);
        }
    } 
    else if (isCondBranch()) {
        // conditional pc relative branch.
      if (!targetOverride)
        newOffset = origAddr - relocAddr + getBranchOffset();
      else
	newOffset = targetOverride - relocAddr;
        if (ABS(newOffset) >= MAX_CBRANCH) {
            if ((insn_.bform.bo & BALWAYSmask) == BALWAYScond) {
                assert(insn_.bform.bo == BALWAYScond);

                bool link = (insn_.bform.lk == 1);
                instruction::generateBranch(gen, newOffset, link);
            } else {
                // Figure out if the original branch was predicted as taken or not
                // taken.  We'll set up our new branch to be predicted the same way
                // the old one was.
                
              // This makes my brain melt... here's what I think is happening. 
              // We have two sources of information, the bd (destination) 
              // and the predict bit. 
              // The processor predicts the jump as taken if the offset
              // is negative, and not taken if the offset is positive. 
              // The predict bit says "invert whatever you decided".
              // Since we're forcing the offset to positive, we need to
              // invert the bit if the offset was negative, and leave it
              // alone if positive.
              
              // Get the old flags (includes the predict bit)
              int flags = insn_.bform.bo;

              if (insn_.bform.bd < 0) {
                  // Flip the bit.
                  // xor operator
                  flags ^= BPREDICTbit;
              }
              
              instruction newCondBranch(insn_);
              (*newCondBranch).bform.lk = 0; // This one is non-linking for sure
              
              // Set up the flags
              (*newCondBranch).bform.bo = flags;
              
              // Change the branch to move one instruction ahead
              (*newCondBranch).bform.bd = 2;
              
              newCondBranch.generate(gen);

              // We don't "relocate" the fallthrough target of a conditional
              // branch; instead relying on a third party to make sure
              // we go back to where we want to. So in this case we 
              // generate a "dink" branch to skip past the next instruction.
              // We could also just invert the condition on the first branch;
              // but I don't have the POWER manual with me.
              // -- bernat, 15JUN05

              instruction::generateBranch(gen,
                                          2*instruction::size());

              bool link = (insn_.bform.lk == 1);
              instruction::generateBranch(gen,
                                          newOffset - 2*instruction::size(),
                                          link);
          }
      } else {
          instruction newInsn(insn_);
          (*newInsn).bform.bd = (newOffset >> 2);
          newInsn.generate(gen);
      }
    } else if (insn_.iform.op == SVCop) {
        logLine("attempt to relocate a system call\n");
        assert(0);
    } 
    else {
        generate(gen);
    }
    return true;
}
                           
