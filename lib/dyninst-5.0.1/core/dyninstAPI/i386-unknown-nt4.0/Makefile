#
# $Id: Makefile,v 1.31 2006/04/04 17:33:49 rutar Exp $
#

# Define any symbols needed to invoke configuration changes in make.config

# Include standard make configuration stuff that applies to everything
# in the paradyn tree.

include ../../nmake.config 
DEFCFLAGS = $(DEFCFLAGS) -MD # ccw 12 july 2001

# Now make any necessary architecture specific changes to variables:

# we require an uncommon link
LD		= link
LDFLAGS	= -DLL -debug -pdb:none -export:V_libdyninstAPI  /NODEFAULTLIB:libc.lib # ccw 20 june 2001


SRCS =		../src/pdwinnt.C \
		../src/inst-winnt.C \
		../src/cpuid-x86.S \
		../src/inst-x86.C \
		../src/emit-x86.C \
		../src/arch-x86.C \
		../src/InstrucIter-x86.C \
		../src/syscall-nt.C \
		../src/pdwinntDL.C \
		../src/dynamiclinking.C \
		../src/image-x86.C 
#		../src/MapSymbols.C 
# ccw 13 july 2001

OBJS = 		pdwinnt.obj \
		inst-winnt.obj \
		inst-x86.obj \
		arch-x86.obj \
		emit-x86.obj \
		InstrucIter-x86.obj \
		codeRange.obj \
		syscall-nt.obj \
		pdwinntDL.obj \
		dynamiclinking.obj \
		image-x86.obj

#		MapSymbols.obj 
# ccw 13 july 2001

LIBS		= dbghelp.lib advapi32.lib psapi.lib ws2_32.lib

CXXFLAGS 	= $(CXXFLAGS) -DNO_MDL_PRINT -DBPATCH_DLL_BUILD

# Include the module-specific Makefile, which defines everything about
# the module that is common across architectures.

include ../nmake.module.tmpl

# Include the "standard library template".  This defines all the
# common targets like "clean", "install", etc.

include ../../nmake.library.tmpl

# override target rule to force link to happen
$(TARGET): $(OBJS)
	@$(MAKE) $(VOUCHER)
	$(LD) $(LDFLAGS) -out:$(TARGET) $(VOUCHER).obj $(OBJS) $(LIBS)

install:	$(TARGET)
	$(CP) $(TARGET) $(DEST)
	$(CP) libdyninstAPI.lib $(DEST)

# DO NOT DELETE
