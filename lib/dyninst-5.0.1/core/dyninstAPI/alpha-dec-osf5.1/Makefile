#
# $Id: Makefile,v 1.12 2006/04/12 18:37:27 bernat Exp $
#

# Define any symbols needed to invoke configuration changes in make.config

# XXX get rid of these:
#DO_INLINE_ALL           = true
NO_IMPLICIT_TEMPLATES	 = true
#NO_OPT_FLAG		 = true
#DEBUG_FLAG = -g

ifdef COVERAGE
NO_OPT_FLAG             = true
endif

# Include standard make configuration stuff that applies to everything
# in the paradyn tree.

include ../../make.config 

CXXFLAGS += -O0 -mieee
CFLAGS += -mieee
TFLAGS += -pthread -mieee
//-std=c89

# Now make any necessary architecture specific changes to variables:

SRCS =		 ../src/inst-osf.C \
                 ../src/procfs.C \
                 ../src/alpha.C \
                 ../src/osf.C \
                 ../src/osfDL.C \
		../src/dynamiclinking.C \
		 ../src/unix.C \
                 ../src/inst-alpha.C \
		../src/arch-alpha.C \
		 ../src/Object-coff.C \
		 ../src/parseCoff.C \
		 ../src/parseStab.C \
		../src/image-alpha.C \
		 ../src/InstrucIter-alpha.C \
		 ../../common/src/osfKludges.C \
		 ../../common/src/timing-aix.C \
		../src/syscall-alpha.C

# Add preprocessor and special link information for G++
G_PTHREAD       = -pthread
G_PTHREAD_LD	= -pthread

# Include the module-specific Makefile, which defines everything about
# the module that is common across architectures.

include ../make.module.tmpl

# Include the "standard library template".  This defines all the
# common targets like "clean", "install", etc.

include ../../make.library.tmpl

# the alpha machine at Maryland runs out of virtual memory when building
# templates with optimization
TFLAGS := $(TFLAGS:-O%=)

LD = g++
LIBS += -lmld -liberty

#ifdef USES_LIBDYNINST_SO
#$(TARGET3): $(OBJS)
#	@$(RM) $(TARGET3)
#	@$(MAKE) $(VOUCHER)
#	$(LD) -shared $(LDFLAGS) -o $(TARGET3) $(VOUCHER).o $(OBJS) $(LIBS)
#endif
