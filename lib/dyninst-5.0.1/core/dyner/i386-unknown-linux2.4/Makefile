
USES_TCLTK = true

# include ../Make.common
# DO NOT DELETE

TO_CORE =       ../..
NO_OPT_FLAG=true
NO_IMPLICIT_TEMPLATES=true
USES_DWARF_DEBUG=true

# Include standard make configuration stuff that applies to everything
# in the paradyn tree.

include $(TO_CORE)/make.config

# Now make any necessary architecture specific changes to variables:

SYSLIBS   += -lnsl 
LIBS = -L$(LIBDWARF_LIB) -ldwarf

MUTATEE_CFLAGS += -rdynamic -ldl

# Include the module-specific Makefile, which defines everything about
# the module that is common across architectures.

include ../make.module.tmpl

# Include the "standard program template".  This defines all the
# common targets like "clean", "install", etc.

include $(TO_CORE)/make.program.tmpl
