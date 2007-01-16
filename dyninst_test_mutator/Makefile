CPP = g++
CC  = gcc
BIN_DIR ?= bin

OBJECTS = mutator.o mutator mutatee.o mutatee retee.o retee

all: $(OBJECTS)

clean:
	rm -f $(OBJECTS)

mutator.o: mutator.cpp
	$(CPP) -c $(CPPFLAGS) -I$(DYNINST_ROOT)/core/dyninstAPI/h -o mutator.o mutator.cpp

mutator: mutator.o
	$(CPP) mutator.o -L$(DYNINST_ROOT)/$(PLATFORM)/lib -ldyninstAPI -liberty -lelf -ldwarf -o mutator

mutatee.o: mutatee.c
	$(CC) $(CFLAGS) -c -o mutatee.o mutatee.c

mutatee: mutatee.o
	$(CC) mutatee.o -o mutatee

retee.o: retee.cpp
	$(CPP) -c $(CPPFLAGS) -I$(DYNINST_ROOT)/core/dyninstAPI/h retee.cpp

retee: retee.o
	$(CPP) retee.o -L$(DYNINST_ROOT)/$(PLATFORM)/lib -ldyninstAPI -liberty -lelf -ldwarf -o retee

