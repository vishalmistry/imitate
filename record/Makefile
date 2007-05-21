CC = gcc
CPP = g++
INCLUDES = -I../module/include -I.. -I$(DYNINST_ROOT)/core/dyninstAPI/h
UTIL = ../util

all: patcher record

record.o: record.c
	$(CC) -c $(CFLAGS) $(INCLUDES) record.c -o record.o

patcher.o: patcher.cpp
	$(CPP) -c $(CPPFLAGS) $(INCLUDES) -o patcher.o patcher.cpp

patcher: patcher.o
	$(CPP) patcher.o -L$(DYNINST_ROOT)/$(PLATFORM)/lib -ldyninstAPI -liberty -lelf -ldwarf -o patcher

record: record.o
	$(MAKE) -C $(UTIL)
	$(CC) $(UTIL)/log.o record.o -o record

clean:
	$(MAKE) -C $(UTIL) clean
	rm -f record patcher record.o patcher.o
