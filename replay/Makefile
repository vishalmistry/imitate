CC = gcc
CPP = g++
INCLUDES = -I../module/include -I.. -I$(DYNINST_ROOT)/core/dyninstAPI/h
UTIL = ../util

all: patcher replay

replay.o: replay.c
	$(CC) -c $(CFLAGS) $(INCLUDES) replay.c -o replay.o

patcher.o: patcher.cpp
	$(CPP) -c $(CPPFLAGS) $(INCLUDES) -o patcher.o patcher.cpp

patcher: patcher.o
	$(CPP) patcher.o -L$(DYNINST_ROOT)/$(PLATFORM)/lib -ldyninstAPI -liberty -lelf -ldwarf -o patcher

replay: replay.o
	$(MAKE) -C $(UTIL)
	$(CC) $(UTIL)/log.o replay.o -o replay

clean:
	$(MAKE) -C $(UTIL) clean
	rm -f replay patcher replay.o patcher.o
