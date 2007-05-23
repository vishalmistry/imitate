CC = gcc
CPP = g++
INCLUDES = -I../module/include -I.. -I$(DYNINST_ROOT)/core/dyninstAPI/h
UTIL = ../util

all: patcher record schedread

patch_test: test_prog test_patcher

record.o: record.c
	$(CC) -c $(CFLAGS) $(INCLUDES) record.c -o record.o

patcher.o: patcher.cpp
	$(CPP) -c $(CPPFLAGS) $(INCLUDES) -o patcher.o patcher.cpp

patcher: patcher.o
	$(CPP) patcher.o -L$(DYNINST_ROOT)/$(PLATFORM)/lib -ldyninstAPI -liberty -lelf -ldwarf -o patcher

record: record.o
	$(MAKE) -C $(UTIL)
	$(CC) $(UTIL)/log.o record.o -o record


util/schedread.o: util/schedread.c
	$(CC) -c $(CFLAGS) $(INCLUDES) -o util/schedread.o util/schedread.c

schedread: util/schedread.o
	$(CC) util/schedread.o -o schedread


patch_test/test_patcher.o: patch_test/test_patcher.c
	$(CC) -c $(CFLAGS) $(INCLUDES) -o patch_test/test_patcher.o patch_test/test_patcher.c

test_patcher: patch_test/test_patcher.o
	$(CC) patch_test/test_patcher.o -o test_patcher

patch_test/test_prog.o: patch_test/test_prog.c
	$(CC) -c $(CFLAGS) $(INCLUDES) -o patch_test/test_prog.o patch_test/test_prog.c

test_prog: patch_test/test_prog.o
	$(CC) patch_test/test_prog.o -o test_prog


clean:
	$(MAKE) -C $(UTIL) clean
	rm -f record patcher schedread test_prog test_patcher record.o patcher.o util/schedread.o patch_test/test_patcher.o patch_test/test_prog.o
