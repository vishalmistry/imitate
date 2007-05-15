CC = gcc
INCLUDES = -I../module/include -I..

UTIL = ../util

all: record

record.o: record.c
	$(CC) -c $(CFLAGS) $(INCLUDES) record.c -o record.o

record: record.o
	$(MAKE) -C $(UTIL)
	$(CC) $(UTIL)/log.o record.o -o record

clean:
	$(MAKE) -C $(UTIL) clean
	rm -f record record.o
