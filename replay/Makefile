CC = gcc
INCLUDES = -I../module/include -I..

UTIL = ../util

all: replay

replay.o: replay.c
	$(CC) -c $(CFLAGS) $(INCLUDES) replay.c -o replay.o

replay: replay.o
	$(MAKE) -C $(UTIL)
	$(CC) $(UTIL)/log.o replay.o -o replay

clean:
	$(MAKE) -C $(UTIL) clean
	rm -f replay replay.o
