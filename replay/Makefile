CC = gcc
INCLUDES = -I../module/include

all: replay

replay.o: replay.c
	$(CC) -c $(CFLAGS) $(INCLUDES) replay.c -o replay.o

replay: replay.o
	$(CC) replay.o -o replay

clean:
	rm -f replay replay.o
