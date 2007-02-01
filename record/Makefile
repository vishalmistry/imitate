CC = gcc
INCLUDES = -I../module

all: record

record.o: record.c
	$(CC) -c $(CFLAGS) $(INCLUDES) record.c -o record.o

record: record.o
	$(CC) record.o -o record

clean:
	rm -f record record.o
