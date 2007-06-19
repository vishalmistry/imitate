CC = gcc
CPP = g++
INCLUDES =
LIBS = -lpthread

all: threads mtio

threads.o: threads.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o threads.o threads.c

threads: threads.o
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBS) -o threads threads.o

reader.o: reader.c mtio.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o reader.o reader.c

mtio.o: mtio.c mtio.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o mtio.o mtio.c

mtio: reader.o mtio.o
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBS) -o mtio mtio.o reader.o

clean:
	rm -f mtio.o threads.o reader.o mtio threads
