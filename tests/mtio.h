#ifndef MTIO_H
#define MTIO_H

#define N_THREADS   5
#define N_BYTES     10

extern char* fn;
void* reader(void *tid);

#endif
