#include <pthread.h>
#include <signal.h>
#include <stdio.h>

#define N_THREADS   5
#define N_BYTES     10

char* fn;

pthread_mutex_t readerlock = PTHREAD_MUTEX_INITIALIZER;

void* reader(void *tid)
{
    int r = 0, ttid = *((int*) tid);
    char bytes[N_BYTES+1];
    FILE *file = fopen(fn, "r");

    if (! feof(file))
    {
//        fseek(file, ttid*10, SEEK_SET); 
        fread(bytes, ttid, 1, file);
        bytes[ttid] = 0;
        printf("%d -> read = %s\n", ttid, bytes);
        fflush(stdout);
    }

    fclose(file);
}

int main(int argc, char* argv[])
{
    pthread_t threads[N_THREADS];
    int i, tids[N_THREADS];

    fn = argv[1];

    for (i = 0; i < N_THREADS; i++)
    {
        tids[i] = i+1;
        pthread_create(&(threads[i]), NULL, reader, &(tids[i]));
    }

    for (i = 0; i < N_THREADS; i++)
        pthread_join(threads[i], NULL);

    return 0;
}
