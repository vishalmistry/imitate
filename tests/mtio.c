#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include "mtio.h"

char *fn;

int main(int argc, char* argv[])
{
    pthread_t threads[N_THREADS];
    int i, tids[N_THREADS];
    FILE* randf;

    fn = argv[1];

    randf = fopen("/dev/urandom", "r");
    fread(&i, sizeof(i), 1, randf);
    fclose(randf);
    srand(i);

    for (i = 0; i < N_THREADS; i++)
    {
        tids[i] = i+1;
        pthread_create(&(threads[i]), NULL, reader, &(tids[i]));
    }

    for (i = 0; i < N_THREADS; i++)
        pthread_join(threads[i], NULL);

    return 0;
}
