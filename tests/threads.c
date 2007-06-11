#include <pthread.h>
#include <signal.h>
#include <stdio.h>

void* thread(void *tid)
{
    int ttid = *((int*) tid), i;
    printf("Thread %d - PID %d - TID: %d\n", ttid, getpid(), pthread_self());
    for (i = 0; i < 50000000; i++)
    {
        if ((i % 5000000) == 0)
            printf("%d -> counter = %d\n", ttid, i);
    }
}

int main(int argc, char* argv[])
{
    pthread_t t1, t2;
    int i1 = 1, i2 = 2;
    
    pthread_create(&t1, NULL, thread, &i1);
    pthread_create(&t2, NULL, thread, &i2);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    printf("Done.\n");

    return 0;
}
