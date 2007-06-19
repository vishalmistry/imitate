#include <stdio.h>
#include "mtio.h"

void* reader(void *tid)
{
    int r = 0, ttid = *((int*) tid);
    char bytes[N_BYTES+1];
    FILE *file = fopen(fn, "r");

    for (r = 0; r < ttid*10; r++)
    {
       fread(bytes, 1, 1, file);
    }

    for (r=0; r < 5; r++) usleep(rand() % 400);

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
