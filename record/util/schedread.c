#include <stdio.h>
#include <imitate.h>

int main(int argc, char **argv)
{
    int readcount,i=0;
    sched_log_entry_t sce;

    if (argc < 2)
    {
        fprintf(stderr, "Schedule log file reader\n");
        fprintf(stderr, "Usage: %s <sched_log_file>\n", argv[0]);
        return 0;
    }

    FILE *f = fopen(argv[1], "rb");
    
    while (! feof(f))
    {
        readcount = fread(&sce, sizeof(sched_log_entry_t), 1, f);
        if (readcount < 1 && !feof(f))
        {
            perror("Error reading from log file");
            break;
        }
        if (readcount)
            printf("%d: child_id: %ld, counter: %ld, eip: 0x%lx\n", ++i, sce.child_id, sce.counter, sce.ip);
    }

    fclose(f);
}
