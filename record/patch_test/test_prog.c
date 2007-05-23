#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <imitate.h>
#include <fcntl.h>

int main(int argc, char* argv[])
{
    sched_counter_t* counter;
    int i;

    printf("argc: %d, Monitor pid: %s", argc, argv[1]);
    fflush(stdout);

    int dev = open("/dev/imitate0", O_RDWR);
    if (dev < 0)
    {
        perror("Unable to open /dev/imitate0");
        exit(2);
    }

    printf("OPEN\n");
    fflush(stdout);

    if (ioctl(dev, IMITATE_APP_RECORD, atoi(argv[1])) < 0)
    {
        perror("Notifying kernel device of RECORD");
        exit(2);
    }

    printf("RECORD\n");
    fflush(stdout);

    if ((counter = (sched_counter_t*) mmap(0, sizeof(sched_counter_t), PROT_READ | PROT_WRITE, MAP_SHARED, dev, 0)) == MAP_FAILED)
    {
        perror("Mapping sofware counter");
        exit(2);
    }

    printf("Counter val before: %ld\n", *counter);
    if (*counter == 0)
    {
        *counter = *counter + 1;
    }
    printf("Counter val after: %ld\n", *counter);
    fflush(stdout);

    return 0;
}
