#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
    /* Verify arguments */
    if (argc < 2)
    {
        printf("Imitate Replayer");
        printf("Usage: %s <log_path>", argv[0]);
        return 0;
    }

    /* Read arguments and environments */
    read_arguments();

}
