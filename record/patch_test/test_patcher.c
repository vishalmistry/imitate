#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char* argv[], char* envp[])
{
    int i;

    char* args[3];
    char param[10]; 

    sprintf(param, "%d", getppid());
    args[0] = param;
    args[1] = param;
    args[2] = 0;

    printf("Parent PID: %s\n", param);

    int pid = fork();

    if (pid == 0)
    {
        execve("./testpatch", args, envp);
    }
    else if (pid > 0)
    {
        printf("Waiting...\n");
        waitpid(pid, &i, 0);
    }
}
