#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <imitate.h>

#define FILE_SEPARATOR '/'
#define PROG_ARGS 2

extern char** environ;

char* log_file_path(char* dir, char* fname)
{
    int dir_len = strlen(dir), max_len;
    char* path;
    
    /* Remove file separtor from end of dir */
    while (dir[dir_len-1] == FILE_SEPARATOR)
    {
        dir[dir_len-1] = '\0';
        dir_len--;
    }
    
    /* Build path */
    path = (char*) malloc(dir_len + strlen(fname) + 2);
    sprintf(path, "%s%c%s", dir, FILE_SEPARATOR, fname);
    
    return path;
}

int main(int argc, char* argv[])
{
    char* fpath;
    int i, j, k, dev;
    pid_t app_pid;
    FILE* arguments_file, syscall_file, sched_file;
    char* syscall_log;

    /* Verify arguments */
    if (argc < 1)
    {
        printf("Imitate Recorder\n");
        printf("Usage: %s <log_path> <executable_path> <args>\n",argv[0]);
        return 0;
    }

    /* Create trace directory */
    if (mkdir(argv[1], 0700) < 0)
    {
        perror("Creating log directory");
        return -1;
    }

    /* Create arguments file */
    fpath = log_file_path(argv[1], "args");
    arguments_file = fopen(fpath, "wb");
    free(fpath);
    
    /* Store executable + arguments */
    i = argc - PROG_ARGS;
    fwrite(&i, sizeof(i), 1, arguments_file);
    for(i = PROG_ARGS; i < argc; i++)
    {
        j = strlen(argv[i]);
        fwrite(&j, sizeof(j), 1, arguments_file);
        fwrite(argv[i], j, 1, arguments_file);
    }

    /* Store enviroment variables */
    i = 0;
    while (environ[i]) { i++; }
    fwrite(&i, sizeof(i), 1, arguments_file);

    for (j = 0; j < i; j++)
    {
        k = strlen(environ[j]);
        fwrite(&k, sizeof(k), 1, arguments_file);
        fwrite(environ[j], k, 1, arguments_file);
    }

    fclose(arguments_file);

    dev = open("/dev/imitate0", O_RDWR);
    if (dev < 0)
    {
        perror("Opening imitate kernel device");
        return -1;
    }

    if (ioctl(dev, IMITATE_MONITOR) < 0)
    {
        perror("Notifying imitate kernel driver of MONITOR");
        goto error_after_dev;
    }

    if ((syscall_log = (char*) mmap(NULL, 20971520, PROT_READ, MAP_SHARED, dev, 0)) == MAP_FAILED)
    {
        perror("Memory mapping system call log");
    }
    
    app_pid = fork();

    if (app_pid > 0) /* Parent */
    {

    }
    else if (app_pid == 0) /* Child */
    {
        if (ioctl(dev, IMITATE_APP_RECORD, getppid()) < 0)
        {
            perror("Notifying imitate kernel driver of RECORD");
            goto error_after_dev;
        }

        execve(argv[2], argv[3], environ);
    }
    else /* Error */
    {
        perror("Forking application process");
        goto error_after_dev;
    }

    waitpid(app_pid, &i, NULL);

    printf("%d %d", (unsigned short)(syscall_log[0]), (int) (syscall_log[2]));

    close(dev);

    return 0;

    error_after_dev:
        close(dev);
        return -1;
}
