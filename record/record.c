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
    if (! path)
    {
        perror("Allocating file path string");
    }
    sprintf(path, "%s%c%s", dir, FILE_SEPARATOR, fname);
    
    return path;
}

void store_arguments(char* log_dir, int argc, char* argv[], char* envp[])
{
    char *fpath;
    FILE *arguments_file;
    int i, j, k;

    /* Create arguments file */
    fpath = log_file_path(log_dir, "args");
    arguments_file = fopen(fpath, "wb");
    free(fpath);
    
    /* Store executable + arguments */
    fwrite(&argc, sizeof(argc), 1, arguments_file);
    for(i = 0; i < argc; i++)
    {
        j = strlen(argv[i]);
        fwrite(&j, sizeof(j), 1, arguments_file);
        fwrite(argv[i], j, 1, arguments_file);
    }

    /* Store enviroment variables */
    i = 0;
    while (envp[i]) { i++; }
    fwrite(&i, sizeof(i), 1, arguments_file);

    for (j = 0; j < i; j++)
    {
        k = strlen(envp[j]);
        fwrite(&k, sizeof(k), 1, arguments_file);
        fwrite(envp[j], k, 1, arguments_file);
    }

    fclose(arguments_file);
}

int main(int argc, char* argv[], char* envp[])
{
    int i, dev;
    pid_t app_pid;
    char *syscall_log, *fpath;
    syscall_log_entry_t *log_entry;
    FILE* syscall_log_file, sched_log_file;
    callback_t cbdata =
    {
        .type = NO_DATA,
        .size = 0
    };

    /* Verify arguments */
    if (argc < 3)
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

    store_arguments(argv[1], argc - PROG_ARGS, argv+PROG_ARGS, envp);

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

    if ((syscall_log = (char*) mmap(NULL, SYSCALL_BUFFER_SIZE, PROT_READ, MAP_SHARED, dev, 0)) == MAP_FAILED)
    {
        perror("Memory mapping system call log");
        goto error_after_dev;
    }

    app_pid = fork();

    if (app_pid > 0) /* Parent */
    {
        fpath = log_file_path(argv[1], "syscall");
        syscall_log_file = fopen(fpath, "wb");
        free(fpath);

        while (cbdata.type != APP_EXIT)
        {
            if (ioctl(dev, IMITATE_MONITOR_CB, &cbdata) < 0)
            {
                perror("Requesting log data");
                goto error_after_dev;
            }

            switch(cbdata.type)
            {
                case SYSCALL_DATA:
                    fwrite(syscall_log, cbdata.size, 1, syscall_log_file);
                    break;
            }
        }
    }
    else if (app_pid == 0) /* Child */
    {
        if (ioctl(dev, IMITATE_APP_RECORD, getppid()) < 0)
        {
            perror("Notifying imitate kernel driver of RECORD");
            goto error_after_dev;
        }

        if (execve(argv[2], argv+2, envp) < 0)
        {
            perror("Application execve()");
            return -2;
        }
    }
    else /* Error */
    {
        perror("Forking application process");
        goto error_after_dev;
    }

    fclose(syscall_log_file);

    waitpid(app_pid, &i, NULL);

    close(dev);

    return 0;

    error_after_dev:
        close(dev);
        return -1;
}
