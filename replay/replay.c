#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <imitate.h>

#define FILE_SEPARATOR '/'

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

int read_string_array_from_file(char*** arr, FILE* filp)
{
    int arr_size, str_size, read_count, i;

    read_count = fread(&arr_size, sizeof(arr_size), 1, filp);
    if (read_count < 1)
    {
        return -1;
    }

    *arr = (char**) malloc(sizeof(char*) * (arr_size + 1));
    if (! *arr)
    {
        return -2;
    }

    (*arr)[arr_size] = NULL;
    for (i = 0; i < arr_size; i++)
    {
        read_count = fread(&str_size, sizeof(str_size), 1, filp);
        if (read_count < 1)
        {
            return -1;
        }
        (*arr)[i] = (char*) malloc(sizeof(char) * (str_size + 1));
        read_count = fread((*arr)[i], str_size, 1, filp);
        if (read_count < 1)
        {
            return -1;
        }
        (*arr)[i][str_size] = '\0';
    }
}

void read_arguments_log(char* log_dir, char*** argv, char*** environ)
{
    char *fpath;
    FILE *arguments_file;
    int i, j, k;

    /* Open arguments file */
    fpath = log_file_path(log_dir, "args");
    arguments_file = fopen(fpath, "rb");
    free(fpath);

    if (! arguments_file)
    {
        perror("Opening arguments log");
        exit(-1);
    }

    read_string_array_from_file(argv, arguments_file);
    read_string_array_from_file(environ, arguments_file);

    fclose(arguments_file);
}

void free_arguments_log(char*** argv, char*** environ)
{
    int a = 0;
    while ((*argv)[a] != NULL)
    {
        free((*argv)[a]);
        a++;
    }
    free((*argv));

    a = 0;
    while ((*environ)[a] != NULL)
    {
        free((*environ)[a]);
        a++;
    }
    free((*environ));
}

int main(int argc, char* argv[])
{
    int dev, i;
    pid_t app_pid;
    char **prog_args, **prog_env;
    char *syscall_log, *fpath;
    FILE* syscall_log_file, sched_log_file;
    callback_t cbdata =
    {
        .type = NO_DATA,
        .size = 0
    };

    /* Verify arguments */
    if (argc < 2)
    {
        printf("Imitate Replayer");
        printf("Usage: %s <log_path>", argv[0]);
        return 0;
    }

    /* Read arguments and environment */
    read_arguments_log(argv[1], &prog_args, &prog_env);

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
        syscall_log_file = fopen(fpath, "rb");
        free(fpath);

        while (cbdata.type != APP_EXIT)
        {
            if (ioctl(dev, IMITATE_MONITOR_CB, &cbdata) < 0)
            {
                perror("Sending log data");
                goto error_after_dev;
            }

            switch(cbdata.type)
            {
                case SYSCALL_DATA:
                    fread(syscall_log, cbdata.size, 1, syscall_log_file);
                    break;
            }
        }
  
    }
    else if (app_pid == 0) /* Child */
    {
        if (ioctl(dev, IMITATE_APP_REPLAY, getppid()) < 0)
        {
            perror("Notifying imitate kernel driver of REPLAY");
            goto error_after_dev;
        }

        if (execve(prog_args[0], prog_args+1, prog_env) < 0)
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

    waitpid(app_pid, &i, NULL);

    free_arguments_log(&prog_args, &prog_env);

    close(dev);

    return 0;

    error_after_dev:
        close(dev);
        return -1;
}
