#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <util/include/log.h>
#include <imitate.h>

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

    if (read_string_array_from_file_resize(argv, arguments_file, 1, 1) < 0)
    {
        perror("Reading arguments from arguments log");
        goto read_fail;
    }

    if (read_string_array_from_file(environ, arguments_file) < 0)
    {
        perror("Reading environment from arguments log");
        goto read_fail;
    }
    
    fclose(arguments_file);
    return;

    read_fail:
    fclose(arguments_file);
    exit(-1);
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

void fill_syscall_buffer(FILE* syscall_log_file, char* syscall_log, callback_t *cbdata)
{
    int record_size, read_count;
    char syscall_full;
    syscall_log_entry_t *syscall_log_entry;
    fpos_t fpos;

    cbdata->size = 0;
    syscall_full = 0;

    while (! syscall_full)
    {
        record_size = sizeof(*syscall_log_entry) - sizeof(syscall_log_entry->out_param);

        syscall_log_entry = (syscall_log_entry_t*) (syscall_log + cbdata->size);

        /* Does the buffer have enough room for a record? */
        if (cbdata->size + record_size < SYSCALL_BUFFER_SIZE)
        {
            /* Read the record */
            read_count = fread(syscall_log_entry, record_size, 1, syscall_log_file);

            if (read_count < 1)  /* Read failed */ 
            {
                if (!feof(syscall_log_file))
                {
                    perror("Reading from system call log file (syscall_log_entry)");
                }
                break;
            }
            else        /* Read succeeded */
            {
#if 0
                printf("child: %d, call_no: %d, return_value: %d, out_param_len: %d\n",
                    syscall_log_entry->child_id,
                    syscall_log_entry->call_no,
                    syscall_log_entry->return_value,
                    syscall_log_entry->out_param_len);
#endif

                /* Read out_param if necessary */
                if (syscall_log_entry->out_param_len > 0)
                {
                    record_size += syscall_log_entry->out_param_len;

                    /* Does buffer have space for out_param? */
                    if (cbdata->size + record_size < SYSCALL_BUFFER_SIZE)
                    {
                        read_count = fread(&(syscall_log_entry->out_param), 
                                           syscall_log_entry->out_param_len,
                                           1,
                                           syscall_log_file);

                        if (read_count < 1)  /* Read failed */
                        {
                            perror("Reading from system call log file (out_param)");
                            break;
                        }
                        else        /* Read succeeded */
                        {
                            cbdata->size += record_size;
                        }
                    }
                    else
                    {
                        /* No space. Seek back to beginning of record */
                        if (fseek(syscall_log_file, (long) -(record_size - syscall_log_entry->out_param_len), SEEK_CUR) < 0)
                        {
                            perror("Rewinding system call log file position");
                            break;
                        }
                        syscall_full = 1;
                    }
                }
                else
                {
                    /* No out_param. Just continue */
                    cbdata->size += record_size;
                }
            }
        }
        else
        {
            /* No more space */
            syscall_full = 1;
        }
    }

}

void fill_sched_buffer(FILE* sched_log_file, char* sched_log, callback_t *cbdata)
{
    int record_size, read_count;
    char sched_full;
    sched_log_entry_t *sched_log_entry;

    cbdata->size = 0;
    sched_full = 0;

    while (! sched_full)
    {
        record_size = sizeof(*sched_log_entry);

        sched_log_entry = (sched_log_entry_t*) (sched_log + cbdata->size);

        /* Does the buffer have enough room for a record? */
        if (cbdata->size + record_size < SCHED_BUFFER_SIZE)
        {
            /* Read the record */
            read_count = fread(sched_log_entry, record_size, 1, sched_log_file);

            if (read_count < 1)  /* Read failed */ 
            {
                if (!feof(sched_log_file))
                {
                    perror("Reading from schedule call log file (sched_log_entry)");
                }
                break;
            }
            else        /* Read succeeded */
            {
                cbdata->size += record_size;
            }
        }
        else
        {
            /* No more space */
            sched_full = 1;
        }
    }
}


int main(int argc, char* argv[])
{
    int dev, i;
    pid_t app_pid;
    char **prog_args, **prog_env;
    char *syscall_log, *sched_log, *fpath;
    FILE *syscall_log_file, *sched_log_file;

    callback_t cbdata =
    {
        .type = NO_DATA,
        .size = 0
    };

    prep_replay_t prepdata =
    {
        .syscall_size = 0,
        .sched_size = 0
    };

    /* Verify arguments */
    if (argc < 2)
    {
        printf("Imitate Replayer\n");
        printf("Usage: %s <log_path>\n", argv[0]);
        return 0;
    }

    /* Read arguments and environment */
    read_arguments_log(argv[1], &prog_args, &prog_env);

    /* Open system call log file */
    fpath = log_file_path(argv[1], "syscall");
    syscall_log_file = fopen(fpath, "rb");
    free(fpath);

    if (! syscall_log_file)
    {
        perror("Opening system call log");
        return -1;
    }

    /* Open schedule log file */
    fpath = log_file_path(argv[1], "sched");
    sched_log_file = fopen(fpath, "rb");
    free(fpath);

    if (! sched_log_file)
    {
        perror("Opening schedule log");
        return -1;
    }


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

    if ((syscall_log = (char*) mmap(NULL, SYSCALL_BUFFER_SIZE, PROT_WRITE, MAP_SHARED, dev, 0)) == MAP_FAILED)
    {
        perror("Memory mapping system call log");
        goto error_after_dev;
    }

    if ((sched_log = (char*) mmap(NULL, SCHED_BUFFER_SIZE, PROT_READ, MAP_SHARED, dev, 0)) == MAP_FAILED)
    {
        perror("Memory mapping schedule log");
        goto error_after_dev;
    }

    fill_syscall_buffer(syscall_log_file, syscall_log, &cbdata);
    prepdata.syscall_size = cbdata.size;
    fill_sched_buffer(sched_log_file, sched_log, &cbdata);
    prepdata.sched_size = cbdata.size;

    if (ioctl(dev, IMITATE_PREP_REPLAY, &prepdata) < 0)
    {
        perror("Populating inital buffer sizes");
        goto error_after_dev;
    }

    app_pid = fork();

    if (app_pid > 0) /* Parent */
    {
        while (cbdata.type != APP_EXIT && cbdata.type != APP_KILLED)
        {
            if (ioctl(dev, IMITATE_MONITOR_CB, &cbdata) < 0)
            {
                perror("Sending log data");
                goto error_after_dev;
            }

            switch(cbdata.type)
            {
                case SYSCALL_DATA:
                    fill_syscall_buffer(syscall_log_file, syscall_log, &cbdata);
                    break;

                case SCHED_DATA:
                    fill_sched_buffer(sched_log_file, sched_log, &cbdata);
                    break;

                case APP_KILLED:
                    fprintf(stderr, "Replayed application killed by kernel driver.\n");
                    break;
            }
        }
  
    }
    else if (app_pid == 0) /* Child */
    {
        prog_args[0] = malloc(strlen("./patcher")+1);
        strcpy(prog_args[0], "./patcher");

        if (execve(prog_args[0], prog_args, prog_env) < 0)
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
