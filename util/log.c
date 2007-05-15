/*
 * Imitate record/replay framework
 * Logging utility functions
 * Copyright (c) 2007, Vishal Mistry
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/log.h"

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
        return NULL;
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

    return 0;
}
