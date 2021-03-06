/*
 * Imitate record/replay framework
 * Logging utility functions
 * Copyright (c) 2007, Vishal Mistry
 */

char* log_file_path(char* dir, char* fname);
int read_string_array_from_file(char*** arr, FILE* filp);
int read_string_array_from_file_resize(char*** arr, FILE* filp, int increase_size, int offset);
