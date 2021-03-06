#include <iostream>
#include <cstring>
#include <dirent.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "strlist.h"
#include "config.h"
#include "utils.h"
#include "log.h"

Config config;

bool getNext_SingleBinary();
bool getNext_BatchDirectory();
bool getNext_BatchFile();

void configInit()
{
    const char *homedir;

    /* Propogate config structure with default values. */
    config.transMode = TRANS_NONE;

    config.target[0] = '\0';
    config.outfd = stdout;
    
    config.record_enabled = false;
    config.no_fork = false;
    config.recursive = false;
    config.summary = false;
    config.include_libs = false;
    config.use_attach = false;
    config.use_merge_tramp = false;
    config.use_save_world = false;
    config.saved_mutatee = NULL;

    config.trace_inst = false;
    config.trace_count = 0;
    config.pipefd = -1;

    config.pid = 0;
    config.grandchildren = set< int >();

    config.verbose = INFO;

    config.parse_level = PARSE_MODULE;
    config.inst_level = INST_NONE;

    config.time_limit = 0;

    config.state = NORMAL;

    config.dynlib = NULL;

    homedir = getenv("HOME");
    if (!homedir) {
	config.record_dir[0] = '\0';
	config.pipe_filename[0] = '\0';
    } else {
	if (homedir[ strlen(homedir) - 1 ] == '/') {
	    snprintf(config.record_dir, sizeof(config.record_dir), "%s%s", homedir, HISTORY_RECORD_DIR_DEFAULT);
	    snprintf(config.pipe_filename, sizeof(config.pipe_filename), "%spipe-%d", homedir, (int)getpid());
	} else {
	    snprintf(config.record_dir, sizeof(config.record_dir), "%s/%s", homedir, HISTORY_RECORD_DIR_DEFAULT);
	    snprintf(config.pipe_filename, sizeof(config.pipe_filename), "%s/pipe-%d", homedir, (int)getpid());
	}
    }
    config.curr_rec = record_init();
}

bool getNextTarget()
{
    switch (config.runMode) {
    case SINGLE_BINARY: return getNext_SingleBinary();
    case BATCH_DIRECTORY: return getNext_BatchDirectory();
    case BATCH_FILE: return getNext_BatchFile();
    default:
	dlog(ERR, "*** parseThat error.  Invalid config.runMode detected in getNextTarget().\n");
	dlog(ERR, "*** parseThat exiting.\n");
	exit(-10);
    }

    // We should never get here.
    return false;
}

bool validate_file(const char *file)
{
    int retval;
    char header[2];
    FILE *fd = fopen(file, "r");

    if (!fd) {
	dlog(ERR, "Could not open %s for read: %s\n", file, strerror(errno));
	return false;
    }
    errno = 0;
    retval = fscanf(fd, "%c%c", &header[0], &header[1]);
    fclose(fd);

    if (errno) {
	dlog(ERR, "Could not read from target mutatee %s.  Dyninst requires read access to mutatees.\n", file);
	return false;
    }

    if (retval == 2 && header[0] == '#' && header[1] == '!') {
	dlog(ERR, "%s looks like a script.  Dyninst cannot process script files.\n", file);
	return false;
    }

    return true;
}

bool getNext_SingleBinary()
{
    static int runOnce = 0;

    if (runOnce > 0) {
	config.target[0] = '\0';
	return false;
    }
    runOnce = 1;
    return validate_file(config.target);
}

bool getNext_BatchDirectory()
{
    static strlist *dir_q = NULL;
    static DIR *dirfd = NULL;
    static char base_dir[ PATH_MAX ];

    int i;
    struct dirent *d_entry;

    if (dir_q == NULL) {
	// Initial call.  Push first directory onto queue.
	//
	// config.target should hold directory specified on command line.
	dir_q = strlist_alloc();
	if (!dir_q) {
	    dlog(ERR, "Could not allocate memory for strlist in getNext_BatchDirectory()\n");
	    exit(-2);
	}
	strlist_push_back(dir_q, config.target);
    }

    while (dir_q->count > 0 || dirfd != NULL) {
	if (dirfd == NULL) {
	    char *data = strlist_get(dir_q, 0);
	    if ( data[ strlen(data)-1 ] != '/' )
		snprintf(base_dir, sizeof(base_dir), "%s/", data);
	    else
		strncpy(base_dir, data, sizeof(base_dir));
	    strlist_pop_front(dir_q);

	    dirfd = opendir(base_dir);
	    if (dirfd == NULL) {
		dlog(ERR, "Could not open directory %s: %s\n", base_dir, strerror(errno));
		break;
	    }
	}

	while ( (d_entry = readdir(dirfd)) != NULL) {
	    if (strcmp(d_entry->d_name, ".") == 0) continue;
	    if (strcmp(d_entry->d_name, "..") == 0) continue;

	    /*
	     * Generate target filename in config.target from base_dir and d_entry->d_name.
	     */
	    snprintf(config.target, sizeof(config.target), "%s%s", base_dir, d_entry->d_name);
	    config.argv[0] = strrchr(config.target, '/') + 1;   /* strrchr() will never return NULL
								   because we control base_dir. */

	    /*
	     * Check if target filename is a directory, or executable via stat().  Ignore if neither.
	     */
	    struct stat file_stat;
	    i = 0;
	    do {
		if (i++ > 10) break;
		errno = 0;
	    } while (stat(config.target, &file_stat) != 0 && errno == EINTR);

	    if (errno == EINTR) {
		dlog(ERR, "Skipping %s.  stat() interrupted 10 times.\n", config.target);
		continue;

	    } else if (errno) {
		dlog(ERR, "Skipping %s.  Error on stat(): %s\n", config.target, strerror(errno));
		continue;
	    }

	    if ((file_stat.st_mode & S_IFMT) == S_IFDIR) {
		if (config.recursive)
		    strlist_push_back(dir_q, config.target);
		else
		    dlog(INFO, "%s is a directory.\n", config.target);

	    } else if ((file_stat.st_mode & S_IXOTH) == S_IXOTH ||
		       (file_stat.st_mode & S_IXGRP) == S_IXGRP ||
		       (file_stat.st_mode & S_IXUSR) == S_IXUSR) {
		if (validate_file(config.target)) return true;

	    } else {
		dlog(VERB1, "Skipping %s.  Not executable.\n", config.target);
	    }
	}

	if (errno != 0) {
	    dlog(ERR, "Error on readdir(): %s\n", strerror(errno));
	    dirfd = NULL;
	    continue;
	}

	/* Done processing directory.  Close directory descriptor. */
	i = 0;
	while (closedir(dirfd) != 0) {
	    if (++i > 10) {
		dlog(ERR, "Warning: closedir() failed 10 times.  Ignoring open descriptor.\n");
		break;
	    }
	}
	dirfd = NULL;
    }
    return false;
}

bool getNext_BatchFile()
{
    static unsigned maxArgc = 0;
    static FILE *filefd = NULL;
    strlist cmdline = STRLIST_INITIALIZER;

    unsigned i = 0;
    if (filefd == NULL) {
	errno = 0;
	filefd = fopen(config.config_file, "r");
	if (filefd == NULL && errno != EINTR) {
	    dlog(ERR, "Could not open batch config file %s: %s\n", config.config_file, strerror(errno));
	    exit(-2);
	}
	if (++i > 10) {
	    dlog(ERR, "open() for %s has been interrupted 10 times.  Try again later.\n", config.config_file);
	    exit(-2);
	}
	config.argv = NULL;
    }

    char *buf;
    while ( (buf = fgets_static(filefd))) {
	strlist_clear(&cmdline);
	cmdline = char2strlist(buf);

	strncpy(config.target, strlist_get(&cmdline, 0), sizeof(config.target));

	if (maxArgc < (cmdline.count + 1)) {
	    char **newargv = (char **)realloc(config.argv, (cmdline.count + 1) * sizeof(char *));
	    if (!newargv) {
		dlog(ERR, "Could not allocate memory for argv array in getNext_BatchFile().\n");
		exit(-2);
	    }
	    config.argv = newargv;
	}
	for (i = 0; i < cmdline.count; ++i)
	    config.argv[i] = strlist_get(&cmdline, i);
	config.argv[i] = NULL;

	if (strrchr(config.argv[0], '/'))
	    config.argv[0] = strrchr(config.argv[0], '/') + 1;

	if (validate_file(config.target)) return true;
    }
    return false;
}
