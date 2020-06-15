/*

  utils.c

  MAST: Multicast Audio Streaming Toolkit
  Copyright (C) 2019  Nicholas Humfrey
  License: MIT

*/

#include "mast.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <dirent.h>
#include <errno.h>

#include "openavb_log_pub.h"

int running = TRUE;
int exit_code = 0;
int quiet = 0;
int verbose = 0;

static void termination_handler(int signum)
{
    running = FALSE;
    switch(signum) {
    case SIGTERM:
        mast_info("Got termination signal");
        break;
    case SIGINT:
        mast_info("Got interupt signal");
        break;
    }
    signal(signum, termination_handler);
}


void setup_signal_hander()
{
    signal(SIGTERM, termination_handler);
    signal(SIGINT, termination_handler);
    signal(SIGHUP, termination_handler);
}

void mast_log(mast_log_level level, const char *fmt, ...)
{
    va_list args;
    int avbLevel;
    const char *sz;

    // Display the message level
    switch(level) {
    case mast_LOG_DEBUG:
	avbLevel = AVB_LOG_LEVEL_DEBUG;
	sz = "DEBUG";
	break;
    case mast_LOG_INFO:
	avbLevel = AVB_LOG_LEVEL_INFO;
	sz = "INFO";
        break;
    case mast_LOG_WARN:
	avbLevel = AVB_LOG_LEVEL_WARNING;
	sz = "WARNING";
        break;
    case mast_LOG_ERROR:
	avbLevel = AVB_LOG_LEVEL_ERROR;
	sz = "ERROR";
        break;
    default:
	avbLevel = AVB_LOG_LEVEL_VERBOSE;
	sz = "VERBOSE";
        break;
    }

    va_start(args, fmt);
    __avbLogFn(avbLevel, sz, AVB_LOG_COMPANY, "AES67 Library", __FILE__, __LINE__, fmt, args);
    va_end(args);
}

int mast_read_file_string(const char* filename, char* buffer, size_t buffer_len)
{
    int bytes;
    int retcode = -1;

    // Open the file for reading
    FILE* file = fopen(filename, "rb");
    if (!file) {
        mast_error(
            "Failed to open file '%s': %s",
            filename,
            strerror(errno)
        );
        return retcode;
    }

    // Read as much as we can into the buffer
    bytes = fread(buffer, 1, buffer_len - 1, file);
    if (bytes <= 0) {
        mast_error(
            "Error reading from file '%s': %s",
            filename,
            strerror(errno)
        );

        // FIXME: check that buffer wasn't too small

    } else {
        // Terminate the string
        buffer[bytes] = '\0';
        retcode = 0;
    }

    fclose(file);

    return retcode;
}



int mast_directory_exists(const char* path)
{
    DIR* dir = opendir(path);
    if (dir) {
        /* Directory exists. */
        closedir(dir);
        return TRUE;
    } else if (ENOENT == errno) {
        /* Directory does not exist. */
        return FALSE;
    } else {
        /* opendir() failed for some other reason. */
        mast_error(
            "checking if directory '%s' exists: %s",
            path,
            strerror(errno)
        );
        return FALSE;
    }
}


const char* mast_encoding_names[MAST_ENCODING_MAX] = {
    [MAST_ENCODING_L8] = "L8",
    [MAST_ENCODING_L16] = "L16",
    [MAST_ENCODING_L24] = "L24",
    [MAST_ENCODING_PCMU] = "PCMU",
    [MAST_ENCODING_PCMA] = "PCMA",
    [MAST_ENCODING_G722] = "G722",
    [MAST_ENCODING_GSM] = "GSM",
    [MAST_ENCODING_AM824] = "AM824",
};


const char* mast_encoding_name(int encoding)
{
    if (encoding > 0 && encoding < MAST_ENCODING_MAX) {
        return mast_encoding_names[encoding];
    } else {
        return NULL;
    }
}

int mast_encoding_lookup(const char* name)
{
    int i;

    for(i=0; i< MAST_ENCODING_MAX; i++) {
        if (strcmp(mast_encoding_names[i], name) == 0)
            return i;
    }
    return -1;
}
