#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "log.h"

static FILE *log_file = NULL;
static log_level_t current_level = LOG_LEVEL_INFO;

int log_init(const char *filename, log_level_t level) {
    log_file = fopen(filename, "a");
    if (!log_file) {
        return -1;
    }
    current_level = level;
    return 0;
}

void log_close() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

static const char *level_to_str(log_level_t level) {
    switch (level) {
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_WARN:  return "WARN";
        case LOG_LEVEL_INFO:  return "INFO";
        case LOG_LEVEL_DEBUG: return "DEBUG";
        default:              return "UNKNOWN";
    }
}

void log_write(log_level_t level, const char *fmt, ...) {
    if (!log_file || level > current_level)
        return;

    // Add timestamp
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_now);

    fprintf(log_file, "[%s] [%s] ", timebuf, level_to_str(level));
    va_list args;
    va_start(args, fmt);
    vfprintf(log_file, fmt, args);
    va_end(args);
    fprintf(log_file, "\n");
    fflush(log_file);
}