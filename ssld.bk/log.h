typedef enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
} log_level_t;

int log_init(const char *filename, log_level_t level);
void log_close();
void log_write(log_level_t level, const char *fmt, ...);