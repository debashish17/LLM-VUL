/* safe_string.c — Safe string handling for testing (no vulnerabilities) */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Safe string copy using strncpy */
int safe_copy(char *dest, size_t dest_size, const char *src) {
    if (dest == NULL || src == NULL || dest_size == 0) {
        return -1;
    }
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
    return 0;
}

/* Safe string concatenation using snprintf */
int safe_concat(char *dest, size_t dest_size, const char *a, const char *b) {
    if (dest == NULL || a == NULL || b == NULL) {
        return -1;
    }
    int written = snprintf(dest, dest_size, "%s%s", a, b);
    if (written < 0 || (size_t)written >= dest_size) {
        return -1;  /* truncated */
    }
    return 0;
}

/* Safe input reading using fgets */
int safe_readline(char *buf, size_t buf_size) {
    if (buf == NULL || buf_size == 0) {
        return -1;
    }
    if (fgets(buf, (int)buf_size, stdin) == NULL) {
        return -1;
    }
    /* Remove trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
    return 0;
}

/* Safe number parsing using strtol */
int safe_parse_int(const char *str, int *result) {
    if (str == NULL || result == NULL) {
        return -1;
    }
    char *endptr;
    long val = strtol(str, &endptr, 10);
    if (*endptr != '\0') {
        return -1;  /* invalid characters */
    }
    *result = (int)val;
    return 0;
}
