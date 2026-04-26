/* memory_issues.c — Intentionally vulnerable for testing */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CWE-476: potential NULL pointer dereference */
void process_data(int size) {
    char *buf = malloc(size);
    /* VULNERABLE: no NULL check after malloc */
    memset(buf, 0, size);
    buf[0] = 'A';
    free(buf);
}

/* CWE-416: use after free */
void use_after_free_example() {
    char *data = malloc(100);
    strcpy(data, "sensitive");
    free(data);
    /* VULNERABLE: accessing freed memory */
    printf("Data: %s\n", data);
}

/* CWE-190: integer overflow in malloc */
void allocate_buffer(int width, int height) {
    /* VULNERABLE: width * height can overflow */
    char *pixels = malloc(width * height);
    if (pixels) {
        memset(pixels, 0, width * height);
        free(pixels);
    }
}

/* CWE-401: memory leak — no free on error path */
int read_config(const char *path) {
    char *buffer = malloc(4096);
    FILE *f = fopen(path, "r");
    if (!f) {
        /* VULNERABLE: buffer is leaked */
        return -1;
    }
    fread(buffer, 1, 4096, f);
    fclose(f);
    free(buffer);
    return 0;
}
