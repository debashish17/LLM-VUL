/* buffer_overflow.c — Intentionally vulnerable for testing */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* CWE-120: strcpy without bounds checking */
void copy_username(char *input) {
    char buffer[32];
    strcpy(buffer, input);  /* VULNERABLE: no bounds check */
    printf("Hello, %s\n", buffer);
}

/* CWE-120: gets is always unsafe */
void read_input() {
    char line[64];
    printf("Enter command: ");
    gets(line);  /* VULNERABLE: banned function */
    printf("You said: %s\n", line);
}

/* CWE-120: sprintf without bounds */
void format_message(const char *name, int age) {
    char msg[50];
    sprintf(msg, "User %s is %d years old and has a long description that might overflow", name, age);
    puts(msg);
}

/* CWE-120: strcat without bounds checking */
void build_path(const char *dir, const char *file) {
    char path[128];
    strcpy(path, dir);
    strcat(path, "/");       /* VULNERABLE */
    strcat(path, file);      /* VULNERABLE */
    printf("Path: %s\n", path);
}
