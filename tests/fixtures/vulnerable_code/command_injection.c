/* command_injection.c — Intentionally vulnerable for testing */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CWE-78: system() with user-influenced input */
void run_command(const char *user_input) {
    char cmd[256];
    sprintf(cmd, "ls -la %s", user_input);
    system(cmd);  /* VULNERABLE: command injection */
}

/* CWE-78: popen with concatenated input */
FILE* check_file(const char *filename) {
    char cmd[256];
    sprintf(cmd, "file %s", filename);
    return popen(cmd, "r");  /* VULNERABLE: command injection */
}

/* CWE-134: format string vulnerability */
void log_message(char *user_msg) {
    printf(user_msg);  /* VULNERABLE: user-controlled format string */
}

/* CWE-676: atoi without error handling */
int parse_port(const char *port_str) {
    return atoi(port_str);  /* VULNERABLE: no error handling */
}
