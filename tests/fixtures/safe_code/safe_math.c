/* safe_math.c — Clean utility functions for testing (no vulnerabilities) */
#include <stdint.h>
#include <limits.h>

/* Safe addition with overflow check */
int safe_add(int a, int b, int *result) {
    if ((b > 0 && a > INT_MAX - b) || (b < 0 && a < INT_MIN - b)) {
        return -1;  /* overflow */
    }
    *result = a + b;
    return 0;
}

/* Safe multiplication with overflow check */
int safe_multiply(int a, int b, int *result) {
    if (a > 0 && b > 0 && a > INT_MAX / b) return -1;
    if (a > 0 && b < 0 && b < INT_MIN / a) return -1;
    if (a < 0 && b > 0 && a < INT_MIN / b) return -1;
    if (a < 0 && b < 0 && a < INT_MAX / b) return -1;
    *result = a * b;
    return 0;
}

/* Compute GCD using Euclidean algorithm */
unsigned int gcd(unsigned int a, unsigned int b) {
    while (b != 0) {
        unsigned int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

/* Clamp a value to a range */
int clamp(int value, int min_val, int max_val) {
    if (value < min_val) return min_val;
    if (value > max_val) return max_val;
    return value;
}
