"""
CWE Enrichment Database
Maps CWE IDs to human-readable names, descriptions, CVSS-like severity
scores, mitigation advice, and example fixes.  Covers the most common
C/C++ vulnerability classes seen in training data and static analysis tools.
"""
from typing import Dict, Optional


# ---------------------------------------------------------------------------
# Database — keyed by CWE-ID string (e.g. "CWE-120")
# ---------------------------------------------------------------------------
CWE_DATABASE: Dict[str, dict] = {

    # ── Memory Safety ─────────────────────────────────────────────────────
    'CWE-119': {
        'name': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
        'severity': 'CRITICAL',
        'cvss': 9.8,
        'description': 'The software performs operations on a memory buffer without restricting the size of operations to the buffer boundaries.',
        'mitigation': 'Use safe buffer-handling functions (snprintf, strncpy). Validate all indices and sizes before memory access.',
        'example_fix': 'Replace: memcpy(dst, src, len)  →  if (len <= sizeof(dst)) memcpy(dst, src, len);',
    },
    'CWE-120': {
        'name': 'Buffer Copy without Checking Size of Input (Classic Buffer Overflow)',
        'severity': 'CRITICAL',
        'cvss': 9.8,
        'description': 'The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.',
        'mitigation': 'Replace unbounded copy functions: strcpy→strncpy, sprintf→snprintf, gets→fgets. Always check destination size.',
        'example_fix': 'strncpy(dest, src, sizeof(dest)-1); dest[sizeof(dest)-1] = \'\\0\';',
    },
    'CWE-121': {
        'name': 'Stack-based Buffer Overflow',
        'severity': 'CRITICAL',
        'cvss': 9.8,
        'description': 'A stack-based buffer overflow condition is a condition where the buffer being overwritten is allocated on the stack.',
        'mitigation': 'Use bounded string functions. Enable stack protectors (-fstack-protector). Use ASLR.',
        'example_fix': 'char buf[256]; fgets(buf, sizeof(buf), stdin);',
    },
    'CWE-122': {
        'name': 'Heap-based Buffer Overflow',
        'severity': 'CRITICAL',
        'cvss': 9.8,
        'description': 'A heap-based buffer overflow is a condition where the buffer being overwritten is allocated in the heap portion of memory.',
        'mitigation': 'Validate allocation sizes. Use calloc for zero-initialised memory. Check return values of realloc.',
        'example_fix': 'char *buf = calloc(size + 1, 1); if (!buf) return -1;',
    },
    'CWE-125': {
        'name': 'Out-of-bounds Read',
        'severity': 'HIGH',
        'cvss': 7.5,
        'description': 'The software reads data past the end, or before the beginning, of the intended buffer.',
        'mitigation': 'Always validate index values against buffer length before reading.',
        'example_fix': 'if (index < array_len) value = array[index];',
    },
    'CWE-787': {
        'name': 'Out-of-bounds Write',
        'severity': 'CRITICAL',
        'cvss': 9.8,
        'description': 'The software writes data past the end, or before the beginning, of the intended buffer.',
        'mitigation': 'Validate index and size parameters. Use bounded write functions.',
        'example_fix': 'if (offset + len <= buf_size) memcpy(buf + offset, data, len);',
    },
    'CWE-416': {
        'name': 'Use After Free',
        'severity': 'CRITICAL',
        'cvss': 9.8,
        'description': 'Referencing memory after it has been freed can cause a program to crash or execute arbitrary code.',
        'mitigation': 'Set pointers to NULL immediately after free. Use static analysis to detect dangling pointers.',
        'example_fix': 'free(ptr); ptr = NULL;',
    },
    'CWE-415': {
        'name': 'Double Free',
        'severity': 'CRITICAL',
        'cvss': 9.8,
        'description': 'The product calls free() twice on the same memory address, potentially leading to corruption of the memory allocator.',
        'mitigation': 'Set pointer to NULL after free to prevent double-free. Use ASAN during testing.',
        'example_fix': 'free(ptr); ptr = NULL;  /* second free(ptr) is now a safe no-op */',
    },
    'CWE-476': {
        'name': 'NULL Pointer Dereference',
        'severity': 'HIGH',
        'cvss': 7.5,
        'description': 'A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL.',
        'mitigation': 'Always check pointer return values before dereferencing. Use assertions in debug builds.',
        'example_fix': 'char *p = malloc(size); if (p == NULL) { handle_error(); return; }',
    },
    'CWE-401': {
        'name': 'Missing Release of Memory after Effective Lifetime (Memory Leak)',
        'severity': 'MEDIUM',
        'cvss': 5.3,
        'description': 'The software does not sufficiently track and release allocated memory after it has been used.',
        'mitigation': 'Ensure every malloc/calloc/realloc has a corresponding free on all code paths, including error paths.',
        'example_fix': 'Use goto-cleanup pattern: goto cleanup; ... cleanup: free(buf); return ret;',
    },

    # ── Integer Issues ────────────────────────────────────────────────────
    'CWE-190': {
        'name': 'Integer Overflow or Wraparound',
        'severity': 'HIGH',
        'cvss': 8.1,
        'description': 'The software performs a calculation that can produce an integer overflow or wraparound.',
        'mitigation': 'Use safe integer arithmetic. Check for overflow before operations. Use size_t for sizes.',
        'example_fix': 'if (a > SIZE_MAX / b) { error(); } else { result = a * b; }',
    },
    'CWE-191': {
        'name': 'Integer Underflow',
        'severity': 'HIGH',
        'cvss': 8.1,
        'description': 'The product subtracts one value from another, such that the result is less than the minimum allowable integer value.',
        'mitigation': 'Check that subtraction result will not underflow before performing the operation.',
        'example_fix': 'if (a >= b) { result = a - b; } else { handle_underflow(); }',
    },
    'CWE-189': {
        'name': 'Numeric Errors',
        'severity': 'MEDIUM',
        'cvss': 5.3,
        'description': 'Weaknesses in this category are related to improper calculation or conversion of numbers.',
        'mitigation': 'Validate numeric inputs. Use appropriate data types. Check for overflow/underflow.',
        'example_fix': 'Prefer size_t for sizes; check casts between signed and unsigned.',
    },

    # ── Input Validation ──────────────────────────────────────────────────
    'CWE-20': {
        'name': 'Improper Input Validation',
        'severity': 'HIGH',
        'cvss': 7.5,
        'description': 'The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program.',
        'mitigation': 'Validate all external inputs against expected type, length, range, and format.',
        'example_fix': 'if (len < 0 || len > MAX_LEN) { return ERROR_INVALID; }',
    },
    'CWE-134': {
        'name': 'Use of Externally-Controlled Format String',
        'severity': 'HIGH',
        'cvss': 8.6,
        'description': 'The software uses a function that accepts a format string as an argument, but the format string originates from an external source.',
        'mitigation': 'Never pass user-controlled strings as format arguments. Use constant format strings.',
        'example_fix': 'printf("%s", user_input);  // NOT printf(user_input);',
    },
    'CWE-78': {
        'name': 'OS Command Injection',
        'severity': 'CRITICAL',
        'cvss': 9.8,
        'description': 'The software constructs all or part of an OS command using externally-influenced input.',
        'mitigation': 'Avoid system()/popen(). Use exec-family with argument arrays. Validate and sanitise all inputs.',
        'example_fix': 'execl("/bin/ls", "ls", "-l", dir_path, NULL);  // NOT system(cmd);',
    },
    'CWE-22': {
        'name': 'Path Traversal',
        'severity': 'HIGH',
        'cvss': 7.5,
        'description': 'The software uses external input to construct a pathname to access a restricted directory, but does not properly neutralize sequences such as "..".',
        'mitigation': 'Canonicalise paths with realpath(). Check that resolved path starts with the expected base directory.',
        'example_fix': 'char *resolved = realpath(user_path, NULL); if (strncmp(resolved, base, strlen(base)) != 0) abort();',
    },
    'CWE-89': {
        'name': 'SQL Injection',
        'severity': 'CRITICAL',
        'cvss': 9.8,
        'description': 'The software constructs SQL statements from user input without proper neutralisation.',
        'mitigation': 'Use parameterised queries / prepared statements. Never concatenate user input into SQL.',
        'example_fix': 'sqlite3_prepare_v2(db, "SELECT * FROM t WHERE id=?", -1, &stmt, 0); sqlite3_bind_int(stmt, 1, id);',
    },

    # ── Dangerous Functions ───────────────────────────────────────────────
    'CWE-676': {
        'name': 'Use of Potentially Dangerous Function',
        'severity': 'MEDIUM',
        'cvss': 5.3,
        'description': 'The program invokes a potentially dangerous function that could introduce a vulnerability.',
        'mitigation': 'Replace dangerous functions with safer alternatives (atoi→strtol, gets→fgets).',
        'example_fix': 'long val = strtol(str, &endptr, 10); if (*endptr != \'\\0\') handle_error();',
    },
    'CWE-242': {
        'name': 'Use of Inherently Dangerous Function',
        'severity': 'CRITICAL',
        'cvss': 9.8,
        'description': 'The program calls a function that can never be guaranteed to work safely (e.g. gets()).',
        'mitigation': 'Remove all calls to gets(). Use fgets() with explicit buffer size.',
        'example_fix': 'fgets(buf, sizeof(buf), stdin);',
    },

    # ── Concurrency ───────────────────────────────────────────────────────
    'CWE-362': {
        'name': 'Race Condition (Concurrent Execution using Shared Resource)',
        'severity': 'HIGH',
        'cvss': 8.1,
        'description': 'The program contains a code sequence that can run concurrently with other code, and requires temporary exclusive access to a shared resource.',
        'mitigation': 'Use mutexes / locks around shared resource access. Minimise the critical section.',
        'example_fix': 'pthread_mutex_lock(&mtx); shared_counter++; pthread_mutex_unlock(&mtx);',
    },
    'CWE-667': {
        'name': 'Improper Locking',
        'severity': 'HIGH',
        'cvss': 7.5,
        'description': 'The software does not properly acquire or release a lock on a resource, leading to unexpected behaviour.',
        'mitigation': 'Use RAII-style locking in C++ or goto-cleanup in C to guarantee lock release.',
        'example_fix': 'std::lock_guard<std::mutex> guard(mtx);  // automatic unlock on scope exit',
    },

    # ── Crypto & Secrets ──────────────────────────────────────────────────
    'CWE-327': {
        'name': 'Use of Broken or Risky Cryptographic Algorithm',
        'severity': 'HIGH',
        'cvss': 7.5,
        'description': 'The use of a broken or risky cryptographic algorithm (MD5, SHA-1, DES, RC4).',
        'mitigation': 'Use modern algorithms: SHA-256, SHA-512, AES-256-GCM. Avoid MD5, SHA-1, DES.',
        'example_fix': 'Use EVP_sha256() instead of EVP_md5() in OpenSSL.',
    },
    'CWE-798': {
        'name': 'Hard-coded Credentials',
        'severity': 'HIGH',
        'cvss': 7.5,
        'description': 'The software contains hard-coded credentials such as passwords or cryptographic keys.',
        'mitigation': 'Store secrets in environment variables or a secure vault. Never commit credentials.',
        'example_fix': 'const char *key = getenv("API_KEY"); if (!key) abort();',
    },

    # ── Resource Management ───────────────────────────────────────────────
    'CWE-399': {
        'name': 'Resource Management Errors',
        'severity': 'MEDIUM',
        'cvss': 5.3,
        'description': 'The software does not properly manage a resource throughout its lifetime.',
        'mitigation': 'Track every acquired resource and ensure release on all code paths.',
        'example_fix': 'Use goto-cleanup pattern or RAII for automatic resource management.',
    },
    'CWE-772': {
        'name': 'Missing Release of Resource after Effective Lifetime',
        'severity': 'MEDIUM',
        'cvss': 5.3,
        'description': 'The software does not release a resource after its effective lifetime has ended (file handles, sockets, etc.).',
        'mitigation': 'Close all file descriptors and sockets. Use cleanup labels in C.',
        'example_fix': 'FILE *f = fopen(path, "r"); if (!f) return -1; ... fclose(f);',
    },
    'CWE-400': {
        'name': 'Uncontrolled Resource Consumption',
        'severity': 'MEDIUM',
        'cvss': 5.3,
        'description': 'The software does not properly control the allocation and maintenance of a limited resource.',
        'mitigation': 'Set upper limits on allocations. Use resource quotas and timeouts.',
        'example_fix': 'if (requested_size > MAX_ALLOC) { return ERROR_TOO_LARGE; }',
    },

    # ── Information / Permissions ─────────────────────────────────────────
    'CWE-200': {
        'name': 'Exposure of Sensitive Information to an Unauthorized Actor',
        'severity': 'MEDIUM',
        'cvss': 5.3,
        'description': 'The software exposes sensitive information to an actor not explicitly authorised to have access.',
        'mitigation': 'Zero-out sensitive buffers after use. Avoid logging secrets. Restrict error messages.',
        'example_fix': 'memset(password_buf, 0, sizeof(password_buf));',
    },
    'CWE-264': {
        'name': 'Permissions, Privileges, and Access Controls',
        'severity': 'HIGH',
        'cvss': 7.5,
        'description': 'Weaknesses in this category are related to the management of permissions, privileges, and other security features.',
        'mitigation': 'Apply principle of least privilege. Drop privileges after startup. Validate file permissions.',
        'example_fix': 'setuid(unprivileged_uid); setgid(unprivileged_gid);',
    },

    # ── XSS (less common in C but flagged by pattern matcher) ─────────────
    'CWE-79': {
        'name': 'Cross-Site Scripting (XSS)',
        'severity': 'MEDIUM',
        'cvss': 6.1,
        'description': 'Improper neutralization of input during web page generation.',
        'mitigation': 'Sanitise and escape user input. Use Content Security Policy headers.',
        'example_fix': 'html_escape(user_input, escaped_buf, sizeof(escaped_buf));',
    },
}

# Convenience alias for common CWE categories
CWE_CATEGORIES = {
    'memory': ['CWE-119', 'CWE-120', 'CWE-121', 'CWE-122', 'CWE-125', 'CWE-787',
               'CWE-416', 'CWE-415', 'CWE-476', 'CWE-401'],
    'integer': ['CWE-190', 'CWE-191', 'CWE-189'],
    'input_validation': ['CWE-20', 'CWE-134', 'CWE-78', 'CWE-22', 'CWE-89'],
    'dangerous_functions': ['CWE-676', 'CWE-242'],
    'concurrency': ['CWE-362', 'CWE-667'],
    'crypto': ['CWE-327', 'CWE-798'],
    'resource': ['CWE-399', 'CWE-772', 'CWE-400'],
    'information': ['CWE-200', 'CWE-264', 'CWE-79'],
}


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------
def get_cwe_info(cwe_id: str) -> Optional[dict]:
    """Return the enrichment dict for *cwe_id*, or None."""
    return CWE_DATABASE.get(cwe_id)


def enrich_finding(cwe_id: Optional[str]) -> dict:
    """
    Return a dict of enrichment fields for a finding.
    If *cwe_id* is unknown or None, returns generic guidance.
    """
    if cwe_id and cwe_id in CWE_DATABASE:
        info = CWE_DATABASE[cwe_id]
        return {
            'cwe_id': cwe_id,
            'cwe_name': info['name'],
            'severity': info['severity'],
            'severity_score': info.get('cvss'),
            'mitigation': info['mitigation'],
            'recommendation': info.get('example_fix', ''),
        }
    return {
        'cwe_id': cwe_id,
        'cwe_name': None,
        'severity': None,
        'severity_score': None,
        'mitigation': 'Manual code review recommended — this finding was not mapped to a known CWE.',
        'recommendation': 'Inspect the flagged code for potential security issues.',
    }
