"""
CWE Mapping and Pattern Detection
Maps vulnerability patterns to CWE identifiers
"""
from typing import List, Dict, Optional
import re


class CWEDatabase:
    """Database of CWE patterns and information"""
    
    PATTERNS = {
        'CWE-89': {
            'name': 'SQL Injection',
            'severity': 'High',
            'description': 'Improper neutralization of special elements in SQL commands',
            'patterns': [
                r'SELECT.*\+.*',
                r'INSERT.*\+.*',
                r'UPDATE.*\+.*',
                r'DELETE.*\+.*',
                r'execute\s*\(\s*[\'"].*\+',
                r'query\s*=\s*[\'"].*\+',
            ],
            'safe_patterns': [
                r'execute\s*\(.*,\s*\(',  # Parameterized
                r'prepare\s*\(',
                r'\?',  # Placeholders
            ],
            'mitigation': 'Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.',
            'example_fix': 'query = "SELECT * FROM users WHERE id=?"; cursor.execute(query, (user_id,))'
        },
        
        'CWE-79': {
            'name': 'Cross-Site Scripting (XSS)',
            'severity': 'Medium',
            'description': 'Improper neutralization of input during web page generation',
            'patterns': [
                r'innerHTML\s*=',
                r'document\.write\s*\(',
                r'eval\s*\(',
                r'<script>',
                r'\.html\s*\(',
            ],
            'safe_patterns': [
                r'textContent\s*=',
                r'\.escape\(',
                r'sanitize\(',
            ],
            'mitigation': 'Sanitize and escape user input. Use textContent instead of innerHTML. Implement Content Security Policy.',
            'example_fix': 'element.textContent = userInput; // Instead of innerHTML'
        },
        
        'CWE-78': {
            'name': 'OS Command Injection',
            'severity': 'High',
            'description': 'Improper neutralization of special elements in OS commands',
            'patterns': [
                r'os\.system\s*\(',
                r'subprocess\.call\s*\(',
                r'exec\s*\(',
                r'shell=True',
                r'popen\s*\(',
            ],
            'safe_patterns': [
                r'shell=False',
                r'shlex\.quote\(',
            ],
            'mitigation': 'Avoid system calls with user input. Use safe APIs. Always validate and sanitize inputs.',
            'example_fix': 'subprocess.run(["command", arg1, arg2], shell=False)'
        },
        
        'CWE-22': {
            'name': 'Path Traversal',
            'severity': 'High',
            'description': 'Improper limitation of pathname to restricted directory',
            'patterns': [
                r'\.\./','r\.\.\\'r'file://',
                r'open\s*\(.*\+',
            ],
            'safe_patterns': [
                r'os\.path\.abspath\(',
                r'Path\(.+\)\.resolve\(',
            ],
            'mitigation': 'Validate file paths against whitelist. Use os.path.abspath() and check path prefix.',
            'example_fix': 'safe_path = os.path.abspath(user_path); if safe_path.startswith(base_dir): ...'
        },
        
        'CWE-120': {
            'name': 'Buffer Overflow',
            'severity': 'Critical',
            'description': 'Buffer copy without checking size of input',
            'patterns': [
                r'strcpy\s*\(',
                r'strcat\s*\(',
                r'gets\s*\(',
                r'sprintf\s*\(',
            ],
            'safe_patterns': [
                r'strncpy\s*\(',
                r'strncat\s*\(',
                r'snprintf\s*\(',
                r'fgets\s*\(',
            ],
            'mitigation': 'Use safe string functions: strncpy, snprintf, strncat. Always check buffer sizes.',
            'example_fix': 'strncpy(dest, src, sizeof(dest)-1); dest[sizeof(dest)-1] = 0;'
        },
        
        'CWE-798': {
            'name': 'Hard-coded Credentials',
            'severity': 'High',
            'description': 'Software contains hard-coded credentials',
            'patterns': [
                r'password\s*=\s*[\'"][^\'"]+[\'"]',
                r'pwd\s*=\s*[\'"][^\'"]+[\'"]',
                r'api_key\s*=\s*[\'"][^\'"]+[\'"]',
                r'secret\s*=\s*[\'"][^\'"]+[\'"]',
                r'token\s*=\s*[\'"][^\'"]+[\'"]',
            ],
            'safe_patterns': [
                r'os\.environ\[',
                r'getenv\(',
                r'config\.',
            ],
            'mitigation': 'Use environment variables or secure credential storage. Never commit credentials to code.',
            'example_fix': 'password = os.environ.get("DB_PASSWORD")'
        },
        
        'CWE-327': {
            'name': 'Use of Broken Crypto',
            'severity': 'High',
            'description': 'Use of broken or risky cryptographic algorithm',
            'patterns': [
                r'MD5\s*\(',
                r'SHA1\s*\(',
                r'DES\s*\(',
                r'RC4\s*\(',
            ],
            'safe_patterns': [
                r'SHA256\s*\(',
                r'SHA512\s*\(',
                r'AES\s*\(',
            ],
            'mitigation': 'Use modern cryptographic algorithms: SHA-256, SHA-512, AES. Avoid MD5, SHA1, DES.',
            'example_fix': 'hashlib.sha256(data).hexdigest()  # Instead of md5'
        },
    }
    
    @classmethod
    def detect_patterns(cls, code: str) -> List[Dict]:
        """
        Detect CWE patterns in code
        
        Args:
            code: Source code string
            
        Returns:
            List of detected CWE dictionaries
        """
        detected = []
        code_lower = code.lower()
        
        for cwe_id, info in cls.PATTERNS.items():
            # Check if any vulnerability pattern matches
            has_vuln_pattern = any(
                re.search(pattern, code, re.IGNORECASE) 
                for pattern in info['patterns']
            )
            
            if not has_vuln_pattern:
                continue
            
            # Check if safe patterns are present (reduces confidence)
            has_safe_pattern = any(
                re.search(pattern, code, re.IGNORECASE)
                for pattern in info.get('safe_patterns', [])
            )
            
            if has_vuln_pattern and not has_safe_pattern:
                detected.append({
                    'cwe_id': cwe_id,
                    'name': info['name'],
                    'severity': info['severity'],
                    'description': info['description'],
                    'mitigation': info['mitigation'],
                    'example_fix': info.get('example_fix', ''),
                    'confidence': 'high' if not has_safe_pattern else 'medium'
                })
        
        return detected
    
    @classmethod
    def get_cwe_info(cls, cwe_id: str) -> Optional[Dict]:
        """Get information about a specific CWE"""
        return cls.PATTERNS.get(cwe_id)
    
    @classmethod
    def get_all_cwes(cls) -> List[str]:
        """Get list of all tracked CWE IDs"""
        return list(cls.PATTERNS.keys())


# Convenience function
def detect_cwe(code: str) -> List[Dict]:
    """Detect CWE patterns in code"""
    return CWEDatabase.detect_patterns(code)


# CLI test
if __name__ == "__main__":
    test_code = """
def login(username, password):
    query = "SELECT * FROM users WHERE name='" + username + "' AND pwd='secret123'"
    cursor.execute(query)
    return cursor.fetchone()
"""
    
    results = detect_cwe(test_code)
    print(f"Found {len(results)} potential vulnerabilities:\n")
    for vuln in results:
        print(f"{vuln['cwe_id']}: {vuln['name']}")
        print(f"  Severity: {vuln['severity']}")
        print(f"  Mitigation: {vuln['mitigation']}")
        print()