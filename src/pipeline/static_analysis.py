"""
Static Analysis Module
Runs CppCheck, Flawfinder, and regex-based pattern matching on C/C++ code.
"""
import subprocess
import xml.etree.ElementTree as ET
import csv
import io
import json
import re
import os
import sys
import shutil
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path

from .ingestion import SourceFile, FunctionUnit, IngestionResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool discovery paths
# ---------------------------------------------------------------------------
CPPCHECK_PATHS = [
    r"C:\Program Files\Cppcheck\cppcheck.exe",
    r"C:\Program Files (x86)\Cppcheck\cppcheck.exe",
    "cppcheck",
]

# ---------------------------------------------------------------------------
# Severity normalisation maps
# ---------------------------------------------------------------------------
CPPCHECK_SEVERITY_MAP = {
    'error': 'HIGH',
    'warning': 'MEDIUM',
    # 'style', 'performance', 'portability', 'information' are NOT mapped.
    # They are code-quality findings, not security findings — filtering them
    # out eliminates the majority of false positives on safe code.
}

# CppCheck severities to silently skip (non-security noise)
CPPCHECK_SKIP_SEVERITIES = {'style', 'performance', 'portability', 'information'}

# CppCheck rule IDs that ARE security-relevant even when reported as style/perf
# (override the severity skip for these specific rules)
CPPCHECK_SECURITY_OVERRIDES = {
    'nullPointer', 'nullPointerRedundantCheck', 'nullPointerArithmetic',
    'uninitvar', 'uninitdata', 'uninitMemberVar', 'uninitStructMember',
    'memleak', 'resourceLeak', 'memleakOnRealloc',
    'doubleFree', 'deallocuse', 'deallocDealloc',
    'bufferAccessOutOfBounds', 'arrayIndexOutOfBounds',
    'negativeIndex', 'negativeArraySize',
    'danglingLifetime', 'danglingReference', 'danglingTempReference',
    'invalidFunctionArg', 'invalidIterator1',
    'zerodiv', 'zerodivcond',
}

FLAWFINDER_LEVEL_MAP = {
    5: 'CRITICAL',
    4: 'HIGH',
    3: 'MEDIUM',
    2: 'LOW',
    1: 'LOW',
    0: 'LOW',
}

SEVERITY_CONFIDENCE = {
    'CRITICAL': 0.95,
    'HIGH': 0.85,
    'MEDIUM': 0.70,
    'LOW': 0.50,
}

# Semgrep severity normalisation
SEMGREP_SEVERITY_MAP = {
    'ERROR': 'HIGH',
    'WARNING': 'MEDIUM',
    'INFO': 'LOW',
}

# Semgrep rulesets to use (p/ references Semgrep Registry)
# Using local rules file for better Windows compatibility and C/C++ coverage
SEMGREP_RULES_FILE = Path(__file__).parent / 'semgrep_rules.yaml'

# ---------------------------------------------------------------------------
# Regex-based vulnerability patterns for C/C++
# ---------------------------------------------------------------------------
C_VULN_PATTERNS: Dict[str, dict] = {
    'CWE-120': {
        'name': 'Buffer Copy without Checking Size',
        'severity': 'CRITICAL',
        'patterns': [
            (r'\bstrcpy\s*\(', 'strcpy — no bounds checking'),
            (r'\bstrcat\s*\(', 'strcat — no bounds checking'),
            (r'\bgets\s*\(', 'gets — always unsafe, banned function'),
            (r'\bsprintf\s*\(', 'sprintf — no bounds checking'),
            (r'\bvsprintf\s*\(', 'vsprintf — no bounds checking'),
        ],
        'safe_patterns': [r'\bstrncpy\b', r'\bstrncat\b', r'\bsnprintf\b', r'\bfgets\b'],
    },
    'CWE-134': {
        'name': 'Externally-Controlled Format String',
        'severity': 'HIGH',
        'patterns': [
            (r'\bprintf\s*\(\s*[a-zA-Z_]\w*\s*\)', 'printf with variable format string'),
            (r'\bfprintf\s*\([^,]+,\s*[a-zA-Z_]\w*\s*\)', 'fprintf with variable format string'),
        ],
        'safe_patterns': [r'printf\s*\(\s*"'],
    },
    'CWE-78': {
        'name': 'OS Command Injection',
        'severity': 'HIGH',
        'patterns': [
            (r'\bsystem\s*\(', 'system() — potential command injection'),
            (r'\bpopen\s*\(', 'popen() — potential command injection'),
        ],
        'safe_patterns': [],
    },
    'CWE-190': {
        'name': 'Integer Overflow or Wraparound',
        'severity': 'MEDIUM',
        'patterns': [
            (r'\bmalloc\s*\([^)]*\*[^)]*\)', 'malloc with multiplication — potential integer overflow'),
        ],
        'safe_patterns': [],
    },
    'CWE-676': {
        'name': 'Use of Potentially Dangerous Function',
        'severity': 'MEDIUM',
        'patterns': [
            (r'\batoi\s*\(', 'atoi — no error handling, prefer strtol'),
            (r'\batof\s*\(', 'atof — no error handling, prefer strtod'),
        ],
        'safe_patterns': [r'\bstrtol\b', r'\bstrtod\b'],
    },
    'CWE-242': {
        'name': 'Use of Inherently Dangerous Function',
        'severity': 'CRITICAL',
        'patterns': [
            (r'\bgets\s*\(', 'gets() is always unsafe — use fgets()'),
        ],
        'safe_patterns': [],
    },
    # --- Advanced patterns (double-free, UAF, TOCTOU, etc.) ---
    'CWE-415': {
        'name': 'Double Free',
        'severity': 'HIGH',
        'patterns': [
            # free() appearing twice in the same function (heuristic)
            (r'\bfree\s*\([^)]+\).*\bfree\s*\(\1\)', 'Possible double free of the same pointer'),
            # free followed by free without intervening assignment (simpler heuristic)
            (r'\bfree\s*\(\s*(\w+)\s*\)(?:(?!\1\s*=).)*?\bfree\s*\(\s*\1\s*\)',
             'Potential double free — pointer freed twice without reassignment'),
        ],
        'safe_patterns': [r'=\s*NULL\s*;'],  # Setting to NULL between frees is safe
    },
    'CWE-416': {
        'name': 'Use After Free',
        'severity': 'CRITICAL',
        'patterns': [
            # free(ptr) followed by use of ptr without reassignment
            (r'\bfree\s*\(\s*(\w+)\s*\)\s*;(?:(?!\1\s*=).)*?\b\1\s*[\[\.\->]',
             'Potential use-after-free — pointer used after free()'),
            (r'\bfree\s*\(\s*(\w+)\s*\)\s*;(?:(?!\1\s*=).)*?\*\s*\1\b',
             'Potential use-after-free — pointer dereferenced after free()'),
        ],
        'safe_patterns': [r'=\s*NULL\s*;'],
    },
    'CWE-476': {
        'name': 'NULL Pointer Dereference',
        'severity': 'HIGH',
        'patterns': [
            # malloc/calloc/realloc without NULL check
            (r'(\w+)\s*=\s*\b(malloc|calloc|realloc)\s*\([^)]*\)\s*;(?:(?!if\s*\(\s*\1|if\s*\(\s*!\s*\1|if\s*\(\s*NULL\s*[!=]=\s*\1).){0,120}[\[\.\->]',
             'Heap allocation result used without NULL check'),
            # Direct NULL risk: function return used without check
            (r'(\w+)\s*=\s*\bfopen\s*\([^)]*\)\s*;(?:(?!if\s*\(\s*\1|if\s*\(\s*!\s*\1).){0,80}\bfread\b',
             'fopen() result used without NULL check before I/O'),
        ],
        'safe_patterns': [],
    },
    'CWE-362': {
        'name': 'Race Condition (TOCTOU)',
        'severity': 'MEDIUM',
        'patterns': [
            # Classic TOCTOU: access/stat followed by open/fopen
            (r'\b(access|stat|lstat)\s*\([^)]*\).*\b(open|fopen|creat|unlink|remove|rename)\s*\(',
             'TOCTOU race — check-then-act on filesystem without atomic operation'),
        ],
        'safe_patterns': [],
    },
    'CWE-457': {
        'name': 'Use of Uninitialized Variable',
        'severity': 'MEDIUM',
        'patterns': [
            # Variable declared (non-pointer, non-array) with no initialiser, then used
            (r'\b(int|char|float|double|long|short|unsigned|size_t)\s+(\w+)\s*;(?:(?!\2\s*=).){0,100}\b\2\s*[+\-\*/\|&<>!=\[]',
             'Variable declared without initialisation then used — potential undefined behaviour'),
        ],
        'safe_patterns': [r'=\s*0\s*;', r'memset'],
    },
    'CWE-252': {
        'name': 'Unchecked Return Value',
        'severity': 'LOW',
        'patterns': [
            # Ignoring return value of security-critical functions
            (r'^\s*(read|write|recv|send|fread|fwrite)\s*\(',
             'Return value of I/O function not checked — data loss or partial read/write'),
        ],
        'safe_patterns': [r'if\s*\(', r'while\s*\(', r'(\w+)\s*='],
    },
    'CWE-119': {
        'name': 'Buffer Overflow (Improper Memory Operations)',
        'severity': 'HIGH',
        'patterns': [
            # memcpy/memmove with non-sizeof third argument heuristic
            (r'\b(memcpy|memmove)\s*\([^,]+,[^,]+,\s*[a-zA-Z_]\w*\s*\)',
             'memcpy/memmove with variable size — ensure bounds are checked'),
            # Array access with user-influenced index
            (r'\[\s*(argc|argv|optarg|getenv|fgets|scanf|gets)\b',
             'Array indexed by external input — potential out-of-bounds access'),
        ],
        'safe_patterns': [r'sizeof\s*\(', r'MIN\s*\(', r'min\s*\('],
    },
    'CWE-401': {
        'name': 'Memory Leak',
        'severity': 'MEDIUM',
        'patterns': [
            # malloc without corresponding free in same function (heuristic)
            (r'\b(malloc|calloc|strdup)\s*\([^)]*\)',
             'Heap allocation — ensure corresponding free() exists on all paths'),
        ],
        'safe_patterns': [r'\bfree\s*\(', r'\breturn\s+\w+\s*;'],
    },
    'CWE-22': {
        'name': 'Path Traversal',
        'severity': 'HIGH',
        'patterns': [
            (r'\.\./|\.\.\\\\', 'Path traversal sequence (../) detected in string'),
            (r'\b(fopen|open|creat)\s*\([^"]*\b(argv|getenv|optarg|input|param|request)\b',
             'File operation with external input — potential path traversal'),
        ],
        'safe_patterns': [r'realpath', r'basename'],
    },
}

# CppCheck rule IDs to suppress (non-actionable noise)
CPPCHECK_SUPPRESS = {
    'missingIncludeSystem', 'missingInclude', 'unknownMacro',
    'preprocessorErrorDirective', 'noValidConfiguration',
    'unmatchedSuppression', 'checkersReport',
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class StaticFinding:
    """A single finding from a static analysis tool."""
    tool: str                       # 'cppcheck' | 'flawfinder' | 'pattern_matcher'
    rule_id: str                    # Tool-specific rule identifier
    cwe_id: Optional[str]           # e.g. 'CWE-120' or None
    cwe_name: Optional[str]
    severity: str                   # 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
    confidence: float               # 0.0 – 1.0
    message: str
    file_path: str                  # Relative path inside ZIP
    line: int
    column: Optional[int] = None
    highlighted_code: Optional[str] = None


@dataclass
class StaticAnalysisResult:
    """Aggregated result of the static analysis phase."""
    all_findings: List[StaticFinding]
    function_findings: Dict[str, List[StaticFinding]]   # function uid → findings
    clean_functions: List[FunctionUnit]                  # No findings at all
    tools_used: List[str]


# ---------------------------------------------------------------------------
# Analyser
# ---------------------------------------------------------------------------
class StaticAnalyzer:
    """Orchestrates CppCheck, Flawfinder, and regex pattern matching."""

    def __init__(self):
        self.cppcheck_path = self._find_cppcheck()
        self.flawfinder_path = self._find_flawfinder()
        self.semgrep_path = self._find_semgrep()

    # ------------------------------------------------------------------
    # Tool discovery
    # ------------------------------------------------------------------
    @staticmethod
    def _find_cppcheck() -> Optional[str]:
        for path in CPPCHECK_PATHS:
            if os.path.isfile(path):
                logger.info(f"Found cppcheck: {path}")
                return path
        found = shutil.which("cppcheck")
        if found:
            logger.info(f"Found cppcheck in PATH: {found}")
            return found
        logger.warning("cppcheck not found — will skip cppcheck analysis")
        return None

    @staticmethod
    def _find_flawfinder() -> Optional[str]:
        # First look in the current venv's Scripts / bin directory
        venv_scripts = Path(sys.executable).parent
        for name in ("flawfinder.exe", "flawfinder"):
            candidate = venv_scripts / name
            if candidate.exists():
                logger.info(f"Found flawfinder: {candidate}")
                return str(candidate)
        # Fall back to PATH
        found = shutil.which("flawfinder")
        if found:
            logger.info(f"Found flawfinder in PATH: {found}")
            return found
        logger.warning("flawfinder not found — will skip flawfinder analysis")
        return None

    @staticmethod
    def _find_semgrep() -> Optional[str]:
        # Semgrep installs as a Python package with CLI
        venv_scripts = Path(sys.executable).parent
        for name in ("semgrep.exe", "semgrep"):
            candidate = venv_scripts / name
            if candidate.exists():
                logger.info(f"Found semgrep: {candidate}")
                return str(candidate)
        # Fall back to PATH
        found = shutil.which("semgrep")
        if found:
            logger.info(f"Found semgrep in PATH: {found}")
            return found
        logger.warning("semgrep not found — will skip semgrep analysis")
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def analyze(self, ingestion_result: IngestionResult) -> StaticAnalysisResult:
        """
        Run every available static tool on the ingested codebase.

        Returns a ``StaticAnalysisResult`` with findings mapped to functions
        and a list of *clean* functions that had zero findings.
        """
        all_findings: List[StaticFinding] = []
        tools_used: List[str] = []

        # --- CppCheck ---
        if self.cppcheck_path:
            tools_used.append('cppcheck')
            for src in ingestion_result.files:
                all_findings.extend(self._run_cppcheck(src))
            n = sum(1 for f in all_findings if f.tool == 'cppcheck')
            logger.info(f"CppCheck: {n} finding(s)")

        # --- Flawfinder ---
        if self.flawfinder_path:
            tools_used.append('flawfinder')
            for src in ingestion_result.files:
                all_findings.extend(self._run_flawfinder(src))
            n = sum(1 for f in all_findings if f.tool == 'flawfinder')
            logger.info(f"Flawfinder: {n} finding(s)")

        # --- Semgrep ---
        if self.semgrep_path:
            tools_used.append('semgrep')
            # Run Semgrep once on the entire temp directory for efficiency
            all_findings.extend(self._run_semgrep(ingestion_result))
            n = sum(1 for f in all_findings if f.tool == 'semgrep')
            logger.info(f"Semgrep: {n} finding(s)")

        # Map findings → functions
        func_findings = self._map_findings_to_functions(
            all_findings, ingestion_result.functions
        )

        # Deduplicate per function
        for uid in func_findings:
            func_findings[uid] = self._deduplicate(func_findings[uid])

        # Separate clean vs flagged
        flagged_uids = {uid for uid, fl in func_findings.items() if fl}
        clean = [f for f in ingestion_result.functions if f.uid not in flagged_uids]

        logger.info(
            f"Static analysis done — {len(all_findings)} total finding(s), "
            f"{len(flagged_uids)} function(s) flagged, {len(clean)} clean"
        )

        return StaticAnalysisResult(
            all_findings=all_findings,
            function_findings=func_findings,
            clean_functions=clean,
            tools_used=tools_used,
        )

    # ------------------------------------------------------------------
    # CppCheck
    # ------------------------------------------------------------------
    def _run_cppcheck(self, src: SourceFile) -> List[StaticFinding]:
        findings: List[StaticFinding] = []
        std = '--std=c11' if src.language == 'c' else '--std=c++14'

        try:
            result = subprocess.run(
                [
                    self.cppcheck_path,
                    '--xml', '--enable=all', std,
                    '--suppress=missingInclude',
                    '--suppress=missingIncludeSystem',
                    '--suppress=unmatchedSuppression',
                    '--suppress=checkersReport',
                    src.abs_path,
                ],
                capture_output=True, text=True, timeout=120,
            )
            xml_out = result.stderr
            if not xml_out.strip():
                return findings

            root = ET.fromstring(xml_out)
            for error in root.iter('error'):
                eid = error.get('id', '')
                if eid in CPPCHECK_SUPPRESS:
                    continue

                sev = error.get('severity', 'information')
                msg = error.get('verbose', error.get('msg', ''))
                cwe = error.get('cwe', '')

                # --- False-positive filter ---
                # Skip non-security severity unless the rule is a known
                # security-relevant check (CPPCHECK_SECURITY_OVERRIDES).
                if sev in CPPCHECK_SKIP_SEVERITIES and eid not in CPPCHECK_SECURITY_OVERRIDES:
                    continue

                loc = error.find('location')
                line = int(loc.get('line', 0)) if loc is not None else 0
                col = int(loc.get('column', 0)) if loc is not None and loc.get('column') else None
                if line == 0:
                    continue

                norm_sev = CPPCHECK_SEVERITY_MAP.get(sev, 'MEDIUM')
                findings.append(StaticFinding(
                    tool='cppcheck',
                    rule_id=eid,
                    cwe_id=f"CWE-{cwe}" if cwe else None,
                    cwe_name=None,
                    severity=norm_sev,
                    confidence=SEVERITY_CONFIDENCE.get(norm_sev, 0.5),
                    message=msg,
                    file_path=src.rel_path,
                    line=line,
                    column=col,
                ))

        except subprocess.TimeoutExpired:
            logger.warning(f"CppCheck timed out: {src.rel_path}")
        except ET.ParseError as e:
            logger.warning(f"CppCheck XML parse error ({src.rel_path}): {e}")
        except Exception as e:
            logger.error(f"CppCheck failed ({src.rel_path}): {e}")

        return findings

    # ------------------------------------------------------------------
    # Flawfinder
    # ------------------------------------------------------------------
    def _run_flawfinder(self, src: SourceFile) -> List[StaticFinding]:
        findings: List[StaticFinding] = []

        try:
            result = subprocess.run(
                [self.flawfinder_path, '--csv', '--context', '--columns', src.abs_path],
                capture_output=True, text=True, timeout=60,
            )
            output = result.stdout
            if not output.strip():
                return findings

            reader = csv.DictReader(io.StringIO(output))
            for row in reader:
                try:
                    line = int(row.get('Line', 0))
                    if line == 0:
                        continue

                    level = int(row.get('Level', row.get('DefaultLevel', 0)))
                    name = row.get('Name', '')
                    warning = row.get('Warning', '')
                    context = row.get('Context', '')

                    # Extract CWE from Warning text or URL field
                    cwe_id = None
                    searchable = ' '.join(
                        str(row.get(k, ''))
                        for k in ('Warning', 'Category', 'Note', 'URL', 'CWEs')
                    )
                    m = re.search(r'CWE-(\d+)', searchable)
                    if not m:
                        # Try extracting from the cwe.mitre.org URL
                        m = re.search(r'definitions/(\d+)', searchable)
                    if m:
                        cwe_id = f"CWE-{m.group(1)}"

                    norm_sev = FLAWFINDER_LEVEL_MAP.get(level, 'LOW')
                    col = int(row.get('Column', 0)) or None

                    findings.append(StaticFinding(
                        tool='flawfinder',
                        rule_id=f"flawfinder:{name}",
                        cwe_id=cwe_id,
                        cwe_name=None,
                        severity=norm_sev,
                        confidence=SEVERITY_CONFIDENCE.get(norm_sev, 0.5),
                        message=warning or f"{name}: {context}",
                        file_path=src.rel_path,
                        line=line,
                        column=col,
                        highlighted_code=context.strip() if context else None,
                    ))
                except (ValueError, KeyError) as e:
                    logger.debug(f"Skipping flawfinder row: {e}")

        except subprocess.TimeoutExpired:
            logger.warning(f"Flawfinder timed out: {src.rel_path}")
        except Exception as e:
            logger.error(f"Flawfinder failed ({src.rel_path}): {e}")

        return findings

    # ------------------------------------------------------------------
    # Semgrep
    # ------------------------------------------------------------------
    def _run_semgrep(self, ingestion_result: IngestionResult) -> List[StaticFinding]:
        """Run Semgrep on the entire extracted codebase."""
        findings: List[StaticFinding] = []
        temp_dir = ingestion_result.temp_dir

        try:
            # Run semgrep with JSON output
            # Use local rules file or fallback to auto if missing
            config_arg = str(SEMGREP_RULES_FILE) if SEMGREP_RULES_FILE.exists() else 'auto'
            result = subprocess.run(
                [
                    self.semgrep_path,
                    '--config', config_arg,
                    '--json',
                    '--quiet',
                    '--no-git-ignore',
                    '--timeout', '120',
                    '--metrics', 'off',  # Disable telemetry
                    temp_dir,
                ],
                capture_output=True, text=True, timeout=180,
                env={**os.environ, 'PYTHONIOENCODING': 'utf-8'},
            )
            
            if not result.stdout.strip():
                return findings

            data = json.loads(result.stdout)
            results = data.get('results', [])

            # Build a mapping of absolute paths to SourceFile objects
            abs_to_src = {
                src.abs_path: src for src in ingestion_result.files
            }

            for r in results:
                path = r.get('path', '')
                start = r.get('start', {})
                line = start.get('line', 0)
                col = start.get('col', None)

                if line == 0:
                    continue

                # Find matching SourceFile
                src = abs_to_src.get(path)
                if not src:
                    # Try to find by matching suffix
                    for abs_path, source in abs_to_src.items():
                        if path.endswith(source.rel_path.replace('\\', '/')):
                            src = source
                            break
                    if not src:
                        continue

                extra = r.get('extra', {})
                severity = extra.get('severity', 'INFO').upper()
                message = extra.get('message', r.get('check_id', 'Semgrep finding'))
                rule_id = r.get('check_id', 'unknown')

                # Extract CWE from metadata
                metadata = extra.get('metadata', {})
                cwe = metadata.get('cwe', [])
                cwe_id = f"CWE-{cwe[0].split('-')[1]}" if cwe and isinstance(cwe, list) and len(cwe) > 0 else None

                # Get highlighted code snippet
                lines_data = r.get('extra', {}).get('lines', '')
                highlighted = lines_data.strip() if lines_data else None

                norm_sev = SEMGREP_SEVERITY_MAP.get(severity, 'LOW')
                findings.append(StaticFinding(
                    tool='semgrep',
                    rule_id=rule_id,
                    cwe_id=cwe_id,
                    cwe_name=None,
                    severity=norm_sev,
                    confidence=SEVERITY_CONFIDENCE.get(norm_sev, 0.7),
                    message=message,
                    file_path=src.rel_path,
                    line=line,
                    column=col,
                    highlighted_code=highlighted,
                ))

        except subprocess.TimeoutExpired:
            logger.warning(f"Semgrep timed out on {temp_dir}")
        except json.JSONDecodeError as e:
            logger.warning(f"Semgrep JSON parse error: {e}")
        except Exception as e:
            logger.error(f"Semgrep failed: {e}")

        return findings

    # ------------------------------------------------------------------
    # Regex pattern matcher
    # ------------------------------------------------------------------
    @staticmethod
    def _run_pattern_matcher(func: FunctionUnit) -> List[StaticFinding]:
        findings: List[StaticFinding] = []
        code = func.code

        for cwe_id, info in C_VULN_PATTERNS.items():
            has_safe = any(
                re.search(p, code, re.IGNORECASE | re.DOTALL)
                for p in info.get('safe_patterns', [])
            )

            for pattern, message in info['patterns']:
                try:
                    matches = list(re.finditer(pattern, code, re.IGNORECASE | re.DOTALL))
                except re.error:
                    logger.debug(f"Regex error in pattern for {cwe_id}: {pattern}")
                    continue

                for match in matches:
                    line_in_func = code[:match.start()].count('\n')
                    abs_line = func.start_line + line_in_func

                    lines = code.split('\n')
                    highlighted = (
                        lines[line_in_func].strip()
                        if line_in_func < len(lines) else None
                    )

                    severity = info['severity']
                    confidence = SEVERITY_CONFIDENCE.get(severity, 0.5)

                    if has_safe:
                        confidence *= 0.6
                        severity = 'LOW'

                    findings.append(StaticFinding(
                        tool='pattern_matcher',
                        rule_id=f"regex:{cwe_id}",
                        cwe_id=cwe_id,
                        cwe_name=info['name'],
                        severity=severity,
                        confidence=round(confidence, 2),
                        message=message,
                        file_path=func.file_rel_path,
                        line=abs_line,
                        highlighted_code=highlighted,
                    ))

        return findings

    # ------------------------------------------------------------------
    # Simple function-level analysis (for CombinedAnalyzer)
    # ------------------------------------------------------------------
    def analyze_batch(
        self,
        functions: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Analyze a list of functions efficiently by batching them.
        Creates temporary files for batch analysis.
        """
        import tempfile
        from src.pipeline.ingestion import SourceFile, FunctionUnit, IngestionResult
        
        # We need mapping back to the dictionary indices
        results = [{'is_vulnerable': False, 'confidence': 0.0, 'severity': 'LOW', 'findings': []} for _ in functions]
        
        if not functions:
            return results

        try:
            # 1. Create a dummy workspace
            temp_dir = tempfile.mkdtemp()
            
            src_files = []
            func_units = []
            
            # Map for restoring later: uid -> list index
            uid_to_idx = {}
            
            for i, func_dict in enumerate(functions):
                # Write code to file
                fname = f"func_{i}.c" if func_dict.get('language') == 'c' else f"func_{i}.cpp"
                fpath = os.path.join(temp_dir, fname)
                
                with open(fpath, 'w', encoding='utf-8') as f:
                    f.write(func_dict['code'])
                
                src = SourceFile(
                    abs_path=fpath,
                    rel_path=fname,
                    language=func_dict.get('language', 'c'),
                    content=func_dict['code'],
                    size=len(func_dict['code'])
                )
                src_files.append(src)
                
                # Assume 1 function per file starting at line 1
                func_name = func_dict.get('function_name', f'unknown_{i}')
                f_unit = FunctionUnit(
                    file_rel_path=fname,
                    file_abs_path=fpath,
                    function_name=func_name,
                    code=func_dict['code'],
                    start_line=1,
                    end_line=func_dict['code'].count('\n') + 1,
                    language=src.language,
                )
                func_units.append(f_unit)
                uid_to_idx[f_unit.uid] = i
            
            mock_ingestion = IngestionResult(
                temp_dir=temp_dir,
                source_zip="",
                files=src_files,
                functions=func_units,
                skipped_files=[]
            )
            
            # 2. Run batch analysis
            static_results = self.analyze(mock_ingestion)
            
            # 3. Map findings back
            for uid, findings in static_results.function_findings.items():
                if not findings or uid not in uid_to_idx:
                    continue
                
                idx = uid_to_idx[uid]
                
                # Deduplicate again just in case
                findings = self._deduplicate(findings)
                
                # Maximum confidence from all findings
                max_confidence = max((f.confidence for f in findings), default=0.0)
                
                # Maximum severity
                severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
                max_severity = max(
                    (f.severity for f in findings),
                    key=lambda s: severity_order.get(s, 0)
                ) if findings else 'LOW'
                
                results[idx] = {
                    'is_vulnerable': len(findings) > 0,
                    'confidence': float(max_confidence),
                    'severity': max_severity,
                    'findings': [
                        {
                            'tool': f.tool,
                            'rule_id': f.rule_id,
                            'cwe_id': f.cwe_id,
                            'cwe_name': f.cwe_name,
                            'severity': f.severity,
                            'confidence': f.confidence,
                            'message': f.message,
                            'line': f.line,
                            'highlighted_code': f.highlighted_code,
                        }
                        for f in findings
                    ]
                }

        finally:
            if 'temp_dir' in locals() and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
                
        return results

    # ------------------------------------------------------------------
    # Mapping & deduplication helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _map_findings_to_functions(
        findings: List[StaticFinding],
        functions: List[FunctionUnit],
    ) -> Dict[str, List[StaticFinding]]:
        """Assign each finding to the function whose line-range contains it."""
        # Build per-file function index
        file_funcs: Dict[str, List[FunctionUnit]] = {}
        for f in functions:
            file_funcs.setdefault(f.file_rel_path, []).append(f)
        for k in file_funcs:
            file_funcs[k].sort(key=lambda x: x.start_line)

        result: Dict[str, List[StaticFinding]] = {f.uid: [] for f in functions}

        for finding in findings:
            candidates = file_funcs.get(finding.file_path, [])
            matched = False
            for func in candidates:
                if func.start_line <= finding.line <= func.end_line:
                    result[func.uid].append(finding)
                    matched = True
                    break
            if not matched and candidates:
                # Assign to nearest function
                nearest = min(candidates, key=lambda f: abs(f.start_line - finding.line))
                result[nearest.uid].append(finding)

        return result

    @staticmethod
    def _deduplicate(findings: List[StaticFinding]) -> List[StaticFinding]:
        """Merge findings where multiple tools flag the same line + CWE."""
        if len(findings) <= 1:
            return findings

        grouped: Dict[Tuple, List[StaticFinding]] = {}
        ungrouped: List[StaticFinding] = []

        for f in findings:
            if f.cwe_id:
                grouped.setdefault((f.line, f.cwe_id), []).append(f)
            else:
                ungrouped.append(f)

        deduped: List[StaticFinding] = []
        for _key, group in grouped.items():
            if len(group) == 1:
                deduped.append(group[0])
            else:
                best = max(group, key=lambda x: x.confidence)
                tools = sorted({g.tool for g in group})
                best.confidence = min(best.confidence + 0.05, 1.0)
                best.message = f"[{', '.join(tools)}] {best.message}"
                best.tool = '+'.join(tools)
                deduped.append(best)

        deduped.extend(ungrouped)
        return sorted(deduped, key=lambda x: x.line)
