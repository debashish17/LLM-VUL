import asyncio
import logging
import tempfile
import uuid
import shutil
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

try:
    from git import Repo
except ImportError:
    Repo = None

from src.parser.code_parser import CodeParser
from src.pipeline.combined_analyzer import CombinedAnalyzer

# Global in-memory storage for jobs and the singleton analyzer
_jobs: Dict[str, Dict[str, Any]] = {}
_analyzer_instance = None

# ─── Per-job log capture ──────────────────────────────────────────────────────
class _JobLogHandler(logging.Handler):
    """Captures log records for a specific job_id into _jobs[job_id]['logs']."""

    def __init__(self, job_id: str):
        super().__init__()
        self.job_id = job_id

    def emit(self, record: logging.LogRecord):
        # Ignore external library / API logs (like uvicorn, fastapi)
        if not record.name.startswith("src."):
            return
            
        job = _jobs.get(self.job_id)
        if job is None:
            return
        ts = datetime.utcfromtimestamp(record.created).strftime('%H:%M:%S')
        # Strip the logger name prefix (e.g. "INFO:src.pipeline.static_analysis:" → message only)
        msg = record.getMessage()
        
        # Map log level names correctly for frontend expectations
        if record.levelname == 'ERROR':
            level = 'ERR'
        elif record.levelname == 'WARNING':
            level = 'WARN'
        elif record.levelname == 'INFO':
            level = 'INFO'
        elif record.levelname == 'DEBUG':
            level = 'DBUG'
        else:
            level = record.levelname[:4]

        job['logs'].append({'ts': ts, 'level': level, 'msg': msg})


def _attach_job_logger(job_id: str) -> _JobLogHandler:
    handler = _JobLogHandler(job_id)
    handler.setLevel(logging.DEBUG)
    # Attach to root so we catch all src.* loggers
    logging.getLogger().addHandler(handler)
    return handler


def _detach_job_logger(handler: _JobLogHandler):
    logging.getLogger().removeHandler(handler)

def get_analyzer():
    """Lazy load the analyzer to avoid importing heavy models at startup."""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = CombinedAnalyzer()
    return _analyzer_instance

def get_job(job_id: str):
    return _jobs.get(job_id)

def create_job() -> str:
    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "job_id": job_id,
        "status": "pending",
        "progress": 0,
        "message": "Initializing...",
        "error": None,
        "static_results": None,
        "ml_results": None,
        "static_summary": None,
        "ml_summary": None,
        "lora_summary": None,
        "ml_model_used": None,
        "report": None,
        "temp_dir": None,
        "logs": [],
    }
    return job_id

def clone_github_repo(repo_url: str, job_id: str) -> Path:
    if Repo is None:
        raise Exception("GitPython is not installed. Please run: pip install GitPython")
    
    temp_dir = Path(tempfile.mkdtemp())
    _jobs[job_id]["temp_dir"] = temp_dir
    repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
    clone_path = temp_dir / repo_name
    
    try:
        Repo.clone_from(repo_url, clone_path, depth=1)
        return clone_path
    except Exception as e:
        raise Exception(f"Failed to clone repository: {str(e)}")

def extract_c_cpp_files(directory: Path, max_files: int = 100) -> List[Path]:
    extensions = {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx'}
    files = []
    for ext in extensions:
        files.extend(directory.rglob(f'*{ext}'))
        if len(files) >= max_files:
            break
    return files[:max_files]

def parse_code_functions(file_paths: List[Path]) -> List[Dict[str, Any]]:
    parser = CodeParser()
    functions = []
    for file_path in file_paths:
        try:
            language = parser.detect_language(str(file_path))
            if not language:
                continue
            parse_result = parser.parse_file(str(file_path), language)
            if not parse_result.get('success'):
                continue
            
            extracted = parser.extract_functions(parse_result)
            for f in extracted:
                if 10 < len(f['code']) < 5000:
                    functions.append({
                        'function_name': f['name'],
                        'code': f['code'],
                        'file_path': str(file_path),
                        'language': language,
                        'line_number': f['start_line']
                    })
        except Exception:
            continue
    return functions

def generate_static_summary(static_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    vuln_count = sum(1 for r in static_results if r['static_vulnerable'])
    safe_count = len(static_results) - vuln_count

    tool_counts: Dict[str, int] = {}
    cwe_frequency: Dict[str, int] = {}

    for r in static_results:
        for finding in r.get('static_findings', []):
            tool = finding.get('tool', 'unknown')
            tool_counts[tool] = tool_counts.get(tool, 0) + 1

        for cwe in r.get('cwe_types', []):
            cwe_frequency[cwe] = cwe_frequency.get(cwe, 0) + 1

    return {
        "total_functions": len(static_results),
        "vulnerable": vuln_count,
        "safe": safe_count,
        "tool_counts": tool_counts,
        "cwe_frequency": cwe_frequency,
    }


def generate_lora_summary(ml_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    vuln_count = sum(1 for r in ml_results if r['ml_vulnerable'])
    safe_count = len(ml_results) - vuln_count
    critical = sum(1 for r in ml_results if r.get('severity') == 'CRITICAL')
    high     = sum(1 for r in ml_results if r.get('severity') == 'HIGH')
    medium   = sum(1 for r in ml_results if r.get('severity') == 'MEDIUM')
    low      = sum(1 for r in ml_results if r.get('severity') == 'LOW')
    avg_conf = (
        sum(r['ml_confidence'] for r in ml_results if r['ml_vulnerable']) / max(vuln_count, 1)
    )
    return {
        "total_functions": len(ml_results),
        "vulnerable": vuln_count,
        "safe": safe_count,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "avg_lora_confidence": round(avg_conf, 4),
    }


def generate_ml_summary(ml_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    vuln_count = sum(1 for r in ml_results if r['ml_vulnerable'])
    safe_count = len(ml_results) - vuln_count
    critical = sum(1 for r in ml_results if r.get('severity') == 'CRITICAL')
    high = sum(1 for r in ml_results if r.get('severity') == 'HIGH')
    medium = sum(1 for r in ml_results if r.get('severity') == 'MEDIUM')
    low = sum(1 for r in ml_results if r.get('severity') == 'LOW')
    avg_conf = (
        sum(r['ml_confidence'] for r in ml_results if r['ml_vulnerable']) / max(vuln_count, 1)
    )

    return {
        "total_functions": len(ml_results),
        "vulnerable": vuln_count,
        "safe": safe_count,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "avg_ml_confidence": avg_conf,
    }


def generate_report(
    static_results: List[Dict[str, Any]],
    ml_results: List[Dict[str, Any]],
    file_paths: List[Path],
    ml_model_used: str = "ensemble",
) -> Dict[str, Any]:
    threshold = ml_results[0].get('ml_threshold', 0.308) if ml_results else 0.308
    static_vulnerable = [r for r in static_results if r['static_vulnerable']]
    ml_vulnerable = [r for r in ml_results if r['ml_vulnerable']]
    model_label = "LoRA CodeBERT" if ml_model_used == "lora" else "Run12 Ensemble"

    return {
        'metadata': {
            'generated_at': datetime.now().isoformat(),
            'model_version': f'{model_label} + Static Analysis',
            'ml_model': ml_model_used,
            'threshold': threshold,
            'total_files_analyzed': len(file_paths),
            'total_functions_analyzed': len(static_results),
        },
        'static_summary': {
            'total_vulnerable': len(static_vulnerable),
            'total_safe': len(static_results) - len(static_vulnerable),
        },
        'ml_summary': {
            'total_vulnerable': len(ml_vulnerable),
            'total_safe': len(ml_results) - len(ml_vulnerable),
        },
        'static_findings': static_vulnerable,
        'ml_findings': ml_vulnerable,
    }

async def run_analysis_task(job_id: str, repo_url: str, max_files: int, threshold: float, ml_model: str = "ensemble"):
    job = _jobs[job_id]
    job["status"] = "processing"
    log_handler = _attach_job_logger(job_id)
    try:
        # Step 1: Load analyzer
        job["message"] = "Loading models..."
        job["progress"] = 10
        analyzer = await asyncio.to_thread(get_analyzer)
        
        # Step 2: Clone Repo
        job["message"] = f"Cloning repository {repo_url}..."
        job["progress"] = 20
        # Offload blocking clone to thread
        clone_path = await asyncio.to_thread(clone_github_repo, repo_url, job_id)
        
        # Step 3: Extract files
        job["message"] = "Extracting C/C++ files..."
        job["progress"] = 40
        c_cpp_files = await asyncio.to_thread(extract_c_cpp_files, clone_path, max_files)
        if not c_cpp_files:
            raise Exception("No C/C++ files found in repository")

        # Step 4: Parse Functions
        job["message"] = f"Parsing {len(c_cpp_files)} files to extract functions..."
        job["progress"] = 60
        functions = await asyncio.to_thread(parse_code_functions, c_cpp_files)
        if not functions:
            raise Exception("No standard functions found in the extracted files")

        # Step 5: Analyze
        job["message"] = f"Running Static + {'LoRA CodeBERT' if ml_model == 'lora' else 'Ensemble'} Analysis..."
        job["progress"] = 80
        analysis = await asyncio.to_thread(analyzer.analyze, functions, threshold, ml_model)
        static_results = analysis['static_results']
        ml_results = analysis['ml_results']
        ml_model_used = analysis['ml_model_used']

        # Step 6: Generate artifacts
        job["message"] = "Generating reports..."
        job["progress"] = 90
        report = generate_report(static_results, ml_results, c_cpp_files, ml_model_used)
        static_summary = generate_static_summary(static_results)

        if ml_model_used == "lora":
            lora_summary = generate_lora_summary(ml_results)
            ml_summary = None
        else:
            ml_summary = generate_ml_summary(ml_results)
            lora_summary = None

        job["static_results"] = static_results
        job["ml_results"] = ml_results
        job["static_summary"] = static_summary
        job["ml_summary"] = ml_summary
        job["lora_summary"] = lora_summary
        job["ml_model_used"] = ml_model_used
        job["report"] = report
        job["status"] = "completed"
        job["progress"] = 100
        job["message"] = "Analysis completed successfully"

    except Exception as e:
        traceback.print_exc()
        job["status"] = "failed"
        job["error"] = str(e)
        job["message"] = "Analysis failed"
    finally:
        _detach_job_logger(log_handler)
        # Cleanup cloned repo to save space
        temp_dir = job.get("temp_dir")
        if temp_dir and temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
