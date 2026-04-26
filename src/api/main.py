import sys
from pathlib import Path
import logging

# Add the project root strictly to path before imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from src.api.models import (
    AnalyzeRequest, JobStatusResponse, AnalysisResultsResponse,
    StaticSummary, MLSummary, LoRASummary
)
from src.api.services import create_job, get_job, run_analysis_task

logging.basicConfig(level=logging.INFO)
# Silence noisy third-party debug loggers
for _noisy in ('httpcore', 'httpx', 'graphviz', 'matplotlib', 'bitsandbytes', 'git'):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="LLM-VUL API",
    description="FastAPI Backend for Vulnerability Detection",
    version="1.0"
)

# CORS configuration to allow local React development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    """Simple API status and model liveness check."""
    return {"status": "ok", "api": "online"}

@app.post("/api/analyze/github", response_model=JobStatusResponse)
async def map_github_repo(request: AnalyzeRequest, background_tasks: BackgroundTasks):
    """Clone a GitHub repository and initiate static + ML analysis."""
    job_id = create_job()
    logger.info(f"Created job {job_id} for repo: {request.repo_url}")
    
    # Push the heavily synchronous processing to the background
    background_tasks.add_task(
        run_analysis_task,
        job_id,
        request.repo_url,
        request.max_files,
        request.confidence_threshold,
        request.ml_model,
    )
    
    return JobStatusResponse(
        job_id=job_id,
        status="pending",
        progress=0,
        message="Job queued for processing",
        error=None
    )

@app.get("/api/analyze/status/{job_id}", response_model=JobStatusResponse)
def get_job_status(job_id: str):
    """Poll the parsing and analysis progress."""
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
        
    return JobStatusResponse(
        job_id=job_id,
        status=job["status"],
        progress=job["progress"],
        message=job["message"],
        error=job.get("error")
    )

@app.get("/api/analyze/logs/{job_id}")
def get_job_logs(job_id: str, since: int = 0):
    """Return pipeline log entries for a job, optionally offset by 'since' index."""
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    logs = job.get("logs", [])
    return {"job_id": job_id, "logs": logs[since:], "total": len(logs)}

@app.get("/api/analyze/results/{job_id}", response_model=AnalysisResultsResponse)
def get_job_results(job_id: str):
    """Retrieve full analysis summary and mapped vulnerabilities."""
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
        
    if job["status"] not in ["completed", "failed"]:
        raise HTTPException(status_code=400, detail="Job is not finished yet. Keep polling.")
        
    if job["status"] == "failed":
        raise HTTPException(status_code=500, detail=f"Job failed: {job.get('error')}")

    return AnalysisResultsResponse(
        job_id=job_id,
        status=job["status"],
        ml_model_used=job.get("ml_model_used"),
        static_summary=StaticSummary(**job["static_summary"]) if job.get("static_summary") else None,
        ml_summary=MLSummary(**job["ml_summary"]) if job.get("ml_summary") else None,
        lora_summary=LoRASummary(**job["lora_summary"]) if job.get("lora_summary") else None,
        static_results=job.get("static_results"),
        ml_results=job.get("ml_results"),
        report=job.get("report"),
    )
