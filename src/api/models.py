from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class AnalyzeRequest(BaseModel):
    repo_url: str
    max_files: int = Field(default=1000, description="Maximum number of C/C++ files to scan")
    confidence_threshold: float = Field(default=0.308, description="Threshold for ML Model confidence (0.0 - 1.0)")
    ml_model: str = Field(default="ensemble", description="ML model to use: 'ensemble' or 'lora'")

class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    progress: int
    message: str
    error: Optional[str] = None

class StaticFinding(BaseModel):
    tool: str
    message: str
    severity: str
    cwe_id: str
    cwe_name: str

class StaticFunctionResult(BaseModel):
    function_name: str
    file_path: str
    line_number: Any
    code: str
    code_snippet: str
    static_vulnerable: bool
    static_confidence: float
    static_findings: List[StaticFinding]
    cwe_types: List[str]

class MLFunctionResult(BaseModel):
    function_name: str
    file_path: str
    line_number: Any
    code: str
    code_snippet: str
    ml_vulnerable: bool
    ml_confidence: float
    severity: str
    individual_models: Dict[str, float]
    ml_threshold: float

class LoRASummary(BaseModel):
    total_functions: int
    vulnerable: int
    safe: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    avg_lora_confidence: float

class StaticSummary(BaseModel):
    total_functions: int
    vulnerable: int
    safe: int
    tool_counts: Dict[str, int]
    cwe_frequency: Dict[str, int]

class MLSummary(BaseModel):
    total_functions: int
    vulnerable: int
    safe: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    avg_ml_confidence: float

class AnalysisResultsResponse(BaseModel):
    job_id: str
    status: str
    ml_model_used: Optional[str] = None
    static_summary: Optional[StaticSummary] = None
    ml_summary: Optional[MLSummary] = None
    lora_summary: Optional[LoRASummary] = None
    static_results: Optional[List[Dict[str, Any]]] = None
    ml_results: Optional[List[Dict[str, Any]]] = None
    report: Optional[Dict[str, Any]] = None
