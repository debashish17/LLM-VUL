export interface AnalyzeRequest {
  repo_url: string;
  max_files: number;
  confidence_threshold: number;
  ml_model: 'ensemble' | 'lora';
}

export interface JobStatusResponse {
  job_id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  progress: number;
  message: string;
  error?: string;
}

export interface StaticFinding {
  tool: string;
  message: string;
  severity: string;
  cwe_id: string;
  cwe_name: string;
}

export interface StaticFunctionResult {
  function_name: string;
  file_path: string;
  line_number: number | string;
  code: string;
  code_snippet: string;
  static_vulnerable: boolean;
  static_confidence: number;
  static_findings: StaticFinding[];
  cwe_types: string[];
}

export interface MLFunctionResult {
  function_name: string;
  file_path: string;
  line_number: number | string;
  code: string;
  code_snippet: string;
  ml_vulnerable: boolean;
  ml_confidence: number;
  severity: string;
  individual_models: Record<string, number>;
  ml_threshold: number;
}

export interface LoRASummary {
  total_functions: number;
  vulnerable: number;
  safe: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  avg_lora_confidence: number;
}

export interface StaticSummary {
  total_functions: number;
  vulnerable: number;
  safe: number;
  tool_counts: Record<string, number>;
  cwe_frequency: Record<string, number>;
}

export interface MLSummary {
  total_functions: number;
  vulnerable: number;
  safe: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  avg_ml_confidence: number;
}

export interface AnalysisResultsResponse {
  job_id: string;
  status: string;
  ml_model_used: 'ensemble' | 'lora' | null;
  static_summary: StaticSummary | null;
  ml_summary: MLSummary | null;
  lora_summary: LoRASummary | null;
  static_results: StaticFunctionResult[] | null;
  ml_results: MLFunctionResult[] | null;
  report: Record<string, any> | null;
}
