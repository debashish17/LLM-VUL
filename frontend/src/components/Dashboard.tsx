import { useState, useEffect, useRef, useCallback } from 'react';
import type { FormEvent } from 'react';
import { useStartAnalysis, useJobStatus, useJobResults } from '../hooks/useAnalysis';
import { VirtualizedResultList } from './VirtualizedResultList';
import type { ResultMode, StatusFilter, SeverityFilter, MergedResult } from './VirtualizedResultList';
import { cn } from './VirtualizedResultList';
import { api } from '../lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────
interface LogEntry { ts: string; level: string; msg: string; }

// ─── Filter Bar ───────────────────────────────────────────────────────────────
interface FilterBarProps {
  statusFilter: StatusFilter;
  severityFilter: SeverityFilter;
  detectorFilter?: string;
  showSeverity?: boolean;
  showDetector?: boolean;
  onStatusChange: (v: StatusFilter) => void;
  onSeverityChange: (v: SeverityFilter) => void;
  onDetectorChange?: (v: string) => void;
  total: number;
  shown: number;
}

function FilterBar({
  statusFilter, severityFilter, detectorFilter,
  showSeverity = true, showDetector, onStatusChange, onSeverityChange, onDetectorChange,
  total, shown,
}: FilterBarProps) {
  const chip = 'px-3 py-1 text-xs font-600 rounded-full border transition-colors cursor-pointer';
  const active   = 'bg-[var(--accent)] text-white border-[var(--accent)]';
  const inactive = 'bg-white text-[var(--ink-mid)] border-[var(--border)] hover:border-[var(--accent)] hover:text-[var(--accent)]';

  const statusOpts: StatusFilter[]     = ['all', 'vulnerable', 'safe'];
  const severityOpts: SeverityFilter[] = ['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const detectorOpts                   = ['all', 'Both (Static + ML)', 'ML Model', 'Static Analysis'];

  return (
    <div className="flex flex-wrap items-center gap-4 mb-4 pb-4 border-b border-[var(--border)]">
      <div className="flex items-center gap-2">
        <span className="text-[11px] text-[var(--ink-muted)] font-500 uppercase tracking-wide">Status</span>
        <div className="flex gap-1">
          {statusOpts.map(opt => (
            <button key={opt} type="button" className={cn(chip, statusFilter === opt ? active : inactive)} onClick={() => onStatusChange(opt)}>
              {opt === 'all' ? 'All' : opt.charAt(0).toUpperCase() + opt.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {showSeverity && (
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-[var(--ink-muted)] font-500 uppercase tracking-wide">Severity</span>
          <div className="flex gap-1">
            {severityOpts.map(opt => (
              <button key={opt} type="button" className={cn(chip, severityFilter === opt ? active : inactive)} onClick={() => onSeverityChange(opt)}>
                {opt === 'all' ? 'All' : opt}
              </button>
            ))}
          </div>
        </div>
      )}

      {showDetector && onDetectorChange && (
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-[var(--ink-muted)] font-500 uppercase tracking-wide">Detector</span>
          <div className="flex gap-1">
            {detectorOpts.map(opt => (
              <button key={opt} type="button" className={cn(chip, detectorFilter === opt ? active : inactive)} onClick={() => onDetectorChange(opt)}>
                {opt === 'all' ? 'All' : opt.replace('Both (Static + ML)', 'Both').replace('ML Model', 'ML').replace('Static Analysis', 'Static')}
              </button>
            ))}
          </div>
        </div>
      )}

      <span className="ml-auto text-xs text-[var(--ink-muted)]">
        Showing <span className="text-[var(--ink)] font-600">{shown}</span> of {total}
      </span>
    </div>
  );
}

// ─── helpers ─────────────────────────────────────────────────────────────────
function applyStatusFilter(results: MergedResult[], filter: StatusFilter, mlBased = false): MergedResult[] {
  if (filter === 'all') return results;
  const vuln = filter === 'vulnerable';
  return results.filter(r => (mlBased ? (r.ml_vulnerable ?? r.vulnerable) : r.vulnerable) === vuln);
}
function applySeverityFilter(results: MergedResult[], filter: SeverityFilter): MergedResult[] {
  if (filter === 'all') return results;
  return results.filter(r => r.severity === filter);
}
// ─── Tab state ────────────────────────────────────────────────────────────────
interface TabFilters { status: StatusFilter; severity: SeverityFilter; detector: string; }
const DEFAULT_FILTERS: TabFilters = { status: 'all', severity: 'all', detector: 'all' };

type NavTab = 'system' | 'logs';
type ResultTab = ResultMode;

// ─── Stat Card ────────────────────────────────────────────────────────────────
function StatCard({ label, value, sub, variant = 'default' }: {
  label: string;
  value: string | number;
  sub?: string;
  variant?: 'default' | 'danger' | 'success' | 'accent';
}) {
  const valueColor = {
    default: 'text-[var(--ink)]',
    danger:  'text-[var(--danger)]',
    success: 'text-[var(--success)]',
    accent:  'text-[var(--accent)]',
  }[variant];

  const dotColor = {
    default: 'bg-[var(--ink-ghost)]',
    danger:  'bg-[var(--danger)]',
    success: 'bg-[var(--success)]',
    accent:  'bg-[var(--accent)]',
  }[variant];

  return (
    <div className="bg-white border border-[var(--border)] rounded-[var(--radius-lg)] p-5 fade-up">
      <div className="flex items-center gap-2 mb-3">
        <span className={cn('w-2 h-2 rounded-full', dotColor)} />
        <span className="text-[11px] text-[var(--ink-muted)] font-600 uppercase tracking-widest">{label}</span>
      </div>
      <p className={cn('text-3xl font-800 leading-none mb-1', valueColor)}>{value}</p>
      {sub && <p className="text-[11px] text-[var(--ink-muted)] mt-1">{sub}</p>}
    </div>
  );
}

// ─── Log panel ────────────────────────────────────────────────────────────────
function LogPanel({ logs }: { logs: LogEntry[] }) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs.length]);

  const levelStyle = (level: string): string => {
    if (level === 'ERR')  return 'bg-[var(--danger-light)] text-[var(--danger)] border border-[var(--danger-dim)]';
    if (level === 'WARN') return 'bg-[var(--warn-light)] text-[var(--warn)] border border-amber-200';
    if (level === 'OK')   return 'bg-[var(--success-light)] text-[var(--success)] border border-[var(--success-dim)]';
    if (level === 'DBUG') return 'bg-[var(--bg-subtle)] text-[var(--ink-muted)] border border-[var(--border)]';
    return 'bg-[var(--accent-light)] text-[var(--accent)] border border-[var(--accent-dim)]';
  };

  return (
    <div className="bg-white border border-[var(--border)] rounded-[var(--radius-lg)] h-[520px] overflow-y-auto">
      {logs.length === 0 ? (
        <div className="flex items-center justify-center h-full flex-col gap-3 text-[var(--ink-muted)]">
          <div className="w-12 h-12 rounded-full bg-[var(--bg-subtle)] flex items-center justify-center">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <p className="text-sm font-500">No pipeline logs yet</p>
          <p className="text-xs text-[var(--ink-ghost)]">Run a scan to see output here</p>
        </div>
      ) : (
        <div className="p-4 space-y-1 font-['DM_Mono',monospace]">
          {logs.filter(e => e.level !== 'DBUG').map((entry, i) => (
            <div key={i} className="flex items-start gap-3 text-[12px] py-1 px-2 rounded hover:bg-[var(--bg-subtle)] transition-colors">
              <span className="text-[var(--ink-ghost)] shrink-0 w-20 pt-px">{entry.ts}</span>
              <span className={cn('text-[10px] font-600 px-1.5 py-0.5 rounded shrink-0 leading-none mt-px', levelStyle(entry.level))}>
                {entry.level}
              </span>
              <span className="text-[var(--ink-mid)] break-all leading-relaxed">{entry.msg}</span>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
      )}
    </div>
  );
}

// ─── Dashboard ───────────────────────────────────────────────────────────────
export function Dashboard() {
  const [repoUrl, setRepoUrl]   = useState('');
  const [maxFiles, setMaxFiles] = useState(50);
  const [mlModel, setMlModel]   = useState<'ensemble' | 'lora'>('ensemble');
  const [jobId, setJobId]       = useState<string | null>(null);
  const [navTab, setNavTab]     = useState<NavTab>('system');
  const [activeTab, setActiveTab] = useState<ResultTab>('ml');
  const [logs, setLogs]         = useState<LogEntry[]>([]);

  const [mlFilters, setMlFilters] = useState<TabFilters>({ ...DEFAULT_FILTERS });

  const startAnalysis = useStartAnalysis();
  const { data: statusData } = useJobStatus(jobId);
  const isCompleted = statusData?.status === 'completed';
  const { data: resultsData } = useJobResults(jobId, isCompleted);

  const logOffsetRef = useRef(0);
  const pollRef      = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);

  useEffect(() => {
    if (!jobId) return;
    logOffsetRef.current = 0;
    const poll = async () => {
      try {
        const res = await api.getJobLogs(jobId, logOffsetRef.current);
        if (res.logs.length > 0) {
          logOffsetRef.current += res.logs.length;
          setLogs(prev => [...prev, ...res.logs]);
        }
      } catch { /* job may not exist yet */ }
    };
    poll();
    pollRef.current = setInterval(poll, 1500);
    return stopPolling;
  }, [jobId, stopPolling]);

  useEffect(() => {
    if (statusData?.status === 'completed' || statusData?.status === 'failed') {
      if (jobId) api.getJobLogs(jobId, logOffsetRef.current).then(res => {
        if (res.logs.length > 0) setLogs(prev => [...prev, ...res.logs]);
      }).catch(() => {});
      stopPolling();
    }
  }, [statusData?.status, jobId, stopPolling]);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!repoUrl) return;
    const now = new Date();
    const ts  = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`;
    setLogs(prev => [...prev,
      { ts, level: 'INIT', msg: `Scan started: ${repoUrl}` },
      { ts, level: 'INIT', msg: `Options: max-files=${maxFiles} model=${mlModel}` },
    ]);
    startAnalysis.mutate(
      { repo_url: repoUrl, max_files: maxFiles, confidence_threshold: 0.308, ml_model: mlModel },
      { onSuccess: (data) => setJobId(data.job_id) }
    );
  };

  const isAnalyzing = statusData?.status === 'pending' || statusData?.status === 'processing';

  const staticResults  = resultsData?.static_results ?? [];
  const mlResults      = resultsData?.ml_results ?? [];
  const staticSummary  = resultsData?.static_summary;
  const mlSummary      = resultsData?.ml_summary;
  const loraSummary    = resultsData?.lora_summary;
  const mlModelUsed    = resultsData?.ml_model_used ?? mlModel;

  const mergedResults: MergedResult[] = (staticResults.length > 0)
    ? staticResults.map((sr, i) => {
        const mr = mlResults[i];
        const vulnerable = sr.static_vulnerable || (mr?.ml_vulnerable ?? false);
        return { ...sr, ...(mr ?? {}), vulnerable, agreement: false, detector_source: 'None' };
      })
    : [];

  const activeSummary  = mlModelUsed === 'lora' ? loraSummary : mlSummary;
  const total_functions = staticSummary?.total_functions ?? activeSummary?.total_functions ?? 0;
  const summaryVulnerable = mergedResults.filter(r => r.vulnerable).length;
  const avgConf = activeSummary
    ? mlModelUsed === 'lora'
      ? (loraSummary?.avg_lora_confidence ?? 0)
      : (mlSummary?.avg_ml_confidence ?? 0)
    : 0;

  const summary = {
    total_functions,
    vulnerable:   summaryVulnerable,
    safe:         total_functions - summaryVulnerable,
    avg_conf:     avgConf,
  };

  const staticFiltered = mergedResults.filter(r => r.static_vulnerable);
  const mlFiltered     = applySeverityFilter(applyStatusFilter(mergedResults, mlFilters.status, true), mlFilters.severity);

  const mlTabLabel  = mlModelUsed === 'lora' ? 'LoRA Detection' : 'ML Detection';
  const mlTabHeader = mlModelUsed === 'lora'
    ? 'LoRA CodeBERT — QLoRA Adapter · Threshold 0.55'
    : 'Run12 Ensemble: XGBoost · LightGBM · CatBoost — Threshold 0.308';

  const resultTabs: { id: ResultTab; label: string; count: number }[] = [
    { id: 'static', label: 'Static Analysis', count: staticFiltered.length },
    { id: 'ml',     label: mlTabLabel,         count: mergedResults.length },
  ];

  const progress = statusData?.progress ?? 0;

  return (
    <div className="min-h-screen bg-[var(--bg)]">

      {/* ── Header ─────────────────────────────────────────── */}
      <header className="sticky top-0 z-50 bg-white border-b border-[var(--border)] px-6 h-14 flex items-center justify-between shadow-sm">
        <div className="flex items-center gap-8">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-[6px] bg-[var(--accent)] flex items-center justify-center">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <span className="text-[15px] font-700 text-[var(--ink)] tracking-tight">VulnDetect</span>
            <span className="text-[10px] font-600 text-[var(--ink-muted)] bg-[var(--bg-subtle)] border border-[var(--border)] px-1.5 py-0.5 rounded-full">v1.0</span>
          </div>

          <nav className="hidden md:flex gap-1">
            {(['system', 'logs'] as NavTab[]).map(tab => (
              <button
                key={tab}
                type="button"
                onClick={() => setNavTab(tab)}
                className={cn(
                  'px-3.5 py-1.5 rounded-[var(--radius)] text-sm font-500 transition-colors relative',
                  navTab === tab
                    ? 'bg-[var(--accent-light)] text-[var(--accent)] font-600'
                    : 'text-[var(--ink-mid)] hover:text-[var(--ink)] hover:bg-[var(--bg-subtle)]'
                )}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
                {tab === 'logs' && logs.length > 0 && (
                  <span className="ml-1.5 text-[10px] bg-[var(--accent)] text-white px-1.5 py-0.5 rounded-full font-600 leading-none">
                    {logs.length}
                  </span>
                )}
              </button>
            ))}
          </nav>
        </div>

        <div className="flex items-center gap-3 text-xs">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--success)] pulse-dot" />
            <span className="text-[var(--ink-muted)] font-500">Online</span>
          </div>
          <div className="w-px h-4 bg-[var(--border)]" />
          <span className="text-[var(--ink-muted)] font-500 hidden lg:block">
            {mlModelUsed === 'lora' ? 'LoRA CodeBERT' : 'Run12 Ensemble'}
          </span>
        </div>
      </header>

      {/* ── Main content ─────────────────────────────────────────── */}
      <main className="max-w-5xl mx-auto px-4 py-8 space-y-6">

        {/* ── SYSTEM tab ─────────────────────────────────────────── */}
        {navTab === 'system' && (
          <>
            {/* Hero section */}
            <section className="fade-up">
              <h1 className="text-2xl font-800 text-[var(--ink)] tracking-tight mb-1">
                Vulnerability Detection
              </h1>
              <p className="text-[var(--ink-muted)] text-sm">
                Static analysis + ML models scanning your repository for security vulnerabilities.
              </p>
              <div className="flex flex-wrap gap-2 mt-3">
                {['CppCheck', 'Flawfinder', 'Semgrep', mlModel === 'lora' ? 'LoRA CodeBERT' : 'Run12 Ensemble'].map(tool => (
                  <span key={tool} className="text-[11px] font-600 text-[var(--ink-mid)] bg-white border border-[var(--border)] px-2.5 py-1 rounded-full">
                    {tool}
                  </span>
                ))}
              </div>
            </section>

            {/* Scan form */}
            <section className="bg-white border border-[var(--border)] rounded-[var(--radius-lg)] p-6 shadow-sm fade-up fade-up-1">
              <h2 className="text-sm font-700 text-[var(--ink)] mb-4">Scan Repository</h2>

              <form onSubmit={handleSubmit} className="space-y-4">
                {/* URL input */}
                <div>
                  <label className="block text-xs font-600 text-[var(--ink-mid)] uppercase tracking-wide mb-1.5">
                    Repository URL
                  </label>
                  <input
                    type="url"
                    value={repoUrl}
                    onChange={e => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/owner/repo"
                    className="w-full h-10 px-3.5 bg-[var(--bg-subtle)] border border-[var(--border)] rounded-[var(--radius)] text-sm text-[var(--ink)] placeholder:text-[var(--ink-ghost)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)] focus:border-transparent transition-shadow font-['DM_Mono',monospace]"
                    required
                    disabled={isAnalyzing}
                  />
                </div>

                {/* Options row */}
                <div className="flex flex-wrap gap-4 items-end">
                  <div>
                    <label className="block text-xs font-600 text-[var(--ink-mid)] uppercase tracking-wide mb-1.5">
                      Max Files
                    </label>
                    <input
                      type="number"
                      min="10"
                      max="1000"
                      value={maxFiles}
                      onChange={e => setMaxFiles(parseInt(e.target.value))}
                      className="h-10 w-24 px-3 bg-[var(--bg-subtle)] border border-[var(--border)] rounded-[var(--radius)] text-sm text-[var(--ink)] text-center focus:outline-none focus:ring-2 focus:ring-[var(--accent)] focus:border-transparent transition-shadow font-['DM_Mono',monospace]"
                      disabled={isAnalyzing}
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-600 text-[var(--ink-mid)] uppercase tracking-wide mb-1.5">
                      ML Model
                    </label>
                    <div className="flex gap-1 h-10 items-center bg-[var(--bg-subtle)] border border-[var(--border)] rounded-[var(--radius)] p-1">
                      {(['ensemble', 'lora'] as const).map(m => (
                        <button
                          key={m}
                          type="button"
                          disabled={isAnalyzing}
                          onClick={() => setMlModel(m)}
                          className={cn(
                            'px-3 h-full rounded-[5px] text-xs font-600 transition-all',
                            mlModel === m
                              ? 'bg-white text-[var(--ink)] shadow-sm'
                              : 'text-[var(--ink-muted)] hover:text-[var(--ink)]'
                          )}
                        >
                          {m === 'ensemble' ? 'Ensemble' : 'LoRA CodeBERT'}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="ml-auto">
                    <button
                      type="submit"
                      disabled={isAnalyzing || !repoUrl}
                      className="h-10 px-6 bg-[var(--accent)] text-white font-600 text-sm rounded-[var(--radius)] hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors shadow-sm"
                    >
                      {isAnalyzing ? (
                        <span className="flex items-center gap-2">
                          <svg className="animate-spin w-3.5 h-3.5" viewBox="0 0 24 24" fill="none">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                          </svg>
                          Scanning…
                        </span>
                      ) : 'Run Scan'}
                    </button>
                  </div>
                </div>
              </form>

              {/* Progress */}
              {statusData && !isCompleted && statusData.status !== 'failed' && (
                <div className="mt-5 pt-5 border-t border-[var(--border)] space-y-3">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-[var(--ink-mid)] font-500">
                      {statusData.status === 'pending' ? 'Connecting to repository…' : statusData.message}
                    </span>
                    <span className="text-[var(--ink)] font-600 font-['DM_Mono',monospace]">{Math.round(progress)}%</span>
                  </div>
                  <div className="h-1.5 bg-[var(--bg-subtle)] rounded-full overflow-hidden">
                    <div
                      className="h-full bg-[var(--accent)] rounded-full transition-all duration-500"
                      style={{ width: `${Math.round(progress)}%` }}
                    />
                  </div>
                </div>
              )}

              {statusData?.status === 'failed' && (
                <div className="mt-5 pt-5 border-t border-[var(--border)] flex items-start gap-2.5 bg-[var(--danger-light)] rounded-[var(--radius)] p-3">
                  <svg className="w-4 h-4 text-[var(--danger)] shrink-0 mt-px" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" />
                    <line x1="12" y1="8" x2="12" y2="12" />
                    <line x1="12" y1="16" x2="12.01" y2="16" />
                  </svg>
                  <p className="text-sm text-[var(--danger)] font-500">{statusData.error || statusData.message}</p>
                </div>
              )}
            </section>

            {/* Results */}
            {isCompleted && resultsData && (
              <section className="space-y-5 fade-up fade-up-2">
                {/* Stat cards */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <StatCard label="Functions"   value={summary.total_functions} variant="default" />
                  <StatCard label="Vulnerable"  value={summary.vulnerable}      variant="danger"
                    sub={`${summary.total_functions > 0 ? Math.round(summary.vulnerable / summary.total_functions * 100) : 0}% of total`} />
                  <StatCard label="Safe"        value={summary.safe}            variant="success" />
                  <StatCard label="Avg Confidence" value={`${(summary.avg_conf * 100).toFixed(1)}%`} variant="accent"
                    sub={mlModelUsed === 'lora' ? 'LoRA · vuln only' : 'Ensemble · vuln only'} />
                </div>

                {/* Results tabs */}
                <div className="bg-white border border-[var(--border)] rounded-[var(--radius-lg)] overflow-hidden shadow-sm">
                  <div className="flex border-b border-[var(--border)] bg-[var(--bg-subtle)] px-1 pt-1 gap-1">
                    {resultTabs.map(tab => (
                      <button
                        key={tab.id}
                        type="button"
                        onClick={() => setActiveTab(tab.id)}
                        className={cn(
                          'px-4 py-2 text-sm font-500 rounded-t-[var(--radius)] transition-colors relative -mb-px border border-transparent',
                          activeTab === tab.id
                            ? 'bg-white text-[var(--ink)] font-600 border-[var(--border)] border-b-white'
                            : 'text-[var(--ink-mid)] hover:text-[var(--ink)] hover:bg-white/60'
                        )}
                      >
                        {tab.label}
                        <span className={cn(
                          'ml-2 text-[10px] font-600 px-1.5 py-0.5 rounded-full',
                          activeTab === tab.id
                            ? 'bg-[var(--accent-light)] text-[var(--accent)]'
                            : 'bg-[var(--bg-subtle)] text-[var(--ink-muted)]'
                        )}>
                          {tab.count}
                        </span>
                      </button>
                    ))}
                  </div>

                  <div className="p-5">
                    {activeTab === 'static' && (
                      <>
                        <p className="text-xs text-[var(--ink-muted)] mb-4 font-500">
                          CppCheck · Flawfinder · Semgrep — Vulnerable functions only
                        </p>
                        <VirtualizedResultList results={staticFiltered} mode="static" />
                      </>
                    )}

                    {activeTab === 'ml' && (
                      <>
                        <p className="text-xs text-[var(--ink-muted)] mb-4 font-500">{mlTabHeader}</p>
                        <FilterBar
                          statusFilter={mlFilters.status}
                          severityFilter={mlFilters.severity}
                          showSeverity={mlFilters.status !== 'safe'}
                          onStatusChange={v => setMlFilters(f => ({ ...f, status: v }))}
                          onSeverityChange={v => setMlFilters(f => ({ ...f, severity: v }))}
                          total={mergedResults.length}
                          shown={mlFiltered.length}
                        />
                        <VirtualizedResultList results={mlFiltered} mode="ml" mlModelUsed={mlModelUsed} />
                      </>
                    )}
                  </div>
                </div>
              </section>
            )}
          </>
        )}

        {/* ── LOGS tab ───────────────────────────────────────────── */}
        {navTab === 'logs' && (
          <section className="space-y-4 fade-up">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-700 text-[var(--ink)]">Pipeline Logs</h2>
                <p className="text-xs text-[var(--ink-muted)] mt-0.5">{logs.length} entries</p>
              </div>
              {logs.length > 0 && (
                <button
                  type="button"
                  onClick={() => setLogs([])}
                  className="text-xs text-[var(--ink-muted)] border border-[var(--border)] px-3 py-1.5 rounded-[var(--radius)] hover:border-[var(--danger-dim)] hover:text-[var(--danger)] transition-colors font-500"
                >
                  Clear logs
                </button>
              )}
            </div>
            <LogPanel logs={logs} />
          </section>
        )}

      </main>
    </div>
  );
}
