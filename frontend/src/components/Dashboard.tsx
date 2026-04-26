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
  const btnBase = 'px-3 py-1 text-xs font-bold uppercase tracking-wider border transition-none cursor-crosshair';
  const active   = 'bg-[#ff8c00] text-[#131313] border-[#ff8c00]';
  const inactive = 'bg-transparent text-[#a48c7a] border-[#a48c7a]/30 hover:border-[#ff8c00] hover:text-[#ff8c00]';

  const statusOpts: StatusFilter[]     = ['all', 'vulnerable', 'safe'];
  const severityOpts: SeverityFilter[] = ['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const detectorOpts                   = ['all', 'Both (Static + ML)', 'ML Model', 'Static Analysis'];

  return (
    <div className="flex flex-wrap items-center gap-4 mb-4 pb-4 border-b border-[#a48c7a]/20">
      <div className="flex items-center gap-2">
        <span className="text-[10px] text-[#a48c7a] uppercase tracking-widest mr-1">--STATUS=</span>
        <div className="flex gap-1">
          {statusOpts.map(opt => (
            <button key={opt} type="button" className={cn(btnBase, statusFilter === opt ? active : inactive)} onClick={() => onStatusChange(opt)}>
              {opt === 'all' ? 'ALL' : opt.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {showSeverity && (
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-[#a48c7a] uppercase tracking-widest mr-1">--SEVERITY=</span>
          <div className="flex gap-1">
            {severityOpts.map(opt => (
              <button key={opt} type="button" className={cn(btnBase, severityFilter === opt ? active : inactive)} onClick={() => onSeverityChange(opt)}>
                {opt === 'all' ? 'ALL' : opt}
              </button>
            ))}
          </div>
        </div>
      )}

      {showDetector && onDetectorChange && (
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-[#a48c7a] uppercase tracking-widest mr-1">--DETECTOR=</span>
          <div className="flex gap-1">
            {detectorOpts.map(opt => (
              <button key={opt} type="button" className={cn(btnBase, detectorFilter === opt ? active : inactive)} onClick={() => onDetectorChange(opt)}>
                {opt === 'all' ? 'ALL' : opt.replace('Both (Static + ML)', 'BOTH').replace('ML Model', 'ML').replace('Static Analysis', 'STATIC')}
              </button>
            ))}
          </div>
        </div>
      )}

      <span className="ml-auto text-[10px] text-[#a48c7a] uppercase tracking-wider">
        SHOWING <span className="text-[#ff8c00] font-bold">{shown}</span>/{total}
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
function applyDetectorFilter(results: MergedResult[], filter: string): MergedResult[] {
  if (filter === 'all') return results;
  return results.filter(r => r.detector_source === filter);
}

// ─── Tab state ────────────────────────────────────────────────────────────────
interface TabFilters { status: StatusFilter; severity: SeverityFilter; detector: string; }
const DEFAULT_FILTERS: TabFilters = { status: 'all', severity: 'all', detector: 'all' };

type NavTab = 'system' | 'logs';
type ResultTab = ResultMode;

// ─── Stat Card ────────────────────────────────────────────────────────────────
function StatCard({ label, value, sub, accent }: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div className="bg-[#1c1b1b] border border-[#a48c7a]/25 p-4 relative">
      <span className="absolute top-0 left-0 text-[#ff8c00]/40 text-xs leading-none select-none">┌</span>
      <span className="absolute top-0 right-0 text-[#ff8c00]/40 text-xs leading-none select-none">┐</span>
      <span className="absolute bottom-0 left-0 text-[#ff8c00]/40 text-xs leading-none select-none">└</span>
      <span className="absolute bottom-0 right-0 text-[#ff8c00]/40 text-xs leading-none select-none">┘</span>
      <p className="text-[10px] uppercase tracking-widest text-[#a48c7a] mb-2">{label}</p>
      <p className={cn('text-3xl font-black', accent ?? 'text-[#ffb77d]')}>{value}</p>
      {sub && <p className="text-[10px] text-[#a48c7a] mt-1 uppercase">{sub}</p>}
    </div>
  );
}

// ─── Log panel ────────────────────────────────────────────────────────────────
function LogPanel({ logs }: { logs: LogEntry[] }) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs.length]);

  const levelColor = (level: string) => {
    if (level === 'ERR')  return 'text-red-400';
    if (level === 'WARN') return 'text-[#ffb77d]';
    if (level === 'OK')   return 'text-[#39ff14]';
    if (level === 'DBUG') return 'text-gray-400';
    return 'text-[#ff8c00]';
  };

  return (
    <div className="bg-[#0a0a0a] border border-[#a48c7a]/20 h-130 overflow-y-auto p-4 font-mono text-xs relative">
      <span className="absolute top-0 left-0 text-[#ff8c00]/30 text-xs leading-none select-none">┌</span>
      <span className="absolute top-0 right-0 text-[#ff8c00]/30 text-xs leading-none select-none">┐</span>
      <span className="absolute bottom-0 left-0 text-[#ff8c00]/30 text-xs leading-none select-none">└</span>
      <span className="absolute bottom-0 right-0 text-[#ff8c00]/30 text-xs leading-none select-none">┘</span>

      {logs.length === 0 ? (
        <div className="flex items-center gap-2 text-[#a48c7a]/50 h-full justify-center flex-col uppercase tracking-widest">
          <p className="text-2xl text-[#ff8c00]/20">{'>'}_</p>
          <p>// NO_PIPELINE_LOGS_YET</p>
          <p className="text-[9px]">run a scan to see output</p>
        </div>
      ) : (
        <div className="space-y-0.5">
          {logs.filter(entry => entry.level !== 'DBUG').map((entry, i) => (
            <div key={i} className="flex items-start gap-3 leading-relaxed hover:bg-[#ff8c00]/5 px-1">
              <span className="text-[#a48c7a]/50 shrink-0 w-20">{entry.ts}</span>
              <span className={cn('font-black shrink-0 w-10', levelColor(entry.level))}>
                [{entry.level}]
              </span>
              <span className="text-[#ffb77d]/80 break-all">{entry.msg}</span>
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

  // ── Poll backend logs while job is running ────────────────────────────────
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

  // Stop polling once the job finishes
  useEffect(() => {
    if (statusData?.status === 'completed' || statusData?.status === 'failed') {
      // One final fetch to catch any trailing log lines
      if (jobId) api.getJobLogs(jobId, logOffsetRef.current).then(res => {
        if (res.logs.length > 0) setLogs(prev => [...prev, ...res.logs]);
      }).catch(() => {});
      stopPolling();
    }
  }, [statusData?.status, jobId, stopPolling]);

  // Add a log entry when scan starts
  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!repoUrl) return;
    const now = new Date();
    const ts  = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`;
    setLogs(prev => [...prev,
      { ts, level: 'INIT', msg: `Scan started: ${repoUrl}` },
      { ts, level: 'INIT', msg: `Options: --max-files=${maxFiles} --model=${mlModel}` },
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

  // Merge static + ml results for rendering (keyed by index — same order guaranteed)
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

  const mlTabLabel = mlModelUsed === 'lora' ? 'LORA_DETECT' : 'ML_DETECT';
  const mlTabHeader = mlModelUsed === 'lora'
    ? '// LORA CODEBERT — QLORA ADAPTER · THRESHOLD 0.55'
    : '// RUN12 ENSEMBLE: XGBOOST · LIGHTGBM · CATBOOST — THRESHOLD 0.308';

  const resultTabs: { id: ResultTab; label: string; count: number }[] = [
    { id: 'static', label: 'STATIC',    count: staticFiltered.length },
    { id: 'ml',     label: mlTabLabel,  count: mergedResults.length },
  ];

  const cliCmd = repoUrl
    ? `analyze --repo ${repoUrl} --max-files ${maxFiles} --model ${mlModel}`
    : `analyze --repo <url> --max-files ${maxFiles} --model ${mlModel}`;

  return (
    <div className="min-h-screen bg-[#131313] font-mono">

      {/* ── Header ─────────────────────────────────────────────── */}
      <header className="sticky top-0 z-50 bg-[#131313] border-b border-[#a48c7a]/25 px-6 py-2 flex items-center justify-between">
        <div className="flex items-center gap-6">
          <span className="text-[#ff8c00] font-black text-lg tracking-tighter uppercase">
            VULNDETECT_SYS<span className="text-[#a48c7a]">_v1.0</span>
          </span>
          <nav className="hidden md:flex gap-0 text-xs uppercase tracking-widest">
            {(['system', 'logs'] as NavTab[]).map(tab => (
              <button
                key={tab}
                type="button"
                onClick={() => setNavTab(tab)}
                className={cn(
                  'px-5 py-1.5 transition-none border-b-2',
                  navTab === tab
                    ? 'text-[#ff8c00] border-[#ff8c00]'
                    : 'text-[#a48c7a] border-transparent hover:text-[#ff8c00]'
                )}
              >
                {tab.toUpperCase()}
                {tab === 'logs' && logs.length > 0 && (
                  <span className="ml-1.5 text-[9px] bg-[#ff8c00] text-[#131313] px-1 font-black">{logs.length}</span>
                )}
              </button>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-4 text-[10px] text-[#a48c7a] uppercase tracking-widest">
          <span>[ STATUS: <span className="text-[#ff8c00]">ONLINE</span> ]</span>
          <span className="hidden lg:block">[ MODEL: <span className="text-[#ff8c00]">{mlModelUsed === 'lora' ? 'LORA_CODEBERT' : 'RUN12_ENSEMBLE'}</span> ]</span>
        </div>
      </header>

      {/* ── Main content ─────────────────────────────────────────── */}
      <main className="max-w-5xl mx-auto px-3 py-6 space-y-6">

        {/* ── SYSTEM tab ─────────────────────────────────────────── */}
        {navTab === 'system' && (
          <>
            {/* ASCII banner */}
            <section>
              <pre className="text-[7px] md:text-[9px] leading-none text-[#ff8c00] select-none overflow-x-auto">
{`██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██████╗ ███████╗████████╗███████╗ ██████╗████████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
██║   ██║██║   ██║██║     ██╔██╗ ██║██║  ██║█████╗     ██║   █████╗  ██║        ██║
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝  `}
              </pre>
              <div className="mt-3 flex flex-wrap gap-4 text-[10px] uppercase tracking-widest text-[#a48c7a]">
                <span>[ STATUS: <span className="text-[#ff8c00]">OPERATIONAL</span> ]</span>
                <span>[ DETECTORS: <span className="text-[#ff8c00]">CPPCHECK · FLAWFINDER · SEMGREP · {mlModel === 'lora' ? 'LORA_CODEBERT' : 'RUN12_ENSEMBLE'}</span> ]</span>
                <span>[ THREAT_LEVEL: <span className="text-red-400">CRITICAL</span> ]</span>
              </div>
            </section>

            {/* Command input */}
            <section className="bg-[#0e0e0e] border border-[#ff8c00]/30 p-4 relative">
              <span className="absolute top-0 left-0 text-[#ff8c00]/30 text-xs select-none">┌</span>
              <span className="absolute top-0 right-0 text-[#ff8c00]/30 text-xs select-none">┐</span>
              <span className="absolute bottom-0 left-0 text-[#ff8c00]/30 text-xs select-none">└</span>
              <span className="absolute bottom-0 right-0 text-[#ff8c00]/30 text-xs select-none">┘</span>

              <form onSubmit={handleSubmit} className="space-y-3">
                <div className="flex items-center gap-3 text-sm">
                  <span className="text-[#a48c7a] shrink-0 select-none">user@vulndetect:~$</span>
                  <input
                    type="url"
                    value={repoUrl}
                    onChange={e => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/owner/repo"
                    className="flex-1 bg-transparent border-none outline-none text-[#ffb77d] placeholder:text-[#a48c7a]/40 font-mono text-sm caret-[#ff8c00]"
                    required
                    disabled={isAnalyzing}
                  />
                  {!repoUrl && <span className="term-cursor text-transparent select-none"> </span>}
                </div>

                <div className="flex items-center gap-4 text-[11px] text-[#a48c7a] pl-45 flex-wrap">
                  <span className="text-[#ff8c00]/60">--max-files=</span>
                  <input
                    type="number"
                    min="10"
                    max="1000"
                    value={maxFiles}
                    onChange={e => setMaxFiles(parseInt(e.target.value))}
                    className="bg-transparent border-b border-[#ff8c00]/40 outline-none text-[#ffb77d] font-mono text-xs w-16 text-center caret-[#ff8c00]"
                    disabled={isAnalyzing}
                    title="Max files"
                    placeholder="50"
                  />
                  <span className="text-[#a48c7a]/40">--threshold=auto</span>
                  <button
                    type="submit"
                    disabled={isAnalyzing || !repoUrl}
                    className="ml-auto bg-[#ff8c00] text-[#131313] font-black text-xs uppercase px-6 py-1.5 tracking-widest hover:bg-[#ffb77d] disabled:opacity-30 disabled:cursor-not-allowed transition-none"
                  >
                    {isAnalyzing ? 'SCANNING...' : 'EXECUTE_SCAN ▶'}
                  </button>
                </div>

                <div className="flex items-center gap-3 text-[11px] text-[#a48c7a] pl-45 flex-wrap">
                  <span className="text-[#ff8c00]/60">--model=</span>
                  <div className="flex gap-1">
                    {(['ensemble', 'lora'] as const).map(m => (
                      <button
                        key={m}
                        type="button"
                        disabled={isAnalyzing}
                        onClick={() => setMlModel(m)}
                        className={cn(
                          'px-3 py-0.5 text-[10px] font-black uppercase tracking-wider border transition-none',
                          mlModel === m
                            ? 'bg-[#ff8c00] text-[#131313] border-[#ff8c00]'
                            : 'bg-transparent text-[#a48c7a] border-[#a48c7a]/30 hover:border-[#ff8c00] hover:text-[#ff8c00]'
                        )}
                      >
                        {m === 'ensemble' ? 'ENSEMBLE' : 'LORA_CODEBERT'}
                      </button>
                    ))}
                  </div>
                  <span className="text-[#a48c7a]/40">
                    {mlModel === 'ensemble' ? '// run12 xgb·lgbm·catboost' : '// qlora codebert adapter'}
                  </span>
                </div>

                {repoUrl && (
                  <div className="text-[10px] text-[#a48c7a]/50 pl-45 pt-1 font-mono">
                    $ {cliCmd}
                  </div>
                )}
              </form>

              {/* Progress */}
              {statusData && !isCompleted && statusData.status !== 'failed' && (
                <div className="mt-4 pt-4 border-t border-[#a48c7a]/20 space-y-1 font-mono text-xs">
                  <div className="text-[#a48c7a]">
                    <span className="text-[#ff8c00]">[INIT]</span> Connecting to repository...
                  </div>
                  {statusData.status === 'processing' && (
                    <div className="text-[#a48c7a]">
                      <span className="text-[#ff8c00]">[PROC]</span> {statusData.message}
                    </div>
                  )}
                  <div className="flex items-center gap-3 mt-2">
                    <span className="text-[#a48c7a] text-[10px] shrink-0 w-8">{Math.round(statusData.progress)}%</span>
                    <div className="flex-1 h-px bg-[#2a2a2a] relative overflow-hidden">
                      <div
                        className={`h-full bg-[#ff8c00] transition-all duration-500 w-[${Math.round(statusData.progress)}%]`}
                      />
                    </div>
                    <span className="term-cursor text-transparent select-none"> </span>
                  </div>
                </div>
              )}

              {statusData?.status === 'failed' && (
                <div className="mt-4 pt-4 border-t border-red-500/30 text-xs font-mono text-red-400">
                  <span className="text-red-500">[ERR]</span> {statusData.error || statusData.message}
                </div>
              )}
            </section>

            {/* Results */}
            {isCompleted && resultsData && (
              <section className="space-y-6">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <StatCard label="TOTAL_FUNCS"  value={summary.total_functions} />
                  <StatCard label="VULNERABLE"   value={summary.vulnerable}      accent="text-red-400"
                    sub={`${summary.total_functions > 0 ? Math.round(summary.vulnerable / summary.total_functions * 100) : 0}% OF TOTAL`} />
                  <StatCard label="SAFE"         value={summary.safe}            accent="text-[#39ff14]" />
                  <StatCard label="AVG_CONFIDENCE" value={`${(summary.avg_conf * 100).toFixed(1)}%`} accent="text-[#ffb77d]" sub={mlModelUsed === 'lora' ? 'LORA · VULN ONLY' : 'ENSEMBLE · VULN ONLY'} />
                </div>

                <div className="border border-[#a48c7a]/25 bg-[#1c1b1b]">
                  <div className="flex border-b border-[#a48c7a]/25">
                    {resultTabs.map(tab => (
                      <button
                        key={tab.id}
                        type="button"
                        onClick={() => setActiveTab(tab.id)}
                        className={cn(
                          'px-6 py-2.5 text-xs font-black uppercase tracking-widest transition-none border-r border-[#a48c7a]/20 last:border-r-0',
                          activeTab === tab.id
                            ? 'bg-[#ff8c00] text-[#131313]'
                            : 'text-[#a48c7a] hover:text-[#ff8c00] hover:bg-[#2a2a2a]'
                        )}
                      >
                        {tab.label}
                        <span className={cn('ml-2 text-[10px]', activeTab === tab.id ? 'text-[#131313]' : 'text-[#a48c7a]/60')}>
                          [{tab.count}]
                        </span>
                      </button>
                    ))}
                  </div>

                  <div className="p-5">
                    {activeTab === 'static' && (
                      <>
                        <div className="text-[10px] text-[#a48c7a] uppercase tracking-widest mb-4 flex justify-between">
                          <span>// CPPCHECK · FLAWFINDER · SEMGREP — VULNERABLE ONLY</span>
                          <span className="text-[#ff8c00]">[{staticFiltered.length}]</span>
                        </div>
                        <VirtualizedResultList results={staticFiltered} mode="static" />
                      </>
                    )}

                    {activeTab === 'ml' && (
                      <>
                        <div className="text-[10px] text-[#a48c7a] uppercase tracking-widest mb-4">
                          {mlTabHeader}
                        </div>
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
          <section className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="text-[10px] text-[#a48c7a] uppercase tracking-widest">
                // PIPELINE_LOGS — <span className="text-[#ff8c00]">{logs.length} ENTRIES</span>
              </div>
              {logs.length > 0 && (
                <button
                  type="button"
                  onClick={() => setLogs([])}
                  className="text-[9px] text-[#a48c7a] border border-[#a48c7a]/30 px-3 py-1 uppercase tracking-widest hover:border-red-500 hover:text-red-400 transition-none"
                >
                  CLEAR_LOG
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
