import { useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import type { StaticFunctionResult, MLFunctionResult, StaticFinding } from '../types/api';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

export type MergedResult = StaticFunctionResult & MLFunctionResult & {
  vulnerable: boolean;
  detector_source: string;
  agreement: boolean;
};

export type ResultMode    = 'static' | 'ml' | 'all';
export type StatusFilter  = 'all' | 'vulnerable' | 'safe';
export type SeverityFilter = 'all' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

interface Props { results: MergedResult[]; mode: ResultMode; mlModelUsed?: 'ensemble' | 'lora'; }

// ─── Severity helpers ─────────────────────────────────────────────────────────
const SEV_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-50 text-red-700 border border-red-200',
  HIGH:     'bg-orange-50 text-orange-700 border border-orange-200',
  MEDIUM:   'bg-amber-50 text-amber-700 border border-amber-200',
  LOW:      'bg-slate-50 text-slate-600 border border-slate-200',
};

function SevBadge({ sev }: { sev: string }) {
  const cls = SEV_BADGE[sev] ?? 'bg-slate-50 text-slate-600 border border-slate-200';
  return (
    <span className={cn('text-[10px] font-700 px-2 py-0.5 rounded-full uppercase tracking-wide', cls)}>
      {sev}
    </span>
  );
}

// ─── Confidence bar ───────────────────────────────────────────────────────────
function ConfBar({ value, label }: { value: number; label: string }) {
  const pct   = Math.round(value * 100);
  const barColor = pct >= 75 ? 'bg-red-500' : pct >= 50 ? 'bg-orange-400' : pct >= 25 ? 'bg-amber-400' : 'bg-green-500';
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-[11px]">
        <span className="text-[var(--ink-muted)] font-500 truncate">{label}</span>
        <span className="text-[var(--ink)] font-700 ml-2 font-['DM_Mono',monospace]">{pct}%</span>
      </div>
      <div className="h-1.5 bg-[var(--bg-subtle)] rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full transition-all', barColor)} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

// ─── Static findings table ────────────────────────────────────────────────────
function FindingsTable({ findings }: { findings: StaticFinding[] }) {
  if (!findings || findings.length === 0)
    return <p className="text-xs text-[var(--ink-muted)] italic">No static findings</p>;

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-[11px] border-collapse">
        <thead>
          <tr className="text-[var(--ink-muted)] font-600 uppercase tracking-wide border-b border-[var(--border)]">
            <th className="text-left px-2 py-1.5">Tool</th>
            <th className="text-left px-2 py-1.5">CWE</th>
            <th className="text-left px-2 py-1.5">Severity</th>
            <th className="text-left px-2 py-1.5">Message</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <tr key={i} className="border-b border-[var(--border)] hover:bg-[var(--bg-subtle)] transition-colors">
              <td className="px-2 py-1.5 font-600 text-[var(--accent)]">{f.tool}</td>
              <td className="px-2 py-1.5 text-[var(--ink-mid)] font-['DM_Mono',monospace]">{f.cwe_id || '—'}</td>
              <td className="px-2 py-1.5">
                <SevBadge sev={f.severity} />
              </td>
              <td className="px-2 py-1.5 text-[var(--ink-mid)]">{f.message}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Model scores ─────────────────────────────────────────────────────────────
function ModelScores({ models }: { models: Record<string, number> }) {
  if (!models || Object.keys(models).length === 0)
    return <p className="text-xs text-[var(--ink-muted)] italic">No model scores</p>;
  return (
    <div className="space-y-2.5">
      {Object.entries(models).map(([name, score]) => (
        <ConfBar key={name} value={score} label={name} />
      ))}
    </div>
  );
}

// ─── Status badge ─────────────────────────────────────────────────────────────
function StatusBadge({ vulnerable, conf }: { vulnerable: boolean; conf?: number }) {
  const pct = conf !== undefined ? Math.round(conf * 100) : null;
  if (vulnerable) {
    return (
      <span className="inline-flex items-center gap-1.5 text-[11px] font-700 px-2.5 py-1 rounded-full bg-red-50 text-red-700 border border-red-200">
        <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
        Vulnerable{pct !== null ? ` · ${pct}%` : ''}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-700 px-2.5 py-1 rounded-full bg-green-50 text-green-700 border border-green-200">
      <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
      Safe
    </span>
  );
}

// ─── Card shell ───────────────────────────────────────────────────────────────
function CardShell({ vulnerable, children }: { vulnerable: boolean; children: React.ReactNode }) {
  return (
    <div className={cn(
      'bg-white border rounded-[var(--radius-lg)] p-4 transition-shadow hover:shadow-md',
      vulnerable ? 'border-l-4 border-l-red-400 border-[var(--border)]' : 'border-l-4 border-l-green-400 border-[var(--border)]'
    )}>
      {children}
    </div>
  );
}

// ─── Static card ─────────────────────────────────────────────────────────────
function StaticCard({ result, index }: { result: MergedResult; index: number }) {
  const isVuln = result.vulnerable;
  const hasFn  = result.static_findings && result.static_findings.length > 0;

  return (
    <CardShell vulnerable={isVuln}>
      <div className="flex items-start justify-between mb-3 gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-1.5 flex-wrap">
            <StatusBadge vulnerable={isVuln} />
            {result.severity && result.severity !== 'N/A' && <SevBadge sev={result.severity} />}
          </div>
          <p className="text-sm font-700 text-[var(--ink)] truncate font-['DM_Mono',monospace]">
            #{index + 1} {result.function_name}
          </p>
        </div>
        <span className="text-[10px] font-600 text-[var(--ink-muted)] bg-[var(--bg-subtle)] border border-[var(--border)] px-2 py-0.5 rounded-full shrink-0">
          Static
        </span>
      </div>

      <p className="text-[11px] text-[var(--ink-muted)] font-['DM_Mono',monospace] mb-3 truncate">
        {result.file_path}:{result.line_number}
      </p>

      {result.cwe_types && result.cwe_types.length > 0 && (
        <div className="mb-3 flex flex-wrap gap-1">
          {result.cwe_types.map(cwe => (
            <span key={cwe} className="text-[10px] font-600 bg-[var(--accent-light)] text-[var(--accent)] border border-[var(--accent-dim)] px-2 py-0.5 rounded font-['DM_Mono',monospace]">
              {cwe}
            </span>
          ))}
        </div>
      )}

      {hasFn && (
        <div className="mb-3 bg-[var(--bg-subtle)] border border-[var(--border)] rounded-[var(--radius)] p-3">
          <FindingsTable findings={result.static_findings} />
        </div>
      )}

      <details className="mt-1 group">
        <summary className="text-xs text-[var(--accent)] cursor-pointer hover:underline select-none list-none font-600">
          <span className="group-open:hidden">View code ↓</span>
          <span className="hidden group-open:inline">Hide code ↑</span>
        </summary>
        <div className="mt-2 bg-[var(--bg-subtle)] border border-[var(--border)] rounded-[var(--radius)] p-3 overflow-x-auto">
          <pre className="text-[11px] text-[var(--ink-mid)] font-['DM_Mono',monospace] whitespace-pre-wrap leading-relaxed">
            <code>{result.code}</code>
          </pre>
        </div>
      </details>
    </CardShell>
  );
}

// ─── ML card ─────────────────────────────────────────────────────────────────
function MLCard({ result, index, mlModelUsed }: { result: MergedResult; index: number; mlModelUsed?: 'ensemble' | 'lora'; }) {
  const mlVuln = result.ml_vulnerable ?? result.vulnerable;

  return (
    <CardShell vulnerable={mlVuln}>
      <div className="flex items-start justify-between mb-3 gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-1.5 flex-wrap">
            <StatusBadge vulnerable={mlVuln} conf={result.ml_confidence} />
            {mlVuln && result.severity && result.severity !== 'N/A' && <SevBadge sev={result.severity} />}
            {result.agreement && (
              <span className="text-[10px] font-600 bg-blue-50 text-blue-700 border border-blue-200 px-2 py-0.5 rounded-full">
                ✓ Confirmed
              </span>
            )}
          </div>
          <p className="text-sm font-700 text-[var(--ink)] truncate font-['DM_Mono',monospace]">
            #{index + 1} {result.function_name}
          </p>
        </div>
        <span className="text-[10px] font-600 text-[var(--ink-muted)] bg-[var(--bg-subtle)] border border-[var(--border)] px-2 py-0.5 rounded-full shrink-0">
          {mlModelUsed === 'lora' ? 'LoRA' : 'Ensemble'}
        </span>
      </div>

      <p className="text-[11px] text-[var(--ink-muted)] font-['DM_Mono',monospace] mb-3 truncate">
        {result.file_path}:{result.line_number}
      </p>

      <div className="mb-3 bg-[var(--bg-subtle)] border border-[var(--border)] rounded-[var(--radius)] p-3">
        <ConfBar value={result.ml_confidence} label="ML Confidence" />
      </div>

      {mlVuln && result.cwe_types && result.cwe_types.length > 0 && (
        <div className="mb-3 flex flex-wrap gap-1">
          {result.cwe_types.map(cwe => (
            <span key={cwe} className="text-[10px] font-600 bg-[var(--accent-light)] text-[var(--accent)] border border-[var(--accent-dim)] px-2 py-0.5 rounded font-['DM_Mono',monospace]">
              {cwe}
            </span>
          ))}
        </div>
      )}

      <details className="mt-1 group">
        <summary className="text-xs text-[var(--accent)] cursor-pointer hover:underline select-none list-none font-600">
          <span className="group-open:hidden">{mlModelUsed === 'lora' ? 'LoRA scores' : 'Ensemble scores'} + code ↓</span>
          <span className="hidden group-open:inline">Collapse ↑</span>
        </summary>
        <div className="mt-2 grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="bg-[var(--bg-subtle)] border border-[var(--border)] rounded-[var(--radius)] p-3">
            <p className="text-[10px] text-[var(--ink-muted)] font-600 uppercase tracking-wide mb-2">Model Scores</p>
            <ModelScores models={result.individual_models} />
          </div>
          <div className="bg-[var(--bg-subtle)] border border-[var(--border)] rounded-[var(--radius)] p-3 overflow-x-auto max-h-48 overflow-y-auto">
            <p className="text-[10px] text-[var(--ink-muted)] font-600 uppercase tracking-wide mb-2">Code Snippet</p>
            <pre className="text-[11px] text-[var(--ink-mid)] font-['DM_Mono',monospace] whitespace-pre-wrap leading-relaxed">
              <code>{result.code}</code>
            </pre>
          </div>
        </div>
      </details>
    </CardShell>
  );
}

// ─── All card ─────────────────────────────────────────────────────────────────
function AllCard({ result, index, mlModelUsed }: { result: MergedResult; index: number; mlModelUsed?: 'ensemble' | 'lora'; }) {
  const isVuln    = result.vulnerable;
  const mlConfPct = Math.round(result.ml_confidence * 100);

  return (
    <CardShell vulnerable={isVuln}>
      <div className="flex items-start justify-between mb-3 gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-1.5 flex-wrap">
            <StatusBadge vulnerable={isVuln} />
            {isVuln && result.severity && result.severity !== 'N/A' && <SevBadge sev={result.severity} />}
          </div>
          <p className="text-sm font-700 text-[var(--ink)] truncate font-['DM_Mono',monospace]">
            #{index + 1} {result.function_name}
          </p>
        </div>
        <span className="text-[10px] font-600 text-[var(--ink-muted)] bg-[var(--bg-subtle)] border border-[var(--border)] px-2 py-0.5 rounded-full shrink-0">
          {result.detector_source}
        </span>
      </div>

      <p className="text-[11px] text-[var(--ink-muted)] font-['DM_Mono',monospace] mb-3 truncate">
        {result.file_path}:{result.line_number}
      </p>

      <div className="grid grid-cols-2 gap-3 text-[11px] mb-3">
        <div className="bg-[var(--bg-subtle)] border border-[var(--border)] rounded-[var(--radius)] p-2.5">
          <p className="text-[10px] text-[var(--ink-muted)] font-600 uppercase tracking-wide mb-1">Detector</p>
          <p className="text-[var(--ink)] font-600">{result.detector_source}</p>
        </div>
        <div className="bg-[var(--bg-subtle)] border border-[var(--border)] rounded-[var(--radius)] p-2.5">
          <p className="text-[10px] text-[var(--ink-muted)] font-600 uppercase tracking-wide mb-1">ML Prediction</p>
          <p className={cn('font-600 font-["DM_Mono",monospace]', (result.ml_vulnerable ?? result.vulnerable) ? 'text-red-600' : 'text-green-600')}>
            {(result.ml_vulnerable ?? result.vulnerable) ? `Vuln · ${mlConfPct}%` : `Safe · ${mlConfPct}%`}
          </p>
        </div>
      </div>

      <div className="mb-3 bg-[var(--bg-subtle)] border border-[var(--border)] rounded-[var(--radius)] p-3">
        <ConfBar value={result.ml_confidence} label="ML Confidence" />
      </div>

      {result.cwe_types && result.cwe_types.length > 0 && (
        <div className="mb-3 flex flex-wrap gap-1">
          {result.cwe_types.map(cwe => (
            <span key={cwe} className="text-[10px] font-600 bg-[var(--accent-light)] text-[var(--accent)] border border-[var(--accent-dim)] px-2 py-0.5 rounded font-['DM_Mono',monospace]">
              {cwe}
            </span>
          ))}
        </div>
      )}

      <details className="mt-1 group">
        <summary className="text-xs text-[var(--accent)] cursor-pointer hover:underline select-none list-none font-600">
          <span className="group-open:hidden">Details ↓</span>
          <span className="hidden group-open:inline">Collapse ↑</span>
        </summary>
        <div className="mt-2 space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="bg-[var(--bg-subtle)] border border-[var(--border)] rounded-[var(--radius)] p-3">
              <p className="text-[10px] text-[var(--ink-muted)] font-600 uppercase tracking-wide mb-2">Static Findings</p>
              <FindingsTable findings={result.static_findings} />
            </div>
            <div className="bg-[var(--bg-subtle)] border border-[var(--border)] rounded-[var(--radius)] p-3">
              <p className="text-[10px] text-[var(--ink-muted)] font-600 uppercase tracking-wide mb-2">
                {mlModelUsed === 'lora' ? 'LoRA Scores' : 'Ensemble Scores'}
              </p>
              <ModelScores models={result.individual_models} />
            </div>
          </div>
          <div className="bg-[var(--bg-subtle)] border border-[var(--border)] rounded-[var(--radius)] p-3 overflow-x-auto max-h-48 overflow-y-auto">
            <p className="text-[10px] text-[var(--ink-muted)] font-600 uppercase tracking-wide mb-2">Code Snippet</p>
            <pre className="text-[11px] text-[var(--ink-mid)] font-['DM_Mono',monospace] whitespace-pre-wrap leading-relaxed">
              <code>{result.code}</code>
            </pre>
          </div>
        </div>
      </details>
    </CardShell>
  );
}

// ─── Virtualized list ─────────────────────────────────────────────────────────
export function VirtualizedResultList({ results, mode, mlModelUsed }: Props) {
  const parentRef = useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count: results.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => mode === 'static' ? 220 : mode === 'ml' ? 160 : 180,
    overscan: 5,
  });

  if (results.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-48 text-[var(--ink-muted)]">
        <div className="w-10 h-10 rounded-full bg-[var(--bg-subtle)] flex items-center justify-center mb-3">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <circle cx="11" cy="11" r="8" />
            <path d="M21 21l-4.35-4.35" />
          </svg>
        </div>
        <p className="text-sm font-500">No results match filters</p>
      </div>
    );
  }

  return (
    <div
      ref={parentRef}
      className="h-[620px] w-full overflow-auto rounded-[var(--radius)]"
    >
      <div className="relative w-full" style={{ height: `${virtualizer.getTotalSize()}px` }}>
        {virtualizer.getVirtualItems().map((virtualItem) => {
          const result = results[virtualItem.index];
          return (
            <div
              key={virtualItem.key}
              ref={virtualizer.measureElement}
              data-index={virtualItem.index}
              className="absolute top-0 left-0 w-full px-1 py-1.5"
              style={{ transform: `translateY(${virtualItem.start}px)` }}
            >
              {mode === 'static' && <StaticCard result={result} index={virtualItem.index} />}
              {mode === 'ml'     && <MLCard     result={result} index={virtualItem.index} mlModelUsed={mlModelUsed} />}
              {mode === 'all'    && <AllCard    result={result} index={virtualItem.index} mlModelUsed={mlModelUsed} />}
            </div>
          );
        })}
      </div>
    </div>
  );
}
