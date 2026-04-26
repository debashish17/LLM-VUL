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
const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'text-red-400 border-red-500',
  HIGH:     'text-[#ff8c00] border-[#ff8c00]',
  MEDIUM:   'text-[#ffb77d] border-[#ffb77d]',
  LOW:      'text-[#a48c7a] border-[#a48c7a]',
};

function SevTag({ sev }: { sev: string }) {
  const cls = SEV_COLOR[sev] ?? 'text-[#a48c7a] border-[#a48c7a]';
  return (
    <span className={cn('text-[10px] font-black border px-1.5 py-0.5 uppercase tracking-wider', cls)}>
      [ {sev} ]
    </span>
  );
}

// ─── Confidence bar (terminal style) ─────────────────────────────────────────
function ConfBar({ value, label }: { value: number; label: string }) {
  const pct   = Math.round(value * 100);
  const color = pct >= 75 ? 'bg-red-500' : pct >= 50 ? 'bg-[#ff8c00]' : pct >= 25 ? 'bg-[#ffb77d]' : 'bg-[#39ff14]';
  const filled = Math.round(pct / 5); // 20 chars max
  const bar   = '█'.repeat(filled) + '░'.repeat(20 - filled);
  return (
    <div className="flex items-center gap-3 text-[11px] font-mono">
      <span className="text-[#a48c7a] w-32 shrink-0 uppercase truncate">{label}</span>
      <span className={cn('tracking-tighter', color)}>{bar}</span>
      <span className="text-[#ffb77d] font-black w-8 text-right shrink-0">{pct}%</span>
    </div>
  );
}

// ─── Static findings table ────────────────────────────────────────────────────
function FindingsTable({ findings }: { findings: StaticFinding[] }) {
  if (!findings || findings.length === 0)
    return <p className="text-[10px] text-[#a48c7a] italic">// NO_STATIC_FINDINGS</p>;

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-[10px] font-mono border-collapse">
        <thead>
          <tr className="text-[#a48c7a] uppercase tracking-widest border-b border-[#a48c7a]/20">
            <th className="text-left px-2 py-1">TOOL</th>
            <th className="text-left px-2 py-1">CWE</th>
            <th className="text-left px-2 py-1">SEV</th>
            <th className="text-left px-2 py-1">MESSAGE</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <tr key={i} className="border-b border-[#a48c7a]/10 hover:bg-[#ff8c00]/5">
              <td className="px-2 py-1 text-[#ff8c00]">{f.tool}</td>
              <td className="px-2 py-1 text-[#ffb77d]">{f.cwe_id || '—'}</td>
              <td className="px-2 py-1">
                <span className={cn('text-[9px] border px-1', SEV_COLOR[f.severity] ?? 'text-[#a48c7a] border-[#a48c7a]')}>
                  {f.severity}
                </span>
              </td>
              <td className="px-2 py-1 text-[#a48c7a]">{f.message}</td>
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
    return <p className="text-[10px] text-[#a48c7a] italic">// NO_MODEL_SCORES</p>;
  return (
    <div className="space-y-1.5">
      {Object.entries(models).map(([name, score]) => (
        <ConfBar key={name} value={score} label={name} />
      ))}
    </div>
  );
}

// ─── Card shell ───────────────────────────────────────────────────────────────
function CardShell({ vulnerable, children }: { vulnerable: boolean; children: React.ReactNode }) {
  return (
    <div className={cn(
      'relative p-4 bg-[#1c1b1b] border-l-2',
      vulnerable ? 'border-l-red-500' : 'border-l-[#39ff14]'
    )}>
      {/* ASCII corners */}
      <span className="absolute top-0 left-0 text-[#ff8c00]/30 text-xs leading-none select-none">┌</span>
      <span className="absolute top-0 right-0 text-[#ff8c00]/30 text-xs leading-none select-none">┐</span>
      <span className="absolute bottom-0 left-0 text-[#ff8c00]/30 text-xs leading-none select-none">└</span>
      <span className="absolute bottom-0 right-0 text-[#ff8c00]/30 text-xs leading-none select-none">┘</span>
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
      {/* Header */}
      <div className="flex items-start justify-between mb-3 gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            {isVuln
              ? <span className="text-[10px] font-black text-red-400 border border-red-500 px-1.5 py-0.5">[ VULN ]</span>
              : <span className="text-[10px] font-black text-[#39ff14] border border-[#39ff14] px-1.5 py-0.5">[ SAFE ]</span>
            }
            {result.severity && result.severity !== 'N/A' && <SevTag sev={result.severity} />}
          </div>
          <p className="text-sm font-black text-[#ffb77d] font-mono uppercase truncate">
            #{index + 1} {result.function_name}
          </p>
        </div>
        <span className="text-[9px] text-[#a48c7a] shrink-0 font-mono">STATIC_ANALYZER</span>
      </div>

      {/* File path */}
      <p className="text-[10px] text-[#a48c7a] font-mono mb-3 truncate">
        &gt; {result.file_path}:{result.line_number}
      </p>

      {/* CWE */}
      {result.cwe_types && result.cwe_types.length > 0 && (
        <div className="mb-3 flex flex-wrap gap-1">
          {result.cwe_types.map(cwe => (
            <span key={cwe} className="text-[9px] border border-[#ff8c00]/40 text-[#ff8c00] px-1.5 py-0.5 font-mono">
              {cwe}
            </span>
          ))}
        </div>
      )}

      {/* Findings */}
      {hasFn && (
        <div className="mb-3 border border-[#a48c7a]/20 bg-[#0e0e0e] p-2">
          <FindingsTable findings={result.static_findings} />
        </div>
      )}

      {/* Code expand */}
      <details className="mt-2 group">
        <summary className="text-[10px] text-[#a48c7a] cursor-pointer hover:text-[#ff8c00] uppercase tracking-widest select-none list-none">
          <span className="group-open:hidden">▶ VIEW_CODE</span>
          <span className="hidden group-open:inline">▼ HIDE_CODE</span>
        </summary>
        <div className="mt-2 bg-[#0a0a0a] border border-[#a48c7a]/20 p-3 overflow-x-auto">
          <pre className="text-[11px] text-[#ffb77d] font-mono whitespace-pre-wrap leading-relaxed">
            <code>{result.code}</code>
          </pre>
        </div>
      </details>
    </CardShell>
  );
}

// ─── ML card ─────────────────────────────────────────────────────────────────
function MLCard({ result, index, mlModelUsed }: { result: MergedResult; index: number; mlModelUsed?: 'ensemble' | 'lora'; }) {
  const mlVuln   = result.ml_vulnerable ?? result.vulnerable;
  const mlConfPct = Math.round(result.ml_confidence * 100);

  return (
    <CardShell vulnerable={mlVuln}>
      {/* Header */}
      <div className="flex items-start justify-between mb-3 gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            {mlVuln
              ? <span className="text-[10px] font-black text-red-400 border border-red-500 px-1.5 py-0.5">[ VULN · {mlConfPct}% ]</span>
              : <span className="text-[10px] font-black text-[#39ff14] border border-[#39ff14] px-1.5 py-0.5">[ SAFE ]</span>
            }
            {mlVuln && result.severity && result.severity !== 'N/A' && <SevTag sev={result.severity} />}
            {result.agreement && (
              <span className="text-[9px] font-black text-[#ffb77d] border border-[#ffb77d]/50 px-1.5 py-0.5">✓ CONFIRMED</span>
            )}
          </div>
          <p className="text-sm font-black text-[#ffb77d] font-mono uppercase truncate">
            #{index + 1} {result.function_name}
          </p>
        </div>
        <span className="text-[9px] text-[#a48c7a] shrink-0 font-mono">{mlModelUsed === 'lora' ? 'LORA_CODEBERT' : 'ML_ENSEMBLE'}</span>
      </div>

      {/* File */}
      <p className="text-[10px] text-[#a48c7a] font-mono mb-3 truncate">
        &gt; {result.file_path}:{result.line_number}
      </p>

      {/* Confidence bar */}
      <div className="mb-3 bg-[#0e0e0e] border border-[#a48c7a]/20 p-2">
        <ConfBar value={result.ml_confidence} label="ML_CONFIDENCE" />
      </div>

      {/* CWE */}
      {mlVuln && result.cwe_types && result.cwe_types.length > 0 && (
        <div className="mb-3 flex flex-wrap gap-1">
          {result.cwe_types.map(cwe => (
            <span key={cwe} className="text-[9px] border border-[#ff8c00]/40 text-[#ff8c00] px-1.5 py-0.5 font-mono">
              {cwe}
            </span>
          ))}
        </div>
      )}

      {/* Expand: model scores + code */}
      <details className="mt-2 group">
        <summary className="text-[10px] text-[#a48c7a] cursor-pointer hover:text-[#ff8c00] uppercase tracking-widest select-none list-none">
          <span className="group-open:hidden">▶ {mlModelUsed === 'lora' ? 'LORA_SCORES' : 'ENSEMBLE_SCORES'} + CODE</span>
          <span className="hidden group-open:inline">▼ COLLAPSE</span>
        </summary>
        <div className="mt-2 grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="bg-[#0e0e0e] border border-[#a48c7a]/20 p-3">
            <p className="text-[9px] text-[#a48c7a] uppercase tracking-widest mb-2">// MODEL_SCORES</p>
            <ModelScores models={result.individual_models} />
          </div>
          <div className="bg-[#0a0a0a] border border-[#a48c7a]/20 p-3 overflow-x-auto max-h-48 overflow-y-auto">
            <p className="text-[9px] text-[#a48c7a] uppercase tracking-widest mb-2">// CODE_SNIPPET</p>
            <pre className="text-[11px] text-[#ffb77d] font-mono whitespace-pre-wrap leading-relaxed">
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
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            {isVuln
              ? <span className="text-[10px] font-black text-red-400 border border-red-500 px-1.5 py-0.5">[ VULNERABLE ]</span>
              : <span className="text-[10px] font-black text-[#39ff14] border border-[#39ff14] px-1.5 py-0.5">[ SAFE ]</span>
            }
            {isVuln && result.severity && result.severity !== 'N/A' && <SevTag sev={result.severity} />}
          </div>
          <p className="text-sm font-black text-[#ffb77d] font-mono uppercase truncate">
            #{index + 1} {result.function_name}
          </p>
        </div>
        <span className="text-[9px] text-[#a48c7a] shrink-0 font-mono">{result.detector_source?.toUpperCase()}</span>
      </div>

      <p className="text-[10px] text-[#a48c7a] font-mono mb-3 truncate">
        &gt; {result.file_path}:{result.line_number}
      </p>

      <div className="grid grid-cols-2 gap-x-4 text-[10px] mb-3 font-mono">
        <div>
          <span className="text-[#a48c7a]">DETECTOR: </span>
          <span className="text-[#ff8c00]">{result.detector_source}</span>
        </div>
        <div>
          <span className="text-[#a48c7a]">ML_PRED: </span>
          <span className={(result.ml_vulnerable ?? result.vulnerable) ? 'text-red-400' : 'text-[#39ff14]'}>
            {(result.ml_vulnerable ?? result.vulnerable) ? `VULN·${mlConfPct}%` : `SAFE·${mlConfPct}%`}
          </span>
        </div>
      </div>

      <div className="bg-[#0e0e0e] border border-[#a48c7a]/20 p-2 mb-3">
        <ConfBar value={result.ml_confidence} label="ML_CONFIDENCE" />
      </div>

      {result.cwe_types && result.cwe_types.length > 0 && (
        <div className="mb-3 flex flex-wrap gap-1">
          {result.cwe_types.map(cwe => (
            <span key={cwe} className="text-[9px] border border-[#ff8c00]/40 text-[#ff8c00] px-1.5 py-0.5 font-mono">
              {cwe}
            </span>
          ))}
        </div>
      )}

      <details className="mt-2 group">
        <summary className="text-[10px] text-[#a48c7a] cursor-pointer hover:text-[#ff8c00] uppercase tracking-widest select-none list-none">
          <span className="group-open:hidden">▶ DETAILS</span>
          <span className="hidden group-open:inline">▼ COLLAPSE</span>
        </summary>
        <div className="mt-2 space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="bg-[#0e0e0e] border border-[#a48c7a]/20 p-2">
              <p className="text-[9px] text-[#a48c7a] uppercase tracking-widest mb-2">// STATIC_FINDINGS</p>
              <FindingsTable findings={result.static_findings} />
            </div>
            <div className="bg-[#0e0e0e] border border-[#a48c7a]/20 p-2">
              <p className="text-[9px] text-[#a48c7a] uppercase tracking-widest mb-2">// {mlModelUsed === 'lora' ? 'LORA_SCORES' : 'ENSEMBLE_SCORES'}</p>
              <ModelScores models={result.individual_models} />
            </div>
          </div>
          <div className="bg-[#0a0a0a] border border-[#a48c7a]/20 p-3 overflow-x-auto max-h-48 overflow-y-auto">
            <p className="text-[9px] text-[#a48c7a] uppercase tracking-widest mb-2">// CODE_SNIPPET</p>
            <pre className="text-[11px] text-[#ffb77d] font-mono whitespace-pre-wrap leading-relaxed">
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
      <div className="flex flex-col items-center justify-center h-48 text-[#a48c7a] font-mono text-xs uppercase tracking-widest">
        <p className="text-[#ff8c00]/50 text-2xl mb-3">{'>'}_</p>
        <p>// NO_RESULTS_MATCH_FILTERS</p>
      </div>
    );
  }

  return (
    <div
      ref={parentRef}
      className="h-155 w-full overflow-auto border border-[#a48c7a]/20 bg-[#131313]"
    >
      <div className="relative w-full" style={{ height: `${virtualizer.getTotalSize()}px` }}>
        {virtualizer.getVirtualItems().map((virtualItem) => {
          const result = results[virtualItem.index];
          return (
            <div
              key={virtualItem.key}
              ref={virtualizer.measureElement}
              data-index={virtualItem.index}
              className="absolute top-0 left-0 w-full px-3 py-2"
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
