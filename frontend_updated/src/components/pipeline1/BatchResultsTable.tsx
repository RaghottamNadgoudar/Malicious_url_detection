import { useState, useMemo } from 'react';
import { ArrowUpDown, ExternalLink } from 'lucide-react';
import type { DaaBatchDecidedRecord, DaaClassifyResult, Verdict } from '../../types/daaApi';

type Row = {
  url:        string;
  verdict:    Verdict;
  confidence: number;
  stage:      string;
  reason:     string;
};

interface BatchResultsTableProps {
  decided:         DaaBatchDecidedRecord[];
  uncertainResults: DaaClassifyResult[];
}

const VERDICT_CHIP: Record<Verdict, string> = {
  safe:       'chip-safe',
  suspicious: 'chip-suspicious',
  malicious:  'chip-malicious',
  error:      'text-white/30 text-xs',
};

const STAGE_MAP: Record<string, string> = {
  'S0-dedup':     'Dedup',
  'S1-whitelist': 'Whitelist',
  'S2-horspool':  'Horspool',
  'S3-greedy':    'Greedy',
  'S4-backtrack': 'Backtrack',
  'S5-DistilBERT':'DistilBERT',
};

export default function BatchResultsTable({ decided, uncertainResults }: BatchResultsTableProps) {
  const [filter, setFilter]   = useState<Verdict | 'all'>('all');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [page, setPage]       = useState(0);
  const PAGE_SIZE = 25;

  const rows: Row[] = useMemo(() => [
    ...decided.map(r => ({ url: r.url, verdict: r.verdict, confidence: r.confidence, stage: r.stage, reason: r.reason })),
    ...uncertainResults.map(r => ({ url: r.url, verdict: r.verdict, confidence: r.confidence, stage: 'S5-DistilBERT', reason: r.reasoning ?? '' })),
  ], [decided, uncertainResults]);

  const filtered = useMemo(() =>
    rows
      .filter(r => filter === 'all' || r.verdict === filter)
      .sort((a, b) => sortDir === 'desc' ? b.confidence - a.confidence : a.confidence - b.confidence),
    [rows, filter, sortDir],
  );

  const pageRows  = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const pageCount = Math.ceil(filtered.length / PAGE_SIZE);

  return (
    <div className="space-y-3">
      {/* Filter + sort bar */}
      <div className="flex flex-wrap items-center gap-2">
        {(['all','safe','suspicious','malicious'] as const).map(v => (
          <button
            key={v}
            onClick={() => { setFilter(v); setPage(0); }}
            className={`px-3 py-1 rounded-lg text-xs font-medium transition-all ${
              filter === v
                ? 'bg-brand/20 border border-brand/40 text-brand-light'
                : 'border border-white/10 text-white/40 hover:text-white/70 hover:border-white/20'
            }`}
          >
            {v === 'all' ? `All (${rows.length})` : `${v} (${rows.filter(r => r.verdict === v).length})`}
          </button>
        ))}
        <button
          onClick={() => setSortDir(d => d === 'desc' ? 'asc' : 'desc')}
          className="ml-auto flex items-center gap-1 text-xs text-white/40 hover:text-white/70 transition-colors"
        >
          <ArrowUpDown size={12} /> Confidence
        </button>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-xl border border-white/[0.07]">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-white/[0.06] text-white/40">
              <th className="text-left p-3 font-medium">URL</th>
              <th className="text-left p-3 font-medium">Verdict</th>
              <th className="text-left p-3 font-medium hidden sm:table-cell">Conf.</th>
              <th className="text-left p-3 font-medium hidden md:table-cell">Stage</th>
              <th className="text-left p-3 font-medium hidden lg:table-cell">Reason</th>
            </tr>
          </thead>
          <tbody>
            {pageRows.map((r, i) => (
              <tr
                key={`${r.url}-${i}`}
                className="border-b border-white/[0.04] hover:bg-white/[0.03] transition-colors animate-fade-in"
                style={{ animationDelay: `${(i % PAGE_SIZE) * 20}ms` }}
              >
                <td className="p-3 max-w-[220px]">
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono truncate text-white/70" title={r.url}>{r.url}</span>
                    <a href={r.url} target="_blank" rel="noopener noreferrer"
                       className="text-white/20 hover:text-white/60 shrink-0">
                      <ExternalLink size={10}/>
                    </a>
                  </div>
                </td>
                <td className="p-3">
                  <span className={VERDICT_CHIP[r.verdict]}>{r.verdict}</span>
                </td>
                <td className="p-3 font-mono text-white/60 hidden sm:table-cell">
                  {Math.round(r.confidence * 100)}%
                </td>
                <td className="p-3 hidden md:table-cell">
                  <span className="tier-badge bg-white/5 border border-white/10 text-white/40">
                    {STAGE_MAP[r.stage] ?? r.stage}
                  </span>
                </td>
                <td className="p-3 text-white/35 max-w-[250px] truncate hidden lg:table-cell" title={r.reason}>
                  {r.reason}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {pageCount > 1 && (
        <div className="flex items-center justify-center gap-2 text-xs text-white/40">
          <button onClick={() => setPage(p => Math.max(0, p-1))} disabled={page === 0}
                  className="px-3 py-1 rounded border border-white/10 hover:border-white/20 disabled:opacity-30">←</button>
          <span>{page + 1} / {pageCount}</span>
          <button onClick={() => setPage(p => Math.min(pageCount-1, p+1))} disabled={page >= pageCount-1}
                  className="px-3 py-1 rounded border border-white/10 hover:border-white/20 disabled:opacity-30">→</button>
        </div>
      )}
    </div>
  );
}
