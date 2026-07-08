import { useState, useRef, useCallback } from 'react';
import { ArrowLeft, Loader2, RotateCcw } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import FileUploader from '../../components/pipeline1/FileUploader';
import FunnelChart from '../../components/pipeline1/FunnelChart';
import VerdictDonut from '../../components/pipeline1/VerdictDonut';
import BatchResultsTable from '../../components/pipeline1/BatchResultsTable';
import SpeedupCallout from '../../components/pipeline1/SpeedupCallout';
import type {
  DaaSseEvent, DaaStageCount, DaaBatchDecidedRecord, DaaClassifyResult, DaaBatchCompleteResult,
} from '../../types/daaApi';
import { batchOptimizeStream } from '../../services/daaApi';

type Phase = 'idle' | 'running' | 'done' | 'error';

interface LiveState {
  total:            number;
  bertDone:         number;
  bertTotal:        number;
  stageCounts:      DaaStageCount | null;
  decided:          DaaBatchDecidedRecord[];
  uncertainResults: DaaClassifyResult[];
  log:              string[];
}

const EMPTY_LIVE: LiveState = {
  total: 0, bertDone: 0, bertTotal: 0,
  stageCounts: null, decided: [], uncertainResults: [], log: [],
};

export default function PipelineOneView() {
  const nav = useNavigate();
  const [phase, setPhase]         = useState<Phase>('idle');
  const [live, setLive]           = useState<LiveState>(EMPTY_LIVE);
  const [result, setResult]       = useState<DaaBatchCompleteResult | null>(null);
  const [error, setError]         = useState('');
  const abortRef                  = useRef<AbortController | null>(null);
  const logRef                    = useRef<HTMLDivElement>(null);

  const pushLog = useCallback((msg: string) => {
    setLive(prev => ({
      ...prev,
      log: [...prev.log.slice(-80), `${new Date().toLocaleTimeString()} ${msg}`],
    }));
    setTimeout(() => logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: 'smooth' }), 50);
  }, []);

  async function handleUrls(urls: string[]) {
    setPhase('running');
    setLive({ ...EMPTY_LIVE, total: urls.length });
    setResult(null);
    setError('');

    abortRef.current = new AbortController();

    try {
      await batchOptimizeStream(
        urls,
        (evt: DaaSseEvent) => {
          if (evt.event === 'start') {
            pushLog(`▶ Batch received — ${evt.total} URLs`);
            setLive(prev => ({ ...prev, total: evt.total }));
          }
          else if (evt.event === 'optimizer_done') {
            pushLog(`✓ DAA stages complete — ${evt.decided_count} pre-classified, ${evt.uncertain_count} → DistilBERT`);
            pushLog(`  Reduction: ${evt.reduction_pct.toFixed(0)}% (${evt.optimizer_elapsed_ms.toFixed(0)} ms)`);
            setLive(prev => ({
              ...prev,
              stageCounts:  evt.stage_counts,
              decided:      evt.decided,
              bertTotal:    evt.uncertain_count,
            }));
          }
          else if (evt.event === 'url_classified') {
            const v = evt.result.verdict;
            pushLog(`  [${evt.index + 1}/${evt.total}] ${v.toUpperCase()} — ${evt.result.url.slice(0, 60)}`);
            setLive(prev => ({
              ...prev,
              bertDone:         prev.bertDone + 1,
              uncertainResults: [...prev.uncertainResults, evt.result],
            }));
          }
          else if (evt.event === 'url_error') {
            pushLog(`  ✗ Error [${evt.index + 1}]: ${evt.url.slice(0, 50)}`);
          }
          else if (evt.event === 'complete') {
            pushLog(`✓ Complete — ${evt.total_input} URLs in ${evt.elapsed_ms.toFixed(0)} ms`);
            setResult(evt as unknown as DaaBatchCompleteResult);
            setPhase('done');
          }
          else if (evt.event === 'error') {
            setError((evt as any).message);
            setPhase('error');
          }
        },
        abortRef.current.signal,
      );
    } catch (e: any) {
      if (e.name !== 'AbortError') {
        setError(e.message);
        setPhase('error');
      }
    }
  }

  function handleReset() {
    abortRef.current?.abort();
    setPhase('idle');
    setLive(EMPTY_LIVE);
    setResult(null);
    setError('');
  }

  // Verdict counts from live + final
  const allResults: DaaClassifyResult[] = result ? result.uncertain_results : live.uncertainResults;
  const decidedAll  = result ? result.decided : live.decided;
  const verdictCounts = {
    safe:       [...decidedAll, ...allResults].filter(r => r.verdict === 'safe').length,
    suspicious: [...decidedAll, ...allResults].filter(r => r.verdict === 'suspicious').length,
    malicious:  [...decidedAll, ...allResults].filter(r => r.verdict === 'malicious').length,
    total:      decidedAll.length + allResults.length,
  };

  return (
    <div className="max-w-7xl mx-auto px-6 py-10 grid-bg min-h-[calc(100vh-4rem)]">
      {/* Header */}
      <div className="flex items-center gap-3 mb-8">
        <button onClick={() => nav('/')} className="text-white/30 hover:text-white/60 transition-colors">
          <ArrowLeft size={18}/>
        </button>
        <div>
          <h1 className="text-2xl font-bold text-white">Pipeline 1 — Batch DAA Mode</h1>
          <p className="text-sm text-white/40 mt-0.5">
            6-stage preprocessing funnel + DistilBERT for uncertain URLs · Live SSE streaming
          </p>
        </div>
        {phase !== 'idle' && (
          <button onClick={handleReset}
                  className="ml-auto flex items-center gap-1.5 text-xs text-white/40 hover:text-white/70 transition-colors">
            <RotateCcw size={13}/> Reset
          </button>
        )}
      </div>

      {/* Upload phase */}
      {phase === 'idle' && (
        <div className="glass border border-white/[0.08] p-6 rounded-2xl mb-8 animate-fade-in">
          <h2 className="text-sm font-semibold text-white mb-4">Upload URLs</h2>
          <FileUploader onUrls={handleUrls} />
        </div>
      )}

      {/* Live streaming phase */}
      {(phase === 'running' || phase === 'done') && (
        <div className="space-y-6">
          {/* Progress bar */}
          {phase === 'running' && (
            <div className="glass border border-white/[0.08] p-5 rounded-2xl animate-fade-in">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2 text-sm text-white/70">
                  <Loader2 size={14} className="animate-spin text-brand-light"/>
                  Processing {live.total} URLs…
                </div>
                <div className="text-xs font-mono text-white/40">
                  DistilBERT: {live.bertDone}/{live.bertTotal}
                </div>
              </div>
              {live.bertTotal > 0 && (
                <div className="score-bar-track mb-3">
                  <div className="score-bar-fill bg-brand transition-all duration-300"
                       style={{ width: `${(live.bertDone / live.bertTotal) * 100}%` }} />
                </div>
              )}
              {/* SSE log */}
              <div ref={logRef}
                   className="font-mono text-[11px] text-white/40 h-32 overflow-y-auto space-y-0.5 bg-black/20 rounded-lg p-3">
                {live.log.map((l, i) => (
                  <div key={i} className={i === live.log.length - 1 ? 'text-white/70' : ''}>{l}</div>
                ))}
                {live.log.length === 0 && <div className="text-white/20">Awaiting events…</div>}
              </div>
            </div>
          )}

          {/* Funnel + donut side by side */}
          {(live.stageCounts || result?.stage_counts) && (
            <div className="grid lg:grid-cols-2 gap-6">
              <div className="glass border border-white/[0.08] p-6 rounded-2xl">
                <FunnelChart stageCounts={result?.stage_counts ?? live.stageCounts!} />
              </div>
              <div className="glass border border-white/[0.08] p-6 rounded-2xl">
                <h3 className="text-sm font-semibold text-white/70 mb-4">Verdict Distribution</h3>
                <VerdictDonut counts={verdictCounts} />
              </div>
            </div>
          )}

          {/* Speedup callout — only on done */}
          {phase === 'done' && result && (
            <SpeedupCallout
              totalInput={result.total_input}
              reductionPct={result.reduction_pct}
              elapsedMs={result.elapsed_ms}
              huffmanRatio={result.huffman_ratio}
            />
          )}

          {/* Results table */}
          {(decidedAll.length > 0 || allResults.length > 0) && (
            <div className="glass border border-white/[0.08] p-6 rounded-2xl">
              <h3 className="text-sm font-semibold text-white/70 mb-4">
                All Results
                {phase === 'running' && (
                  <span className="ml-2 text-brand-light"><span className="live-dot inline-block mr-1"/>live</span>
                )}
              </h3>
              <BatchResultsTable decided={decidedAll} uncertainResults={allResults} />
            </div>
          )}
        </div>
      )}

      {/* Error state */}
      {phase === 'error' && (
        <div className="glass border border-malicious/30 p-6 rounded-2xl animate-fade-in">
          <div className="text-malicious font-medium mb-2">Stream Error</div>
          <div className="text-sm text-white/50 font-mono mb-4">{error}</div>
          <p className="text-xs text-white/30">
            Make sure <code className="font-mono">uvicorn app_nn:app --port 8002</code> is running in the daa_model/ directory.
          </p>
          <button onClick={handleReset} className="mt-4 flex items-center gap-1.5 text-xs text-brand-light hover:text-white transition-colors">
            <RotateCcw size={12}/> Try again
          </button>
        </div>
      )}
    </div>
  );
}
