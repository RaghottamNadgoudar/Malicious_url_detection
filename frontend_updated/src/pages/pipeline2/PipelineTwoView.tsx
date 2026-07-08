import { useState } from 'react';
import { ArrowLeft, Loader2, Search, RotateCcw, AlertCircle, Link } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import VerdictBanner from '../../components/shared/VerdictBanner';
import UmbrellaTierCard from '../../components/pipeline2/UmbrellaTierCard';
import WhitelistTierCard from '../../components/pipeline2/WhitelistTierCard';
import DistilBertTierCard from '../../components/pipeline2/DistilBertTierCard';
import HardSignalTierCard from '../../components/pipeline2/HardSignalTierCard';
import FeatureGrid from '../../components/pipeline2/FeatureGrid';
import type { DaaClassifyDetailResult, DaaExpandResult } from '../../types/daaApi';
import { classifyUrlDetail, expandUrl } from '../../services/daaApi';

type Phase = 'idle' | 'loading' | 'done' | 'error';

export default function PipelineTwoView() {
  const nav = useNavigate();
  const [inputUrl, setInputUrl] = useState('');
  const [phase, setPhase]       = useState<Phase>('idle');
  const [result, setResult]     = useState<DaaClassifyDetailResult | null>(null);
  const [expand, setExpand]     = useState<DaaExpandResult | null>(null);
  const [error, setError]       = useState('');

  async function handleScan() {
    if (!inputUrl.trim()) return;
    setPhase('loading');
    setResult(null);
    setExpand(null);
    setError('');

    try {
      // Run classify-detail and expand-url in parallel
      const [classifyRes, expandRes] = await Promise.allSettled([
        classifyUrlDetail(inputUrl.trim()),
        expandUrl(inputUrl.trim()),
      ]);

      if (classifyRes.status === 'fulfilled') setResult(classifyRes.value);
      else throw new Error((classifyRes.reason as Error).message);

      if (expandRes.status === 'fulfilled') setExpand(expandRes.value);
      // expand failure is non-fatal

      setPhase('done');
    } catch (e: any) {
      setError(e.message ?? 'Unknown error');
      setPhase('error');
    }
  }

  function handleReset() {
    setPhase('idle');
    setResult(null);
    setExpand(null);
    setError('');
    setInputUrl('');
  }

  const exitTier = result?.exit_tier ?? 'T2-DistilBERT';

  return (
    <div className="max-w-5xl mx-auto px-6 py-10 grid-bg min-h-[calc(100vh-4rem)]">
      {/* Header */}
      <div className="flex items-center gap-3 mb-8">
        <button onClick={() => nav('/')} className="text-white/30 hover:text-white/60 transition-colors">
          <ArrowLeft size={18}/>
        </button>
        <div>
          <h1 className="text-2xl font-bold text-white">Pipeline 2 — Single URL Deep Scan</h1>
          <p className="text-sm text-white/40 mt-0.5">
            Trace exact tier decisions · DistilBERT threshold ruler · Hard signal breakdown
          </p>
        </div>
        {phase !== 'idle' && (
          <button onClick={handleReset}
                  className="ml-auto flex items-center gap-1.5 text-xs text-white/40 hover:text-white/70 transition-colors">
            <RotateCcw size={13}/> Reset
          </button>
        )}
      </div>

      {/* URL Input */}
      <div className="glass border border-white/[0.08] p-5 rounded-2xl mb-8 animate-fade-in">
        <div className="flex gap-3">
          <div className="flex-1 flex items-center gap-2 bg-white/[0.04] border border-white/[0.10] rounded-xl px-4 py-2.5
                          focus-within:border-brand/50 focus-within:shadow-[0_0_0_3px_rgba(124,58,237,0.10)] transition-all">
            <Link size={14} className="text-white/30 shrink-0"/>
            <input
              value={inputUrl}
              onChange={e => setInputUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleScan()}
              placeholder="https://example.com or http://suspicious-site.tk/login"
              className="flex-1 bg-transparent text-white text-sm outline-none placeholder:text-white/25 font-mono"
            />
          </div>
          <button
            onClick={handleScan}
            disabled={phase === 'loading' || !inputUrl.trim()}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-brand hover:bg-brand/80
                       text-white font-medium text-sm transition-all duration-200
                       disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
          >
            {phase === 'loading'
              ? <><Loader2 size={14} className="animate-spin"/> Scanning…</>
              : <><Search size={14}/> Scan</>
            }
          </button>
        </div>

        {/* Example URLs */}
        <div className="flex flex-wrap gap-2 mt-3">
          <span className="text-xs text-white/25">Examples:</span>
          {[
            'https://google.com',
            'http://paypal-secure.tk/login',
            'http://192.168.1.1/admin',
          ].map(ex => (
            <button key={ex} onClick={() => setInputUrl(ex)}
                    className="text-[11px] font-mono text-white/30 hover:text-brand-light transition-colors">
              {ex}
            </button>
          ))}
        </div>
      </div>

      {/* Error state */}
      {phase === 'error' && (
        <div className="glass border border-malicious/30 p-5 rounded-2xl mb-6 animate-fade-in flex items-start gap-3">
          <AlertCircle size={16} className="text-malicious shrink-0 mt-0.5"/>
          <div>
            <div className="text-sm text-malicious font-medium">Request Failed</div>
            <div className="text-xs text-white/50 font-mono mt-1">{error}</div>
            <p className="text-xs text-white/30 mt-2">
              Ensure <code className="font-mono">uvicorn app_nn:app --port 8002</code> is running in <code className="font-mono">daa_model/</code>
            </p>
          </div>
        </div>
      )}

      {/* Results */}
      {phase === 'done' && result && (
        <div className="space-y-5">
          {/* Verdict banner */}
          <VerdictBanner
            verdict={result.verdict}
            confidence={result.confidence}
            exitTier={exitTier}
            latencyMs={result.latency_ms}
            reasoning={result.reasoning}
            url={result.url}
          />

          {/* Redirect chain summary */}
          {expand && expand.redirect_count > 0 && (
            <div className="glass border border-white/[0.08] p-5 rounded-2xl animate-slide-up">
              <h3 className="text-sm font-semibold text-white mb-3">
                Redirect Chain ({expand.redirect_count} hop{expand.redirect_count > 1 ? 's' : ''})
              </h3>
              <div className="space-y-2">
                {expand.redirect_chain.map((url, i) => (
                  <div key={i} className="flex items-start gap-3 text-xs font-mono">
                    <span className="w-5 h-5 rounded-md bg-white/5 border border-white/10 flex items-center justify-center shrink-0 text-white/40">
                      {i + 1}
                    </span>
                    <span className="text-white/60 break-all">{url}</span>
                    {expand.status_codes[i] && (
                      <span className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] border
                        ${[301,302,303,307,308].includes(expand.status_codes[i])
                          ? 'bg-suspicious/10 border-suspicious/20 text-suspicious'
                          : 'bg-white/5 border-white/10 text-white/40'}`}>
                        {expand.status_codes[i]}
                      </span>
                    )}
                  </div>
                ))}
              </div>
              {expand.is_shortened && (
                <div className="mt-3 text-xs text-suspicious flex items-center gap-1.5">
                  <AlertCircle size={11}/> Shortened URL detected
                </div>
              )}
            </div>
          )}

          {/* Tier cards */}
          <div className="grid gap-4">
            <UmbrellaTierCard
              umbrella={result.umbrella}
              isDeciding={exitTier === 'T0-URLhaus' || exitTier === 'T0-Umbrella'}
            />
            <WhitelistTierCard
              reasoning={result.reasoning}
              isDeciding={exitTier === 'T1-Whitelist'}
            />
            <DistilBertTierCard
              bertScore={result.expert_scores.distilbert}
              finalConf={result.confidence}
              isDeciding={exitTier === 'T2-DistilBERT'}
              skipped={exitTier === 'T0-URLhaus' || exitTier === 'T0-Umbrella' || exitTier === 'T1-Whitelist'}
            />
            <HardSignalTierCard
              hardScore={result.hard_score}
              breakdown={result.hard_signal_breakdown}
              isDeciding={exitTier === 'T3-HardSignal'}
            />
          </div>

          {/* Feature grid */}
          <FeatureGrid features={result.features} />
        </div>
      )}
    </div>
  );
}
