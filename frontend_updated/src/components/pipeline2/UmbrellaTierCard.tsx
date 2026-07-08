import { HelpCircle, Database } from 'lucide-react';
import type { DaaUmbrellaResult } from '../../types/daaApi';

interface UmbrellaTierCardProps {
  umbrella:    DaaUmbrellaResult | null;
  isDeciding:  boolean;   // true if this tier produced the final verdict
}

const STATUS_LABELS: Record<string, string> = {
  '-1': 'MALICIOUS — flagged by threat DB',
  '0':  'UNKNOWN — low authority or not indexed',
  '1':  'SAFE — high PageRank authority',
};

/** Safe number formatter — never throws on undefined/null */
const safeNum = (v: unknown, digits = 3): string => {
  if (v === undefined || v === null || typeof v !== 'number' || isNaN(v)) return '—';
  return v.toFixed(digits);
};

/** Safe boolean formatter */
const safeBool = (v: unknown): string =>
  v === undefined || v === null ? '—' : Boolean(v) ? 'YES' : 'NO';

/** Derive security rows dynamically from whatever the backend sends */
function buildSecurityRows(security: Record<string, unknown>) {
  const rows: { label: string; value: string; warn: boolean }[] = [];

  // URLhaus fields
  if ('url_count' in security)
    rows.push({ label: 'URL Count',    value: String(security.url_count ?? 0),  warn: Number(security.url_count) > 0 });
  if ('online_count' in security)
    rows.push({ label: 'Online URLs',  value: String(security.online_count ?? 0), warn: Number(security.online_count) > 0 });
  if ('spamhaus_dbl' in security)
    rows.push({ label: 'Spamhaus DBL', value: String(security.spamhaus_dbl ?? '—'), warn: security.spamhaus_dbl !== 'not listed' });
  if ('surbl' in security)
    rows.push({ label: 'SURBL',        value: String(security.surbl ?? '—'),       warn: security.surbl === 'listed' });
  if ('url_status' in security)
    rows.push({ label: 'URL Status',   value: String(security.url_status ?? '—'),   warn: security.url_status === 'online' });

  // Legacy Umbrella fields (kept for compatibility)
  if ('dga_score' in security)
    rows.push({ label: 'DGA Score',   value: safeNum(security.dga_score as number), warn: Number(security.dga_score) > 0.80 });
  if ('spam' in security)
    rows.push({ label: 'Spam Score',  value: safeNum(security.spam as number),       warn: Number(security.spam) > 0.60 });
  if ('fastflux' in security)
    rows.push({ label: 'Fastflux',    value: safeBool(security.fastflux),            warn: Boolean(security.fastflux) });
  if ('botnet' in security)
    rows.push({ label: 'Botnet',      value: safeBool(security.botnet),              warn: Boolean(security.botnet) });

  return rows;
}

export default function UmbrellaTierCard({ umbrella, isDeciding }: UmbrellaTierCardProps) {
  const available = umbrella && umbrella.source !== 'unavailable';
  const verdict   = umbrella?.verdict ?? 'unavailable';

  // Detect which backend is active from the source field
  const isPageRank = umbrella?.source === 'pagerank' || umbrella?.source === 'cached';
  const isUrlhaus  = umbrella?.source === 'urlhaus';
  const tierName   = isPageRank ? 'Open PageRank' : isUrlhaus ? 'URLhaus Threat Intel' : 'Cisco Umbrella Investigate';
  const envHint    = isPageRank ? 'OPEN_PAGERANK_API' : isUrlhaus ? 'URL_HAUS_API' : 'UMBRELLA_INVESTIGATE_TOKEN';

  const borderColor = isDeciding
    ? verdict === 'malicious' ? 'border-malicious/40' : 'border-safe/40'
    : 'border-white/[0.08]';

  const securityRows = (available && umbrella?.security)
    ? buildSecurityRows(umbrella.security as Record<string, unknown>)
    : [];

  const latency = typeof umbrella?.latency_ms === 'number'
    ? `${umbrella.latency_ms.toFixed(0)} ms`
    : '— ms';

  return (
    <div className={`glass border ${borderColor} p-5 rounded-2xl animate-slide-up`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2.5">
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center
            ${isDeciding ? 'bg-brand/20 border border-brand/30' : 'bg-white/5'}`}>
            <Database size={15} className={isDeciding ? 'text-brand-light' : 'text-white/30'} />
          </div>
          <div>
            <div className="text-xs font-mono text-white/40">Tier 0</div>
            <div className="text-sm font-semibold text-white">{tierName}</div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isDeciding && (
            <span className="tier-badge bg-brand/20 border-brand/30 text-brand-light border">
              DECIDED
            </span>
          )}
          <span className={`tier-badge border ${
            !available
              ? 'bg-white/5 border-white/10 text-white/30'
              : verdict === 'malicious' ? 'bg-malicious/10 border-malicious/20 text-malicious'
              : verdict === 'safe'      ? 'bg-safe/10 border-safe/20 text-safe'
              : 'bg-white/5 border-white/10 text-white/50'
          }`}>
            {!available ? 'NOT CONFIGURED' : verdict.toUpperCase()}
          </span>
        </div>
      </div>

      {!available ? (
        <div className="text-xs text-white/30 flex items-center gap-2 py-3">
          <HelpCircle size={13}/>
          Set <span className="font-mono text-white/50">{envHint}</span> in{' '}
          <span className="font-mono text-white/50">daa_model/.env</span> to enable Tier 0.
          DistilBERT handles all URLs.
        </div>
      ) : (
        <div className="space-y-3">
          {/* Domain + source + latency */}
          <div className="flex items-center gap-3 text-xs text-white/50">
            <span className="font-mono text-white/70">{umbrella?.domain ?? '—'}</span>
            <span className="tier-badge bg-white/5 border-white/10 text-white/30 border">
              {umbrella?.source ?? '—'}
            </span>
            <span>{latency}</span>
          </div>

          {/* Status indicator */}
          {umbrella?.status !== null && umbrella?.status !== undefined && (
            <div className="text-xs text-white/40 font-mono">
              status = {umbrella.status}&nbsp;—&nbsp;
              {STATUS_LABELS[String(umbrella.status)] ?? 'Unknown'}
            </div>
          )}

          {/* Confidence bar */}
          <div>
            <div className="flex justify-between text-xs text-white/40 mb-1">
              <span>Confidence</span>
              <span className="font-mono">
                {typeof umbrella?.confidence === 'number'
                  ? `${Math.round(umbrella.confidence * 100)}%`
                  : '—'}
              </span>
            </div>
            <div className="score-bar-track">
              <div
                className={`score-bar-fill ${
                  verdict === 'malicious' ? 'bg-malicious'
                  : verdict === 'safe'    ? 'bg-safe'
                  : 'bg-white/20'}`}
                style={{ width: `${(umbrella?.confidence ?? 0) * 100}%` }}
              />
            </div>
          </div>

          {/* Security indicators — dynamic, works for URLhaus AND Umbrella */}
          {securityRows.length > 0 && (
            <div className="grid grid-cols-2 gap-2">
              {securityRows.map(({ label, value, warn }) => (
                <div key={label} className="flex justify-between text-xs p-2 rounded-lg bg-white/[0.03] border border-white/[0.05]">
                  <span className="text-white/40">{label}</span>
                  <span className={`font-mono ${warn ? 'text-malicious' : 'text-white/60'}`}>
                    {value}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Tags / Categories */}
          {umbrella?.categories && Object.keys(umbrella.categories).length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {Object.keys(umbrella.categories).slice(0, 6).map(cat => (
                <span key={cat} className="text-[10px] px-2 py-0.5 rounded-full bg-malicious/10 border border-malicious/20 text-malicious">
                  {cat}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
