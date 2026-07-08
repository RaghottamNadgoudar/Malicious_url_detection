export type Verdict = 'safe' | 'suspicious' | 'malicious' | 'error';
export type ExitTier = 'T0-URLhaus' | 'T0-Umbrella' | 'T1-Whitelist' | 'T2-DistilBERT' | 'T3-HardSignal';

// ── Feature set — exact 14-field struct from pipeline_bert._feature_summary ──
export interface DaaFeatures {
  url_length:         number;
  domain_length:      number;
  subdomain_depth:    number;
  has_https:          boolean;
  tld_suspicion:      boolean;
  has_ip:             boolean;
  has_at_symbol:      boolean;
  keyword_score:      number;   // 0–1
  brand_in_subdomain: boolean;
  url_entropy:        number;
  dot_count:          number;
  hyphen_count:       number;
  tld:                string;
  registrable_domain: string;
}

// ── Threat intel result — from cisco_umbrella.UmbrellaResult (works for URLhaus too) ──
export interface DaaUmbrellaResult {
  domain:     string;
  verdict:    'malicious' | 'suspicious' | 'safe' | 'unknown' | 'unavailable';
  status:     -1 | 0 | 1 | null;
  confidence: number;
  categories: Record<string, number>;   // URLhaus: tags, Umbrella: categories
  // Flexible security bag — fields vary by backend:
  //   URLhaus:  { url_count, online_count, spamhaus_dbl, surbl, url_status? }
  //   Umbrella: { dga_score, spam, fastflux, botnet, securerank2 }
  security: Record<string, unknown>;
  source:     'urlhaus' | 'umbrella' | 'cached' | 'unavailable';
  latency_ms: number;
}

// ── /classify response — from pipeline_bert._build_result ────────────────────
export interface DaaClassifyResult {
  url:        string;
  verdict:    Verdict;
  confidence: number;
  expert_scores: {
    distilbert: number | null;  // null when short-circuited at T0/T1
  };
  features:   DaaFeatures;
  reasoning:  string;
  pipeline:   'distilbert_only';
  umbrella:   DaaUmbrellaResult | null;
  latency_ms: number;
}

// ── Hard signal breakdown — added by /classify-detail ────────────────────────
export interface HardSignalBreakdown {
  suspicious_tld:    number;
  has_ip:            number;
  has_at:            number;
  brand_in_subdomain: number;
  keyword_boost:     number;
  double_slash_path: number;
  high_entropy:      number;
}

// ── /classify-detail response ─────────────────────────────────────────────────
export interface DaaClassifyDetailResult extends DaaClassifyResult {
  hard_score:            number;
  exit_tier:             ExitTier;
  hard_signal_breakdown: HardSignalBreakdown;
}

// ── BatchOptimizer pre-classified URL (Stage 0–4 decided) ────────────────────
export interface DaaBatchDecidedRecord {
  url:          string;
  verdict:      Verdict;
  confidence:   number;
  stage:        'S0-dedup' | 'S1-whitelist' | 'S2-horspool' | 'S3-greedy' | 'S4-backtrack';
  reason:       string;
  keyword_hits: string[];
  hard_score:   number;
}

// ── Stage counts from BatchOptimizer.process() ───────────────────────────────
export interface DaaStageCount {
  input:            number;
  after_dedup:      number;
  after_whitelist:  number;
  after_horspool:   number;
  after_greedy:     number;
  to_distilbert:    number;
}

// ── /batch-optimize/stream — final 'complete' event payload ──────────────────
export interface DaaBatchCompleteResult {
  total_input:      number;
  stage_counts:     DaaStageCount;
  decided:          DaaBatchDecidedRecord[];
  uncertain_results: DaaClassifyResult[];
  reduction_pct:    number;
  elapsed_ms:       number;
  huffman_ratio:    number;
  selected_features: string[];
}

// ── SSE event union type ──────────────────────────────────────────────────────
export type DaaSseEvent =
  | { event: 'start';          total: number; pipeline: string }
  | { event: 'optimizer_done'; stage_counts: DaaStageCount; decided: DaaBatchDecidedRecord[]; decided_count: number; uncertain_count: number; reduction_pct: number; optimizer_elapsed_ms: number; selected_features: string[] }
  | { event: 'url_classified'; index: number; total: number; result: DaaClassifyResult }
  | { event: 'url_error';      index: number; url: string; error: string }
  | { event: 'complete';       } & DaaBatchCompleteResult
  | { event: 'error';          message: string }

// ── /expand-url response — from url_expander.expand_url() ───────────────────
export interface DaaExpandResult {
  original_url:        string;
  final_url:           string;
  redirect_chain:      string[];
  redirect_count:      number;
  is_shortened:        boolean;
  expansion_successful: boolean;
  error:               string | null;
  status_codes:        number[];
}

// ── /health response ─────────────────────────────────────────────────────────
export interface DaaHealthResult {
  status:       string;
  model_loaded: boolean;
  pipeline:     string;
}
