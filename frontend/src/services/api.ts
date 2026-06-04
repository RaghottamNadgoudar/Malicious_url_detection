import axios from 'axios';
import type { AnalyzeRequest, AnalyzeResponse } from '../types/analysis';

const BASE_URL = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 60_000,
  headers: { 'Content-Type': 'application/json' },
});

// ─── Suspicious URL heuristics ────────────────────────────────
const SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.link', '.work'];
const PHISHING_KEYWORDS = ['login', 'secure', 'verify', 'account', 'update', 'banking', 'paypal', 'amazon', 'apple', 'google', 'microsoft'];

function isUrlSuspicious(url: string): boolean {
  const lower = url.toLowerCase();
  const hasIP = /https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url);
  const hasBadTLD = SUSPICIOUS_TLDS.some(t => lower.includes(t));
  const hasKeyword = PHISHING_KEYWORDS.some(k => lower.includes(k) && !lower.includes('github') && !lower.includes('microsoft.com'));
  return hasIP || hasBadTLD || hasKeyword;
}

// ─── Feature extraction from phase3 array + feature_names ────
function extractFeatures(p3: any, p1: any): Record<string, any> {
  const featObj: Record<string, any> = {};

  // phase3_neural returns features as a flat array + feature_names array
  if (Array.isArray(p3.features) && Array.isArray(p3.feature_names)) {
    p3.feature_names.forEach((name: string, i: number) => {
      featObj[name] = p3.features[i];
    });
  }

  // Some backends use 'tld_suspicion' instead of 'tld_suspicious'
  if ('tld_suspicion' in featObj && !('tld_suspicious' in featObj)) {
    featObj['tld_suspicious'] = Boolean(featObj['tld_suspicion']);
    delete featObj['tld_suspicion'];
  }

  // Convert boolean-like numbers from ML model
  const boolKeys = ['has_https', 'tld_suspicious', 'has_ip', 'has_at_symbol',
    'double_slash_path', 'has_suspicious_port', 'brand_in_subdomain', 'has_homograph'];
  boolKeys.forEach(k => {
    if (k in featObj) featObj[k] = Boolean(featObj[k]);
  });

  // Fallback: also merge phase1 fields if present as an object
  if (p1 && typeof p1 === 'object') {
    const p1Keys = ['url_length','domain_length','subdomain_depth','path_depth',
      'query_length','num_query_params','dot_count','hyphen_count','digit_ratio',
      'uppercase_ratio','special_char_ratio','url_entropy','domain_entropy',
      'has_https','has_ip','redirect_depth','domain_age_proxy'];
    p1Keys.forEach(k => {
      if (!(k in featObj) && k in p1) featObj[k] = p1[k];
    });
  }

  // Ensure all required FeatureSet keys are present
  const defaults: Record<string, any> = {
    url_length: 0, domain_length: 0, subdomain_depth: 0, path_depth: 0,
    query_length: 0, num_query_params: 0, dot_count: 0, hyphen_count: 0,
    digit_ratio: 0, uppercase_ratio: 0, special_char_ratio: 0,
    url_entropy: featObj['url_entropy'] ?? (p3.shannon_entropy ?? 0),
    domain_entropy: 0, has_https: false, tld_suspicious: false,
    has_ip: false, has_at_symbol: false, double_slash_path: false,
    has_suspicious_port: false, redirect_depth: 0, keyword_score: 0,
    brand_in_subdomain: false, has_homograph: false, domain_age_proxy: 0,
    chain_length: 0,
  };

  return { ...defaults, ...featObj };
}

// ─── Build redirect chain from url_expansion ─────────────────
function buildRedirectChain(exp: any): Array<{hop: number; url: string; status_code: number | null; is_suspicious: boolean}> {
  const urls: string[] = Array.isArray(exp?.redirect_chain) ? exp.redirect_chain : [];
  const codes: number[] = Array.isArray(exp?.status_codes) ? exp.status_codes : [];

  if (urls.length === 0) return [];

  return urls.map((url, idx) => ({
    hop: idx + 1,
    url,
    status_code: codes[idx] ?? null,
    is_suspicious: isUrlSuspicious(url),
  }));
}

// ─── Main response adapter ────────────────────────────────────
function adaptFlaskResponse(raw: any): AnalyzeResponse {
  const p3  = raw.phase3_neural  || {};
  const p1  = raw.phase1_graph   || {};
  const exp = raw.url_expansion  || {};
  const fv  = raw.final_verdict  || {};

  // Verdict mapping
  const verdictMap: Record<string, 'Safe' | 'Suspicious' | 'Malicious' | 'Unknown'> = {
    safe:       'Safe',
    malicious:  'Malicious',
    suspicious: 'Suspicious',
    uncertain:  'Suspicious',
    unknown:    'Unknown',
  };
  const rawVerdict = fv.verdict || p3.verdict || 'unknown';
  const label = verdictMap[rawVerdict] ?? 'Unknown';

  // Probabilities & scores
  const threatProb  = Number(fv.threat_probability ?? p3.threat_probability ?? 0);
  const riskScore   = Math.min(100, Math.round(threatProb * 100));

  // Confidence: map text → number
  const confText = fv.confidence ?? 'low';
  const confidence = confText === 'high' ? 0.9 : confText === 'medium' ? 0.7 : 0.5;

  // Redirect chain — built from url_expansion data
  const redirectChain = buildRedirectChain(exp);

  // Redirect count: use exp.redirect_count, fallback to chain length - 1
  const redirectCount = Number(exp.redirect_count ?? Math.max(0, redirectChain.length - 1));

  // Features
  const features = extractFeatures(p3, p1);
  features.chain_length = redirectChain.length;
  features.redirect_depth = Number(p1.redirect_depth ?? redirectCount);

  // Risk score breakdown
  const mlScore       = Math.min(55, Math.round(threatProb * 55));
  const redirectScore = Math.min(25, redirectCount * 5);
  const heurScore     = Math.max(0, Math.min(20, riskScore - mlScore - redirectScore));

  return {
    original_url:       raw.url || '',
    expanded_url:       exp.final_url || raw.analyzed_url || raw.url || '',
    is_shortened:       Boolean(exp.is_shortened),
    shortener_domain:   exp.shortener_domain ?? null,
    redirect_count:     redirectCount,
    redirect_chain:     redirectChain,
    loop_detected:      Boolean(p1.loop_detected ?? false),
    excessive_redirects: redirectCount > 5,
    features: features as any,
    prediction: {
      label,
      confidence,
      threat_probability: threatProb,
    },
    risk_score: {
      score: riskScore,
      level: label,
      breakdown: {
        ml_contribution:        mlScore,
        redirect_contribution:  redirectScore,
        heuristic_contribution: heurScore,
      },
    },
    analysis_time_ms: Math.round(Number(p1.analysis_time_ms || p3.analysis_time_ms || 800)),
    errors: Array.isArray(raw.errors) ? raw.errors : [],
  };
}

export async function analyzeUrl(req: AnalyzeRequest): Promise<AnalyzeResponse> {
  const { data } = await api.post('/api/analyze', { url: req.url });
  return adaptFlaskResponse(data);
}

export async function checkHealth(): Promise<{ status: string; model_loaded: boolean }> {
  const { data } = await api.get('/api/health');
  return { status: data.status, model_loaded: Boolean(data.dataset_loaded ?? true) };
}
