// TypeScript interfaces matching the FastAPI response schemas

export type ThreatLevel = 'Safe' | 'Suspicious' | 'Malicious' | 'Unknown';

export interface RedirectHop {
  hop: number;
  url: string;
  status_code: number | null;
  is_suspicious: boolean;
  hop_risk_score?: number;
}

export interface FeatureSet {
  url_length: number;
  domain_length: number;
  subdomain_depth: number;
  path_depth: number;
  query_length: number;
  num_query_params: number;
  dot_count: number;
  hyphen_count: number;
  digit_ratio: number;
  uppercase_ratio: number;
  special_char_ratio: number;
  url_entropy: number;
  domain_entropy: number;
  has_https: boolean;
  tld_suspicious: boolean;
  has_ip: boolean;
  has_at_symbol: boolean;
  double_slash_path: boolean;
  has_suspicious_port: boolean;
  redirect_depth: number;
  keyword_score: number;
  brand_in_subdomain: boolean;
  has_homograph: boolean;
  domain_age_proxy: number;
  chain_length: number;
}

export interface MLPrediction {
  label: ThreatLevel;
  confidence: number;
  threat_probability: number;
}

export interface RiskScore {
  score: number;
  level: ThreatLevel;
  breakdown: {
    ml_contribution: number;
    redirect_contribution: number;
    heuristic_contribution: number;
  };
}

export interface AnalyzeResponse {
  original_url: string;
  expanded_url: string;
  is_shortened: boolean;
  shortener_domain: string | null;
  redirect_chain: RedirectHop[];
  redirect_count: number;
  loop_detected: boolean;
  excessive_redirects: boolean;
  features: FeatureSet;
  prediction: MLPrediction;
  risk_score: RiskScore;
  analysis_time_ms: number;
  errors: string[];
}

export interface AnalyzeRequest {
  url: string;
  follow_redirects?: boolean;
  timeout?: number;
}

export type AnalysisState =
  | { status: 'idle' }
  | { status: 'loading'; step: string }
  | { status: 'success'; data: AnalyzeResponse }
  | { status: 'error'; message: string };
