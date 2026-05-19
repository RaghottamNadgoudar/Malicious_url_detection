import React, { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, Loader } from 'lucide-react';
import { analyzeURL } from '../services/api';

const URLAnalyzer = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleAnalyze = async (e) => {
    e.preventDefault();
    
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await analyzeURL(url);
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to analyze URL');
    } finally {
      setLoading(false);
    }
  };

  const getVerdictColor = (verdict) => {
    switch (verdict) {
      case 'safe': return 'text-success-600 bg-success-50';
      case 'suspicious': return 'text-warning-600 bg-warning-50';
      case 'malicious': return 'text-danger-600 bg-danger-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getVerdictIcon = (verdict) => {
    switch (verdict) {
      case 'safe': return <CheckCircle className="w-6 h-6" />;
      case 'suspicious': return <AlertTriangle className="w-6 h-6" />;
      case 'malicious': return <XCircle className="w-6 h-6" />;
      default: return <Shield className="w-6 h-6" />;
    }
  };

  return (
    <div className="card">
      <div className="flex items-center gap-3 mb-6">
        <Shield className="w-8 h-8 text-primary-500" />
        <h2 className="text-2xl font-bold">URL Analyzer</h2>
      </div>

      <form onSubmit={handleAnalyze} className="space-y-4">
        <div>
          <label htmlFor="url" className="block text-sm font-medium text-gray-700 mb-2">
            Enter URL to analyze
          </label>
          <input
            type="text"
            id="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="btn btn-primary w-full flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <Loader className="w-5 h-5 animate-spin" />
              Analyzing...
            </>
          ) : (
            <>
              <Shield className="w-5 h-5" />
              Analyze URL
            </>
          )}
        </button>
      </form>

      {error && (
        <div className="mt-4 p-4 bg-danger-50 border border-danger-200 rounded-lg text-danger-600">
          {error}
        </div>
      )}

      {result && (
        <div className="mt-6 space-y-4">
          {/* URL Expansion Info (if shortened) */}
          {result.url_expansion && result.url_expansion.is_shortened && (
            <div className="p-4 bg-yellow-50 border-l-4 border-yellow-400 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-5 h-5 text-yellow-600" />
                <h4 className="font-semibold text-yellow-900">URL Shortener Detected</h4>
              </div>
              <div className="text-sm space-y-1 text-yellow-800">
                <p><span className="font-medium">Original:</span> {result.url}</p>
                <p><span className="font-medium">Final Destination:</span> {result.url_expansion.final_url}</p>
                <p><span className="font-medium">Redirects:</span> {result.url_expansion.redirect_count}</p>
                {result.url_expansion.redirect_chain.length > 1 && (
                  <details className="mt-2">
                    <summary className="cursor-pointer font-medium">View Redirect Chain</summary>
                    <ol className="mt-2 ml-4 list-decimal space-y-1">
                      {result.url_expansion.redirect_chain.map((redirectUrl, idx) => (
                        <li key={idx} className="text-xs break-all">{redirectUrl}</li>
                      ))}
                    </ol>
                  </details>
                )}
              </div>
            </div>
          )}

          {/* Final Verdict */}
          <div className={`p-6 rounded-lg ${getVerdictColor(result.final_verdict.verdict)}`}>
            <div className="flex items-center gap-3 mb-2">
              {getVerdictIcon(result.final_verdict.verdict)}
              <h3 className="text-xl font-bold capitalize">{result.final_verdict.verdict}</h3>
            </div>
            <p className="text-sm mb-2">
              Confidence: <span className="font-semibold">{result.final_verdict.confidence}</span>
            </p>
            <p className="text-sm">
              Threat Probability: <span className="font-semibold">
                {(result.final_verdict.threat_probability * 100).toFixed(1)}%
              </span>
            </p>
            <p className="text-sm mt-2 opacity-90">{result.final_verdict.recommendation}</p>
            {result.final_verdict.warning && (
              <p className="text-sm mt-2 font-semibold">⚠️ {result.final_verdict.warning}</p>
            )}
          </div>

          {/* Phase Results */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Phase 1: Graph */}
            <div className="p-4 bg-blue-50 rounded-lg">
              <h4 className="font-semibold text-blue-900 mb-2">Phase 1: Graph Traversal</h4>
              <div className="text-sm space-y-1 text-blue-800">
                <p>Entropy: {result.phase1_graph.entropy.toFixed(2)}</p>
                <p>Redirect Depth: {result.phase1_graph.redirect_depth}</p>
                <p>Chain Length: {result.phase1_graph.chain_length}</p>
              </div>
            </div>

            {/* Phase 2: Pattern */}
            <div className="p-4 bg-teal-50 rounded-lg">
              <h4 className="font-semibold text-teal-900 mb-2">Phase 2: Pattern Matching</h4>
              <div className="text-sm space-y-1 text-teal-800">
                <p>Pattern Score: {(result.phase2_pattern.pattern_score * 100).toFixed(1)}%</p>
                <p>Keywords Found: {result.phase2_pattern.match_count}</p>
                <p>Has IP: {result.phase2_pattern.has_ip_address ? 'Yes' : 'No'}</p>
              </div>
            </div>

            {/* Phase 3: Neural */}
            <div className="p-4 bg-purple-50 rounded-lg">
              <h4 className="font-semibold text-purple-900 mb-2">Phase 3: Neural Classifier</h4>
              <div className="text-sm space-y-1 text-purple-800">
                <p>Verdict: <span className="capitalize">{result.phase3_neural.verdict}</span></p>
                <p>Action: {result.phase3_neural.action.replace(/_/g, ' ')}</p>
                <p>Probability: {(result.phase3_neural.threat_probability * 100).toFixed(1)}%</p>
              </div>
            </div>

            {/* Phase 5: Bloom Filter */}
            <div className="p-4 bg-pink-50 rounded-lg">
              <h4 className="font-semibold text-pink-900 mb-2">Phase 5: Bloom Filter</h4>
              <div className="text-sm space-y-1 text-pink-800">
                <p>In Filter: {result.phase5_bloom.bloom_result.in_bloom_filter ? 'Yes' : 'No'}</p>
                <p>LSH Similarity: {(result.phase5_bloom.bloom_result.lsh_similarity * 100).toFixed(1)}%</p>
                <p>Verified: {result.phase5_bloom.constraint_verified ? 'Yes' : 'No'}</p>
              </div>
            </div>
          </div>

          {/* Matched Keywords */}
          {result.phase2_pattern.matched_keywords.length > 0 && (
            <div className="p-4 bg-gray-50 rounded-lg">
              <h4 className="font-semibold text-gray-900 mb-2">Matched Phishing Keywords</h4>
              <div className="flex flex-wrap gap-2">
                {result.phase2_pattern.matched_keywords.map((keyword, idx) => (
                  <span key={idx} className="px-2 py-1 bg-warning-100 text-warning-700 rounded text-xs">
                    {keyword}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default URLAnalyzer;
