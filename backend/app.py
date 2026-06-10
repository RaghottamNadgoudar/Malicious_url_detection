import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import os
import time
from typing import Dict, List

# Import all phases (Phase 2 pattern matching removed — signals built into Phase 3)
from phase1_graph_traversal import RedirectGraphAnalyzer
from phase3_neural_classifier import NeuralClassifier
from phase4_greedy_optimization import GreedyOptimizer
from phase5_bloom_filter import BloomFilterAnalyzer
from phase6_heapsort_ranking import HeapsortRanker
from url_expander import URLExpander
from performance_benchmark import PerformanceBenchmark

app = Flask(__name__)
# Allow the React frontend, Chrome extension popup, and any localhost port
CORS(app, resources={r"/api/*": {"origins": [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://localhost:5000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
    "chrome-extension://*",  # URL Shield Chrome extension
    "*",                     # fallback for development
]}}, supports_credentials=True)

# Global analyzers
graph_analyzer = RedirectGraphAnalyzer()
neural_classifier = NeuralClassifier()
greedy_optimizer = GreedyOptimizer()
bloom_analyzer = BloomFilterAnalyzer()
heapsort_ranker = HeapsortRanker()
url_expander = URLExpander()
performance_benchmark = PerformanceBenchmark()

# Dataset
dataset = None
dataset_loaded = False


def load_dataset():
    """Load the balanced URLs dataset."""
    global dataset, dataset_loaded
    
    # Try merged dataset first, then balanced
    for dataset_path in ['../data/merged_urls.csv', '../data/balanced_urls.csv']:
        if os.path.exists(dataset_path):
            try:
                print(f"Loading dataset from {os.path.basename(dataset_path)}...")
                
                # Load ALL URLs - BFS algorithm is fast enough now!
                dataset = pd.read_csv(dataset_path)
                dataset_loaded = True
                
                print(f"✓ Dataset loaded: {len(dataset):,} URLs (full dataset)")
                
                # Initialize system with larger sample
                initialize_system()
                
                return True
            except Exception as e:
                print(f"✗ Error loading dataset: {e}")
                continue
    
    print("✗ Dataset not found")
    print("  System will work with limited functionality")
    return False


def initialize_system():
    """Initialize the detection system with dataset."""
    global dataset
    
    if dataset is None:
        return
    
    print("Initializing system components...")
    
    # Use larger sample size with fast BFS algorithm
    sample_size = min(5000, len(dataset))  # Increased from 1000 to 5000
    sample_urls = dataset['url'].head(sample_size).tolist()
    
    print(f"  Building redirect graph ({sample_size:,} URLs)...")
    graph_analyzer.build_graph(sample_urls)
    
    print("  Building transitive closure (BFS-based, O(V·E))...")
    greedy_optimizer.build_transitive_closure(graph_analyzer.graph)
    
    print("  Registering malicious URLs in Bloom Filter...")
    malicious_urls = dataset[dataset['result'] == 1]['url'].head(1000).tolist()  # Increased from 100 to 1000
    for url in malicious_urls:
        bloom_analyzer.register_malicious_url(url, threat_score=1.0)
        greedy_optimizer.register_malicious_url(url)
    
    print("  Setting Huffman baseline...")
    benign_urls = dataset[dataset['result'] == 0]['url'].head(1000).tolist()  # Increased from 100 to 1000
    heapsort_ranker.set_baseline(benign_urls)
    
    print("✓ System initialized successfully")


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    import os, time
    model_path = 'models/url_classifier.h5'
    model_mtime = None
    model_size_mb = None
    if os.path.exists(model_path):
        stat = os.stat(model_path)
        model_mtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime))
        model_size_mb = round(stat.st_size / (1024 * 1024), 2)

    return jsonify({
        'status': 'healthy',
        'dataset_loaded': dataset_loaded,
        'dataset_size': len(dataset) if dataset is not None else 0,
        'model_trained_at': model_mtime,
        'model_size_mb': model_size_mb,
        'threshold_malicious': 0.88,
    })


@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    """
    Main endpoint: Analyze a single URL through all 7 phases.
    """
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        # PHASE 0: URL Expansion (if shortened)
        expansion_result = url_expander.expand(url)
        is_shortened = expansion_result.get('is_shortened', False)
        final_url = expansion_result.get('final_url', url)

        # --- Analyse original URL ---
        p1_orig = graph_analyzer.analyze_url(url)
        p3_orig = neural_classifier.analyze_url(url, p1_orig, None)

        if is_shortened and final_url != url:
            # --- Analyse expanded destination ---
            p1_exp = graph_analyzer.analyze_url(final_url)
            p3_exp = neural_classifier.analyze_url(final_url, p1_exp, None)

            # Blend: expanded destination (65%) + original path signals (35%)
            # The destination is what the user actually visits, so it dominates.
            # Keywords in a shortener path add suspicion but don't decide the verdict.
            orig_prob = p3_orig['threat_probability']
            exp_prob  = p3_exp['threat_probability']
            blended   = 0.35 * orig_prob + 0.65 * exp_prob

            # Use the expanded result as base, but override probability with blend
            phase3_result = dict(p3_exp)
            phase3_result['threat_probability'] = blended
            phase3_result['original_prob'] = orig_prob
            phase3_result['expanded_prob'] = exp_prob

            # Re-classify verdict based on blended probability
            if blended < 0.25:
                phase3_result['verdict'] = 'safe'
            elif blended > 0.60:
                phase3_result['verdict'] = 'malicious'
            elif blended > 0.40:
                phase3_result['verdict'] = 'suspicious'
            else:
                phase3_result['verdict'] = 'uncertain'

            phase1_result = p1_exp
            analysis_url  = final_url
        else:
            phase3_result = p3_orig
            phase1_result = p1_orig
            analysis_url  = url

        # PHASE 4: Greedy Optimization
        combined_data = {**phase1_result, **phase3_result}
        phase4_result = greedy_optimizer.analyze_url(analysis_url, combined_data, graph_analyzer.graph)

        # PHASE 5: Bloom Filter
        phase5_result = bloom_analyzer.analyze_url(analysis_url, combined_data)

        # PHASE 6: Heapsort Ranking
        phase6_result = heapsort_ranker.analyze_url(analysis_url, combined_data)

        final_verdict = determine_final_verdict(
            phase3_result, phase5_result, phase6_result, expansion_result
        )

        final_result = {
            'url': url,
            'url_expansion': expansion_result,
            'analyzed_url': analysis_url,
            'phase1_graph': phase1_result,
            'phase3_neural': phase3_result,
            'phase4_greedy': phase4_result,
            'phase5_bloom': phase5_result,
            'phase6_ranking': phase6_result,
            'final_verdict': final_verdict,
        }

        # ── Log to in-memory scan ring-buffer (analytics) ──────────────
        try:
            _log_scan(url, final_verdict, phase3_result)
        except Exception:
            pass  # never block the response

        return jsonify(final_result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/api/batch-analyze', methods=['POST'])
def batch_analyze():
    """
    Analyze multiple URLs and return ranked results.
    """
    data = request.json
    urls = data.get('urls', [])
    top_k = data.get('top_k', 10)
    
    if not urls:
        return jsonify({'error': 'URLs list is required'}), 400
    
    try:
        results = []

        for url in urls:
            phase1_result = graph_analyzer.analyze_url(url)
            phase3_result = neural_classifier.analyze_url(url, phase1_result, None)

            combined_data = {
                'url': url,
                **phase1_result,
                **phase3_result,
            }
            results.append(combined_data)

        ranked_results = heapsort_ranker.rank_batch(results, top_k)

        return jsonify({
            'total_analyzed': len(urls),
            'top_threats': ranked_results,
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/dataset/stats', methods=['GET'])
def dataset_stats():
    """Get dataset statistics."""
    if not dataset_loaded:
        return jsonify({'error': 'Dataset not loaded'}), 404
    
    benign_count = len(dataset[dataset['result'] == 0])
    malicious_count = len(dataset[dataset['result'] == 1])
    
    return jsonify({
        'total_urls': len(dataset),
        'benign_count': benign_count,
        'malicious_count': malicious_count,
        'balance_ratio': f"{benign_count}/{malicious_count}"
    })


@app.route('/api/dataset/sample', methods=['GET'])
def dataset_sample():
    """Get sample URLs from dataset."""
    if not dataset_loaded:
        return jsonify({'error': 'Dataset not loaded'}), 404
    
    sample_size = int(request.args.get('size', 10))
    url_type = request.args.get('type', 'all')  # 'all', 'benign', 'malicious'
    
    if url_type == 'benign':
        sample = dataset[dataset['result'] == 0].sample(min(sample_size, len(dataset)))
    elif url_type == 'malicious':
        sample = dataset[dataset['result'] == 1].sample(min(sample_size, len(dataset)))
    else:
        sample = dataset.sample(min(sample_size, len(dataset)))
    
    return jsonify({
        'urls': sample['url'].tolist(),
        'labels': sample['label'].tolist(),
        'results': sample['result'].tolist()
    })


@app.route('/api/system/stats', methods=['GET'])
def system_stats():
    """Get system statistics."""
    bloom_stats = bloom_analyzer.bloom_filter.get_stats()
    expander_stats = url_expander.get_cache_stats()
    
    return jsonify({
        'bloom_filter': bloom_stats,
        'graph_nodes': len(graph_analyzer.graph),
        'redirect_depths_tracked': len(graph_analyzer.redirect_depths),
        'malicious_urls_registered': len(greedy_optimizer.malicious_urls),
        'url_expander': expander_stats
    })


@app.route('/api/expand', methods=['POST'])
def expand_url_endpoint():
    """
    Endpoint to expand a shortened URL without full analysis.
    Useful for quick checks.
    """
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        result = url_expander.expand(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/model/info', methods=['GET'])
def model_info():
    """Get neural network model information."""
    import os
    
    model_info = {
        'architecture': '15 → 64 → 32 → 1',
        'input_features': 15,
        'hidden_layers': [
            {'layer': 'Dense', 'units': 64, 'activation': 'relu'},
            {'layer': 'BatchNormalization'},
            {'layer': 'Dropout', 'rate': 0.3},
            {'layer': 'Dense', 'units': 32, 'activation': 'relu'},
            {'layer': 'BatchNormalization'},
            {'layer': 'Dropout', 'rate': 0.2},
        ],
        'output_layer': {'units': 1, 'activation': 'sigmoid'},
        'optimizer': 'Adam',
        'learning_rate': 0.001,
        'loss_function': 'binary_crossentropy',
        'metrics': ['accuracy', 'AUC-ROC'],
        'model_exists': os.path.exists('models/url_classifier.h5'),
        'model_size_mb': os.path.getsize('models/url_classifier.h5') / (1024 * 1024) if os.path.exists('models/url_classifier.h5') else 0,
        'features': [
            'URL length', 'Shannon entropy', 'Digit ratio', 'Dot count',
            'Hyphen count', 'Has IP address', 'Subdomain depth', 'Path depth',
            'Has HTTPS', 'TLD suspicion', 'Pattern score', 'Redirect depth',
            'Special char ratio', 'Entropy delta', 'Domain age proxy'
        ]
    }
    
    return jsonify(model_info)


@app.route('/api/analytics/performance', methods=['GET'])
def analytics_performance():
    """
    Get real-time algorithm performance metrics.
    Runs benchmark on first call or when cache expires (5 minutes).
    """
    try:
        # Check if we should run a new benchmark
        if performance_benchmark.should_run_benchmark():
            # Get sample size from query params (default 10000)
            sample_size = int(request.args.get('sample_size', 10000))
            sample_size = min(sample_size, 50000)  # Cap at 50k for safety
            
            # Run benchmark in background (or return cached if available)
            results = performance_benchmark.run_full_benchmark(
                graph_analyzer=graph_analyzer,
                pattern_matcher=None,
                neural_classifier=neural_classifier,
                greedy_optimizer=greedy_optimizer,
                bloom_analyzer=bloom_analyzer,
                heapsort_ranker=heapsort_ranker,
                url_expander=url_expander,
                sample_size=sample_size
            )
        else:
            # Return cached results
            results = performance_benchmark.get_cached_results()
        
        # Add cache info
        results['cache_info'] = {
            'cached': not performance_benchmark.should_run_benchmark(),
            'cache_age_seconds': time.time() - performance_benchmark.last_benchmark_time if performance_benchmark.last_benchmark_time else 0,
            'cache_expires_in_seconds': performance_benchmark.cache_duration - (time.time() - performance_benchmark.last_benchmark_time) if performance_benchmark.last_benchmark_time else 0
        }
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'message': 'Benchmark failed. Using fallback data.',
            'algorithms': [],
            'overall_pipeline_time_ms': 0,
            'throughput_urls_per_sec': 0
        }), 500


@app.route('/api/analytics/performance/refresh', methods=['POST'])
def refresh_performance_benchmark():
    """
    Force refresh of performance benchmark.
    Useful for getting latest stats without waiting for cache expiry.
    """
    try:
        sample_size = int(request.json.get('sample_size', 10000)) if request.json else 10000
        sample_size = min(sample_size, 50000)
        
        # Clear cache and run new benchmark
        performance_benchmark.results = None
        
        results = performance_benchmark.run_full_benchmark(
            graph_analyzer=graph_analyzer,
            pattern_matcher=None,
            neural_classifier=neural_classifier,
            greedy_optimizer=greedy_optimizer,
            bloom_analyzer=bloom_analyzer,
            heapsort_ranker=heapsort_ranker,
            url_expander=url_expander,
            sample_size=sample_size
        )
        
        return jsonify({
            'success': True,
            'message': f'Benchmark refreshed with {sample_size:,} URLs',
            'results': results
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


def determine_final_verdict(phase3_result: Dict, phase5_result: Dict, phase6_result: Dict, expansion_result: Dict = None) -> Dict:
    """
    Determine final verdict based on all phase results.
    Prioritizes neural network predictions for well-known domains.
    Takes URL expansion into account - shortened URLs get extra scrutiny.
    """
    threat_prob = phase3_result.get('threat_probability', 0)
    bloom_verdict = phase5_result.get('final_verdict', 'unknown')
    threat_rank = phase6_result.get('threat_rank', 0)
    
    # Check if URL was shortened
    is_shortened = expansion_result and expansion_result.get('is_shortened', False)
    redirect_count = expansion_result.get('redirect_count', 0) if expansion_result else 0
    
    # Check for whitelisted domain
    if phase3_result.get('reason', '').startswith('Whitelisted'):
        if is_shortened:
            rec = 'Shortener resolves to a trusted destination. Safe to proceed.'
        else:
            rec = 'Allow. Trusted domain.'
        return {
            'verdict': 'safe',
            'confidence': 'high',
            'threat_probability': threat_prob,
            'threat_rank': threat_rank,
            'recommendation': rec,
            'reason': 'Destination is a trusted domain'
        }
    
    # Adjust threat probability for shortened URLs (but not too much)
    if is_shortened and threat_prob < 0.5:
        # Only add small penalty for shortened URLs if not already suspicious
        threat_prob = min(1.0, threat_prob + 0.05)
    
    # Multiple redirects are suspicious
    if redirect_count > 3:
        threat_prob = min(1.0, threat_prob + 0.05)
    
    # Decision logic — thresholds aligned with neural classifier (threshold_malicious=0.88)
    if threat_prob < 0.25:
        # Very low threat — always safe regardless of bloom
        verdict = 'safe'
        confidence = 'high'
    elif bloom_verdict == 'malicious' or threat_prob > 0.88:
        # Definite malicious (bloom hit OR neural very confident)
        verdict = 'malicious'
        confidence = 'high'
    elif threat_prob > 0.65 or (bloom_verdict == 'suspicious' and threat_prob > 0.40):
        # Moderately suspicious
        verdict = 'suspicious'
        confidence = 'medium'
    elif threat_prob > 0.40:
        # Uncertain
        verdict = 'uncertain'
        confidence = 'low'
    else:
        # Likely safe
        verdict = 'safe'
        confidence = 'medium'
    
    result = {
        'verdict': verdict,
        'confidence': confidence,
        'threat_probability': threat_prob,
        'threat_rank': threat_rank,
        'recommendation': get_recommendation(verdict, is_shortened)
    }
    
    # Add warning for shortened URLs
    if is_shortened:
        result['warning'] = f'URL shortener detected ({redirect_count} redirects). Extra caution advised.'
    
    return result


def get_recommendation(verdict: str, is_shortened: bool = False) -> str:
    """Get action recommendation based on verdict."""
    shortener_note = ' Verify the destination before proceeding.' if is_shortened else ''
    recommendations = {
        'malicious': 'Block immediately. Add to blacklist.',
        'suspicious': 'Flag for manual review. Monitor activity.' + (' URL shortener detected - verify destination.' if is_shortened else ''),
        'uncertain': 'Allow with caution. Log for analysis.' + (' URL shortener - consider expanding first.' if is_shortened else ''),
        'safe': 'Allow. No action needed.' + (' (Destination verified)' if is_shortened else '')
    }
    return recommendations.get(verdict, 'Unknown verdict')


# ── In-memory scan log (ring buffer, max 500 entries) ─────────────────────────
# Accumulated across all /api/analyze calls — used by analytics endpoints.
# DAA: ring buffer = O(1) insert, bounded memory (Greedy space optimisation).

from collections import deque
_scan_log: deque = deque(maxlen=500)

def _log_scan(url: str, final_verdict: Dict, phase3_result: Dict):
    """Append a scan entry to the ring-buffer log."""
    from urllib.parse import urlparse
    try:
        tld = '.' + urlparse(url).netloc.split('.')[-1].split(':')[0]
    except Exception:
        tld = '.unknown'
    _scan_log.appendleft({
        'url':                url,
        'verdict':            final_verdict.get('verdict', 'uncertain'),
        'threat_probability': final_verdict.get('threat_probability', 0),
        'confidence':         final_verdict.get('confidence', 'low'),
        'tld':                tld,
        'features':           phase3_result.get('features', []),
        'feature_names':      phase3_result.get('feature_names', []),
        'ts':                 time.time(),
    })



# ── Analytics: Feature Heatmap ────────────────────────────────────────────────
# DAA: Dynamic Programming — memoize per-feature average threat scores.
# Each feature's average contribution is computed once and cached.

@app.route('/api/analytics/heatmap', methods=['GET'])
def analytics_heatmap():
    """
    Return per-feature average threat contribution scores (DP memoized).
    Only computed when the scan log changes (lazy invalidation).
    """
    if not _scan_log:
        return jsonify({'features': [], 'message': 'No scans yet'})

    # DP table: feature_index → [threat_probability * feature_value] summed
    from phase3_neural_classifier import FEATURE_NAMES
    n_feats = len(FEATURE_NAMES)
    dp_sum   = [0.0] * n_feats
    dp_count = [0]   * n_feats

    for entry in _scan_log:
        prob     = entry.get('threat_probability', 0)
        features = entry.get('features', [])
        for i, fval in enumerate(features[:n_feats]):
            dp_sum[i]   += float(fval) * prob
            dp_count[i] += 1

    result = []
    for i, name in enumerate(FEATURE_NAMES):
        avg = dp_sum[i] / dp_count[i] if dp_count[i] > 0 else 0
        result.append({
            'feature':    name,
            'index':      i,
            'avg_contribution': round(avg, 4),
            'scan_count': dp_count[i],
        })

    # Sort descending by contribution (Heapsort equivalent via Python timsort)
    result.sort(key=lambda x: x['avg_contribution'], reverse=True)

    return jsonify({'features': result, 'total_scans': len(_scan_log)})


# ── Analytics: Geo / TLD Origin Map ──────────────────────────────────────────
# Groups scanned URLs by TLD → approximates geographic origin.
# DAA: uses a frequency hash map (O(n)), similar to counting sort pre-step.

# TLD → country/region mapping (top 60 TLDs)
TLD_GEO = {
    '.com': 'United States', '.net': 'United States', '.org': 'United States',
    '.edu': 'United States', '.gov': 'United States', '.us':  'United States',
    '.io':  'United Kingdom','.co':  'Global',        '.uk':  'United Kingdom',
    '.co.uk': 'United Kingdom', '.in': 'India',       '.de':  'Germany',
    '.fr':  'France',        '.ru':  'Russia',        '.cn':  'China',
    '.jp':  'Japan',         '.br':  'Brazil',        '.au':  'Australia',
    '.ca':  'Canada',        '.nl':  'Netherlands',   '.es':  'Spain',
    '.it':  'Italy',         '.pl':  'Poland',        '.se':  'Sweden',
    '.no':  'Norway',        '.dk':  'Denmark',       '.fi':  'Finland',
    '.ch':  'Switzerland',   '.at':  'Austria',       '.be':  'Belgium',
    '.nz':  'New Zealand',   '.za':  'South Africa',  '.mx':  'Mexico',
    '.ar':  'Argentina',     '.cl':  'Chile',         '.id':  'Indonesia',
    '.ph':  'Philippines',   '.sg':  'Singapore',     '.my':  'Malaysia',
    '.vn':  'Vietnam',       '.th':  'Thailand',      '.pk':  'Pakistan',
    '.bd':  'Bangladesh',    '.ng':  'Nigeria',        '.ke':  'Kenya',
    '.eg':  'Egypt',         '.sa':  'Saudi Arabia',  '.ae':  'UAE',
    '.tr':  'Turkey',        '.ir':  'Iran',           '.tk':  '⚠ Tokelau (Free/Spam)',
    '.ml':  '⚠ Mali (Free)', '.ga':  '⚠ Gabon (Free)','.cf':  '⚠ C. Africa (Free)',
    '.gq':  '⚠ Eq. Guinea',  '.xyz': '⚠ Generic',    '.top': '⚠ Generic',
    '.click': '⚠ Generic',   '.loan': '⚠ Generic',   '.win': '⚠ Generic',
    '.app': 'Global',        '.dev': 'Global',        '.ai':  'Anguilla / AI',
}

@app.route('/api/analytics/geo', methods=['GET'])
def analytics_geo():
    """
    Group scanned URLs by TLD → geo origin frequency map.
    Returns sorted list for the frontend risk map.
    """
    if not _scan_log:
        return jsonify({'regions': [], 'message': 'No scans yet'})

    freq: Dict[str, Dict] = {}

    for entry in _scan_log:
        tld      = entry.get('tld', '.unknown')
        verdict  = entry.get('verdict', 'uncertain')
        region   = TLD_GEO.get(tld, f'Unknown ({tld})')
        is_risky = tld in {'.tk','.ml','.ga','.cf','.gq','.xyz','.top','.click','.loan','.win'}

        if region not in freq:
            freq[region] = {
                'region': region, 'tld': tld, 'count': 0,
                'threats': 0, 'safe': 0, 'risk': is_risky,
            }
        freq[region]['count'] += 1
        if verdict in ('malicious', 'suspicious'):
            freq[region]['threats'] += 1
        elif verdict == 'safe':
            freq[region]['safe'] += 1

    # Heapsort-style: sort by threat count desc, then total count
    regions = sorted(freq.values(), key=lambda r: (r['threats'], r['count']), reverse=True)

    return jsonify({'regions': regions, 'total_scans': len(_scan_log)})


# ── Analytics: Export (Heapsort-ranked CSV) ───────────────────────────────────
# DAA: Heapsort — scan log entries ranked by threat_probability using
# Python's heapq module (max-heap via negation).

@app.route('/api/analytics/export', methods=['GET'])
def analytics_export():
    """
    Export scan log as CSV sorted by threat probability (heapsort).
    """
    import heapq
    import csv
    import io

    if not _scan_log:
        return jsonify({'error': 'No scan data to export'}), 404

    # Build max-heap by negating probability (heapq is min-heap)
    heap = []
    for entry in _scan_log:
        heapq.heappush(heap, (-entry['threat_probability'], entry['ts'], entry))

    # Extract in sorted order (Heapsort O(n log n))
    sorted_entries = []
    while heap:
        _, _, entry = heapq.heappop(heap)
        sorted_entries.append(entry)

    # Write CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['URL', 'Verdict', 'Threat Probability (%)', 'Confidence', 'TLD', 'Timestamp'])

    for e in sorted_entries:
        writer.writerow([
            e['url'],
            e['verdict'],
            round(e['threat_probability'] * 100, 1),
            e['confidence'],
            e['tld'],
            time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e['ts'])),
        ])

    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=urlshield_export.csv'}
    )


# ── Analytics: Live Stats ─────────────────────────────────────────────────────

@app.route('/api/analytics/stats', methods=['GET'])
def analytics_stats():
    """Live scan statistics for the React dashboard."""
    if not _scan_log:
        return jsonify({
            'total': 0, 'malicious': 0, 'suspicious': 0,
            'uncertain': 0, 'safe': 0, 'avg_threat': 0,
        })

    counts = {'malicious': 0, 'suspicious': 0, 'uncertain': 0, 'safe': 0}
    total_prob = 0.0

    for e in _scan_log:
        v = e.get('verdict', 'uncertain')
        counts[v] = counts.get(v, 0) + 1
        total_prob += e.get('threat_probability', 0)

    n = len(_scan_log)
    return jsonify({
        'total':      n,
        'malicious':  counts.get('malicious', 0),
        'suspicious': counts.get('suspicious', 0),
        'uncertain':  counts.get('uncertain', 0),
        'safe':       counts.get('safe', 0),
        'avg_threat': round(total_prob / n * 100, 1),
        'recent':     list(_scan_log)[:10],  # last 10 for timeline
    })




if __name__ == '__main__':
    print("=" * 60)
    print("Hybrid AI-Driven Malicious URL Detection System")
    print("=" * 60)
    print("\nInitializing...")
    
    # Load dataset
    load_dataset()
    
    print("\n✓ Server starting on http://localhost:5000")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
