"""
Main Flask Application - Hybrid URL Detection System
Integrates all 7 phases of the detection pipeline
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import os
import time
from typing import Dict, List

# Import all phases
from phase1_graph_traversal import RedirectGraphAnalyzer
from phase2_pattern_matching import PatternMatcher
from phase3_neural_classifier import NeuralClassifier
from phase4_greedy_optimization import GreedyOptimizer
from phase5_bloom_filter import BloomFilterAnalyzer
from phase6_heapsort_ranking import HeapsortRanker
from url_expander import URLExpander
from performance_benchmark import PerformanceBenchmark

app = Flask(__name__)
CORS(app)

# Global analyzers
graph_analyzer = RedirectGraphAnalyzer()
pattern_matcher = PatternMatcher()
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
    return jsonify({
        'status': 'healthy',
        'dataset_loaded': dataset_loaded,
        'dataset_size': len(dataset) if dataset is not None else 0
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
        analysis_url = expansion_result['final_url']  # Analyze the final destination
        
        # PHASE 1: Graph Traversal
        phase1_result = graph_analyzer.analyze_url(analysis_url)
        
        # PHASE 2: Pattern Matching
        phase2_result = pattern_matcher.analyze_url(analysis_url)
        
        # PHASE 3: Neural Classification
        phase3_result = neural_classifier.analyze_url(analysis_url, phase1_result, phase2_result)
        
        # PHASE 4: Greedy Optimization
        combined_data = {**phase1_result, **phase2_result, **phase3_result}
        phase4_result = greedy_optimizer.analyze_url(analysis_url, combined_data, graph_analyzer.graph)
        
        # PHASE 5: Bloom Filter
        phase5_result = bloom_analyzer.analyze_url(analysis_url, combined_data)
        
        # PHASE 6: Heapsort Ranking
        phase6_result = heapsort_ranker.analyze_url(analysis_url, combined_data)
        
        # Combine all results
        final_result = {
            'url': url,
            'url_expansion': expansion_result,  # Include expansion info
            'analyzed_url': analysis_url,  # Show what was actually analyzed
            'phase1_graph': phase1_result,
            'phase2_pattern': phase2_result,
            'phase3_neural': phase3_result,
            'phase4_greedy': phase4_result,
            'phase5_bloom': phase5_result,
            'phase6_ranking': phase6_result,
            'final_verdict': determine_final_verdict(phase3_result, phase5_result, phase6_result, expansion_result)
        }
        
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
            # Quick analysis through key phases
            phase1_result = graph_analyzer.analyze_url(url)
            phase2_result = pattern_matcher.analyze_url(url)
            phase3_result = neural_classifier.analyze_url(url, phase1_result, phase2_result)
            
            combined_data = {
                'url': url,
                **phase1_result,
                **phase2_result,
                **phase3_result
            }
            
            results.append(combined_data)
        
        # Rank using heapsort
        ranked_results = heapsort_ranker.rank_batch(results, top_k)
        
        return jsonify({
            'total_analyzed': len(urls),
            'top_threats': ranked_results
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
                pattern_matcher=pattern_matcher,
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
            pattern_matcher=pattern_matcher,
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
        return {
            'verdict': 'safe',
            'confidence': 'high',
            'threat_probability': threat_prob,
            'threat_rank': threat_rank,
            'recommendation': 'Allow. Whitelisted domain.',
            'reason': phase3_result.get('reason')
        }
    
    # Adjust threat probability for shortened URLs (but not too much)
    if is_shortened and threat_prob < 0.5:
        # Only add small penalty for shortened URLs if not already suspicious
        threat_prob = min(1.0, threat_prob + 0.05)
    
    # Multiple redirects are suspicious
    if redirect_count > 3:
        threat_prob = min(1.0, threat_prob + 0.05)
    
    # Decision logic - more conservative thresholds
    if threat_prob < 0.25:
        # Very low threat
        verdict = 'safe'
        confidence = 'high'
    elif bloom_verdict == 'malicious' or threat_prob > 0.75:
        # Definite malicious
        verdict = 'malicious'
        confidence = 'high'
    elif threat_prob > 0.55 or bloom_verdict == 'suspicious':
        # Moderately suspicious
        verdict = 'suspicious'
        confidence = 'medium'
    elif threat_prob > 0.35:
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
    recommendations = {
        'malicious': 'Block immediately. Add to blacklist.',
        'suspicious': 'Flag for manual review. Monitor activity.' + (' URL shortener detected - verify destination.' if is_shortened else ''),
        'uncertain': 'Allow with caution. Log for analysis.' + (' URL shortener - consider expanding first.' if is_shortened else ''),
        'safe': 'Allow. No action needed.' + (' (Destination verified)' if is_shortened else '')
    }
    return recommendations.get(verdict, 'Unknown verdict')


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
