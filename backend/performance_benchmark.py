"""
Performance Benchmarking Module
Runs real-time performance tests on the detection pipeline
"""

import time
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple
import os
from collections import defaultdict

# Import all phases
from phase1_graph_traversal import RedirectGraphAnalyzer
from phase2_pattern_matching import PatternMatcher
from phase3_neural_classifier import NeuralClassifier
from phase4_greedy_optimization import GreedyOptimizer
from phase5_bloom_filter import BloomFilterAnalyzer
from phase6_heapsort_ranking import HeapsortRanker
from url_expander import URLExpander


class PerformanceBenchmark:
    """Real-time performance benchmarking for all pipeline phases."""
    
    def __init__(self):
        self.results = None
        self.last_benchmark_time = None
        self.cache_duration = 300  # Cache results for 5 minutes
        
    def should_run_benchmark(self) -> bool:
        """Check if benchmark should be run (cache expired or first run)."""
        if self.results is None:
            return True
        
        if self.last_benchmark_time is None:
            return True
        
        elapsed = time.time() - self.last_benchmark_time
        return elapsed > self.cache_duration
    
    def load_test_urls(self, sample_size: int = 10000) -> Tuple[List[str], pd.DataFrame]:
        """Load test URLs from dataset."""
        # Try to load dataset
        for dataset_path in ['../data/merged_urls.csv', '../data/balanced_urls.csv']:
            if os.path.exists(dataset_path):
                df = pd.read_csv(dataset_path)
                
                # Sample URLs
                if len(df) > sample_size:
                    df_sample = df.sample(n=sample_size, random_state=42)
                else:
                    df_sample = df
                
                urls = df_sample['url'].tolist()
                return urls, df_sample
        
        # Fallback: generate synthetic URLs for testing
        print("⚠️  Dataset not found, using synthetic URLs for benchmark")
        synthetic_urls = [
            f"https://example{i}.com/path{i}" for i in range(min(sample_size, 1000))
        ]
        df_synthetic = pd.DataFrame({
            'url': synthetic_urls,
            'result': [0] * len(synthetic_urls)
        })
        return synthetic_urls, df_synthetic
    
    def benchmark_phase1(self, urls: List[str], graph_analyzer: RedirectGraphAnalyzer) -> Dict:
        """Benchmark Phase 1: Graph Traversal (BFS/DFS)."""
        times = []
        
        for url in urls[:1000]:  # Test on 1000 URLs
            start = time.perf_counter()
            graph_analyzer.analyze_url(url)
            end = time.perf_counter()
            times.append((end - start) * 1000)  # Convert to ms
        
        return {
            'name': 'BFS/DFS Graph Traversal',
            'unit': 'Unit II',
            'complexity': 'O(V + E)',
            'avg_time_ms': np.mean(times),
            'median_time_ms': np.median(times),
            'std_time_ms': np.std(times),
            'min_time_ms': np.min(times),
            'max_time_ms': np.max(times),
            'p95_time_ms': np.percentile(times, 95),
            'p99_time_ms': np.percentile(times, 99),
            'efficiency': self._calculate_efficiency(np.mean(times), 5.0),
            'samples': len(times)
        }
    
    def benchmark_phase2(self, urls: List[str], pattern_matcher: PatternMatcher) -> Dict:
        """Benchmark Phase 2: Boyer-Moore Pattern Matching."""
        times = []
        
        for url in urls[:1000]:
            start = time.perf_counter()
            pattern_matcher.analyze_url(url)
            end = time.perf_counter()
            times.append((end - start) * 1000)
        
        return {
            'name': 'Boyer-Moore Pattern Matching',
            'unit': 'Unit III',
            'complexity': 'O(n/m)',
            'avg_time_ms': np.mean(times),
            'median_time_ms': np.median(times),
            'std_time_ms': np.std(times),
            'min_time_ms': np.min(times),
            'max_time_ms': np.max(times),
            'p95_time_ms': np.percentile(times, 95),
            'p99_time_ms': np.percentile(times, 99),
            'efficiency': self._calculate_efficiency(np.mean(times), 2.0),
            'samples': len(times)
        }
    
    def benchmark_phase3(self, urls: List[str], neural_classifier: NeuralClassifier,
                        graph_analyzer: RedirectGraphAnalyzer, 
                        pattern_matcher: PatternMatcher) -> Dict:
        """Benchmark Phase 3: Neural Network Inference."""
        times = []
        
        for url in urls[:1000]:
            phase1_result = graph_analyzer.analyze_url(url)
            phase2_result = pattern_matcher.analyze_url(url)
            
            start = time.perf_counter()
            neural_classifier.analyze_url(url, phase1_result, phase2_result)
            end = time.perf_counter()
            times.append((end - start) * 1000)
        
        return {
            'name': 'Neural Network Inference',
            'unit': 'Unit III',
            'complexity': 'O(1)',
            'avg_time_ms': np.mean(times),
            'median_time_ms': np.median(times),
            'std_time_ms': np.std(times),
            'min_time_ms': np.min(times),
            'max_time_ms': np.max(times),
            'p95_time_ms': np.percentile(times, 95),
            'p99_time_ms': np.percentile(times, 99),
            'efficiency': self._calculate_efficiency(np.mean(times), 1.5),
            'samples': len(times)
        }
    
    def benchmark_phase4(self, urls: List[str], greedy_optimizer: GreedyOptimizer,
                        graph_analyzer: RedirectGraphAnalyzer) -> Dict:
        """Benchmark Phase 4: Greedy Optimization (Dijkstra)."""
        times = []
        
        for url in urls[:500]:  # Smaller sample for expensive operation
            combined_data = {'url': url}
            
            start = time.perf_counter()
            greedy_optimizer.analyze_url(url, combined_data, graph_analyzer.graph)
            end = time.perf_counter()
            times.append((end - start) * 1000)
        
        return {
            'name': 'Dijkstra Shortest Path',
            'unit': 'Unit IV',
            'complexity': 'O((V + E) log V)',
            'avg_time_ms': np.mean(times),
            'median_time_ms': np.median(times),
            'std_time_ms': np.std(times),
            'min_time_ms': np.min(times),
            'max_time_ms': np.max(times),
            'p95_time_ms': np.percentile(times, 95),
            'p99_time_ms': np.percentile(times, 99),
            'efficiency': self._calculate_efficiency(np.mean(times), 5.0),
            'samples': len(times)
        }
    
    def benchmark_phase5(self, urls: List[str], bloom_analyzer: BloomFilterAnalyzer) -> Dict:
        """Benchmark Phase 5: Bloom Filter Lookup."""
        times = []
        
        for url in urls[:1000]:
            combined_data = {'url': url}
            
            start = time.perf_counter()
            bloom_analyzer.analyze_url(url, combined_data)
            end = time.perf_counter()
            times.append((end - start) * 1000)
        
        return {
            'name': 'Bloom Filter Lookup',
            'unit': 'Unit III',
            'complexity': 'O(k)',
            'avg_time_ms': np.mean(times),
            'median_time_ms': np.median(times),
            'std_time_ms': np.std(times),
            'min_time_ms': np.min(times),
            'max_time_ms': np.max(times),
            'p95_time_ms': np.percentile(times, 95),
            'p99_time_ms': np.percentile(times, 99),
            'efficiency': self._calculate_efficiency(np.mean(times), 0.5),
            'samples': len(times)
        }
    
    def benchmark_phase6(self, urls: List[str], heapsort_ranker: HeapsortRanker) -> Dict:
        """Benchmark Phase 6: Heapsort Ranking."""
        times = []
        
        # Test batch ranking
        batch_sizes = [10, 50, 100, 500]
        
        for batch_size in batch_sizes:
            if batch_size > len(urls):
                continue
            
            batch_urls = urls[:batch_size]
            results = [{'url': url, 'threat_score': np.random.random()} for url in batch_urls]
            
            start = time.perf_counter()
            heapsort_ranker.rank_batch(results, top_k=min(10, batch_size))
            end = time.perf_counter()
            times.append((end - start) * 1000)
        
        return {
            'name': 'Heapsort Ranking',
            'unit': 'Unit III',
            'complexity': 'O(n log n)',
            'avg_time_ms': np.mean(times),
            'median_time_ms': np.median(times),
            'std_time_ms': np.std(times),
            'min_time_ms': np.min(times),
            'max_time_ms': np.max(times),
            'p95_time_ms': np.percentile(times, 95) if len(times) > 1 else np.mean(times),
            'p99_time_ms': np.percentile(times, 99) if len(times) > 1 else np.mean(times),
            'efficiency': self._calculate_efficiency(np.mean(times), 6.0),
            'samples': len(times),
            'note': f'Tested on batch sizes: {batch_sizes[:len(times)]}'
        }
    
    def benchmark_phase7(self, urls: List[str], greedy_optimizer: GreedyOptimizer,
                        graph_analyzer: RedirectGraphAnalyzer) -> Dict:
        """Benchmark Phase 7: BFS Transitive Closure."""
        times = []
        
        # Build a small graph for testing
        test_graph = {url: [] for url in urls[:100]}
        
        start = time.perf_counter()
        greedy_optimizer.build_transitive_closure(test_graph)
        end = time.perf_counter()
        times.append((end - start) * 1000)
        
        return {
            'name': 'BFS Transitive Closure',
            'unit': 'Unit IV',
            'complexity': 'O(V·E)',
            'avg_time_ms': np.mean(times),
            'median_time_ms': np.median(times),
            'std_time_ms': 0.0,
            'min_time_ms': np.min(times),
            'max_time_ms': np.max(times),
            'p95_time_ms': np.mean(times),
            'p99_time_ms': np.mean(times),
            'efficiency': self._calculate_efficiency(np.mean(times), 10.0),
            'samples': len(times),
            'note': 'Optimized replacement for Warshall O(V³)'
        }
    
    def benchmark_url_expander(self, urls: List[str], url_expander: URLExpander) -> Dict:
        """Benchmark URL Expansion (Phase 0)."""
        times = []
        
        # Test only on a small sample (network operations are slow)
        for url in urls[:50]:
            start = time.perf_counter()
            url_expander.expand(url, use_cache=False)
            end = time.perf_counter()
            times.append((end - start) * 1000)
        
        return {
            'name': 'URL Expansion (Shorteners)',
            'unit': 'Unit II',
            'complexity': 'O(k) network calls',
            'avg_time_ms': np.mean(times),
            'median_time_ms': np.median(times),
            'std_time_ms': np.std(times),
            'min_time_ms': np.min(times),
            'max_time_ms': np.max(times),
            'p95_time_ms': np.percentile(times, 95),
            'p99_time_ms': np.percentile(times, 99),
            'efficiency': self._calculate_efficiency(np.mean(times), 100.0),
            'samples': len(times),
            'note': 'Only runs for shortened URLs'
        }
    
    def benchmark_full_pipeline(self, urls: List[str], 
                                graph_analyzer: RedirectGraphAnalyzer,
                                pattern_matcher: PatternMatcher,
                                neural_classifier: NeuralClassifier,
                                greedy_optimizer: GreedyOptimizer,
                                bloom_analyzer: BloomFilterAnalyzer,
                                heapsort_ranker: HeapsortRanker) -> Dict:
        """Benchmark the complete end-to-end pipeline."""
        times = []
        
        for url in urls[:500]:  # Test on 500 URLs
            start = time.perf_counter()
            
            # Full pipeline
            phase1_result = graph_analyzer.analyze_url(url)
            phase2_result = pattern_matcher.analyze_url(url)
            phase3_result = neural_classifier.analyze_url(url, phase1_result, phase2_result)
            combined_data = {**phase1_result, **phase2_result, **phase3_result}
            greedy_optimizer.analyze_url(url, combined_data, graph_analyzer.graph)
            bloom_analyzer.analyze_url(url, combined_data)
            heapsort_ranker.analyze_url(url, combined_data)
            
            end = time.perf_counter()
            times.append((end - start) * 1000)
        
        avg_time = np.mean(times)
        throughput = 1000.0 / avg_time if avg_time > 0 else 0
        
        return {
            'avg_time_ms': avg_time,
            'median_time_ms': np.median(times),
            'std_time_ms': np.std(times),
            'min_time_ms': np.min(times),
            'max_time_ms': np.max(times),
            'p95_time_ms': np.percentile(times, 95),
            'p99_time_ms': np.percentile(times, 99),
            'throughput_urls_per_sec': throughput,
            'samples': len(times)
        }
    
    def _calculate_efficiency(self, avg_time_ms: float, baseline_ms: float) -> int:
        """Calculate efficiency score (0-100) based on performance vs baseline."""
        if avg_time_ms <= 0:
            return 100
        
        # Efficiency = 100 * (baseline / actual_time)
        # Capped at 100
        efficiency = min(100, int(100 * (baseline_ms / avg_time_ms)))
        return max(0, efficiency)
    
    def run_full_benchmark(self, 
                          graph_analyzer: RedirectGraphAnalyzer,
                          pattern_matcher: PatternMatcher,
                          neural_classifier: NeuralClassifier,
                          greedy_optimizer: GreedyOptimizer,
                          bloom_analyzer: BloomFilterAnalyzer,
                          heapsort_ranker: HeapsortRanker,
                          url_expander: URLExpander,
                          sample_size: int = 10000) -> Dict:
        """Run complete benchmark suite."""
        
        print(f"\n{'='*60}")
        print("🔬 Running Performance Benchmark")
        print(f"{'='*60}")
        
        # Load test URLs
        print(f"📊 Loading {sample_size:,} test URLs...")
        urls, df = self.load_test_urls(sample_size)
        print(f"✓ Loaded {len(urls):,} URLs")
        
        results = {
            'algorithms': [],
            'timestamp': time.time(),
            'sample_size': len(urls)
        }
        
        # Benchmark each phase
        print("\n🧪 Benchmarking individual phases...")
        
        print("  Phase 1: Graph Traversal (BFS/DFS)...")
        results['algorithms'].append(self.benchmark_phase1(urls, graph_analyzer))
        
        print("  Phase 2: Pattern Matching (Boyer-Moore)...")
        results['algorithms'].append(self.benchmark_phase2(urls, pattern_matcher))
        
        print("  Phase 3: Neural Network...")
        results['algorithms'].append(self.benchmark_phase3(urls, neural_classifier, 
                                                          graph_analyzer, pattern_matcher))
        
        print("  Phase 4: Greedy Optimization (Dijkstra)...")
        results['algorithms'].append(self.benchmark_phase4(urls, greedy_optimizer, 
                                                          graph_analyzer))
        
        print("  Phase 5: Bloom Filter...")
        results['algorithms'].append(self.benchmark_phase5(urls, bloom_analyzer))
        
        print("  Phase 6: Heapsort Ranking...")
        results['algorithms'].append(self.benchmark_phase6(urls, heapsort_ranker))
        
        print("  Phase 7: Transitive Closure (BFS)...")
        results['algorithms'].append(self.benchmark_phase7(urls, greedy_optimizer, 
                                                          graph_analyzer))
        
        print("  Phase 0: URL Expansion...")
        results['algorithms'].append(self.benchmark_url_expander(urls, url_expander))
        
        # Benchmark full pipeline
        print("\n🚀 Benchmarking full pipeline...")
        pipeline_stats = self.benchmark_full_pipeline(
            urls, graph_analyzer, pattern_matcher, neural_classifier,
            greedy_optimizer, bloom_analyzer, heapsort_ranker
        )
        
        results['overall_pipeline_time_ms'] = pipeline_stats['avg_time_ms']
        results['pipeline_median_ms'] = pipeline_stats['median_time_ms']
        results['pipeline_p95_ms'] = pipeline_stats['p95_time_ms']
        results['pipeline_p99_ms'] = pipeline_stats['p99_time_ms']
        results['throughput_urls_per_sec'] = pipeline_stats['throughput_urls_per_sec']
        results['pipeline_samples'] = pipeline_stats['samples']
        
        print(f"\n✓ Benchmark complete!")
        print(f"  Average pipeline time: {pipeline_stats['avg_time_ms']:.2f}ms")
        print(f"  Throughput: {pipeline_stats['throughput_urls_per_sec']:.1f} URLs/sec")
        print(f"{'='*60}\n")
        
        # Cache results
        self.results = results
        self.last_benchmark_time = time.time()
        
        return results
    
    def get_cached_results(self) -> Dict:
        """Get cached benchmark results."""
        return self.results
