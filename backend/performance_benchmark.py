"""
Performance Benchmarking Module
Runs real-time performance tests on the detection pipeline.
Phase 2 (Boyer-Moore pattern matching) has been removed;
its slot now benchmarks the self-contained 25-feature extractor.
"""

import time
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple
import os

from phase1_graph_traversal import RedirectGraphAnalyzer
from phase3_neural_classifier import NeuralClassifier, extract_features
from phase4_greedy_optimization import GreedyOptimizer
from phase5_bloom_filter import BloomFilterAnalyzer
from phase6_heapsort_ranking import HeapsortRanker
from url_expander import URLExpander


class PerformanceBenchmark:
    """Real-time performance benchmarking for all pipeline phases."""

    def __init__(self):
        self.results = None
        self.last_benchmark_time = None
        self.cache_duration = 300  # 5-minute cache

    def should_run_benchmark(self) -> bool:
        if self.results is None or self.last_benchmark_time is None:
            return True
        return (time.time() - self.last_benchmark_time) > self.cache_duration

    # ------------------------------------------------------------------
    def load_test_urls(self, sample_size: int = 10000) -> Tuple[List[str], pd.DataFrame]:
        """Load test URLs from dataset."""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(script_dir, '..', 'data')

        for name in ('merged_urls.csv', 'balanced_urls.csv'):
            path = os.path.join(data_dir, name)
            if os.path.exists(path):
                df = pd.read_csv(path)
                df_sample = df.sample(n=min(sample_size, len(df)), random_state=42)
                return df_sample['url'].tolist(), df_sample

        # Fallback synthetic data
        print("⚠️  Dataset not found — using synthetic URLs for benchmark")
        synthetic = [f"https://example{i}.com/path{i}" for i in range(min(sample_size, 1000))]
        df_syn = pd.DataFrame({'url': synthetic, 'result': [0] * len(synthetic)})
        return synthetic, df_syn

    # ------------------------------------------------------------------
    def _stats(self, times: List[float], baseline_ms: float) -> Dict:
        arr = np.array(times)
        return {
            'avg_time_ms':    float(np.mean(arr)),
            'median_time_ms': float(np.median(arr)),
            'std_time_ms':    float(np.std(arr)),
            'min_time_ms':    float(np.min(arr)),
            'max_time_ms':    float(np.max(arr)),
            'p95_time_ms':    float(np.percentile(arr, 95)) if len(arr) > 1 else float(np.mean(arr)),
            'p99_time_ms':    float(np.percentile(arr, 99)) if len(arr) > 1 else float(np.mean(arr)),
            'efficiency':     self._calculate_efficiency(float(np.mean(arr)), baseline_ms),
            'samples':        len(times),
        }

    def _calculate_efficiency(self, avg_ms: float, baseline_ms: float) -> int:
        if avg_ms <= 0:
            return 100
        return max(0, min(100, int(100 * baseline_ms / avg_ms)))

    # ------------------------------------------------------------------
    def benchmark_phase1(self, urls: List[str], graph_analyzer: RedirectGraphAnalyzer) -> Dict:
        """Phase 1 — BFS/DFS Graph Traversal."""
        times = []
        for url in urls[:1000]:
            t0 = time.perf_counter()
            graph_analyzer.analyze_url(url)
            times.append((time.perf_counter() - t0) * 1000)
        return {
            'name': 'BFS/DFS Graph Traversal',
            'unit': 'Unit II',
            'complexity': 'O(V + E)',
            **self._stats(times, 5.0),
        }

    def benchmark_phase2(self, urls: List[str], neural_classifier: NeuralClassifier) -> Dict:
        """
        Phase 2 — 25-Feature Extraction (self-contained, replaces Boyer-Moore).
        Benchmarks how fast the neural classifier extracts its feature vector.
        """
        times = []
        for url in urls[:1000]:
            t0 = time.perf_counter()
            extract_features(url)          # pure feature extraction, no inference
            times.append((time.perf_counter() - t0) * 1000)
        return {
            'name': '25-Feature Extraction (Neural)',
            'unit': 'Unit III',
            'complexity': 'O(n)',
            **self._stats(times, 2.0),
            'note': 'Replaces Boyer-Moore; keyword + homograph + brand signals built-in',
        }

    def benchmark_phase3(self, urls: List[str], neural_classifier: NeuralClassifier,
                         graph_analyzer: RedirectGraphAnalyzer) -> Dict:
        """Phase 3 — Neural Network Inference."""
        times = []
        for url in urls[:1000]:
            phase1 = graph_analyzer.analyze_url(url)
            t0 = time.perf_counter()
            neural_classifier.analyze_url(url, phase1, None)
            times.append((time.perf_counter() - t0) * 1000)
        return {
            'name': 'Neural Network Inference',
            'unit': 'Unit III',
            'complexity': 'O(1)',
            **self._stats(times, 1.5),
        }

    def benchmark_phase4(self, urls: List[str], greedy_optimizer: GreedyOptimizer,
                         graph_analyzer: RedirectGraphAnalyzer) -> Dict:
        """Phase 4 — Dijkstra Shortest Path (Greedy Optimization)."""
        times = []
        for url in urls[:500]:
            t0 = time.perf_counter()
            greedy_optimizer.analyze_url(url, {'url': url}, graph_analyzer.graph)
            times.append((time.perf_counter() - t0) * 1000)
        return {
            'name': 'Dijkstra Shortest Path',
            'unit': 'Unit IV',
            'complexity': 'O((V + E) log V)',
            **self._stats(times, 5.0),
        }

    def benchmark_phase5(self, urls: List[str], bloom_analyzer: BloomFilterAnalyzer) -> Dict:
        """Phase 5 — Bloom Filter Lookup."""
        times = []
        for url in urls[:1000]:
            t0 = time.perf_counter()
            bloom_analyzer.analyze_url(url, {})
            times.append((time.perf_counter() - t0) * 1000)
        return {
            'name': 'Bloom Filter Lookup',
            'unit': 'Unit III',
            'complexity': 'O(k)',
            **self._stats(times, 0.5),
        }

    def benchmark_phase6(self, urls: List[str], heapsort_ranker: HeapsortRanker) -> Dict:
        """Phase 6 — Heapsort Ranking."""
        times = []
        for batch_size in (10, 50, 100, 500):
            if batch_size > len(urls):
                continue
            batch = [{'url': u, 'threat_score': np.random.random(),
                      'threat_probability': np.random.random(), 'entropy': 3.5,
                      'redirect_depth': 0} for u in urls[:batch_size]]
            t0 = time.perf_counter()
            heapsort_ranker.rank_batch(batch, top_k=min(10, batch_size))
            times.append((time.perf_counter() - t0) * 1000)
        return {
            'name': 'Heapsort Ranking',
            'unit': 'Unit III',
            'complexity': 'O(n log n)',
            **self._stats(times, 6.0),
            'note': 'Tested on batch sizes: 10, 50, 100, 500',
        }

    def benchmark_phase7(self, urls: List[str], greedy_optimizer: GreedyOptimizer,
                         graph_analyzer: RedirectGraphAnalyzer) -> Dict:
        """Phase 7 — BFS Transitive Closure."""
        test_graph = {u: [] for u in urls[:100]}
        t0 = time.perf_counter()
        greedy_optimizer.build_transitive_closure(test_graph)
        elapsed = (time.perf_counter() - t0) * 1000
        return {
            'name': 'BFS Transitive Closure',
            'unit': 'Unit IV',
            'complexity': 'O(V·E)',
            **self._stats([elapsed], 10.0),
            'note': 'Optimised replacement for Warshall O(V³)',
        }

    def benchmark_url_expander(self, urls: List[str], url_expander: URLExpander) -> Dict:
        """Phase 0 — URL Expansion."""
        times = []
        for url in urls[:50]:
            t0 = time.perf_counter()
            url_expander.expand(url, use_cache=False)
            times.append((time.perf_counter() - t0) * 1000)
        return {
            'name': 'URL Expansion (Shorteners)',
            'unit': 'Unit II',
            'complexity': 'O(k) network calls',
            **self._stats(times, 100.0),
            'note': 'Only runs for shortened URLs',
        }

    def benchmark_full_pipeline(self, urls: List[str],
                                graph_analyzer: RedirectGraphAnalyzer,
                                neural_classifier: NeuralClassifier,
                                greedy_optimizer: GreedyOptimizer,
                                bloom_analyzer: BloomFilterAnalyzer,
                                heapsort_ranker: HeapsortRanker) -> Dict:
        """End-to-end pipeline benchmark (no pattern matching)."""
        times = []
        for url in urls[:500]:
            t0 = time.perf_counter()
            p1 = graph_analyzer.analyze_url(url)
            p3 = neural_classifier.analyze_url(url, p1, None)
            combined = {**p1, **p3}
            greedy_optimizer.analyze_url(url, combined, graph_analyzer.graph)
            bloom_analyzer.analyze_url(url, combined)
            heapsort_ranker.analyze_url(url, combined)
            times.append((time.perf_counter() - t0) * 1000)

        arr = np.array(times)
        avg = float(np.mean(arr))
        return {
            'avg_time_ms':          avg,
            'median_time_ms':       float(np.median(arr)),
            'std_time_ms':          float(np.std(arr)),
            'min_time_ms':          float(np.min(arr)),
            'max_time_ms':          float(np.max(arr)),
            'p95_time_ms':          float(np.percentile(arr, 95)),
            'p99_time_ms':          float(np.percentile(arr, 99)),
            'throughput_urls_per_sec': 1000.0 / avg if avg > 0 else 0,
            'samples':              len(times),
        }

    # ------------------------------------------------------------------
    def run_full_benchmark(self,
                           graph_analyzer: RedirectGraphAnalyzer,
                           pattern_matcher,            # kept for API compat, ignored
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

        urls, _ = self.load_test_urls(sample_size)
        print(f"✓ Loaded {len(urls):,} URLs")

        results = {
            'algorithms': [],
            'timestamp':  time.time(),
            'sample_size': len(urls),
        }

        print("\n🧪 Benchmarking individual phases...")

        print("  Phase 1: BFS/DFS Graph Traversal...")
        results['algorithms'].append(self.benchmark_phase1(urls, graph_analyzer))

        print("  Phase 2: 25-Feature Extraction (neural, self-contained)...")
        results['algorithms'].append(self.benchmark_phase2(urls, neural_classifier))

        print("  Phase 3: Neural Network Inference...")
        results['algorithms'].append(self.benchmark_phase3(urls, neural_classifier, graph_analyzer))

        print("  Phase 4: Dijkstra / Greedy Optimization...")
        results['algorithms'].append(self.benchmark_phase4(urls, greedy_optimizer, graph_analyzer))

        print("  Phase 5: Bloom Filter Lookup...")
        results['algorithms'].append(self.benchmark_phase5(urls, bloom_analyzer))

        print("  Phase 6: Heapsort Ranking...")
        results['algorithms'].append(self.benchmark_phase6(urls, heapsort_ranker))

        print("  Phase 7: BFS Transitive Closure...")
        results['algorithms'].append(self.benchmark_phase7(urls, greedy_optimizer, graph_analyzer))

        print("  Phase 0: URL Expansion...")
        results['algorithms'].append(self.benchmark_url_expander(urls, url_expander))

        print("\n🚀 Benchmarking full pipeline...")
        pipeline = self.benchmark_full_pipeline(
            urls, graph_analyzer, neural_classifier,
            greedy_optimizer, bloom_analyzer, heapsort_ranker,
        )

        results['overall_pipeline_time_ms']  = pipeline['avg_time_ms']
        results['pipeline_median_ms']        = pipeline['median_time_ms']
        results['pipeline_p95_ms']           = pipeline['p95_time_ms']
        results['pipeline_p99_ms']           = pipeline['p99_time_ms']
        results['throughput_urls_per_sec']   = pipeline['throughput_urls_per_sec']
        results['pipeline_samples']          = pipeline['samples']

        print(f"\n✓ Benchmark complete!")
        print(f"  Avg pipeline: {pipeline['avg_time_ms']:.2f} ms")
        print(f"  Throughput:   {pipeline['throughput_urls_per_sec']:.1f} URLs/sec")
        print(f"{'='*60}\n")

        self.results = results
        self.last_benchmark_time = time.time()
        return results

    def get_cached_results(self) -> Dict:
        return self.results
