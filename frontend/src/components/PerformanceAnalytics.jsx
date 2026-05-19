import { useState, useEffect } from 'react';
import { Activity, RefreshCw, TrendingUp, Clock, Zap, BarChart3 } from 'lucide-react';
import { getPerformanceMetrics, refreshPerformanceBenchmark } from '../services/api';

const PerformanceAnalytics = () => {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadMetrics();
  }, []);

  const loadMetrics = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getPerformanceMetrics();
      setMetrics(data);
    } catch (err) {
      setError('Failed to load performance metrics');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = async () => {
    try {
      setRefreshing(true);
      setError(null);
      await refreshPerformanceBenchmark(10000);
      await loadMetrics();
    } catch (err) {
      setError('Failed to refresh benchmark');
      console.error(err);
    } finally {
      setRefreshing(false);
    }
  };

  const getEfficiencyColor = (efficiency) => {
    if (efficiency >= 95) return 'text-green-600 bg-green-50';
    if (efficiency >= 85) return 'text-blue-600 bg-blue-50';
    if (efficiency >= 70) return 'text-yellow-600 bg-yellow-50';
    return 'text-red-600 bg-red-50';
  };

  const formatTime = (ms) => {
    if (ms < 1) return `${(ms * 1000).toFixed(0)}μs`;
    if (ms < 1000) return `${ms.toFixed(2)}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  };

  if (loading) {
    return (
      <div className="card">
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="w-8 h-8 animate-spin text-primary-500" />
          <span className="ml-3 text-lg">Running performance benchmark...</span>
        </div>
        <p className="text-center text-sm text-gray-500 mt-2">
          Testing on 10,000 URLs. This may take a minute...
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card">
        <div className="text-center py-8">
          <p className="text-red-600 mb-4">{error}</p>
          <button onClick={loadMetrics} className="btn btn-primary">
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="card">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Activity className="w-8 h-8 text-primary-500" />
            <div>
              <h2 className="text-2xl font-bold">Performance Analytics</h2>
              <p className="text-sm text-gray-600">
                Real-time benchmarks on {metrics?.sample_size?.toLocaleString() || '0'} URLs
              </p>
            </div>
          </div>
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="btn btn-secondary flex items-center gap-2"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>

        {/* Cache Info */}
        {metrics?.cache_info && (
          <div className="mt-4 p-3 bg-blue-50 rounded-lg text-sm">
            <div className="flex items-center gap-2 text-blue-800">
              <Clock className="w-4 h-4" />
              {metrics.cache_info.cached ? (
                <span>
                  Cached results (expires in {Math.max(0, Math.floor(metrics.cache_info.cache_expires_in_seconds))}s)
                </span>
              ) : (
                <span>Fresh benchmark results</span>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Overall Pipeline Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card bg-gradient-to-br from-blue-50 to-blue-100">
          <div className="flex items-center gap-3">
            <Clock className="w-8 h-8 text-blue-600" />
            <div>
              <p className="text-sm text-blue-600 font-medium">Avg Pipeline Time</p>
              <p className="text-2xl font-bold text-blue-900">
                {formatTime(metrics?.overall_pipeline_time_ms || 0)}
              </p>
            </div>
          </div>
        </div>

        <div className="card bg-gradient-to-br from-green-50 to-green-100">
          <div className="flex items-center gap-3">
            <Zap className="w-8 h-8 text-green-600" />
            <div>
              <p className="text-sm text-green-600 font-medium">Throughput</p>
              <p className="text-2xl font-bold text-green-900">
                {metrics?.throughput_urls_per_sec?.toFixed(1) || '0'} URLs/s
              </p>
            </div>
          </div>
        </div>

        <div className="card bg-gradient-to-br from-purple-50 to-purple-100">
          <div className="flex items-center gap-3">
            <TrendingUp className="w-8 h-8 text-purple-600" />
            <div>
              <p className="text-sm text-purple-600 font-medium">P95 Latency</p>
              <p className="text-2xl font-bold text-purple-900">
                {formatTime(metrics?.pipeline_p95_ms || 0)}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Algorithm Performance Table */}
      <div className="card">
        <div className="flex items-center gap-3 mb-4">
          <BarChart3 className="w-6 h-6 text-primary-500" />
          <h3 className="text-xl font-bold">Algorithm Performance</h3>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b-2 border-gray-200">
                <th className="text-left py-3 px-4">Algorithm</th>
                <th className="text-left py-3 px-4">Unit</th>
                <th className="text-left py-3 px-4">Complexity</th>
                <th className="text-right py-3 px-4">Avg Time</th>
                <th className="text-right py-3 px-4">Median</th>
                <th className="text-right py-3 px-4">P95</th>
                <th className="text-right py-3 px-4">P99</th>
                <th className="text-center py-3 px-4">Efficiency</th>
                <th className="text-right py-3 px-4">Samples</th>
              </tr>
            </thead>
            <tbody>
              {metrics?.algorithms?.map((algo, idx) => (
                <tr key={idx} className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-3 px-4">
                    <div className="font-medium">{algo.name}</div>
                    {algo.note && (
                      <div className="text-xs text-gray-500 mt-1">{algo.note}</div>
                    )}
                  </td>
                  <td className="py-3 px-4 text-sm text-gray-600">{algo.unit}</td>
                  <td className="py-3 px-4">
                    <code className="text-xs bg-gray-100 px-2 py-1 rounded">
                      {algo.complexity}
                    </code>
                  </td>
                  <td className="py-3 px-4 text-right font-mono text-sm">
                    {formatTime(algo.avg_time_ms)}
                  </td>
                  <td className="py-3 px-4 text-right font-mono text-sm text-gray-600">
                    {formatTime(algo.median_time_ms)}
                  </td>
                  <td className="py-3 px-4 text-right font-mono text-sm text-gray-600">
                    {formatTime(algo.p95_time_ms)}
                  </td>
                  <td className="py-3 px-4 text-right font-mono text-sm text-gray-600">
                    {formatTime(algo.p99_time_ms)}
                  </td>
                  <td className="py-3 px-4 text-center">
                    <span className={`inline-block px-3 py-1 rounded-full text-sm font-semibold ${getEfficiencyColor(algo.efficiency)}`}>
                      {algo.efficiency}%
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right text-sm text-gray-600">
                    {algo.samples?.toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Performance Visualization */}
      <div className="card">
        <h3 className="text-xl font-bold mb-4">Performance Distribution</h3>
        <div className="space-y-4">
          {metrics?.algorithms?.map((algo, idx) => {
            const maxTime = Math.max(...(metrics.algorithms.map(a => a.avg_time_ms) || [1]));
            const widthPercent = (algo.avg_time_ms / maxTime) * 100;
            
            return (
              <div key={idx}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium">{algo.name}</span>
                  <span className="text-sm text-gray-600">{formatTime(algo.avg_time_ms)}</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-3">
                  <div
                    className="bg-gradient-to-r from-blue-500 to-purple-500 h-3 rounded-full transition-all duration-500"
                    style={{ width: `${widthPercent}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Statistics Summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card">
          <h3 className="text-lg font-bold mb-3">Pipeline Statistics</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-600">Average Time:</span>
              <span className="font-mono font-semibold">
                {formatTime(metrics?.overall_pipeline_time_ms || 0)}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Median Time:</span>
              <span className="font-mono font-semibold">
                {formatTime(metrics?.pipeline_median_ms || 0)}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">95th Percentile:</span>
              <span className="font-mono font-semibold">
                {formatTime(metrics?.pipeline_p95_ms || 0)}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">99th Percentile:</span>
              <span className="font-mono font-semibold">
                {formatTime(metrics?.pipeline_p99_ms || 0)}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Samples Tested:</span>
              <span className="font-semibold">
                {metrics?.pipeline_samples?.toLocaleString() || '0'}
              </span>
            </div>
          </div>
        </div>

        <div className="card">
          <h3 className="text-lg font-bold mb-3">Benchmark Info</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-600">Total URLs Tested:</span>
              <span className="font-semibold">
                {metrics?.sample_size?.toLocaleString() || '0'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Timestamp:</span>
              <span className="font-mono text-xs">
                {metrics?.timestamp ? new Date(metrics.timestamp * 1000).toLocaleString() : 'N/A'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Cache Status:</span>
              <span className={metrics?.cache_info?.cached ? 'text-blue-600' : 'text-green-600'}>
                {metrics?.cache_info?.cached ? 'Cached' : 'Fresh'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Algorithms Tested:</span>
              <span className="font-semibold">{metrics?.algorithms?.length || 0}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PerformanceAnalytics;
