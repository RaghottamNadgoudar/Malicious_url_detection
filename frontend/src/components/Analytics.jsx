import { useState, useEffect } from 'react';
import { BarChart, Bar, LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Brain, Database, Zap, TrendingUp, Cpu, Clock } from 'lucide-react';

const Analytics = () => {
  const [modelInfo, setModelInfo] = useState(null);
  const [performance, setPerformance] = useState(null);
  const [datasetStats, setDatasetStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadAnalytics();
  }, []);

  const loadAnalytics = async () => {
    try {
      const [modelRes, perfRes, datasetRes] = await Promise.all([
        fetch('http://localhost:5000/api/model/info'),
        fetch('http://localhost:5000/api/analytics/performance'),
        fetch('http://localhost:5000/api/dataset/stats')
      ]);

      const model = await modelRes.json();
      const perf = await perfRes.json();
      const dataset = await datasetRes.json();

      setModelInfo(model);
      setPerformance(perf);
      setDatasetStats(dataset);
    } catch (err) {
      console.error('Failed to load analytics:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="card">
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-gray-200 rounded w-1/4"></div>
          <div className="h-64 bg-gray-200 rounded"></div>
        </div>
      </div>
    );
  }

  // Colors for charts
  const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#14b8a6'];

  // Dataset distribution data
  const datasetDistribution = datasetStats ? [
    { name: 'Benign', value: datasetStats.benign_count, color: '#10b981' },
    { name: 'Malicious', value: datasetStats.malicious_count, color: '#ef4444' }
  ] : [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="card bg-gradient-to-r from-primary-500 to-primary-600 text-white">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold mb-2">System Analytics Dashboard</h2>
            <p className="text-primary-100">
              Comprehensive analysis of model performance, dataset statistics, and algorithm efficiency
            </p>
          </div>
          <TrendingUp className="w-16 h-16 opacity-50" />
        </div>
      </div>

      {/* Model Information */}
      {modelInfo && (
        <div className="card">
          <div className="flex items-center gap-3 mb-6">
            <Brain className="w-6 h-6 text-primary-500" />
            <h3 className="text-xl font-bold">Neural Network Model</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div className="p-4 bg-purple-50 rounded-lg border border-purple-200">
              <div className="flex items-center gap-2 mb-2">
                <Cpu className="w-5 h-5 text-purple-600" />
                <p className="text-sm text-purple-600 font-medium">Architecture</p>
              </div>
              <p className="text-2xl font-bold text-purple-900">{modelInfo.architecture}</p>
              <p className="text-xs text-purple-600 mt-1">Feedforward Neural Network</p>
            </div>

            <div className="p-4 bg-blue-50 rounded-lg border border-blue-200">
              <div className="flex items-center gap-2 mb-2">
                <Database className="w-5 h-5 text-blue-600" />
                <p className="text-sm text-blue-600 font-medium">Model Size</p>
              </div>
              <p className="text-2xl font-bold text-blue-900">
                {modelInfo.model_size_mb.toFixed(2)} MB
              </p>
              <p className="text-xs text-blue-600 mt-1">
                {modelInfo.model_exists ? '✓ Model Trained' : '✗ Not Trained'}
              </p>
            </div>

            <div className="p-4 bg-green-50 rounded-lg border border-green-200">
              <div className="flex items-center gap-2 mb-2">
                <Zap className="w-5 h-5 text-green-600" />
                <p className="text-sm text-green-600 font-medium">Input Features</p>
              </div>
              <p className="text-2xl font-bold text-green-900">{modelInfo.input_features}</p>
              <p className="text-xs text-green-600 mt-1">Feature Vector Dimension</p>
            </div>
          </div>

          {/* Model Architecture Details */}
          <div className="bg-gray-50 rounded-lg p-4 mb-4">
            <h4 className="font-semibold text-gray-900 mb-3">Layer Configuration</h4>
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm">
                <span className="px-2 py-1 bg-primary-100 text-primary-700 rounded font-mono">
                  Input: {modelInfo.input_features} features
                </span>
                <span className="text-gray-400">→</span>
                {modelInfo.hidden_layers.filter(l => l.layer === 'Dense').map((layer, idx) => (
                  <span key={idx}>
                    <span className="px-2 py-1 bg-purple-100 text-purple-700 rounded font-mono">
                      Dense: {layer.units} ({layer.activation})
                    </span>
                    <span className="text-gray-400 mx-1">→</span>
                  </span>
                ))}
                <span className="px-2 py-1 bg-green-100 text-green-700 rounded font-mono">
                  Output: {modelInfo.output_layer.units} ({modelInfo.output_layer.activation})
                </span>
              </div>
            </div>
          </div>

          {/* Features List */}
          <div className="bg-gray-50 rounded-lg p-4">
            <h4 className="font-semibold text-gray-900 mb-3">15 Extracted Features</h4>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {modelInfo.features.map((feature, idx) => (
                <div key={idx} className="flex items-center gap-2 text-sm">
                  <span className="w-6 h-6 flex items-center justify-center bg-primary-100 text-primary-700 rounded-full text-xs font-bold">
                    {idx + 1}
                  </span>
                  <span className="text-gray-700">{feature}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Training Configuration */}
          <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="p-3 bg-white border border-gray-200 rounded-lg">
              <p className="text-xs text-gray-600">Optimizer</p>
              <p className="font-semibold text-gray-900">{modelInfo.optimizer}</p>
            </div>
            <div className="p-3 bg-white border border-gray-200 rounded-lg">
              <p className="text-xs text-gray-600">Learning Rate</p>
              <p className="font-semibold text-gray-900">{modelInfo.learning_rate}</p>
            </div>
            <div className="p-3 bg-white border border-gray-200 rounded-lg">
              <p className="text-xs text-gray-600">Loss Function</p>
              <p className="font-semibold text-gray-900 text-xs">{modelInfo.loss_function}</p>
            </div>
            <div className="p-3 bg-white border border-gray-200 rounded-lg">
              <p className="text-xs text-gray-600">Metrics</p>
              <p className="font-semibold text-gray-900 text-xs">{modelInfo.metrics.join(', ')}</p>
            </div>
          </div>
        </div>
      )}

      {/* Dataset Statistics */}
      {datasetStats && (
        <div className="card">
          <div className="flex items-center gap-3 mb-6">
            <Database className="w-6 h-6 text-primary-500" />
            <h3 className="text-xl font-bold">Dataset Statistics</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Dataset Overview */}
            <div>
              <div className="grid grid-cols-1 gap-3 mb-4">
                <div className="p-4 bg-primary-50 rounded-lg border border-primary-200">
                  <p className="text-sm text-primary-600 mb-1">Total URLs</p>
                  <p className="text-3xl font-bold text-primary-900">
                    {datasetStats.total_urls.toLocaleString()}
                  </p>
                </div>
                <div className="p-4 bg-success-50 rounded-lg border border-success-200">
                  <p className="text-sm text-success-600 mb-1">Benign URLs</p>
                  <p className="text-2xl font-bold text-success-900">
                    {datasetStats.benign_count.toLocaleString()}
                  </p>
                  <p className="text-xs text-success-600 mt-1">
                    {((datasetStats.benign_count / datasetStats.total_urls) * 100).toFixed(1)}% of dataset
                  </p>
                </div>
                <div className="p-4 bg-danger-50 rounded-lg border border-danger-200">
                  <p className="text-sm text-danger-600 mb-1">Malicious URLs</p>
                  <p className="text-2xl font-bold text-danger-900">
                    {datasetStats.malicious_count.toLocaleString()}
                  </p>
                  <p className="text-xs text-danger-600 mt-1">
                    {((datasetStats.malicious_count / datasetStats.total_urls) * 100).toFixed(1)}% of dataset
                  </p>
                </div>
              </div>
            </div>

            {/* Distribution Chart */}
            <div>
              <h4 className="font-semibold text-gray-900 mb-3">Class Distribution</h4>
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={datasetDistribution}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(1)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {datasetDistribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* Algorithm Performance */}
      {performance && (
        <div className="card">
          <div className="flex items-center gap-3 mb-6">
            <Zap className="w-6 h-6 text-primary-500" />
            <h3 className="text-xl font-bold">Algorithm Performance Analysis</h3>
          </div>

          {/* Overall Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div className="p-4 bg-amber-50 rounded-lg border border-amber-200">
              <div className="flex items-center gap-2 mb-2">
                <Clock className="w-5 h-5 text-amber-600" />
                <p className="text-sm text-amber-600 font-medium">Pipeline Time</p>
              </div>
              <p className="text-2xl font-bold text-amber-900">
                {performance.overall_pipeline_time_ms.toFixed(1)} ms
              </p>
              <p className="text-xs text-amber-600 mt-1">Average per URL</p>
            </div>

            <div className="p-4 bg-green-50 rounded-lg border border-green-200">
              <div className="flex items-center gap-2 mb-2">
                <TrendingUp className="w-5 h-5 text-green-600" />
                <p className="text-sm text-green-600 font-medium">Throughput</p>
              </div>
              <p className="text-2xl font-bold text-green-900">
                {performance.throughput_urls_per_sec.toFixed(1)} URLs/s
              </p>
              <p className="text-xs text-green-600 mt-1">Processing Rate</p>
            </div>

            <div className="p-4 bg-blue-50 rounded-lg border border-blue-200">
              <div className="flex items-center gap-2 mb-2">
                <Cpu className="w-5 h-5 text-blue-600" />
                <p className="text-sm text-blue-600 font-medium">Algorithms</p>
              </div>
              <p className="text-2xl font-bold text-blue-900">{performance.algorithms.length}</p>
              <p className="text-xs text-blue-600 mt-1">7-Phase Pipeline</p>
            </div>
          </div>

          {/* Execution Time Chart */}
          <div className="mb-6">
            <h4 className="font-semibold text-gray-900 mb-3">Execution Time by Algorithm</h4>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={performance.algorithms}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} fontSize={12} />
                <YAxis label={{ value: 'Time (ms)', angle: -90, position: 'insideLeft' }} />
                <Tooltip />
                <Bar dataKey="avg_time_ms" fill="#3b82f6" name="Avg Time (ms)" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Efficiency Chart */}
          <div className="mb-6">
            <h4 className="font-semibold text-gray-900 mb-3">Algorithm Efficiency</h4>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={performance.algorithms}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} fontSize={12} />
                <YAxis label={{ value: 'Efficiency (%)', angle: -90, position: 'insideLeft' }} domain={[80, 100]} />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="efficiency" stroke="#10b981" strokeWidth={2} name="Efficiency %" />
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* Algorithm Details Table */}
          <div className="overflow-x-auto">
            <h4 className="font-semibold text-gray-900 mb-3">Detailed Algorithm Metrics</h4>
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Algorithm
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Complexity
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Avg Time
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Efficiency
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {performance.algorithms.map((algo, idx) => (
                  <tr key={idx} className="hover:bg-gray-50">
                    <td className="px-4 py-3 text-sm font-medium text-gray-900">{algo.name}</td>
                    <td className="px-4 py-3 text-sm font-mono text-gray-600">{algo.complexity}</td>
                    <td className="px-4 py-3 text-sm text-gray-600">{algo.avg_time_ms.toFixed(2)} ms</td>
                    <td className="px-4 py-3 text-sm">
                      <div className="flex items-center gap-2">
                        <div className="flex-1 bg-gray-200 rounded-full h-2">
                          <div
                            className="bg-green-500 h-2 rounded-full"
                            style={{ width: `${algo.efficiency}%` }}
                          ></div>
                        </div>
                        <span className="text-gray-900 font-medium">{algo.efficiency}%</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default Analytics;
