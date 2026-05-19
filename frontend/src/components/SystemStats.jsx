import React, { useState, useEffect } from 'react';
import { Database, Activity, Shield, TrendingUp } from 'lucide-react';
import { getDatasetStats, getSystemStats } from '../services/api';

const SystemStats = () => {
  const [datasetStats, setDatasetStats] = useState(null);
  const [systemStats, setSystemStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      const [dataset, system] = await Promise.all([
        getDatasetStats(),
        getSystemStats()
      ]);
      setDatasetStats(dataset);
      setSystemStats(system);
    } catch (err) {
      console.error('Failed to load stats:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="card">
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-gray-200 rounded w-1/4"></div>
          <div className="h-20 bg-gray-200 rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Dataset Stats */}
      {datasetStats && (
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <Database className="w-6 h-6 text-primary-500" />
            <h3 className="text-xl font-bold">Dataset Statistics</h3>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-primary-50 rounded-lg">
              <p className="text-sm text-primary-600 mb-1">Total URLs</p>
              <p className="text-2xl font-bold text-primary-900">
                {datasetStats.total_urls.toLocaleString()}
              </p>
            </div>
            
            <div className="p-4 bg-success-50 rounded-lg">
              <p className="text-sm text-success-600 mb-1">Benign URLs</p>
              <p className="text-2xl font-bold text-success-900">
                {datasetStats.benign_count.toLocaleString()}
              </p>
            </div>
            
            <div className="p-4 bg-danger-50 rounded-lg">
              <p className="text-sm text-danger-600 mb-1">Malicious URLs</p>
              <p className="text-2xl font-bold text-danger-900">
                {datasetStats.malicious_count.toLocaleString()}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* System Stats */}
      {systemStats && (
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <Activity className="w-6 h-6 text-primary-500" />
            <h3 className="text-xl font-bold">System Statistics</h3>
          </div>
          
          <div className="space-y-4">
            {/* Bloom Filter */}
            <div className="p-4 bg-pink-50 rounded-lg">
              <h4 className="font-semibold text-pink-900 mb-3">Bloom Filter</h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                <div>
                  <p className="text-pink-600">Size</p>
                  <p className="font-semibold text-pink-900">
                    {systemStats.bloom_filter.standard_bloom.size_kb.toFixed(2)} KB
                  </p>
                </div>
                <div>
                  <p className="text-pink-600">Hash Functions</p>
                  <p className="font-semibold text-pink-900">
                    {systemStats.bloom_filter.standard_bloom.hash_functions}
                  </p>
                </div>
                <div>
                  <p className="text-pink-600">Elements</p>
                  <p className="font-semibold text-pink-900">
                    {systemStats.bloom_filter.standard_bloom.elements_added.toLocaleString()}
                  </p>
                </div>
                <div>
                  <p className="text-pink-600">Load Factor</p>
                  <p className="font-semibold text-pink-900">
                    {(systemStats.bloom_filter.standard_bloom.load_factor * 100).toFixed(1)}%
                  </p>
                </div>
              </div>
            </div>

            {/* Graph Stats */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 bg-blue-50 rounded-lg">
                <p className="text-sm text-blue-600 mb-1">Graph Nodes</p>
                <p className="text-xl font-bold text-blue-900">
                  {systemStats.graph_nodes.toLocaleString()}
                </p>
              </div>
              
              <div className="p-4 bg-purple-50 rounded-lg">
                <p className="text-sm text-purple-600 mb-1">Redirect Depths Tracked</p>
                <p className="text-xl font-bold text-purple-900">
                  {systemStats.redirect_depths_tracked.toLocaleString()}
                </p>
              </div>
              
              <div className="p-4 bg-danger-50 rounded-lg">
                <p className="text-sm text-danger-600 mb-1">Malicious URLs Registered</p>
                <p className="text-xl font-bold text-danger-900">
                  {systemStats.malicious_urls_registered.toLocaleString()}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Algorithm Coverage */}
      <div className="card">
        <div className="flex items-center gap-3 mb-4">
          <TrendingUp className="w-6 h-6 text-primary-500" />
          <h3 className="text-xl font-bold">Algorithm Coverage</h3>
        </div>
        
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { name: 'BFS/DFS', color: 'blue' },
            { name: 'Boyer-Moore', color: 'teal' },
            { name: 'Neural Net', color: 'purple' },
            { name: 'Dijkstra', color: 'amber' },
            { name: 'Bloom Filter', color: 'pink' },
            { name: 'Heapsort', color: 'green' },
            { name: 'Greedy', color: 'amber' },
            { name: 'Backtracking', color: 'red' }
          ].map((algo, idx) => (
            <div key={idx} className={`p-3 bg-${algo.color}-50 rounded-lg border border-${algo.color}-200`}>
              <p className={`font-semibold text-${algo.color}-900 text-sm`}>{algo.name}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default SystemStats;
