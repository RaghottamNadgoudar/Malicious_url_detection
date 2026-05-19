import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const analyzeURL = async (url) => {
  const response = await api.post('/analyze', { url });
  return response.data;
};

export const batchAnalyze = async (urls, topK = 10) => {
  const response = await api.post('/batch-analyze', { urls, top_k: topK });
  return response.data;
};

export const getDatasetStats = async () => {
  const response = await api.get('/dataset/stats');
  return response.data;
};

export const getDatasetSample = async (size = 10, type = 'all') => {
  const response = await api.get(`/dataset/sample?size=${size}&type=${type}`);
  return response.data;
};

export const getSystemStats = async () => {
  const response = await api.get('/system/stats');
  return response.data;
};

export const healthCheck = async () => {
  const response = await api.get('/health');
  return response.data;
};

export const getModelInfo = async () => {
  const response = await api.get('/model/info');
  return response.data;
};

export const getAnalyticsPerformance = async () => {
  const response = await api.get('/analytics/performance');
  return response.data;
};

export const getPerformanceMetrics = async (sampleSize = 10000) => {
  const response = await api.get(`/analytics/performance?sample_size=${sampleSize}`);
  return response.data;
};

export const refreshPerformanceBenchmark = async (sampleSize = 10000) => {
  const response = await api.post('/analytics/performance/refresh', { sample_size: sampleSize });
  return response.data;
};

export default api;
