import axios from 'axios';
import type { AnalyzeRequest, AnalyzeResponse } from '../types/analysis';

const BASE_URL = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json' },
});

export async function analyzeUrl(req: AnalyzeRequest): Promise<AnalyzeResponse> {
  const { data } = await api.post<AnalyzeResponse>('/analyze', req);
  return data;
}

export async function checkHealth(): Promise<{ status: string; model_loaded: boolean }> {
  const { data } = await api.get('/health');
  return data;
}
