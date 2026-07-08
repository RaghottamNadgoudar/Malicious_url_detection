import axios from 'axios';
import type {
  DaaClassifyResult,
  DaaClassifyDetailResult,
  DaaExpandResult,
  DaaHealthResult,
  DaaSseEvent,
} from '../types/daaApi';

const DAA_BASE = import.meta.env.VITE_DAA_API_URL ?? 'http://localhost:8002';

const client = axios.create({
  baseURL: DAA_BASE,
  timeout: 120_000,
  headers: { 'Content-Type': 'application/json' },
});

// ── Single URL — standard classify ──────────────────────────────────────────
export async function classifyUrl(url: string): Promise<DaaClassifyResult> {
  const { data } = await client.post<DaaClassifyResult>('/classify', { url });
  return data;
}

// ── Single URL — with hard signal breakdown + exit tier ─────────────────────
export async function classifyUrlDetail(url: string): Promise<DaaClassifyDetailResult> {
  const { data } = await client.post<DaaClassifyDetailResult>('/classify-detail', { url });
  return data;
}

// ── URL expansion / redirect chain ──────────────────────────────────────────
export async function expandUrl(url: string): Promise<DaaExpandResult> {
  const { data } = await client.post<DaaExpandResult>('/expand-url', { url });
  return data;
}

// ── Health check ─────────────────────────────────────────────────────────────
export async function checkDaaHealth(): Promise<DaaHealthResult> {
  const { data } = await client.get<DaaHealthResult>('/health');
  return data;
}

/**
 * Streaming batch optimize — consumes SSE from POST /batch-optimize/stream.
 *
 * Because browsers' native EventSource only supports GET,
 * we use fetch() + ReadableStream to handle POST-based SSE.
 *
 * @param urls       List of URLs to classify
 * @param onEvent    Callback called for each SSE event (parsed JSON)
 * @param signal     AbortSignal to cancel the stream
 */
export async function batchOptimizeStream(
  urls: string[],
  onEvent: (evt: DaaSseEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const response = await fetch(`${DAA_BASE}/batch-optimize/stream`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ urls }),
    signal,
  });

  if (!response.ok || !response.body) {
    throw new Error(`Stream failed: ${response.status} ${response.statusText}`);
  }

  const reader  = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });

    // SSE events are separated by double-newline
    const parts = buffer.split('\n\n');
    buffer = parts.pop() ?? '';   // keep incomplete tail

    for (const part of parts) {
      const line = part.trim();
      if (!line.startsWith('data: ')) continue;
      try {
        const payload = JSON.parse(line.slice(6)) as DaaSseEvent;
        onEvent(payload);
      } catch {
        /* skip malformed lines */
      }
    }
  }
}
