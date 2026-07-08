"""
app_nn.py — FastAPI backend — DistilBERT-Only Pipeline
======================================================
Runs on port 8002 (coexists with the full ensemble on port 8001).

Endpoints:
  GET  /health                  → liveness check
  POST /classify                → single URL  { "url": "..." }
  POST /classify-detail         → single URL + hard signal breakdown + exit tier
  POST /batch                   → up to 10 URLs { "urls": [...] }
  POST /batch-optimize/stream   → SSE streaming batch with 6-stage BatchOptimizer
  POST /expand-url              → URL expansion / redirect chain
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, validator
from typing import List
import asyncio
import json
import time
import re
from urllib.parse import urlparse

_pipeline = None


def get_pipeline():
    global _pipeline
    if _pipeline is None:
        from pipeline_bert import BertPipeline
        _pipeline = BertPipeline(quiet=True)
    return _pipeline


app = FastAPI(
    title="DistilBERT URL Detector API",
    description="Single-Expert DistilBERT pipeline for malicious URL detection.",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ── Request models ─────────────────────────────────────────────────────────────

class URLRequest(BaseModel):
    url: str


class BatchURLRequest(BaseModel):
    urls: List[str]

    @validator('urls')
    def max_10(cls, v):
        if len(v) > 10:
            raise ValueError("Maximum 10 URLs per batch request")
        return v


class BatchStreamRequest(BaseModel):
    urls: List[str]


class ExpandURLRequest(BaseModel):
    url: str


# ── Existing endpoints ─────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_loaded": _pipeline is not None,
        "pipeline": "distilbert_only",
    }


@app.post("/classify")
def classify(req: URLRequest):
    try:
        pipe = get_pipeline()
        t0 = time.time()
        result = pipe.classify(req.url)
        result['latency_ms'] = round((time.time() - t0) * 1000, 1)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/batch")
def batch_classify(req: BatchURLRequest):
    pipe = get_pipeline()
    results = []
    for url in req.urls:
        try:
            t0 = time.time()
            r = pipe.classify(url)
            r['latency_ms'] = round((time.time() - t0) * 1000, 1)
            results.append(r)
        except Exception as e:
            results.append({"url": url, "error": str(e), "verdict": "error"})
    return {"results": results, "total": len(results)}


# ── New endpoints ──────────────────────────────────────────────────────────────

@app.post("/classify-detail")
def classify_detail(req: URLRequest):
    """
    Extended classify — returns everything from /classify plus:
      hard_score              — combined structural suspicion score (0-1)
      exit_tier               — which tier produced the final verdict
      hard_signal_breakdown   — per-component contribution to hard_score
    """
    try:
        from pipeline_bert import (
            _parse_domain, _keyword_score, _brand_in_subdomain,
            _entropy, SUSPICIOUS_TLDS,
        )

        pipe = get_pipeline()
        t0 = time.time()
        result = pipe.classify(req.url)
        result['latency_ms'] = round((time.time() - t0) * 1000, 1)

        url = req.url.strip()
        ext = _parse_domain(url)

        # Per-component breakdown — mirrors _hard_signal() in pipeline_bert.py
        susp_tld_contrib     = 0.40 if ext['suffix'] in SUSPICIOUS_TLDS else 0.0
        has_ip_contrib       = 0.30 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0.0
        has_at_contrib       = 0.25 if '@' in url else 0.0
        brand_sub_contrib    = 0.35 if _brand_in_subdomain(url, ext) else 0.0
        ks                   = _keyword_score(url)
        kw_boost_contrib     = round(ks * 0.20, 4) if ks > 0.05 else 0.0
        double_slash_contrib = 0.15 if '//' in (urlparse(url).path or '') else 0.0
        high_entropy_contrib = 0.10 if _entropy(url) > 5.0 else 0.0

        hard_score = min(
            susp_tld_contrib + has_ip_contrib + has_at_contrib + brand_sub_contrib
            + kw_boost_contrib + double_slash_contrib + high_entropy_contrib,
            1.0,
        )

        # Determine which tier produced the verdict
        reasoning = result.get('reasoning', '')
        umbrella  = result.get('umbrella')
        if umbrella and umbrella.get('verdict') in ('malicious', 'safe') and umbrella.get('source') != 'unavailable':
            exit_tier = 'T0-Umbrella'
        elif 'Whitelisted' in reasoning:
            exit_tier = 'T1-Whitelist'
        elif 'Hard signals override' in reasoning or 'Moderate hard signals' in reasoning:
            exit_tier = 'T3-HardSignal'
        else:
            exit_tier = 'T2-DistilBERT'

        result['hard_score'] = round(hard_score, 4)
        result['exit_tier']  = exit_tier
        result['hard_signal_breakdown'] = {
            'suspicious_tld':    susp_tld_contrib,
            'has_ip':            has_ip_contrib,
            'has_at':            has_at_contrib,
            'brand_in_subdomain': brand_sub_contrib,
            'keyword_boost':     kw_boost_contrib,
            'double_slash_path': double_slash_contrib,
            'high_entropy':      high_entropy_contrib,
        }

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/expand-url")
def expand_url_endpoint(req: ExpandURLRequest):
    """
    Follow redirects for a URL and return the full hop chain.
    Uses url_expander.py (copied from backend/).
    """
    try:
        from url_expander import expand_url
        return expand_url(req.url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/batch-optimize/stream")
async def batch_optimize_stream(req: BatchStreamRequest):
    """
    SSE streaming batch — runs the 6-stage DAA BatchOptimizer, then streams
    each DistilBERT result one by one so the frontend can show live progress.

    SSE event types:
      start           — batch accepted, N URLs incoming
      optimizer_done  — all DAA preprocessing stages complete; includes stage_counts
                        and the list of pre-classified (decided) URLs
      url_classified  — one URL's DistilBERT result (index / total)
      url_error       — non-fatal DistilBERT error for one URL
      complete        — final merged result with all counts and timing
    """
    async def generate():
        urls = req.urls
        yield f"data: {json.dumps({'event': 'start', 'total': len(urls), 'pipeline': 'distilbert_only'})}\n\n"

        from batch_optimizer import BatchOptimizer, huffman_compress_log

        optimizer = BatchOptimizer(verbose=False)

        try:
            result = await asyncio.to_thread(optimizer.process, urls)
        except Exception as e:
            yield f"data: {json.dumps({'event': 'error', 'message': str(e)})}\n\n"
            return

        decided_list = [
            {
                'url':          r.url,
                'verdict':      r.verdict,
                'confidence':   r.confidence,
                'stage':        r.stage,
                'reason':       r.reason,
                'keyword_hits': r.keyword_hits,
                'hard_score':   r.hard_score,
            }
            for r in result.decided
        ]

        yield f"data: {json.dumps({'event': 'optimizer_done', 'stage_counts': result.stage_counts, 'decided': decided_list, 'decided_count': len(decided_list), 'uncertain_count': len(result.uncertain_urls), 'reduction_pct': result.reduction_pct, 'optimizer_elapsed_ms': result.elapsed_ms, 'selected_features': optimizer.selected_features})}\n\n"

        # Stream DistilBERT results one per event
        pipe = get_pipeline()
        uncertain_results = []

        for idx, url in enumerate(result.uncertain_urls):
            try:
                t0 = time.time()
                r = await asyncio.to_thread(pipe.classify, url)
                r['latency_ms'] = round((time.time() - t0) * 1000, 1)
                uncertain_results.append(r)
                yield f"data: {json.dumps({'event': 'url_classified', 'index': idx, 'total': len(result.uncertain_urls), 'result': r})}\n\n"
            except Exception as e:
                uncertain_results.append({'url': url, 'verdict': 'error', 'error': str(e)})
                yield f"data: {json.dumps({'event': 'url_error', 'index': idx, 'url': url, 'error': str(e)})}\n\n"

        # Huffman audit-log compression ratio (Unit IV demo)
        log_text = json.dumps({
            'total':     result.total_input,
            'decided':   len(decided_list),
            'uncertain': len(uncertain_results),
        })
        _, huffman_ratio = huffman_compress_log(log_text)

        yield f"data: {json.dumps({'event': 'complete', 'total_input': result.total_input, 'stage_counts': result.stage_counts, 'decided': decided_list, 'uncertain_results': uncertain_results, 'reduction_pct': result.reduction_pct, 'elapsed_ms': result.elapsed_ms, 'huffman_ratio': round(huffman_ratio, 4), 'selected_features': optimizer.selected_features})}\n\n"

    return StreamingResponse(
        generate(),
        media_type='text/event-stream',
        headers={
            'Cache-Control':    'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection':       'keep-alive',
        },
    )
