"""
app_nn.py — FastAPI backend — DistilBERT-Only Pipeline
======================================================
Runs on port 8002 (coexists with the full ensemble on port 8001).

Endpoints:
  GET  /health         → liveness check
  POST /classify       → single URL  { "url": "..." }
  POST /batch          → up to 10 URLs { "urls": [...] }
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
from typing import List
import time

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
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class URLRequest(BaseModel):
    url: str


class BatchURLRequest(BaseModel):
    urls: List[str]

    @validator('urls')
    def max_10(cls, v):
        if len(v) > 10:
            raise ValueError("Maximum 10 URLs per batch request")
        return v


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
