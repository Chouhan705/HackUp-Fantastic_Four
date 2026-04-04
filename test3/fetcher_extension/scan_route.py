"""
parser/scan_route.py

Drop this into your FastAPI app.
It wires the MIME parser to your existing engine fan-out.
"""

import asyncio
import sys
import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from mime_parser import parse_raw_email, ParsedEmail

# Ensure analyzers can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analyzers.email.email_analyzer import EmailAnalyzer
from analyzers.behaviour.behaviour_analyzer import BehaviourAnalyzer
from analyzers.clustering.clustering_analyzer import ClusteringAnalyzer

# Initialize engines
email_engine = EmailAnalyzer()
behaviour_engine = BehaviourAnalyzer()
cluster_engine = ClusteringAnalyzer()

router = APIRouter()

class ScanRequest(BaseModel):
    message_id: str
    raw_email:  str   # base64url string from Gmail API


class EngineSignal(BaseModel):
    engine: str
    score:  int
    flags:  list[str]


class ScanResponse(BaseModel):
    message_id: str
    score:      int
    verdict:    str   # "safe" | "suspicious" | "phishing"
    confidence: str   # "high" | "medium" | "low"
    signals:    list[EngineSignal]
    cached:     bool = False


def verdict_from_score(score: int) -> tuple[str, str]:
    if score >= 70:
        return "phishing",   "high"   if score >= 85 else "medium"
    if score >= 40:
        return "suspicious", "medium"
    return "safe", "high"


def weighted_aggregate(signals: list[dict]) -> int:
    """
    Weighted average: URL (40%) + NLP (35%) + Headers (25%).
    Clamp to 0-100.
    """
    weights = {"url": 0.40, "nlp": 0.35, "headers": 0.25}
    total = sum(
        s["score"] * weights.get(s["engine"], 0.33)
        for s in signals
    )
    return max(0, min(100, round(total)))


@router.post("/scan", response_model=ScanResponse)
async def scan_email(req: ScanRequest):
    # 1. Parse raw email
    try:
        parsed = parse_raw_email(req.raw_email)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"MIME parse error: {e}")

    # 2. Fan out to engines in parallel
    
    # Header & Email Analyzer (acts as our headers engine)
    try:
        num_attachments = len(getattr(parsed, "attachments", []))
        em_res = email_engine.analyze(
            raw_headers=parsed.headers, 
            body_text=parsed.text_body, 
            num_attachments=num_attachments, 
            gmail_id=req.message_id
        )
        header_result = {
            "score": em_res.get("score", 0), 
            "flags": [s["id"] for s in em_res.get("signals", [])]
        }
    except Exception as e:
        header_result = {"score": 0, "flags": [f"email_error"] }
        print(f"Email analyzer error: {e}")

    # URL / Behaviour Analyzer (acts as our URL engine)
    try:
        first_url = parsed.urls[0] if parsed.urls else ""
        beh_res = behaviour_engine.analyze(text=parsed.text_body, url=first_url)
        url_result = {
            "score": beh_res.get("score", 0),
            "flags": [s["id"] for s in beh_res.get("signals", [])]
        }
    except Exception as e:
        url_result = {"score": 0, "flags": [f"url_error"]}
        print(f"Behaviour analyzer error: {e}")

    # NLP / Clustering Analyzer (acts as our NLP engine)
    try:
        clu_res = cluster_engine.analyze(text=parsed.text_body, source_id=req.message_id)
        nlp_result = {
            "score": clu_res.get("score", 0),
            "flags": [s["id"] for s in clu_res.get("signals", [])]
        }
    except Exception as e:
        nlp_result = {"score": 0, "flags": [f"nlp_error"]}
        print(f"Clustering analyzer error: {e}")

    signals = [
        {"engine": "url",     **url_result},
        {"engine": "nlp",     **nlp_result},
        {"engine": "headers", **header_result},
    ]

    # 3. Aggregate
    final_score        = weighted_aggregate(signals)
    verdict, confidence = verdict_from_score(final_score)

    return ScanResponse(
        message_id = req.message_id,
        score      = final_score,
        verdict    = verdict,
        confidence = confidence,
        signals    = [EngineSignal(**s) for s in signals],
    )

class WebsiteRequest(BaseModel):
    url: str
    title: str = ""
    content: str = ""

@router.post("/scan-website", response_model=ScanResponse)
async def scan_website(req: WebsiteRequest):
    # Pass the URL and page text to our existing engines.
    # We fallback to generating a dummy "message_id".
    
    url_result = {"score": 0, "flags": []}
    try:
        beh_res = behaviour_engine.analyze(text=req.content, url=req.url)
        url_result = {
            "score": beh_res.get("score", 0),
            "flags": [s["id"] for s in beh_res.get("signals", [])]
        }
    except Exception as e:
        print(f"Website URL analyzer error: {e}")
        
    nlp_result = {"score": 0, "flags": []}
    try:
        if req.content:
            clu_res = cluster_engine.analyze(text=req.content, source_id="website_scan")
            nlp_result = {
                "score": clu_res.get("score", 0),
                "flags": [s["id"] for s in clu_res.get("signals", [])]
            }
    except Exception as e:
        print(f"Website NLP analyzer error: {e}")

    signals = [
        {"engine": "url", **url_result},
        {"engine": "nlp", **nlp_result},
        {"engine": "headers", "score": 0, "flags": []} # No headers for general websites
    ]

    final_score = weighted_aggregate(signals)
    verdict, confidence = verdict_from_score(final_score)

    return ScanResponse(
        message_id = req.url[:50],  # using truncated URL as a fallback ID
        score      = final_score,
        verdict    = verdict,
        confidence = confidence,
        signals    = [EngineSignal(**s) for s in signals],
    )
