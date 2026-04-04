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

from .mime_parser import parse_raw_email, ParsedEmail

# Ensure analyzers can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
# Allow attachment analyzers to import 'src' modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "analyzers", "attachements")))

from analyzers.email.email_analyzer import EmailAnalyzer
from analyzers.behaviour.behaviour_analyzer import BehaviourAnalyzer
from analyzers.clustering.clustering_analyzer import ClusteringAnalyzer

from analyzers.attachements.src.analyzers.file_id import MagicAnalyzer
from analyzers.attachements.src.analyzers.yara_scanner import YaraAnalyzer
from analyzers.attachements.src.analyzers.office import OfficeAnalyzer
from analyzers.attachements.src.analyzers.pdf import PDFAnalyzer
from analyzers.attachements.src.analyzers.archive import ArchiveAnalyzer

# Initialize engines
email_engine = EmailAnalyzer()
behaviour_engine = BehaviourAnalyzer()
cluster_engine = ClusteringAnalyzer()

att_analyzers = [
    MagicAnalyzer(),
    YaraAnalyzer(),
    OfficeAnalyzer(),
    PDFAnalyzer(),
    ArchiveAnalyzer()
]

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
    explanation: str = ""
    cached:     bool = False
    malicious_urls: list[str] = []


def verdict_from_score(score: int) -> tuple[str, str]:
    if score >= 70:
        return "phishing",   "high"   if score >= 85 else "medium"
    if score >= 40:
        return "suspicious", "medium"
    return "safe", "high"


def weighted_aggregate(signals: list[dict]) -> int:
    """
    Risk-based weighted aggregation:
    - Normalizes weights for available engines.
    - If any engine detects a high risk (score >= 70), it prevents score dilution.
    """
    weights = {"url": 0.40, "nlp": 0.35, "headers": 0.25, "attachments": 0.40}
    
    # Calculate total weight dynamically based on present signals
    present_weights = {s["engine"]: weights.get(s["engine"], 0.33) for s in signals}
    total_weight = sum(present_weights.values())
    
    if total_weight == 0:
        return 0
        
    weighted_sum = sum(s["score"] * present_weights[s["engine"]] for s in signals)
    weighted_avg = round(weighted_sum / total_weight)
    
    max_score = max((s.get("score", 0) for s in signals), default=0)
    
    # If there's a strong phishing indicator, don't dilute it down to "safe"
    if max_score >= 70:
        final_val = max(weighted_avg, max_score)
    elif max_score >= 40:
        # Boost suspicious items a bit so they aren't completely ignored
        final_val = max(weighted_avg, round((weighted_avg + max_score) / 2))
    else:
        final_val = weighted_avg
        
    return max(0, min(100, final_val))


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
    url_flags = []
    max_url_score = 0
    malicious_urls = []
    print("[*] Running URL/Behaviour Analyzer for ALL URLs...")
    for u in getattr(parsed, "urls", []):
        try:
            beh_res = behaviour_engine.analyze(text=parsed.text_body, url=u)
            score = beh_res.get("score", 0)
            if score > 0:
                print(f"    - URL Score: {score}/100 for {u}")
                
            if score >= 30: # or logic dependent on scoring threshold
                malicious_urls.append(u)
                url_flags.extend([s["id"] for s in beh_res.get("signals", [])])
                max_url_score = max(max_url_score, score)
                
            if score == 0:
                pass # print(f"    - Clean URL for {u}")
        except Exception as e:
            print(f"    [!] Behaviour analyzer error on {u}: {e}")

    url_result = {
        "score": max_url_score,
        "flags": list(set(url_flags))
    }

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

    # Attachments
    import tempfile
    print("[*] Running Attachment Analyzers...")
    att_score = 0
    att_flags = []
    att_explanation_parts = []
    
    for att in getattr(parsed, "attachments", []):
        if not att.content: continue
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(att.content)
                tmp_path = tmp.name
            
            for analyzer in att_analyzers:
                try:
                    res = analyzer.analyze(tmp_path)
                    if res.get("is_flagged"):
                        att_score = max(att_score, 80)
                        fname = att.filename or "unknown"
                        flag_id = f"att_{analyzer.name}_flag"
                        att_flags.append(flag_id)
                        
                        detail = f"{fname} flagged by {analyzer.name}: {res.get('raw_output')}"
                        att_explanation_parts.append(detail)
                        print(f"    - [ATT] {detail}")
                except Exception as e:
                    print(f"    [!] {analyzer.name} error on {att.filename}: {e}")
            os.remove(tmp_path)
        except Exception as e:
            print(f"    [!] Attachment temp file error: {e}")

    signals = [
        {"engine": "url",     **url_result},
        {"engine": "nlp",     **nlp_result},
        {"engine": "headers", **header_result},
    ]
    if att_score > 0:
        signals.append({"engine": "attachments", "score": att_score, "flags": list(set(att_flags))})

    explanation = ""
    if att_explanation_parts:
        explanation += "Attachment findings: " + " | ".join(att_explanation_parts)

    # 3. Aggregate
    final_score        = weighted_aggregate(signals)
    verdict, confidence = verdict_from_score(final_score)

    return ScanResponse(
        message_id = req.message_id,
        score      = final_score,
        verdict    = verdict,
        confidence = confidence,
        signals    = [EngineSignal(**s) for s in signals],
        explanation = explanation,
        malicious_urls = list(set(malicious_urls))
    )

class WebsiteRequest(BaseModel):
    url: str
    title: str = ""
    content: str = ""

@router.post("/scan-website", response_model=ScanResponse)
async def scan_website(req: WebsiteRequest):
    print(f"\n{'='*50}")
    print(f"[*] Starting Website Scan for: {req.url}")
    print(f"[*] Page Title: {req.title}")
    text_len = len(req.content) if req.content else 0
    print(f"[*] Content Extracted: {text_len} characters")
    
    url_result = {"score": 0, "flags": []}
    try:
        print("[*] Running URL/Behaviour Analyzer...")
        beh_res = behaviour_engine.analyze(text=req.content, url=req.url)
        url_result = {
            "score": beh_res.get("score", 0),
            "flags": [s["id"] for s in beh_res.get("signals", [])]
        }
        print(f"    - URL Score: {url_result['score']}/100")
        print(f"    - URL Flags: {url_result['flags']}")
    except Exception as e:
        print(f"    [!] Website URL analyzer error: {e}")
        
    nlp_result = {"score": 0, "flags": []}
    try:
        if req.content:
            print("[*] Running NLP/Clustering Analyzer...")
            clu_res = cluster_engine.analyze(text=req.content, source_id="website_scan")
            nlp_result = {
                "score": clu_res.get("score", 0),
                "flags": [s["id"] for s in clu_res.get("signals", [])]
            }
            print(f"    - NLP Score: {nlp_result['score']}/100")
            print(f"    - NLP Flags: {nlp_result['flags']}")
        else:
            print("    [!] Skipping NLP analyzer (no page content)")
    except Exception as e:
        print(f"    [!] Website NLP analyzer error: {e}")

    signals = [
        {"engine": "url", **url_result},
        {"engine": "nlp", **nlp_result},
        {"engine": "headers", "score": 0, "flags": []}
    ]

    final_score = weighted_aggregate(signals)
    verdict, confidence = verdict_from_score(final_score)
    print(f"[*] Overall Aggregated Score: {final_score}/100")
    print(f"[*] Final Verdict: {verdict.upper()} ({confidence} confidence)")
    print(f"{'='*50}\n")
    
    # Generate human readable explanation
    explanation = f"Analyzed {req.url}. "
    if url_result['flags'] or nlp_result['flags']:
        all_flags = url_result['flags'] + nlp_result['flags']
        explanation += f"Found {len(all_flags)} suspicious flags: " + ", ".join(all_flags) + "."
    else:
        explanation += "No explicit phishing signals were detected."

    return ScanResponse(
        message_id = req.url[:50],
        score      = final_score,
        verdict    = verdict,
        confidence = confidence,
        signals    = [EngineSignal(**s) for s in signals],
        explanation = explanation,
    )
