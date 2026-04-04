"""
parser/scan_route.py

Drop this into your FastAPI app.
It wires the MIME parser to your existing engine fan-out.

Assumes your engines live in:
  engines.url_analyzer   → async def analyze(urls: list[str]) -> EngineResult
  engines.nlp_analyzer   → async def analyze(text: str, html: str) -> EngineResult
  engines.header_analyzer→ async def analyze(auth: AuthResults, sender: SenderInfo, headers: dict) -> EngineResult

Each engine returns: { "score": int, "flags": list[str] }
"""

import asyncio
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .mime_parser import parse_raw_email, ParsedEmail

# 🔧 Import your own engine modules here
# from engines.url_analyzer    import analyze as url_analyze
# from engines.nlp_analyzer    import analyze as nlp_analyze
# from engines.header_analyzer import analyze as header_analyze

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
    Clamp to 0–100.
    """
    weights = {"url": 0.40, "nlp": 0.35, "headers": 0.25}
    total = sum(
        s["score"] * weights.get(s["engine"], 0.33)
        for s in signals
    )
    return max(0, min(100, round(total)))


@router.post("/scan", response_model=ScanResponse)
async def scan_email(req: ScanRequest):
    # ── 1. Parse raw email ───────────────────────────────────────────────────
    try:
        parsed: ParsedEmail = parse_raw_email(req.raw_email)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"MIME parse error: {e}")

    # ── 2. Fan out to engines in parallel ────────────────────────────────────
    # Uncomment and replace with your real engine calls:
    #
    # url_result, nlp_result, header_result = await asyncio.gather(
    #     url_analyze(parsed.urls),
    #     nlp_analyze(parsed.text_body, parsed.html_body),
    #     header_analyze(parsed.auth, parsed.sender, parsed.headers),
    # )

    # ── Stub responses (remove when engines are wired) ──────────────────────
    url_result    = {"score": 0,  "flags": []}
    nlp_result    = {"score": 0,  "flags": []}
    header_result = {"score": 0,  "flags": []}

    # Auto-score from parsed data so you get something useful immediately
    # even before engines are wired up:
    if parsed.sender.reply_to_mismatch:
        header_result["flags"].append("reply-to-mismatch")
        header_result["score"] += 40
    if parsed.auth.spf in ("fail", "softfail"):
        header_result["flags"].append(f"spf-{parsed.auth.spf}")
        header_result["score"] += 30
    if parsed.auth.dkim == "fail":
        header_result["flags"].append("dkim-fail")
        header_result["score"] += 25
    if parsed.auth.dmarc == "fail":
        header_result["flags"].append("dmarc-fail")
        header_result["score"] += 20
    header_result["score"] = min(100, header_result["score"])
    # ────────────────────────────────────────────────────────────────────────

    signals = [
        {"engine": "url",     **url_result},
        {"engine": "nlp",     **nlp_result},
        {"engine": "headers", **header_result},
    ]

    # ── 3. Aggregate ─────────────────────────────────────────────────────────
    final_score        = weighted_aggregate(signals)
    verdict, confidence = verdict_from_score(final_score)

    return ScanResponse(
        message_id = req.message_id,
        score      = final_score,
        verdict    = verdict,
        confidence = confidence,
        signals    = [EngineSignal(**s) for s in signals],
    )
