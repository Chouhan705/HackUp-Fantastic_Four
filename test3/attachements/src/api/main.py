import json
import time
from fastapi import FastAPI, BackgroundTasks, HTTPException
import uvicorn

from src.core.imap_fetcher import process_inbox
from src.core.pipeline import run_analysis
from src.core.risk_engine import calculate_risk
from src.core.sandbox_client import run_sandbox
from src.core.attachment_report import build_attachment_report
from src.db.database import get_db_connection
from src.api.schemas import TriggerResponse

app = FastAPI(title="Phish Pipeline API", version="1.0")

_results_cache: dict = {}
_cache_ttl: dict = {}
CACHE_SECONDS = 30


def background_pipeline_task():
    print("--- Starting Background IMAP Fetch ---")
    fetch_result = process_inbox()
    print(f"--- Fetch Complete: {fetch_result} ---")
    print("--- Starting Static Analysis Pipeline ---")
    analysis_result = run_analysis()
    print(f"--- Analysis Complete: {analysis_result} ---")
    _results_cache.clear()
    _cache_ttl.clear()


@app.post("/api/pipeline/trigger", response_model=TriggerResponse)
async def trigger_pipeline(background_tasks: BackgroundTasks):
    """Triggers the full pipeline in the background."""
    background_tasks.add_task(background_pipeline_task)
    return {"message": "Pipeline triggered in background.", "status": "processing"}


@app.get("/api/emails")
async def get_emails():
    """List all processed emails, most recent first."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, uid, sender, subject, date_received 
        FROM emails ORDER BY id DESC LIMIT 100
    """)
    emails = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"count": len(emails), "emails": emails}


@app.get("/api/attachments")
async def get_attachments():
    """List all extracted attachments with email context."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a.id, a.filename, a.sha256, a.status, a.risk_score,
               e.sender, e.subject
        FROM attachments a
        LEFT JOIN emails e ON a.email_id = e.id
        ORDER BY a.id DESC LIMIT 100
    """)
    attachments = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"count": len(attachments), "attachments": attachments}


@app.get("/api/results/{sha256}")
async def get_analysis_results(sha256: str):
    """
    Returns the full structured attachment report in the standardised schema:
    iocs, features, signals, graph, attack_story, verdict, score, confidence.
    """
    if sha256 in _results_cache:
        if time.time() - _cache_ttl.get(sha256, 0) < CACHE_SECONDS:
            return _results_cache[sha256]

    try:
        report = build_attachment_report(sha256)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")

    # Attach sandbox results if available
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT provider, is_flagged, detection_rate, flagged_by, raw_report, submitted_at
        FROM sandbox_results WHERE attachment_sha256 = ?
    """, (sha256,))
    sandbox_row = cursor.fetchone()
    conn.close()

    if sandbox_row:
        sb = dict(sandbox_row)
        try:
            sb["flagged_by"] = json.loads(sb["flagged_by"])
            sb["raw_report"] = json.loads(sb["raw_report"])
        except (json.JSONDecodeError, TypeError):
            pass
        sb["is_flagged"] = bool(sb["is_flagged"])
        report["sandbox"] = sb
    else:
        report["sandbox"] = {"status": "not_submitted"}

    _results_cache[sha256] = report
    _cache_ttl[sha256] = time.time()
    return report


@app.post("/api/sandbox/{sha256}")
async def trigger_sandbox_manually(sha256: str, background_tasks: BackgroundTasks):
    """Manually submit a file to VirusTotal sandbox."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT sha256 FROM attachments WHERE sha256 = ?", (sha256,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="File not found in DB.")

    from src.core.config import QUARANTINE_DIR
    file_path = QUARANTINE_DIR / sha256
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File missing from quarantine.")

    background_tasks.add_task(run_sandbox, sha256, file_path)
    return {
        "message": f"Sandbox submission triggered for {sha256}.",
        "status": "submitted",
        "note": "Check /api/results/{sha256} in ~60 seconds for results."
    }


@app.get("/api/sandbox/{sha256}")
async def get_sandbox_results(sha256: str):
    """Get the VirusTotal sandbox report for a specific file."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT provider, is_flagged, detection_rate, flagged_by, raw_report, submitted_at
        FROM sandbox_results WHERE attachment_sha256 = ?
    """, (sha256,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="No sandbox results yet. Submit first via POST /api/sandbox/{sha256}."
        )

    result = dict(row)
    try:
        result["flagged_by"] = json.loads(result["flagged_by"])
        result["raw_report"] = json.loads(result["raw_report"])
    except (json.JSONDecodeError, TypeError):
        pass
    result["is_flagged"] = bool(result["is_flagged"])
    return {"sha256": sha256, "sandbox": result}


@app.get("/api/status")
async def get_status():
    """Pipeline health check with counts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as total FROM emails")
    email_count = cursor.fetchone()["total"]
    cursor.execute("SELECT COUNT(*) as total FROM attachments")
    att_total = cursor.fetchone()["total"]
    cursor.execute("SELECT COUNT(*) as total FROM attachments WHERE status = 'pending_analysis'")
    att_pending = cursor.fetchone()["total"]
    cursor.execute("SELECT COUNT(*) as total FROM attachments WHERE status = 'analyzed'")
    att_analyzed = cursor.fetchone()["total"]
    cursor.execute("SELECT COUNT(*) as total FROM attachments WHERE risk_score >= 70")
    att_high_risk = cursor.fetchone()["total"]
    cursor.execute("SELECT COUNT(*) as total FROM sandbox_results")
    sandboxed = cursor.fetchone()["total"]
    cursor.execute("SELECT COUNT(*) as total FROM sandbox_results WHERE is_flagged = 1")
    sandbox_flagged = cursor.fetchone()["total"]
    conn.close()
    return {
        "emails_processed": email_count,
        "attachments": {
            "total": att_total,
            "pending": att_pending,
            "analyzed": att_analyzed,
            "high_risk": att_high_risk
        },
        "sandbox": {
            "total_submitted": sandboxed,
            "flagged_by_vt": sandbox_flagged
        }
    }


if __name__ == "__main__":
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)