import json
import time
from fastapi import FastAPI, BackgroundTasks, HTTPException
import uvicorn

# Core Pipeline Imports
from src.core.imap_fetcher import process_inbox
from src.core.pipeline import run_analysis
from src.core.risk_engine import calculate_risk
from src.db.database import get_db_connection
from src.api.schemas import TriggerResponse

app = FastAPI(title="Phish Pipeline API", version="1.0")

# Simple in-memory cache for results
_results_cache: dict = {}
_cache_ttl: dict = {}
CACHE_SECONDS = 30


def background_pipeline_task():
    """Runs the full pipeline: fetch emails then analyze attachments."""
    print("--- Starting Background IMAP Fetch ---")
    fetch_result = process_inbox()
    print(f"--- Fetch Complete: {fetch_result} ---")

    print("--- Starting Static Analysis Pipeline ---")
    analysis_result = run_analysis()
    print(f"--- Analysis Complete: {analysis_result} ---")

    # Clear cache after new analysis so results are always fresh
    _results_cache.clear()
    _cache_ttl.clear()


@app.post("/api/pipeline/trigger", response_model=TriggerResponse)
async def trigger_pipeline(background_tasks: BackgroundTasks):
    """Triggers the IMAP fetch and analysis pipeline in the background."""
    background_tasks.add_task(background_pipeline_task)
    return {"message": "Pipeline triggered in background.", "status": "processing"}


@app.get("/api/emails")
async def get_emails():
    """List all processed emails, most recent first."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, uid, sender, subject, date_received 
        FROM emails 
        ORDER BY id DESC 
        LIMIT 100
    """)
    emails = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"count": len(emails), "emails": emails}


@app.get("/api/attachments")
async def get_attachments():
    """List all extracted attachments and their current analysis status."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a.id, a.filename, a.sha256, a.status, a.risk_score,
               e.sender, e.subject
        FROM attachments a
        LEFT JOIN emails e ON a.email_id = e.id
        ORDER BY a.id DESC
        LIMIT 100
    """)
    attachments = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"count": len(attachments), "attachments": attachments}


@app.get("/api/results/{sha256}")
async def get_analysis_results(sha256: str):
    """
    View the detailed JSON output and the final RISK SCORE for a specific file.
    """
    # Return cached result if still fresh
    if sha256 in _results_cache:
        if time.time() - _cache_ttl.get(sha256, 0) < CACHE_SECONDS:
            return _results_cache[sha256]

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch attachment info
    cursor.execute(
        "SELECT filename, risk_score, status FROM attachments WHERE sha256 = ?",
        (sha256,)
    )
    attachment = cursor.fetchone()

    if not attachment:
        conn.close()
        raise HTTPException(status_code=404, detail="File not found.")

    attachment_data = dict(attachment)

    # Recalculate risk summary for response
    risk_summary = calculate_risk(sha256)

    # Fetch raw analyzer results
    cursor.execute("""
        SELECT analyzer_name, is_flagged, raw_output 
        FROM analysis_results 
        WHERE attachment_sha256 = ?
    """, (sha256,))

    raw_results = []
    for row in cursor.fetchall():
        res_dict = dict(row)
        try:
            res_dict["raw_output"] = json.loads(res_dict["raw_output"])
        except json.JSONDecodeError:
            res_dict["raw_output"] = {"error": "Failed to parse stored JSON"}
        res_dict["is_flagged"] = bool(res_dict["is_flagged"])
        raw_results.append(res_dict)

    conn.close()

    if not raw_results:
        raise HTTPException(
            status_code=404,
            detail="No analysis results found. File may still be pending."
        )

    response = {
        "file_info": {
            "sha256": sha256,
            "filename": attachment_data["filename"],
            "status": attachment_data["status"]
        },
        "risk_assessment": risk_summary,
        "detailed_analysis": raw_results
    }

    # Cache result
    _results_cache[sha256] = response
    _cache_ttl[sha256] = time.time()

    return response


@app.get("/api/status")
async def get_status():
    """Quick health check — shows pipeline counts."""
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
    conn.close()
    return {
        "emails_processed": email_count,
        "attachments": {
            "total": att_total,
            "pending": att_pending,
            "analyzed": att_analyzed,
            "high_risk": att_high_risk
        }
    }


if __name__ == "__main__":
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)