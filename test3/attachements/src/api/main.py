import json
from fastapi import FastAPI, BackgroundTasks
import uvicorn

# Core Pipeline Imports
from src.core.imap_fetcher import process_inbox
from src.core.pipeline import run_analysis
from src.db.database import get_db_connection
from src.api.schemas import TriggerResponse

app = FastAPI(title="Phish Pipeline API", version="1.0")

def background_pipeline_task():
    """
    Wrapper for the background task that runs the entire pipeline sequentially.
    """
    print("--- Starting Background IMAP Fetch ---")
    fetch_result = process_inbox()
    print(f"--- Fetch Complete: {fetch_result} ---")
    
    print("--- Starting Static Analysis Pipeline ---")
    analysis_result = run_analysis()
    print(f"--- Analysis Complete: {analysis_result} ---")


@app.post("/api/pipeline/trigger", response_model=TriggerResponse)
async def trigger_pipeline(background_tasks: BackgroundTasks):
    """
    Manually triggers the IMAP fetch and static analysis pipeline.
    Runs asynchronously so the API doesn't hang.
    """
    background_tasks.add_task(background_pipeline_task)
    return {"message": "Pipeline triggered in background.", "status": "processing"}


@app.get("/api/emails")
async def get_emails():
    """
    List all processed emails.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM emails ORDER BY id DESC")
    emails = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"emails": emails}


@app.get("/api/attachments")
async def get_attachments():
    """
    List all extracted attachments and their current analysis status.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename, sha256, status, risk_score FROM attachments ORDER BY id DESC")
    attachments = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"attachments": attachments}


@app.get("/api/results/{sha256}")
async def get_analysis_results(sha256: str):
    """
    View the detailed JSON output of the analyzers for a specific file.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch results for the specific file hash
    cursor.execute("""
        SELECT analyzer_name, is_flagged, raw_output 
        FROM analysis_results 
        WHERE attachment_sha256 = ?
    """, (sha256,))
    
    results = []
    for row in cursor.fetchall():
        res_dict = dict(row)
        # The database stores the raw_output as a JSON string.
        # We parse it back into a Python dictionary so FastAPI serves it as clean JSON.
        try:
            res_dict["raw_output"] = json.loads(res_dict["raw_output"])
        except json.JSONDecodeError:
            res_dict["raw_output"] = {"error": "Failed to parse JSON from DB"}
            
        # Convert SQLite boolean (1/0) to Python True/False
        res_dict["is_flagged"] = bool(res_dict["is_flagged"])
        
        results.append(res_dict)
        
    conn.close()
    
    if not results:
        return {"sha256": sha256, "message": "No analysis results found or file pending."}
        
    return {"sha256": sha256, "analysis": results}


if __name__ == "__main__":
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)