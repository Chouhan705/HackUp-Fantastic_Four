from fastapi import FastAPI, BackgroundTasks
import uvicorn
from src.core.imap_fetcher import process_inbox
from src.db.database import get_db_connection
from src.api.schemas import TriggerResponse

app = FastAPI(title="Phish Pipeline API", version="1.0")

def background_pipeline_task():
    """Wrapper for the background task."""
    print("--- Starting Background IMAP Fetch ---")
    result = process_inbox()
    print(f"--- Fetch Complete: {result} ---")
    # In Phase 2, we will trigger the static analyzers right here!

@app.post("/api/pipeline/trigger", response_model=TriggerResponse)
async def trigger_pipeline(background_tasks: BackgroundTasks):
    """Manually triggers the IMAP fetch and analysis pipeline."""
    background_tasks.add_task(background_pipeline_task)
    return {"message": "Pipeline triggered in background.", "status": "processing"}

@app.get("/api/emails")
async def get_emails():
    """List all processed emails."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM emails ORDER BY id DESC")
    emails = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"emails": emails}

@app.get("/api/attachments")
async def get_attachments():
    """List all extracted attachments."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename, sha256, status, risk_score FROM attachments")
    attachments = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"attachments": attachments}

if __name__ == "__main__":
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)