import json
import logging
from src.core.config import QUARANTINE_DIR
from src.db.database import get_db_connection
from src.analyzers.file_id import MagicAnalyzer
from src.analyzers.yara_scanner import YaraAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Instantiate analyzers (they compile rules/load assets on boot)
ANALYZERS = [
    MagicAnalyzer(),
    YaraAnalyzer()
]

def run_analysis():
    """Finds pending attachments and runs them through all analyzers."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get attachments waiting for analysis
    cursor.execute("SELECT id, sha256, filename FROM attachments WHERE status = 'pending_analysis'")
    pending_files = cursor.fetchall()

    if not pending_files:
        logger.info("No pending files to analyze.")
        conn.close()
        return {"status": "success", "analyzed": 0}

    analyzed_count = 0

    for file_record in pending_files:
        att_id = file_record["id"]
        sha256 = file_record["sha256"]
        filename = file_record["filename"]
        file_path = QUARANTINE_DIR / sha256

        if not file_path.exists():
            logger.error(f"File missing from quarantine: {sha256}")
            cursor.execute("UPDATE attachments SET status = 'error_missing_file' WHERE id = ?", (att_id,))
            continue

        logger.info(f"Analyzing {filename} ({sha256})...")

        # Run through every analyzer
        for analyzer in ANALYZERS:
            try:
                result = analyzer.analyze(file_path)
                
                # Save result to DB
                cursor.execute("""
                    INSERT INTO analysis_results (attachment_sha256, analyzer_name, is_flagged, raw_output)
                    VALUES (?, ?, ?, ?)
                """, (
                    sha256, 
                    analyzer.name, 
                    result["is_flagged"], 
                    json.dumps(result["raw_output"]) # Store dict as JSON string
                ))
            except Exception as e:
                logger.error(f"Analyzer {analyzer.name} failed on {sha256}: {e}")

        # Update attachment status
        cursor.execute("UPDATE attachments SET status = 'analyzed' WHERE id = ?", (att_id,))
        analyzed_count += 1

    conn.commit()
    conn.close()
    
    return {"status": "success", "analyzed": analyzed_count}