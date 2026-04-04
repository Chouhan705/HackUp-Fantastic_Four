import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.core.config import QUARANTINE_DIR
from src.db.database import get_db_connection

# Analyzers
from src.analyzers.file_id import MagicAnalyzer
from src.analyzers.yara_scanner import YaraAnalyzer
from src.analyzers.office import OfficeAnalyzer
from src.analyzers.pdf import PDFAnalyzer
from src.analyzers.archive import ArchiveAnalyzer

# Risk Engine & Sandbox
from src.core.risk_engine import calculate_risk
from src.core.sandbox_client import run_sandbox

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Instantiate analyzers once at boot (compiles rules/loads assets)
ANALYZERS = [
    MagicAnalyzer(),
    YaraAnalyzer(),
    OfficeAnalyzer(),
    PDFAnalyzer(),
    ArchiveAnalyzer()
]


def run_single_analyzer(analyzer, file_path, sha256):
    """Runs one analyzer on one file. Used for parallel execution."""
    try:
        result = analyzer.analyze(file_path)
        return {
            "analyzer_name": analyzer.name,
            "sha256": sha256,
            "is_flagged": result["is_flagged"],
            "raw_output": json.dumps(result["raw_output"])
        }
    except Exception as e:
        logger.error(f"Analyzer {analyzer.name} failed on {sha256}: {e}")
        return {
            "analyzer_name": analyzer.name,
            "sha256": sha256,
            "is_flagged": False,
            "raw_output": json.dumps({"error": str(e)})
        }


def analyze_file(file_record):
    """Runs all analyzers concurrently on a single file."""
    att_id = file_record["id"]
    sha256 = file_record["sha256"]
    filename = file_record["filename"]
    file_path = QUARANTINE_DIR / sha256

    if not file_path.exists():
        logger.error(f"File missing from quarantine: {sha256}")
        return att_id, sha256, None  # Signal missing file

    logger.info(f"Analyzing {filename} ({sha256})...")

    results = []
    # Run all analyzers in parallel for this file
    with ThreadPoolExecutor(max_workers=len(ANALYZERS)) as executor:
        futures = {
            executor.submit(run_single_analyzer, analyzer, file_path, sha256): analyzer.name
            for analyzer in ANALYZERS
        }
        for future in as_completed(futures):
            results.append(future.result())

    return att_id, sha256, results


def run_analysis():
    """Finds pending attachments and runs them through all analyzers in parallel."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, sha256, filename FROM attachments WHERE status = 'pending_analysis'")
    pending_files = cursor.fetchall()

    if not pending_files:
        logger.info("No pending files to analyze.")
        conn.close()
        return {"status": "success", "analyzed": 0}

    logger.info(f"Found {len(pending_files)} file(s) to analyze.")
    analyzed_count = 0

    # Process multiple files concurrently (max 4 at a time)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(analyze_file, record): record for record in pending_files}

        for future in as_completed(futures):
            att_id, sha256, results = future.result()

            if results is None:
                # File was missing from quarantine
                cursor.execute(
                    "UPDATE attachments SET status = 'error_missing_file' WHERE id = ?",
                    (att_id,)
                )
                continue

            # Batch insert all analyzer results at once
            cursor.executemany("""
                INSERT OR IGNORE INTO analysis_results 
                    (attachment_sha256, analyzer_name, is_flagged, raw_output)
                VALUES (:sha256, :analyzer_name, :is_flagged, :raw_output)
            """, results)

            # Commit before running risk engine so it can read the results
            conn.commit()

            # Run risk engine to calculate final score
            calculate_risk(sha256)
            
            # Fetch the updated score to see if sandbox auto-submission is needed
            cursor.execute("SELECT risk_score FROM attachments WHERE id = ?", (att_id,))
            risk_row = cursor.fetchone()
            risk_score = risk_row["risk_score"] if risk_row else 0
            
            # Auto-submit files scoring >= 70 to the sandbox
            if risk_score >= 70:
                logger.warning(f"File {sha256} scored {risk_score} (>= 70). Auto-submitting to Sandbox...")
                file_path = QUARANTINE_DIR / sha256
                run_sandbox(sha256, file_path)

            cursor.execute(
                "UPDATE attachments SET status = 'analyzed' WHERE id = ?",
                (att_id,)
            )
            analyzed_count += 1

    conn.commit()
    conn.close()

    logger.info(f"Analysis complete. Processed {analyzed_count} file(s).")
    return {"status": "success", "analyzed": analyzed_count}