import json
import logging
from src.db.database import get_db_connection

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def calculate_risk(sha256: str):
    """
    Reads all analysis results for a specific file, computes a risk score (0-100),
    and generates explainable reasons. Updates the attachments table.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Fetch the original filename and current score
    cursor.execute("SELECT filename FROM attachments WHERE sha256 = ?", (sha256,))
    attachment = cursor.fetchone()
    if not attachment:
        conn.close()
        return None
    
    filename = attachment["filename"].lower()

    # 2. Fetch all analysis results for this file
    cursor.execute("SELECT analyzer_name, is_flagged, raw_output FROM analysis_results WHERE attachment_sha256 = ?", (sha256,))
    results = cursor.fetchall()

    score = 0
    reasons = []

    # 3. Apply Heuristics (Scoring Rules)
    for row in results:
        analyzer = row["analyzer_name"]
        is_flagged = bool(row["is_flagged"])
        
        try:
            output = json.loads(row["raw_output"])
        except:
            output = {}

        if not is_flagged:
            continue  # Skip if the tool didn't flag anything

        # --- Rule 1: YARA Signatures ---
        if analyzer == "yara":
            score += 100
            reasons.append("YARA matched a known malware signature.")

        # --- Rule 2: Office Macros ---
        elif analyzer == "oletools":
            if output.get("auto_exec"):
                score += 100
                reasons.append("Office document contains highly dangerous AUTO-EXECUTING macros.")
            else:
                score += 40
                reasons.append("Office document contains macros.")

        # --- Rule 3: PDF Anomalies ---
        elif analyzer == "pdf_structure":
            score += 40
            reasons.append("PDF contains suspicious elements like JavaScript or auto-launch actions.")

        # --- Rule 4: Risky Archives ---
        elif analyzer == "zip_inspector":
            if output.get("is_encrypted"):
                score += 20
                reasons.append("Archive is password-protected (common evasion tactic).")
            if output.get("risky_files_found"):
                score += 60
                reasons.append(f"Archive contains dangerous file types: {', '.join(output.get('risky_files_found'))}.")

        # --- Rule 5: File Extension Spoofing ---
        elif analyzer == "python-magic":
            # If magic flags it, it means it's an executable/script. 
            # If the filename claims to be a safe document, that's malicious spoofing.
            safe_extensions = ('.pdf', '.txt', '.jpg', '.png', '.doc', '.csv')
            if filename.endswith(safe_extensions):
                score += 80
                reasons.append(f"EXTENSION SPOOFING: File claims to be safe but is actually an executable/script.")
            else:
                score += 20
                reasons.append("File is a recognized executable or script format.")

    # 4. Cap the score at 100 and determine severity
    score = min(score, 100)
    
    if score == 0:
        severity = "Safe"
    elif score < 50:
        severity = "Suspicious"
    else:
        severity = "Malicious"

    # 5. Update the attachments table
    cursor.execute("""
        UPDATE attachments 
        SET risk_score = ?, status = 'completed' 
        WHERE sha256 = ?
    """, (score, sha256))
    
    conn.commit()
    conn.close()

    logger.info(f"Risk calculated for {sha256}: {score}/100 ({severity})")
    return {
        "score": score, 
        "severity": severity, 
        "reasons": reasons
    }