import time
import logging
import requests
from pathlib import Path
from src.core.config import VIRUSTOTAL_API_KEY
from src.db.database import get_db_connection

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}

# VirusTotal free tier: 4 requests/minute, 500/day
REQUEST_DELAY = 16  # seconds between submissions to stay under rate limit


def submit_file(file_path: Path, sha256: str) -> dict:
    """
    Submits a file to VirusTotal for analysis.
    Returns the analysis ID if successful.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set in .env"}

    try:
        with open(file_path, "rb") as f:
            response = requests.post(
                f"{VT_BASE}/files",
                headers=HEADERS,
                files={"file": (sha256, f)},
                timeout=30
            )

        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]
            logger.info(f"Submitted {sha256} to VirusTotal. Analysis ID: {analysis_id}")
            return {"analysis_id": analysis_id, "status": "submitted"}
        else:
            logger.error(f"VT submission failed: {response.status_code} {response.text}")
            return {"error": f"HTTP {response.status_code}: {response.text}"}

    except Exception as e:
        logger.error(f"VT submission error for {sha256}: {e}")
        return {"error": str(e)}


def check_existing_report(sha256: str) -> dict | None:
    """
    Checks if VirusTotal already has a report for this hash.
    Returns the report dict if found, None if not found.
    Saves an API call if the file was already seen by VT.
    """
    if not VIRUSTOTAL_API_KEY:
        return None

    try:
        response = requests.get(
            f"{VT_BASE}/files/{sha256}",
            headers=HEADERS,
            timeout=15
        )
        if response.status_code == 200:
            return parse_vt_report(response.json())
        elif response.status_code == 404:
            return None  # Never seen by VT before
        else:
            logger.warning(f"VT lookup returned {response.status_code} for {sha256}")
            return None

    except Exception as e:
        logger.error(f"VT lookup error: {e}")
        return None


def fetch_analysis_report(analysis_id: str, retries: int = 5, wait: int = 20) -> dict:
    """
    Polls VirusTotal for the analysis result.
    Retries up to `retries` times with `wait` seconds between each.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set in .env"}

    for attempt in range(retries):
        try:
            response = requests.get(
                f"{VT_BASE}/analyses/{analysis_id}",
                headers=HEADERS,
                timeout=15
            )

            if response.status_code != 200:
                logger.warning(f"VT poll attempt {attempt+1} failed: {response.status_code}")
                time.sleep(wait)
                continue

            data = response.json()
            status = data["data"]["attributes"]["status"]

            if status == "completed":
                # Fetch the full file report using the sha256 from meta
                sha256 = data.get("meta", {}).get("file_info", {}).get("sha256")
                if sha256:
                    return check_existing_report(sha256) or parse_vt_report(data)
                return parse_vt_report(data)

            logger.info(f"VT analysis status: {status}. Waiting {wait}s... (attempt {attempt+1}/{retries})")
            time.sleep(wait)

        except Exception as e:
            logger.error(f"VT poll error: {e}")
            time.sleep(wait)

    return {"error": "Analysis timed out after maximum retries."}


def parse_vt_report(data: dict) -> dict:
    """
    Parses a VirusTotal API response into a clean, structured summary.
    """
    try:
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        # Collect names of engines that flagged it
        flagged_by = [
            engine for engine, result in results.items()
            if result.get("category") in ("malicious", "suspicious")
        ]

        total_engines = sum(stats.values())
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": stats.get("undetected", 0),
            "total_engines": total_engines,
            "detection_rate": f"{malicious}/{total_engines}",
            "flagged_by": flagged_by[:20],  # Top 20 engines that flagged it
            "is_flagged": malicious > 0 or suspicious > 2,
            "vt_link": f"https://www.virustotal.com/gui/file/{data['data'].get('id', '')}"
        }

    except (KeyError, TypeError) as e:
        logger.error(f"Failed to parse VT report: {e}")
        return {"error": f"Failed to parse report: {e}"}


def run_sandbox(sha256: str, file_path: Path) -> dict:
    """
    Main entry point for sandbox analysis.
    1. Check if VT already has a report (saves API quota).
    2. If not, submit the file.
    3. Poll for results.
    4. Save to DB.
    """
    if not VIRUSTOTAL_API_KEY:
        logger.warning("Skipping sandbox: VIRUSTOTAL_API_KEY not configured.")
        return {"error": "API key not configured"}

    logger.info(f"Running sandbox analysis for {sha256}...")

    # Step 1: Check if VT already knows this file
    existing = check_existing_report(sha256)
    if existing and "error" not in existing:
        logger.info(f"VT already has a report for {sha256}. Using cached report.")
        save_sandbox_result(sha256, existing)
        return existing

    # Step 2: Submit the file
    submission = submit_file(file_path, sha256)
    if "error" in submission:
        return submission

    # Step 3: Wait and poll for results
    logger.info(f"Waiting for VT analysis to complete...")
    time.sleep(REQUEST_DELAY)
    report = fetch_analysis_report(submission["analysis_id"])

    # Step 4: Save to DB
    if "error" not in report:
        save_sandbox_result(sha256, report)

    return report


def save_sandbox_result(sha256: str, report: dict):
    """Saves the sandbox report to the database."""
    import json
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO sandbox_results 
                (attachment_sha256, provider, is_flagged, detection_rate, flagged_by, raw_report)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            sha256,
            "virustotal",
            1 if report.get("is_flagged") else 0,
            report.get("detection_rate", "0/0"),
            json.dumps(report.get("flagged_by", [])),
            json.dumps(report)
        ))
        conn.commit()
        logger.info(f"Saved sandbox result for {sha256}: {report.get('detection_rate')}")
    except Exception as e:
        logger.error(f"Failed to save sandbox result: {e}")
    finally:
        conn.close()