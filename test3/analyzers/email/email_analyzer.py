import re
import uuid
import time
import base64
import json
import os
import tldextract
from datetime import datetime

from dotenv import load_dotenv
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# ---------------------------------------------------------------------------
# OAuth2 configuration
# ---------------------------------------------------------------------------
import os
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '.env')
load_dotenv(env_path)  # strictly load the unified root .env file

def _get_client_config() -> dict:
    """
    Builds the OAuth2 client config dict from environment variables.
    Raises a clear error when either variable is missing.
    """
    client_id     = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")

    missing = [k for k, v in [("GOOGLE_CLIENT_ID", client_id), ("GOOGLE_CLIENT_SECRET", client_secret)] if not v]
    if missing:
        raise EnvironmentError(
            f"Missing required environment variable(s): {', '.join(missing)}\n"
            "Add them to your .env file:\n"
            "  GOOGLE_CLIENT_ID=<your-client-id>\n"
            "  GOOGLE_CLIENT_SECRET=<your-client-secret>"
        )

    return {
        "installed": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["http://localhost"],
        }
    }


# ---------------------------------------------------------------------------
# Gmail authentication & fetching helpers
# ---------------------------------------------------------------------------

import os
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
TOKEN_FILE = "token.json"


def get_gmail_service():
    creds = None

    # Load token if exists
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    # Refresh or create new creds
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_config({
                "installed": {
                    "client_id": os.environ["GOOGLE_CLIENT_ID"],
                    "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            }, SCOPES)

            creds = flow.run_local_server(port=0)

        # Save token
        with open(TOKEN_FILE, "w") as f:
            f.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def fetch_recent_messages(service, count: int = 5) -> list[dict]:
    """
    Returns the `count` most recent messages from the inbox as raw message dicts.
    Each dict contains 'headers' (dict) and 'body' (str).
    """
    results = (
        service.users()
        .messages()
        .list(userId="me", labelIds=["INBOX"], maxResults=count)
        .execute()
    )
    message_ids = [m["id"] for m in results.get("messages", [])]

    emails = []
    for msg_id in message_ids:
        raw = (
            service.users()
            .messages()
            .get(userId="me", id=msg_id, format="full")
            .execute()
        )
        emails.append(_parse_raw_message(raw))
    return emails


def _parse_raw_message(raw: dict) -> dict:
    """
    Extracts headers dict, plain-text body, and attachment count from a
    raw Gmail API message object.
    """
    payload = raw.get("payload", {})
    header_list = payload.get("headers", [])
    headers = {h["name"]: h["value"] for h in header_list}

    body_text = _extract_body(payload)
    num_attachments = _count_attachments(payload)

    return {
        "headers": headers,
        "body": body_text,
        "num_attachments": num_attachments,
        "gmail_id": raw.get("id"),
        "thread_id": raw.get("threadId"),
    }


def _extract_body(payload: dict) -> str:
    """
    Recursively walks the MIME payload tree and returns the first
    text/plain part decoded from base64url, or falls back to text/html
    stripped of tags.
    """
    mime_type = payload.get("mimeType", "")
    parts = payload.get("parts", [])

    if not parts:
        # Leaf node
        data = payload.get("body", {}).get("data", "")
        if data:
            decoded = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
            if "html" in mime_type:
                decoded = re.sub(r"<[^>]+>", " ", decoded)
            return decoded.strip()
        return ""

    # Prefer text/plain over text/html
    for part in parts:
        if part.get("mimeType") == "text/plain":
            return _extract_body(part)
    for part in parts:
        if part.get("mimeType") == "text/html":
            return _extract_body(part)
    for part in parts:
        result = _extract_body(part)
        if result:
            return result
    return ""


def _count_attachments(payload: dict) -> int:
    """Counts MIME parts that look like file attachments."""
    count = 0
    for part in payload.get("parts", []):
        disposition = ""
        for h in part.get("headers", []):
            if h["name"].lower() == "content-disposition":
                disposition = h["value"].lower()
        if "attachment" in disposition:
            count += 1
        count += _count_attachments(part)
    return count


# ---------------------------------------------------------------------------
# Email analysis engine (unchanged core logic)
# ---------------------------------------------------------------------------

class EmailAnalyzer:
    """
    Analyses raw email headers and body to produce a structured JSON report
    for a multi-stage phishing detection system.
    """

    def __init__(self):
        self.url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
        self.email_pattern = re.compile(
            r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        )

    def _extract_domain_parts(self, email_address: str):
        if not email_address or "@" not in email_address:
            return None, None
        domain = email_address.split("@")[-1].lower()
        ext = tldextract.extract(domain)
        root_domain = f"{ext.domain}.{ext.suffix}"
        return domain, root_domain

    def analyze(
        self,
        raw_headers: dict,
        body_text: str,
        num_attachments: int = 0,
        gmail_id: str | None = None,
        thread_id: str | None = None,
    ) -> dict:
        start_time = time.time()

        # 1. Header extraction
        sender = raw_headers.get("From", "")
        return_path = raw_headers.get("Return-Path", "").strip("<>")
        reply_to = raw_headers.get("Reply-To", "").strip("<>")
        auth_results = raw_headers.get("Authentication-Results", "").lower()
        subject = raw_headers.get("Subject", "(no subject)")
        date_str = raw_headers.get("Date", "")

        sender_match = self.email_pattern.search(sender)
        sender_email = sender_match.group(0) if sender_match else ""
        primary_domain, root_domain = self._extract_domain_parts(sender_email)

        # 2. IOC extraction
        found_urls = list(set(self.url_pattern.findall(body_text)))
        found_emails = list(set(self.email_pattern.findall(body_text)))
        found_domains = list(
            set(
                tldextract.extract(u).registered_domain
                for u in found_urls
                if tldextract.extract(u).registered_domain
            )
        )

        # 3. Authentication analysis
        has_spf_pass = "spf=pass" in auth_results
        has_dkim_pass = "dkim=pass" in auth_results
        has_dmarc_pass = "dmarc=pass" in auth_results
        is_reply_to_different = bool(
            reply_to and sender_email and reply_to.lower() != sender_email.lower()
        )

        # 4. Signal generation & scoring
        signals = []
        patterns = {
            "spoofed_sender": [],
            "suspicious_headers": [],
            "reply_to_mismatch": [],
        }

        if sender_email and return_path and sender_email.lower() != return_path.lower():
            ev = f"From header ({sender_email}) does not match Return-Path ({return_path})."
            patterns["spoofed_sender"].append(ev)
            signals.append({
                "id": "spoofed_sender",
                "category": "STRUCTURAL",
                "severity": "HIGH",
                "weight": 40,
                "confidence": 1.0,
                "evidence": ev,
            })

        if is_reply_to_different:
            ev = f"Reply-To ({reply_to}) directs replies to a different address than the sender."
            patterns["reply_to_mismatch"].append(ev)
            signals.append({
                "id": "reply_to_mismatch",
                "category": "STRUCTURAL",
                "severity": "MEDIUM",
                "weight": 20,
                "confidence": 0.9,
                "evidence": ev,
            })

        if not has_spf_pass and not has_dkim_pass:
            signals.append({
                "id": "failed_authentication",
                "category": "INFRASTRUCTURE",
                "severity": "MEDIUM",
                "weight": 25,
                "confidence": 1.0,
                "evidence": "Email failed both SPF and DKIM sender authentication checks.",
            })

        score = min(sum(s["weight"] for s in signals), 100)
        verdict = (
            "DANGEROUS"  if score >= 70 else
            "SUSPICIOUS" if score >= 40 else
            "LOW RISK"   if score >= 15 else
            "CLEAN"
        )

        # 5. Graph construction
        nodes = [
            {"id": sender_email, "type": "email",  "entity_id": f"email:{sender_email}"},
            {"id": primary_domain, "type": "domain", "entity_id": f"domain:{primary_domain}"},
        ]
        edges = [{"from": sender_email, "to": primary_domain, "type": "sent_from"}]
        for url in found_urls:
            edges.append({"from": sender_email, "to": url, "type": "contains_link"})

        # 6. Assemble output
        output = {
            "id": str(uuid.uuid4()),
            "gmail_id": gmail_id,
            "thread_id": thread_id,
            "session_id": None,
            "parent_id": None,
            "type": "email",
            "source": "gmail_api",
            "subject": subject,
            "date": date_str,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "iocs": {
                "domains": found_domains,
                "ips": [],
                "urls": found_urls,
                "emails": found_emails,
                "hashes": [],
                "patterns": patterns,
            },
            "infrastructure": {
                "primary_domain": primary_domain,
                "root_domain": root_domain,
                "resolved_ips": [],
                "mx_records": [],
                "geo": {"country": None, "high_risk": False},
            },
            "features": {
                "has_spf_pass": has_spf_pass,
                "has_dkim_pass": has_dkim_pass,
                "has_dmarc_pass": has_dmarc_pass,
                "sender_domain_age_days": None,
                "num_links": len(found_urls),
                "num_attachments": num_attachments,
                "is_reply_to_different": is_reply_to_different,
            },
            "signals": signals,
            "graph": {"nodes": nodes, "edges": edges},
            "correlation_keys": {
                "domains": list(set(filter(None, [primary_domain, root_domain]))),
                "ips": [],
                "brands": [],
                "emails": list(set(filter(None, [sender_email, return_path, reply_to]))),
                "hashes": [],
            },
            "attack_type": (
                ["phishing"]             if score >= 40 else
                ["social_engineering"]   if score >= 15 else
                ["benign_communication"]
            ),
            "primary_attack_vector": "email_delivery",
            "attack_story": (
                f"Email from {sender_email} (subject: \"{subject}\") was classified as "
                f"{verdict}. It contains {len(found_urls)} URLs. "
                f"Key signals: {len(signals)} detected, including potential sender "
                f"spoofing ({'Yes' if patterns['spoofed_sender'] else 'No'})."
            ),
            "score": score,
            "verdict": verdict,
            "confidence": 0.9 if score > 40 else 0.75,
            "analysis_time_ms": round((time.time() - start_time) * 1000, 2),
        }
        return output


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    print("[*] Authenticating with Gmail via OAuth2 …")
    service = get_gmail_service()
    print("[*] Fetching 5 most recent inbox messages …")
    emails = fetch_recent_messages(service, count=5)

    analyzer = EmailAnalyzer()
    reports = []

    for i, email_data in enumerate(emails, start=1):
        print(f"[*] Analysing email {i}/5 …")
        report = analyzer.analyze(
            raw_headers=email_data["headers"],
            body_text=email_data["body"],
            num_attachments=email_data["num_attachments"],
            gmail_id=email_data["gmail_id"],
            thread_id=email_data["thread_id"],
        )
        reports.append(report)

    # Save all reports to a JSON file
    output_path = "gmail_analysis_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2, ensure_ascii=False)

    print(f"\n[✓] Analysis complete. Reports saved to '{output_path}'")
    print("\n── Per-email summary ──────────────────────────────────────────────")
    for r in reports:
        print(
            f"  Subject : {r['subject']}\n"
            f"  From    : {r['correlation_keys']['emails']}\n"
            f"  Verdict : {r['verdict']}  (score={r['score']})\n"
            f"  Signals : {len(r['signals'])}\n"
        )

    # Also pretty-print to stdout for quick inspection
    print("\n── Full JSON output ───────────────────────────────────────────────")
    print(json.dumps(reports, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()