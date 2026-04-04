"""
parser/mime_parser.py

Accepts a base64url-encoded raw RFC 2822 email (as returned by Gmail API with format=raw)
and extracts everything the phishing engines need:
  - Plain text body
  - HTML body
  - All URLs (from body + headers)
  - Parsed headers dict
  - Authentication results (SPF / DKIM / DMARC)
  - Sender / Reply-To / Return-Path info
  - Attachment metadata (without content)

Usage:
    from parser.mime_parser import parse_raw_email
    result = parse_raw_email(base64url_string)
"""

import base64
import email
import email.policy
import re
import quopri
from email import message_from_bytes
from email.header import decode_header, make_header
from typing import Optional
from dataclasses import dataclass, field


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class AuthResults:
    spf:   Optional[str] = None   # "pass" | "fail" | "softfail" | "neutral" | "none"
    dkim:  Optional[str] = None   # "pass" | "fail" | "none"
    dmarc: Optional[str] = None   # "pass" | "fail" | "none"
    raw_received_spf:       Optional[str] = None
    raw_authentication_results: Optional[str] = None


@dataclass
class SenderInfo:
    from_raw:     Optional[str] = None
    from_name:    Optional[str] = None
    from_address: Optional[str] = None
    from_domain:  Optional[str] = None
    reply_to:     Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path:  Optional[str] = None
    reply_to_mismatch: bool = False   # True if reply-to domain != from domain


@dataclass
class Attachment:
    filename:     Optional[str] = None
    content_type: str = ""
    size_bytes:   int = 0


@dataclass
class ParsedEmail:
    # Bodies
    text_body:  str = ""
    html_body:  str = ""

    # URLs extracted from body + hrefs
    urls:       list[str] = field(default_factory=list)

    # All headers as a flat dict (lowercase keys, last value wins for duplicates)
    headers:    dict[str, str] = field(default_factory=dict)

    # Structured sub-extracts
    auth:       AuthResults = field(default_factory=AuthResults)
    sender:     SenderInfo  = field(default_factory=SenderInfo)
    attachments: list[Attachment] = field(default_factory=list)

    subject:    str = ""
    date:       Optional[str] = None
    message_id: Optional[str] = None


# ── URL Extraction ────────────────────────────────────────────────────────────

# Matches http/https URLs in plain text and HTML
_URL_RE = re.compile(
    r'https?://'
    r'(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+)',
    re.IGNORECASE
)

# Extracts href="..." values from raw HTML
_HREF_RE = re.compile(r'href=["\']([^"\'>\s]+)["\']', re.IGNORECASE)


def extract_urls(text: str, html: str) -> list[str]:
    """Return a deduplicated list of all URLs found in plain text and HTML."""
    found = set()

    # From plain text
    for url in _URL_RE.findall(text):
        found.add(url.rstrip(".,;:)\"'"))

    # From HTML: both href attributes and inline text URLs
    for href in _HREF_RE.findall(html):
        if href.startswith("http"):
            found.add(href.rstrip(".,;:)\"'"))
    for url in _URL_RE.findall(html):
        found.add(url.rstrip(".,;:)\"'"))

    # Filter out common false positives (tracking pixel URLs are still legit signals)
    return sorted(found)


# ── Header helpers ────────────────────────────────────────────────────────────

def decode_mime_header(value: str) -> str:
    """Decode encoded MIME header value (e.g. =?UTF-8?B?...?=) to plain string."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def parse_address(raw: str) -> tuple[str, str]:
    """
    Extract (display_name, email_address) from an RFC 2822 address string.
    e.g. '"PayPal Security" <security@paypa1.com>' → ('PayPal Security', 'security@paypa1.com')
    """
    raw = raw.strip()
    m = re.match(r'^"?([^"<]*?)"?\s*<([^>]+)>', raw)
    if m:
        return m.group(1).strip(), m.group(2).strip().lower()

    # Bare email address
    m2 = re.match(r'^[\w.+\-]+@[\w.\-]+$', raw)
    if m2:
        return "", raw.lower()

    return "", raw.lower()


def extract_domain(address: str) -> Optional[str]:
    m = re.search(r'@([\w.\-]+)$', address)
    return m.group(1).lower() if m else None


# ── Auth header parsers ───────────────────────────────────────────────────────

def parse_spf(received_spf: str) -> str:
    """Extract SPF result from Received-SPF header."""
    if not received_spf:
        return "none"
    lower = received_spf.lower().strip()
    for result in ("pass", "fail", "softfail", "neutral", "temperror", "permerror", "none"):
        if lower.startswith(result):
            return result
    return "unknown"


def parse_dkim(auth_results: str) -> str:
    """Extract DKIM result from Authentication-Results header."""
    if not auth_results:
        return "none"
    m = re.search(r'dkim\s*=\s*(\w+)', auth_results, re.IGNORECASE)
    return m.group(1).lower() if m else "none"


def parse_dmarc(auth_results: str) -> str:
    """Extract DMARC result from Authentication-Results header."""
    if not auth_results:
        return "none"
    m = re.search(r'dmarc\s*=\s*(\w+)', auth_results, re.IGNORECASE)
    return m.group(1).lower() if m else "none"


# ── Body extraction ───────────────────────────────────────────────────────────

def decode_payload(part) -> str:
    """Safely decode a MIME part's payload to a UTF-8 string."""
    charset = part.get_content_charset() or "utf-8"
    cte     = (part.get("Content-Transfer-Encoding") or "").lower()

    raw = part.get_payload(decode=True)  # Returns bytes, handles base64/QP
    if not raw:
        return ""

    # Sometimes get_payload(decode=True) still returns base64 for multipart
    if isinstance(raw, str):
        raw = raw.encode("utf-8")

    try:
        return raw.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return raw.decode("utf-8", errors="replace")


def walk_parts(msg) -> tuple[str, str]:
    """
    Walk the MIME tree and collect the best text/plain and text/html parts.
    Handles nested multipart/alternative, multipart/related, multipart/mixed.
    """
    text_parts = []
    html_parts = []

    for part in msg.walk():
        ctype    = part.get_content_type()
        disp     = str(part.get("Content-Disposition") or "")

        # Skip attachments
        if "attachment" in disp:
            continue

        if ctype == "text/plain":
            text_parts.append(decode_payload(part))
        elif ctype == "text/html":
            html_parts.append(decode_payload(part))

    return "\n".join(text_parts), "\n".join(html_parts)


def collect_attachments(msg) -> list[Attachment]:
    attachments = []
    for part in msg.walk():
        disp = str(part.get("Content-Disposition") or "")
        if "attachment" in disp:
            filename = part.get_filename()
            if filename:
                filename = decode_mime_header(filename)
            payload = part.get_payload(decode=True) or b""
            attachments.append(Attachment(
                filename     = filename,
                content_type = part.get_content_type(),
                size_bytes   = len(payload),
            ))
    return attachments


# ── Main entry point ──────────────────────────────────────────────────────────

def parse_raw_email(raw_base64url: str) -> ParsedEmail:
    """
    Parse a Gmail API raw (base64url) email into a ParsedEmail dataclass.

    Args:
        raw_base64url: The `raw` field from a Gmail API message resource
                       (format=raw). Standard base64url encoding.

    Returns:
        ParsedEmail with all fields populated.

    Raises:
        ValueError: if the input cannot be decoded or parsed.
    """
    # ── Decode base64url → bytes ───────────────────────────────────────────
    try:
        # base64url uses - and _ instead of + and /; add padding if needed
        padded = raw_base64url.replace("-", "+").replace("_", "/")
        padded += "=" * (4 - len(padded) % 4) if len(padded) % 4 else ""
        raw_bytes = base64.b64decode(padded)
    except Exception as e:
        raise ValueError(f"Failed to decode base64url email: {e}") from e

    # ── Parse RFC 2822 ─────────────────────────────────────────────────────
    try:
        msg = message_from_bytes(raw_bytes, policy=email.policy.compat32)
    except Exception as e:
        raise ValueError(f"Failed to parse MIME email: {e}") from e

    result = ParsedEmail()

    # ── Headers ────────────────────────────────────────────────────────────
    for key in msg.keys():
        k = key.lower()
        v = decode_mime_header(str(msg[key]))
        result.headers[k] = v  # Last value wins for duplicates

    result.subject    = decode_mime_header(msg.get("Subject", ""))
    result.date       = msg.get("Date")
    result.message_id = msg.get("Message-ID")

    # ── Auth ───────────────────────────────────────────────────────────────
    received_spf  = result.headers.get("received-spf", "")
    auth_results  = result.headers.get("authentication-results", "")

    result.auth = AuthResults(
        spf                         = parse_spf(received_spf),
        dkim                        = parse_dkim(auth_results),
        dmarc                       = parse_dmarc(auth_results),
        raw_received_spf            = received_spf or None,
        raw_authentication_results  = auth_results or None,
    )

    # ── Sender ─────────────────────────────────────────────────────────────
    from_raw    = decode_mime_header(msg.get("From", ""))
    reply_raw   = decode_mime_header(msg.get("Reply-To", ""))
    return_raw  = decode_mime_header(msg.get("Return-Path", ""))

    from_name, from_addr   = parse_address(from_raw)
    _,          reply_addr = parse_address(reply_raw)

    from_domain  = extract_domain(from_addr)
    reply_domain = extract_domain(reply_addr) if reply_addr else None

    result.sender = SenderInfo(
        from_raw     = from_raw,
        from_name    = from_name,
        from_address = from_addr,
        from_domain  = from_domain,
        reply_to     = reply_addr or None,
        reply_to_domain = reply_domain,
        return_path  = return_raw or None,
        reply_to_mismatch = bool(
            reply_domain
            and from_domain
            and reply_domain != from_domain
        ),
    )

    # ── Bodies ─────────────────────────────────────────────────────────────
    result.text_body, result.html_body = walk_parts(msg)

    # ── URLs ───────────────────────────────────────────────────────────────
    result.urls = extract_urls(result.text_body, result.html_body)

    # ── Attachments ────────────────────────────────────────────────────────
    result.attachments = collect_attachments(msg)

    return result


# ── CLI test helper ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, json

    if len(sys.argv) < 2:
        print("Usage: python mime_parser.py <base64url_string>")
        print("       python mime_parser.py --file <path_to_base64url_file>")
        sys.exit(1)

    if sys.argv[1] == "--file":
        with open(sys.argv[2]) as f:
            raw = f.read().strip()
    else:
        raw = sys.argv[1]

    parsed = parse_raw_email(raw)

    print(json.dumps({
        "subject":    parsed.subject,
        "date":       parsed.date,
        "message_id": parsed.message_id,
        "sender": {
            "from":             parsed.sender.from_address,
            "from_name":        parsed.sender.from_name,
            "from_domain":      parsed.sender.from_domain,
            "reply_to":         parsed.sender.reply_to,
            "reply_to_domain":  parsed.sender.reply_to_domain,
            "reply_to_mismatch": parsed.sender.reply_to_mismatch,
        },
        "auth": {
            "spf":   parsed.auth.spf,
            "dkim":  parsed.auth.dkim,
            "dmarc": parsed.auth.dmarc,
        },
        "urls":         parsed.urls,
        "text_preview": parsed.text_body[:300],
        "html_preview": parsed.html_body[:300],
        "attachments": [
            {"filename": a.filename, "type": a.content_type, "size": a.size_bytes}
            for a in parsed.attachments
        ],
    }, indent=2))
