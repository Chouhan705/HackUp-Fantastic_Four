"""Structural checks for URL analysis."""
from __future__ import annotations

import ipaddress
import logging
from contextlib import suppress

from url_analyzer.models import CheckCategory, Finding, ParsedURL, Severity

logger = logging.getLogger(__name__)

# Constants
BAD_PORTS = {8080, 8443, 4443, 9999, 1337, 4444, 6666, 6667}
PHISHING_KEYWORDS = {
    "login", "signin", "sign-in", "secure", "verify", "account",
    "update", "confirm", "banking", "credential", "password", "authenticate",
    "validation", "recover", "suspend", "limited", "unusual", "billing"
}
OPEN_REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "url", "uri", "next", "goto", "return",
    "returnurl", "return_url", "target", "link", "forward", "dest", "destination",
    "continue", "back", "location", "out", "view", "to"
}
BRANDS = [
    "google", "paypal", "amazon", "apple", "microsoft", "facebook", "netflix", "instagram",
    "linkedin", "twitter", "chase", "wellsfargo", "bankofamerica", "steam", "discord", "dropbox",
    "github", "coinbase", "binance", "robinhood", "spotify", "adobe", "docusign",
    "dhl", "fedex", "usps", "irs", "outlook", "office365", "onedrive", "sharepoint"
]


def check_ip_host(parsed: ParsedURL) -> Finding | None:
    """Check if the hostname is an IP address."""
    if not parsed.hostname:
        return None
    with suppress(ValueError):
        ip = ipaddress.ip_address(parsed.hostname)
        return Finding(
            check="ip_host",
            category=CheckCategory.STRUCTURAL,
            severity=Severity.HIGH,
            description="Hostname is an IP address",
            evidence=str(ip)
        )
    return None


def check_credentials_in_url(parsed: ParsedURL) -> Finding | None:
    """Check for credentials in the URL netloc."""
    # urllib.parse.urlparse already extracts netloc. 
    # If '@' is in the raw netloc portion, it means credentials are used.
    # However, since ParsedURL doesn't store netloc, we can check raw string.
    import urllib.parse
    p = urllib.parse.urlparse(parsed.raw)
    if "@" in (p.netloc or ""):
        return Finding(
            check="credentials_in_url",
            category=CheckCategory.STRUCTURAL,
            severity=Severity.CRITICAL,
            description="Credentials found in URL",
            evidence=p.netloc
        )
    return None


def check_port_abuse(parsed: ParsedURL) -> Finding | None:
    """Check if a suspicious port is used."""
    if parsed.port in BAD_PORTS:
        return Finding(
            check="port_abuse",
            category=CheckCategory.STRUCTURAL,
            severity=Severity.MEDIUM,
            description=f"Suspicious port {parsed.port} used",
            evidence=str(parsed.port)
        )
    return None


def check_subdomain_depth(parsed: ParsedURL) -> Finding | None:
    """Check if the subdomain is too deep."""
    if not parsed.subdomain:
        return None
    labels = parsed.subdomain.split(".")
    if len(labels) >= 4:
        return Finding(
            check="subdomain_depth",
            category=CheckCategory.STRUCTURAL,
            severity=Severity.MEDIUM,
            description="Subdomain is excessively deep (4+ labels)",
            evidence=f"Depth: {len(labels)}"
        )
    return None


def check_path_url_mimicry(parsed: ParsedURL) -> Finding | None:
    """Check if the path contains a URL scheme, suggesting mimicry."""
    path_lower = parsed.path.lower()
    if "http://" in path_lower or "https://" in path_lower:
        return Finding(
            check="path_url_mimicry",
            category=CheckCategory.STRUCTURAL,
            severity=Severity.HIGH,
            description="URL scheme found in path",
            evidence=parsed.path
        )
    return None


def check_dangerous_scheme(parsed: ParsedURL) -> Finding | None:
    """Check for dangerous URL schemes."""
    if parsed.scheme.lower() in {"data", "javascript"}:
        return Finding(
            check="dangerous_scheme",
            category=CheckCategory.STRUCTURAL,
            severity=Severity.CRITICAL,
            description="Dangerous URL scheme used",
            evidence=parsed.scheme
        )
    return None


def check_url_length(parsed: ParsedURL) -> Finding | None:
    """Check if the URL is excessively long."""
    length = len(parsed.raw)
    if length > 150:
        return Finding(
            check="url_length",
            category=CheckCategory.STRUCTURAL,
            severity=Severity.MEDIUM,
            description="URL is very long",
            evidence=f"Length: {length}"
        )
    if length > 75:
        return Finding(
            check="url_length",
            category=CheckCategory.STRUCTURAL,
            severity=Severity.LOW,
            description="URL is long",
            evidence=f"Length: {length}"
        )
    return None


def check_hyphen_abuse(parsed: ParsedURL) -> Finding | None:
    """Check for excessive hyphens in the domain."""
    if not parsed.domain:
        return None
    hyphen_count = parsed.domain.count("-")
    if hyphen_count >= 3:
        return Finding(
            check="hyphen_abuse",
            category=CheckCategory.STRUCTURAL,
            severity=Severity.MEDIUM,
            description="Domain contains 3 or more hyphens",
            evidence=f"Hyphens: {hyphen_count}"
        )
    return None


def check_brand_in_subdomain(parsed: ParsedURL) -> Finding | None:
    """Check if a brand name is in the subdomain but not the domain."""
    if not parsed.subdomain:
        return None
    sub_lower = parsed.subdomain.lower()
    dom_lower = parsed.domain.lower()
    for brand in BRANDS:
        if brand in sub_lower and dom_lower != brand:
            return Finding(
                check="brand_in_subdomain",
                category=CheckCategory.STRUCTURAL,
                severity=Severity.HIGH,
                description="Brand name in subdomain but not in domain",
                evidence=f"Brand: {brand}, Domain: {dom_lower}"
            )
    return None


def check_phishing_keywords(parsed: ParsedURL) -> Finding | None:
    """Check for phishing-related keywords in hostname and path."""
    target_str = f"{parsed.hostname}{parsed.path}".lower()
    matches = [kw for kw in PHISHING_KEYWORDS if kw in target_str]
    count = len(matches)
    if count >= 2:
        return Finding(
            check="phishing_keywords",
            category=CheckCategory.STRUCTURAL,
            severity=Severity.MEDIUM,
            description="Multiple phishing keywords found",
            evidence=", ".join(matches)
        )
    elif count == 1:
        return Finding(
            check="phishing_keywords",
            category=CheckCategory.STRUCTURAL,
            severity=Severity.LOW,
            description="Phishing keyword found",
            evidence=matches[0]
        )
    return None


def check_open_redirect(parsed: ParsedURL) -> Finding | None:
    """Check for open redirect parameters."""
    for param_name in OPEN_REDIRECT_PARAMS:
        if param_name in parsed.params:
            for val in parsed.params[param_name]:
                val_lower = val.lower()
                if val_lower.startswith(("http://", "https://", "//", "javascript:")):
                    return Finding(
                        check="open_redirect",
                        category=CheckCategory.STRUCTURAL,
                        severity=Severity.HIGH,
                        description="Potential open redirect parameter found",
                        evidence=f"{param_name}={val}"
                    )
    return None


def run_all(parsed: ParsedURL) -> list[Finding]:
    """Run all structural checks."""
    checks = [
        check_ip_host,
        check_credentials_in_url,
        check_port_abuse,
        check_subdomain_depth,
        check_path_url_mimicry,
        check_dangerous_scheme,
        check_url_length,
        check_hyphen_abuse,
        check_brand_in_subdomain,
        check_phishing_keywords,
        check_open_redirect
    ]
    findings = []
    for check in checks:
        if result := check(parsed):
            findings.append(result)
    return findings
