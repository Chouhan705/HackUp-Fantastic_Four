"""Encoding and obfuscation checks."""
from __future__ import annotations

import contextlib
import ipaddress
import logging
import re

from url_analyzer.models import CheckCategory, Finding, ParsedURL, Severity

logger = logging.getLogger(__name__)


def check_double_encoding(parsed: ParsedURL) -> Finding | None:
    """Check for percentage sign encoding (%25)."""
    if "%25" in parsed.raw:
        return Finding(
            check="double_encoding",
            category=CheckCategory.ENCODING,
            severity=Severity.HIGH,
            description="URL contains double URL encoding (%25)",
            evidence="%25 found"
        )
    return None


def check_encoded_hostname(parsed: ParsedURL) -> Finding | None:
    """Check for URL encoding in the hostname."""
    if re.search(r"%[0-9a-fA-F]{2}", parsed.hostname):
        return Finding(
            check="encoded_hostname",
            category=CheckCategory.ENCODING,
            severity=Severity.CRITICAL,
            description="Hostname contains URL-encoded characters",
            evidence=parsed.hostname
        )
    return None


def check_null_byte(parsed: ParsedURL) -> Finding | None:
    """Check for null bytes in URL."""
    if "%00" in parsed.raw or "\x00" in parsed.raw:
        return Finding(
            check="null_byte",
            category=CheckCategory.ENCODING,
            severity=Severity.CRITICAL,
            description="URL contains a null byte",
            evidence="Null byte found"
        )
    return None


def check_decimal_ip(parsed: ParsedURL) -> Finding | None:
    """Check if the hostname is a decimal representation of an IP."""
    if not parsed.hostname.isdigit():
        return None
        
    with contextlib.suppress(ValueError):
        num = int(parsed.hostname)
        ip = ipaddress.IPv4Address(num)
        return Finding(
            check="decimal_ip",
            category=CheckCategory.ENCODING,
            severity=Severity.CRITICAL,
            description="Hostname is a decimal IP address",
            evidence=str(ip)
        )
    return None


def check_octal_ip(parsed: ParsedURL) -> Finding | None:
    """Check if the hostname is an octal representation of an IP."""
    parts = parsed.hostname.split(".")
    has_octal = any(part.startswith("0") and len(part) > 1 and part.isdigit() for part in parts)
    
    if has_octal:
        return Finding(
            check="octal_ip",
            category=CheckCategory.ENCODING,
            severity=Severity.CRITICAL,
            description="Hostname contains octal IP address components",
            evidence=parsed.hostname
        )
    return None


def run_all(parsed: ParsedURL) -> list[Finding]:
    """Run all encoding checks."""
    checks = [
        check_double_encoding,
        check_encoded_hostname,
        check_null_byte,
        check_decimal_ip,
        check_octal_ip
    ]
    findings = []
    for check in checks:
        if result := check(parsed):
            findings.append(result)
    return findings
