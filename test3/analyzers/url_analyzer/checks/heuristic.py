"""Heuristic checks: entropy, typosquatting, etc."""
from __future__ import annotations

import logging
import math

import Levenshtein

from url_analyzer.models import CheckCategory, Finding, ParsedURL, Severity
from url_analyzer.checks.structural import BRANDS

logger = logging.getLogger(__name__)


SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "short.link", "rebrand.ly", "cutt.ly", "is.gd", "v.gd", "tiny.cc", "shorte.st",
    "adf.ly", "bc.vc", "cli.re", "s.id", "bl.ink", "snip.ly", "rb.gy", "lnkd.in", "youtu.be"
}


def check_typosquat(parsed: ParsedURL) -> Finding | None:
    """Check if the domain is a typosquat of a known brand."""
    domain_lower = parsed.domain.lower()
    if not domain_lower:
        return None

    for brand in BRANDS:
        if domain_lower == brand:
            return None  # Exact match is legitimate

        # Calculate Levenshtein distance
        distance = Levenshtein.distance(domain_lower, brand)
        if distance <= 2:
            return Finding(
                check="typosquat",
                category=CheckCategory.HEURISTIC,
                severity=Severity.CRITICAL,
                description="Domain is highly similar to a known brand",
                evidence=f"Brand: {brand}, Distance: {distance}"
            )
    return None


def check_url_shortener(parsed: ParsedURL) -> Finding | None:
    """Check if the hostname is a known URL shortener."""
    hostname = parsed.hostname.lower()
    
    if hostname in SHORTENERS or any(hostname.endswith(f".{s}") for s in SHORTENERS):
        return Finding(
            check="url_shortener",
            category=CheckCategory.HEURISTIC,
            severity=Severity.MEDIUM,
            description="URL uses a shortener service",
            evidence=hostname
        )
    return None


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def check_entropy(parsed: ParsedURL) -> Finding | None:
    """Check if the domain label has high entropy."""
    if not parsed.domain:
        return None
        
    entropy = calculate_entropy(parsed.domain)
    if entropy > 4.0:
        return Finding(
            check="entropy",
            category=CheckCategory.HEURISTIC,
            severity=Severity.LOW,
            description="Domain label has high entropy (random-looking)",
            evidence=f"Entropy: {entropy:.2f}"
        )
    return None


def run_all(parsed: ParsedURL) -> list[Finding]:
    """Run all heuristic checks."""
    checks = [
        check_typosquat,
        check_url_shortener,
        check_entropy,
    ]
    findings = []
    for check in checks:
        if result := check(parsed):
            findings.append(result)
    return findings
