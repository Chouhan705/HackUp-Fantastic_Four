"""Scoring Engine."""
from __future__ import annotations

from url_analyzer.models import CheckCategory, Finding, Severity

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 5,
    Severity.LOW: 15,
    Severity.MEDIUM: 25,
    Severity.HIGH: 40,
    Severity.CRITICAL: 60
}

CATEGORY_CAPS: dict[CheckCategory, int] = {
    CheckCategory.STRUCTURAL: 60,
    CheckCategory.UNICODE: 60,
    CheckCategory.HEURISTIC: 50,
    CheckCategory.ENCODING: 60,
    CheckCategory.REDIRECT: 40,
    CheckCategory.TLS: 50,
    CheckCategory.REPUTATION: 80,
    CheckCategory.BEHAVIOR: 70
}


def score(findings: list[Finding]) -> tuple[int, str]:
    """
    Calculate the total score and verdict from findings.
    
    Args:
        findings: List of Finding objects.
        
    Returns:
        A tuple of (total_score: int, verdict: str).
    """
    category_scores: dict[CheckCategory, int] = {cat: 0 for cat in CheckCategory}
    
    for f in findings:
        category_scores[f.category] += SEVERITY_WEIGHTS.get(f.severity, 0)
        
    total_score = 0
    for cat, raw_score in category_scores.items():
        capped = min(raw_score, CATEGORY_CAPS[cat])
        total_score += capped
        
    total_score = max(0, min(100, total_score))
    
    if total_score < 10:
        verdict = "CLEAN"
    elif total_score < 30:
        verdict = "LOW RISK"
    elif total_score < 60:
        verdict = "SUSPICIOUS"
    else:
        verdict = "DANGEROUS"
        
    return total_score, verdict
