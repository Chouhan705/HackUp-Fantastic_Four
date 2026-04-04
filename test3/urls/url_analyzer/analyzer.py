"""Analyzer orchestrator."""
from __future__ import annotations

import asyncio
import logging
import os
import time

from dotenv import load_dotenv
import url_analyzer.checks.encoding as c_encoding
import url_analyzer.checks.heuristic as c_heuristic
import url_analyzer.checks.redirect as c_redirect
import url_analyzer.checks.reputation as c_reputation
import url_analyzer.checks.structural as c_structural
import url_analyzer.checks.tls as c_tls
import url_analyzer.checks.unicode as c_unicode
from url_analyzer.models import AnalysisConfig, AnalysisResult, ParsedURL
from url_analyzer.normalizer import normalize_url, parse_url
from url_analyzer.scorer import score

logger = logging.getLogger(__name__)


def _load_env_config(config: AnalysisConfig) -> AnalysisConfig:
    """Load config from environment variables as fallback."""
    load_dotenv()
    if not config.google_api_key:
        config.google_api_key = os.environ.get("URL_ANALYZER_GSB_KEY")
    if not config.virustotal_api_key:
        config.virustotal_api_key = os.environ.get("URL_ANALYZER_VT_KEY")
    if not config.maxmind_db_path:
        config.maxmind_db_path = os.environ.get("URL_ANALYZER_MAXMIND_PATH")
    return config


async def analyze(url: str, config: AnalysisConfig | None = None) -> AnalysisResult:
    """
    Run a full URL analysis.
    
    Args:
        url: The raw URL to analyze.
        config: AnalysisConfig instance. If None, default is used.
        
    Returns:
        AnalysisResult object.
    """
    start_time = time.perf_counter()
    if config is None:
        config = AnalysisConfig()
    config = _load_env_config(config)

    normalized = normalize_url(url)
    parsed = parse_url(normalized)
    
    findings = []
    
    # Run sync static checks
    findings.extend(c_structural.run_all(parsed))
    findings.extend(c_unicode.run_all(parsed))
    findings.extend(c_heuristic.run_all(parsed))
    findings.extend(c_encoding.run_all(parsed))

    # Setup async tasks
    tasks = [
        c_reputation.run_all(parsed, config)
    ]
    
    if config.check_tls:
        tasks.append(c_tls.check_tls(parsed, config))
        
    redirect_task = None
    if config.resolve_redirects:
        redirect_task = c_redirect.resolve_redirect_chain(normalized, config)
        tasks.append(redirect_task)
        
    # Execute async tasks
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    redirect_chain = []
    
    for i, res in enumerate(results):
        if isinstance(res, Exception):
            logger.warning(f"Async analyze task failed: {res!r}")
            continue
            
        if tasks[i] is redirect_task:
            hop_dicts = res
            redirect_chain = [h["url"] for h in hop_dicts]
            redirect_findings = c_redirect.check_redirect_chain(hop_dicts, lambda u: parse_url(normalize_url(u)))
            findings.extend(redirect_findings)
        else:
            findings.extend(res) # type: ignore
            
    # Score
    total_score, verdict = score(findings)
    
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    
    return AnalysisResult(
        url=url,
        normalized_url=normalized,
        score=total_score,
        verdict=verdict,
        findings=findings,
        redirect_chain=redirect_chain,
        analysis_time_ms=elapsed_ms
    )
