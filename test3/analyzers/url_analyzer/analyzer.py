"""Analyzer orchestrator."""
from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
import socket
from datetime import datetime, timezone

from dotenv import load_dotenv

import analyzers.url_analyzer.checks.encoding as c_encoding
import analyzers.url_analyzer.checks.heuristic as c_heuristic
import analyzers.url_analyzer.checks.redirect as c_redirect
import analyzers.url_analyzer.checks.reputation as c_reputation
import analyzers.url_analyzer.checks.structural as c_structural
import analyzers.url_analyzer.checks.tls as c_tls
import analyzers.url_analyzer.checks.unicode as c_unicode
from analyzers.url_analyzer.models import AnalysisConfig, AnalysisResult, ParsedURL, Signal, Severity
from analyzers.url_analyzer.normalizer import normalize_url, parse_url
from analyzers.url_analyzer.scorer import score, SEVERITY_WEIGHTS
from analyzers.url_analyzer.ioc_extractor import extract_iocs
from analyzers.url_analyzer.feature_builder import build_features
from analyzers.url_analyzer.graph_builder import build_graph
from analyzers.url_analyzer.cache import cache

logger = logging.getLogger(__name__)


def _load_env_config(config: AnalysisConfig) -> AnalysisConfig:
    import os
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '.env')
    load_dotenv(env_path)
    if not config.google_api_key:
        config.google_api_key = os.environ.get("URL_ANALYZER_GSB_KEY")
    if not config.virustotal_api_key:
        config.virustotal_api_key = os.environ.get("URL_ANALYZER_VT_KEY")
    if not config.maxmind_db_path:
        config.maxmind_db_path = os.environ.get("URL_ANALYZER_MAXMIND_PATH")
    return config


async def _resolve_ips(hostname: str) -> list[str]:
    if not hostname:
        return []
    cache_key = f"dns_ip:{hostname}"
    cached = await cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        loop = asyncio.get_running_loop()
        info = await loop.run_in_executor(None, socket.getaddrinfo, hostname, None)
        ips = list(set(i[4][0] for i in info))
        await cache.set(cache_key, ips)
        return ips
    except Exception:
        await cache.set(cache_key, [])
        return []


async def analyze(url: str, config: AnalysisConfig | None = None) -> AnalysisResult:
    start_time = time.perf_counter()
    if config is None:
        config = AnalysisConfig()
    config = _load_env_config(config)

    normalized = normalize_url(url)
    parsed = parse_url(normalized)
    
    findings = []
    
    findings.extend(c_structural.run_all(parsed))
    findings.extend(c_unicode.run_all(parsed))
    findings.extend(c_heuristic.run_all(parsed))
    findings.extend(c_encoding.run_all(parsed))

    tasks = [
        c_reputation.run_all(parsed, config)
    ]
    
    dns_task = _resolve_ips(parsed.hostname)
    tasks.append(dns_task)
    
    if config.check_tls:
        tasks.append(c_tls.check_tls(parsed, config))
        
    redirect_task = None
    if config.resolve_redirects:
        redirect_task = c_redirect.resolve_redirect_chain(normalized, config)
        tasks.append(redirect_task)
        
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    redirect_chain = []
    hop_dicts = []
    resolved_ips_found = []
    
    for i, res in enumerate(results):
        if isinstance(res, Exception):
            logger.warning(f"Async analyze task failed: {res!r}")
            continue
            
        if tasks[i] is redirect_task:
            hop_dicts = res
            redirect_chain = [h["url"] for h in hop_dicts]
            redirect_findings = c_redirect.check_redirect_chain(hop_dicts, lambda u: parse_url(normalize_url(u)))
            findings.extend(redirect_findings)
        elif tasks[i] is dns_task:
            resolved_ips_found = res
        else:
            findings.extend(res)
            
    total_score, verdict = score(findings)
    
    if not findings:
        confidence = 1.0
    else:
        max_sev = max((SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings), default=0)
        cats = len(set(f.category for f in findings))
        
        base_conf = 0.2 + (cats * 0.1)
        if max_sev >= Severity.CRITICAL.value:
            base_conf += 0.4
        elif max_sev >= Severity.HIGH.value:
            base_conf += 0.3
        elif max_sev >= Severity.MEDIUM.value:
            base_conf += 0.2
        else:
            base_conf += 0.1
        
        confidence = min(max(base_conf, 0.0), 1.0)
    
    iocs = extract_iocs(parsed, findings, hop_dicts)
    features = build_features(parsed, findings, hop_dicts)
    graph = build_graph(parsed, hop_dicts, findings)
    
    attack_type = set()
    if features.get("has_credentials_in_url") or len(iocs.get("patterns", {}).get("credential_injection", [])) > 0:
        attack_type.add("credential_harvesting")
    if any(f.check in ["brand_in_subdomain", "typosquat"] for f in findings):
        attack_type.add("brand_impersonation")
    if len(redirect_chain) > 1 or any(f.category == "ENCODING" for f in findings) or len(iocs.get("patterns", {}).get("encoded_segments", [])) > 0:
        attack_type.add("url_obfuscation")
    if any(f.category in ["TLS", "REPUTATION"] for f in findings):
        attack_type.add("infrastructure_abuse")
        
    if not attack_type:
        attack_type.add("unknown")
    attack_type = list(attack_type)
        
    signals = [
        Signal(
            id=f.check.lower().replace(" ", "_"),
            name=f.check.replace("_", " ").title(),
            category=f.category.value,
            severity=f.severity.name,
            weight=SEVERITY_WEIGHTS.get(f.severity, 0),
            confidence=1.0 if SEVERITY_WEIGHTS.get(f.severity, 0) >= Severity.HIGH.value else 0.8,
            evidence=f.evidence
        ) for f in findings
    ]

    actual_domain = f"{parsed.domain}.{parsed.suffix}" if (parsed.domain and parsed.suffix) else parsed.hostname
    root_domain = actual_domain

    detected_brands = [n["id"] for n in graph["nodes"] if n["type"] == "brand"]

    story_parts = []
    creds = iocs.get("patterns", {}).get("credential_injection", [])
    
    if detected_brands:
        brand_str = " and ".join(detected_brands)
        if creds:
            story_parts.append(f"The URL impersonates {brand_str} using a credential injection pattern ({creds[0]}).")
        else:
            story_parts.append(f"The URL impersonates {brand_str}.")
            
        story_parts.append(f"The actual domain is {actual_domain}, indicating a deceptive impersonation attempt.")
    elif "credential_harvesting" in attack_type:
        if creds:
            story_parts.append(f"The URL uses a credential injection pattern ({creds[0]}) to harvest credentials.")
            story_parts.append(f"The actual domain is {actual_domain}.")
        else:
            story_parts.append(f"The URL appears designed for credential harvesting, hosted on {actual_domain}.")
    
    if "url_obfuscation" in attack_type:
        story_parts.append("URL obfuscation and/or redirects are used to hide the final destination.")
        
    infra_details = []
    if "infrastructure_abuse" in attack_type:
        for f in findings:
            if f.check == "dns_mx":
                if "NXDOMAIN" in f.evidence or "no such domain" in f.description.lower():
                    infra_details.append("The domain does not resolve (NXDOMAIN).")
                elif "evidence" in f.evidence or "No MX" in f.description:
                    infra_details.append("No MX records found.")
            elif f.check == "tls_self_signed":
                infra_details.append("The URL uses a self-signed TLS certificate.")
            elif f.check == "tls_cert_age":
                infra_details.append("The TLS certificate was issued very recently.")
            elif "virustotal" in f.check or "gsb" in f.check or "urlhaus" in f.check:
                infra_details.append("The URL is flagged by external threat intelligence feeds.")
                
        if infra_details:
            seen = set()
            unique_infra = [x for x in infra_details if not (x in seen or seen.add(x))]
            story_parts.extend(unique_infra)
        else:
            story_parts.append("Anomalies in DNS, TLS, or reputation feeds indicate infrastructure abuse.")
        
    story = " ".join(story_parts) if story_parts else "No clear attack narrative could be determined from the structured findings."

    final_ips = list(set(iocs.get("ips", []) + resolved_ips_found))

    infrastructure = {
        "primary_domain": actual_domain,
        "root_domain": root_domain,
        "resolved_ips": final_ips,
        "mx_records": [],
        "geo": {
            "country": "Unknown",
            "high_risk": False
        }
    }

    elapsed_ms = (time.perf_counter() - start_time) * 1000
    
    return AnalysisResult(
        id=str(uuid.uuid4()),
        session_id=None,
        parent_id=None,
        type="url",
        source="url_analyzer",
        timestamp=datetime.now(timezone.utc).isoformat(),
        input=url,
        normalized_url=normalized,
        iocs=iocs,
        infrastructure=infrastructure,
        features=features,
        signals=signals,
        graph=graph,
        attack_type=attack_type,
        attack_story=story,
        score=total_score,
        verdict=verdict,
        confidence=round(confidence, 2),
        findings=findings,
        analysis_time_ms=elapsed_ms
    )
