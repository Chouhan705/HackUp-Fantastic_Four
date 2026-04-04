"""TLS Checks."""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from datetime import datetime
from typing import Any

import OpenSSL

from url_analyzer.models import AnalysisConfig, CheckCategory, Finding, ParsedURL, Severity

logger = logging.getLogger(__name__)

TRUSTED_CAS = {
    "DigiCert", "Let's Encrypt", "Sectigo", "GlobalSign",
    "GoDaddy", "Comodo", "Amazon", "Microsoft", "Google",
    "Entrust", "Thawte", "GeoTrust"
}

def _blocking_fetch_tls(hostname: str, port: int, timeout: float) -> dict[str, Any]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            if not cert_der:
                raise ValueError("No certificate returned")
                
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
            
            subject = x509.get_subject()
            subject_cn = subject.CN or ""
            
            issuer = x509.get_issuer()
            issuer_org = issuer.O or ""
            
            not_before_str = x509.get_notBefore()
            not_after_str = x509.get_notAfter()
            
            if not not_before_str or not not_after_str:
                raise ValueError("Missing dates in cert")
                
            not_before = datetime.strptime(not_before_str.decode("ascii"), "%Y%m%d%H%M%SZ")
            not_after = datetime.strptime(not_after_str.decode("ascii"), "%Y%m%d%H%M%SZ")
            
            now = datetime.utcnow()
            cert_age_days = (now - not_before).days
            days_until_expiry = (not_after - now).days
            
            is_self_signed = (subject.CN == issuer.CN and subject.O == issuer.O)
            
            san_domains = []
            for i in range(x509.get_extension_count()):
                ext = x509.get_extension(i)
                if ext.get_short_name() == b"subjectAltName":
                    # Simple parsing
                    val = str(ext)
                    parts = val.split(", ")
                    for p in parts:
                        if p.startswith("DNS:"):
                            san_domains.append(p[4:])
                            
            return {
                "subject_cn": subject_cn,
                "issuer_org": issuer_org,
                "not_before": not_before,
                "not_after": not_after,
                "is_self_signed": is_self_signed,
                "san_domains": san_domains,
                "cert_age_days": cert_age_days,
                "days_until_expiry": days_until_expiry,
            }

async def fetch_tls_info(hostname: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """Fetch TLS information as a dict."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _blocking_fetch_tls, hostname, port, timeout)

def _match_hostname(hostname: str, san_list: list[str], cn: str) -> bool:
    host_lower = hostname.lower()
    names = [cn.lower()] + [s.lower() for s in san_list]
    for name in names:
        if name == host_lower:
            return True
        if name.startswith("*."):
            suffix = name[2:]
            if host_lower == suffix or host_lower.endswith("." + suffix):
                if host_lower.count(".") == suffix.count(".") + 1:
                    return True
    return False

async def check_tls(parsed: ParsedURL, config: AnalysisConfig) -> list[Finding]:
    """Run TLS checks."""
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return []

    port = parsed.port or 443
    findings = []
    
    try:
        info = await fetch_tls_info(parsed.hostname, port, config.timeout_seconds)
        
        if info["is_self_signed"]:
            findings.append(Finding(
                check="tls_self_signed",
                category=CheckCategory.TLS,
                severity=Severity.HIGH,
                description="TLS certificate is self-signed",
                evidence="Self-signed cert"
            ))
            
        if info["cert_age_days"] < 30:
            findings.append(Finding(
                check="tls_cert_age",
                category=CheckCategory.TLS,
                severity=Severity.HIGH,
                description="TLS certificate was issued recently (<30 days)",
                evidence=f"{info['cert_age_days']} days old"
            ))
            
        if info["days_until_expiry"] < 7:
            findings.append(Finding(
                check="tls_cert_expiry",
                category=CheckCategory.TLS,
                severity=Severity.MEDIUM,
                description="TLS certificate expires soon (<7 days)",
                evidence=f"Expires in {info['days_until_expiry']} days"
            ))
            
        if not _match_hostname(parsed.hostname, info["san_domains"], info["subject_cn"]):
            findings.append(Finding(
                check="tls_hostname_mismatch",
                category=CheckCategory.TLS,
                severity=Severity.CRITICAL,
                description="TLS certificate subject does not match hostname",
                evidence=f"CN: {info['subject_cn']}, SANs: {', '.join(info['san_domains'])}"
            ))
            
        issuer_trusted = False
        for ca in TRUSTED_CAS:
            if ca.lower() in info["issuer_org"].lower():
                issuer_trusted = True
                break
                
        if not issuer_trusted:
            findings.append(Finding(
                check="tls_untrusted_ca",
                category=CheckCategory.TLS,
                severity=Severity.LOW,
                description="TLS certificate issued by unknown CA",
                evidence=info["issuer_org"]
            ))
            
    except Exception as e:
        logger.warning(f"TLS check failed for {parsed.hostname}: {e!r}")
        
    return findings
