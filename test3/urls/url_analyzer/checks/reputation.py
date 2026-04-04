"""Reputation Module using async APIs."""
from __future__ import annotations

import asyncio
import base64
import logging
import socket
from datetime import datetime, timezone
from typing import Any

import aiohttp
import certifi
import dns.resolver
import geoip2.database
import io
import contextlib
import ssl
import whois

from url_analyzer.cache import cache
from url_analyzer.models import AnalysisConfig, CheckCategory, Finding, ParsedURL, Severity
from url_analyzer.normalizer import normalize_url

logger = logging.getLogger(__name__)

async def check_domain_age(domain: str, config: AnalysisConfig) -> Finding | None:
    cache_key = f"whois:{domain}"
    cached = await cache.get(cache_key)
    if cached is not None:
        if cached == "error":
            return None
        age_days = cached
    else:
        loop = asyncio.get_event_loop()
        
        def _silent_whois(d: str):
            f = io.StringIO()
            with contextlib.redirect_stdout(f), contextlib.redirect_stderr(f):
                return whois.whois(d)

        try:
            w = await loop.run_in_executor(None, _silent_whois, domain)
            cd = w.creation_date
            if not cd:
                await cache.set(cache_key, "error")
                return None
            if isinstance(cd, list):
                cd = cd[0]
            
            # Ensure cd is datetime
            if isinstance(cd, datetime):
                now = datetime.now(timezone.utc)
                if cd.tzinfo is None:
                    cd = cd.replace(tzinfo=timezone.utc)
                age_days = (now - cd).days
            else:
                await cache.set(cache_key, "error")
                return None
                
            await cache.set(cache_key, age_days)
        except Exception as e:
            logger.warning(f"WHOIS check failed for {domain}: {e!r}")
            await cache.set(cache_key, "error")
            return None

    if age_days < 7:
        return Finding("domain_age", CheckCategory.REPUTATION, Severity.CRITICAL, "Domain very newly registered (<7 days)", f"{age_days} days")
    elif age_days < 30:
        return Finding("domain_age", CheckCategory.REPUTATION, Severity.HIGH, "Domain newly registered (<30 days)", f"{age_days} days")
    elif age_days < 90:
        return Finding("domain_age", CheckCategory.REPUTATION, Severity.MEDIUM, "Domain is relatively new (<90 days)", f"{age_days} days")
    
    return None

async def check_dns_mx(domain: str, config: AnalysisConfig) -> Finding | None:
    cache_key = f"mx:{domain}"
    cached = await cache.get(cache_key)
    if cached is not None:
        status = cached
    else:
        loop = asyncio.get_event_loop()
        try:
            res = dns.resolver.Resolver()
            res.timeout = config.timeout_seconds
            res.lifetime = config.timeout_seconds
            await loop.run_in_executor(None, res.resolve, domain, "MX")
            status = "ok"
        except dns.resolver.NoAnswer:
            status = "no_answer"
        except dns.resolver.NXDOMAIN:
            status = "nxdomain"
        except Exception:
            status = "error"
            
        await cache.set(cache_key, status)
        
    if status == "no_answer":
        return Finding("dns_mx", CheckCategory.REPUTATION, Severity.LOW, "Domain has no MX records", "No MX records")
    elif status == "nxdomain":
        return Finding("dns_mx", CheckCategory.REPUTATION, Severity.HIGH, "Domain does not exist (NXDOMAIN)", "NXDOMAIN")
    return None

async def check_google_safe_browsing(url: str, config: AnalysisConfig) -> Finding | None:
    if not config.google_api_key:
        return None
    
    url_hash = hash(url)
    cache_key = f"gsb:{url_hash}"
    cached = await cache.get(cache_key)
    if cached is not None:
        if cached == "clean":
            return None
        return Finding("google_safe_browsing", CheckCategory.REPUTATION, Severity.CRITICAL, "Flagged by Google Safe Browsing", cached)

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={config.google_api_key}"
    payload = {
        "client": {"clientId": "phishdetect", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=config.timeout_seconds)) as session:
            async with session.post(api_url, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if matches := data.get("matches"):
                        threats = ", ".join({m["threatType"] for m in matches})
                        await cache.set(cache_key, threats)
                        return Finding("google_safe_browsing", CheckCategory.REPUTATION, Severity.CRITICAL, "Flagged by Google Safe Browsing", threats)
                    await cache.set(cache_key, "clean")
    except Exception as e:
        logger.warning(f"GSB check failed: {e!r}")
        
    return None

async def check_virustotal(url: str, config: AnalysisConfig) -> Finding | None:
    if not config.virustotal_api_key:
        return None
        
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b'=').decode()
    cache_key = f"vt:{url_id}"
    cached = await cache.get(cache_key)
    if cached is not None:
        if cached == "clean":
            return None
        mal, sus = cached
        if mal > 2:
            return Finding("virustotal", CheckCategory.REPUTATION, Severity.CRITICAL, "Flagged as malicious by VirusTotal", f"{mal} malicious hits")
        if sus > 3:
            return Finding("virustotal", CheckCategory.REPUTATION, Severity.HIGH, "Flagged as suspicious by VirusTotal", f"{sus} suspicious hits")
        return None

    headers = {"x-apikey": config.virustotal_api_key}
    submit_url = "https://www.virustotal.com/api/v3/urls"
    get_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    try:
        async with aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=config.timeout_seconds)) as session:
            async with session.post(submit_url, data={"url": url}) as resp:
                if resp.status != 200:
                    return None
            async with session.get(get_url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    await cache.set(cache_key, (malicious, suspicious))
                    if malicious > 2:
                        return Finding("virustotal", CheckCategory.REPUTATION, Severity.CRITICAL, "Flagged as malicious by VirusTotal", f"{malicious} malicious hits")
                    if suspicious > 3:
                        return Finding("virustotal", CheckCategory.REPUTATION, Severity.HIGH, "Flagged as suspicious by VirusTotal", f"{suspicious} suspicious hits")
                    await cache.set(cache_key, "clean")
    except Exception as e:
        logger.warning(f"VT check failed: {e!r}")
        
    return None

async def check_openphish(url: str, config: AnalysisConfig) -> Finding | None:
    cache_key = "openphish:feed"
    feed_set = await cache.get(cache_key)
    
    if feed_set is None:
        feed_set = set()
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10.0)) as session:
                async with session.get("https://openphish.com/feed.txt") as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            feed_set.add(normalize_url(line.strip()))
                        await cache.set(cache_key, feed_set)
        except Exception as e:
            logger.warning(f"OpenPhish download failed: {e!r}")
            return None
            
    norm_url = normalize_url(url)
    if norm_url in feed_set:
        return Finding("openphish", CheckCategory.REPUTATION, Severity.CRITICAL, "URL found in OpenPhish feed", "Found in free feed")
    return None

async def check_urlhaus(url: str, config: AnalysisConfig) -> Finding | None:
    import hashlib
    sha256 = hashlib.sha256(url.encode()).hexdigest()
    cache_key = f"urlhaus:{sha256}"
    
    cached = await cache.get(cache_key)
    if cached is not None:
        if cached == "clean":
            return None
        return Finding("urlhaus", CheckCategory.REPUTATION, Severity.CRITICAL, "URL listed in URLhaus", cached)
        
    try:
        ssl_ctx = ssl.create_default_context(cafile=certifi.where())
        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=config.timeout_seconds)) as session:
            async with session.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    status = data.get("query_status")
                    if status == "is_listed":
                        threat = data.get("threat", "unknown")
                        await cache.set(cache_key, threat)
                        return Finding("urlhaus", CheckCategory.REPUTATION, Severity.CRITICAL, "URL listed in URLhaus", threat)
                    else:
                        await cache.set(cache_key, "clean")
    except Exception as e:
        logger.warning(f"URLHaus failed: {e!r}")
        
    return None

async def check_geoip(parsed: ParsedURL, config: AnalysisConfig) -> Finding | None:
    if not config.maxmind_db_path or not parsed.hostname:
        return None
        
    cache_key = f"geoip:{parsed.hostname}"
    cached = await cache.get(cache_key)
    if cached is not None:
        country = cached
    else:
        loop = asyncio.get_event_loop()
        try:
            addr_info = await loop.run_in_executor(None, socket.getaddrinfo, parsed.hostname, None)
            ip = addr_info[0][4][0]
            
            import os
            db_file = os.path.join(config.maxmind_db_path, "GeoLite2-City.mmdb")
            if not os.path.exists(db_file):
                logger.warning(f"GeoIP db not found: {db_file}")
                return None
                
            def lookup(ip_addr: str) -> str:
                with geoip2.database.Reader(db_file) as reader:
                    return reader.city(ip_addr).country.iso_code or ""
                    
            country = await loop.run_in_executor(None, lookup, ip)
            await cache.set(cache_key, country)
        except Exception as e:
            logger.warning(f"GeoIP failed: {e!r}")
            return None
            
    high_risk = {'RU', 'CN', 'KP', 'IR', 'NG', 'RO', 'UA', 'BY', 'VN', 'PK'}
    if country in high_risk:
        # Note: This is a probabilistic signal, not a determination.
        return Finding("geoip", CheckCategory.REPUTATION, Severity.LOW, "Domain resolving to high-risk country", country)
        
    return None

async def run_all(parsed: ParsedURL, config: AnalysisConfig) -> list[Finding]:
    """Run all reputation checks concurrently."""
    tasks = [
        check_openphish(parsed.raw, config),
        check_urlhaus(parsed.raw, config),
        check_google_safe_browsing(parsed.raw, config),
        check_virustotal(parsed.raw, config),
    ]
    
    registered_domain = ""
    if parsed.domain and parsed.suffix:
        registered_domain = f"{parsed.domain}.{parsed.suffix}"
    elif parsed.domain:
        registered_domain = parsed.domain
        
    if registered_domain and config.check_domain_age:
        tasks.append(check_domain_age(registered_domain, config))
        tasks.append(check_dns_mx(registered_domain, config))
    
    tasks.append(check_geoip(parsed, config))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings = []
    for r in results:
        if isinstance(r, Exception):
            logger.warning(f"Reputation check raised exception: {r}")
        elif r is not None:
            findings.append(r)
            
    return findings
