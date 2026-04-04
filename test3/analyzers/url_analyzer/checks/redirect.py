"""Redirect chain resolver."""
from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Any, Callable

import aiohttp
from bs4 import BeautifulSoup

from url_analyzer.models import AnalysisConfig, CheckCategory, Finding, ParsedURL, Severity

logger = logging.getLogger(__name__)

# Basic regex for window.location assignments in script
JS_LOCATION_RE = re.compile(r"(?:window\.)?location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]")


async def resolve_redirect_chain(url: str, config: AnalysisConfig) -> list[dict[str, Any]]:
    """
    Resolve redirect chain for a URL.
    
    Args:
        url: Start URL
        config: AnalysisConfig instance with timeout and max_hops
        
    Returns:
        List of dicts containing hop information.
    """
    chain = []
    current_url = url
    hops = 0
    max_hops = config.max_redirect_hops

    headers = {"User-Agent": "Mozilla/5.0 (compatible; PhishDetect/1.0)"}

    # timeout is handled by aiohttp mechanism across the whole chain or per request. We'll use per-request.
    timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        while hops < max_hops:
            hop_info: dict[str, Any] = {
                "url": current_url,
                "status": None,
                "redirect_type": "terminal",
                "error": None
            }
            
            try:
                async with session.get(current_url, allow_redirects=False) as resp:
                    hop_info["status"] = resp.status
                    
                    if resp.status in {301, 302, 303, 307, 308}:
                        location = resp.headers.get("Location")
                        if location:
                            hop_info["redirect_type"] = "http_3xx"
                            chain.append(hop_info)
                            current_url = urllib.parse.urljoin(current_url, location)
                            hops += 1
                            continue
                    
                    if resp.status == 200:
                        content_type = resp.headers.get("Content-Type", "")
                        if "text/html" in content_type:
                            body = await resp.read()
                            # limit to 50KB roughly
                            body_text = body[:50000].decode(errors="ignore")
                            soup = BeautifulSoup(body_text, "html.parser")
                            
                            # Meta refresh
                            meta = soup.find("meta", attrs={"http-equiv": lambda x: x and x.lower() == "refresh"})
                            if meta and meta.get("content"):
                                content = meta["content"] # type: ignore
                                parts = str(content).split("url=", 1)
                                if len(parts) == 2:
                                    hop_info["redirect_type"] = "meta_refresh"
                                    chain.append(hop_info)
                                    target = parts[1].strip(" '\"")
                                    current_url = urllib.parse.urljoin(current_url, target)
                                    hops += 1
                                    continue
                                    
                            # JS location
                            for script in soup.find_all("script"):
                                if script.string:
                                    match = JS_LOCATION_RE.search(script.string)
                                    if match:
                                        hop_info["redirect_type"] = "js_location"
                                        chain.append(hop_info)
                                        target = match.group(1)
                                        current_url = urllib.parse.urljoin(current_url, target)
                                        hops += 1
                                        break
                            else:
                                # No more inner-loop continue: we didn't break out of script loop
                                pass
                            
                            if hop_info["redirect_type"] != "terminal":
                                continue
                                
                    # If we made it here, no more redirects
                    chain.append(hop_info)
                    break
                    
            except Exception as e:
                logger.warning(f"Error fetching {current_url}: {e!r}")
                hop_info["error"] = str(e)
                hop_info["redirect_type"] = "error"
                chain.append(hop_info)
                break
                
    return chain


def check_redirect_chain(chain: list[dict[str, Any]], parsed_fn: Callable[[str], ParsedURL]) -> list[Finding]:
    """
    Check the resolved redirect chain for anomalies.
    
    Args:
        chain: List of hop dicts
        parsed_fn: Function to parse URLs into ParsedURL
        
    Returns:
        List of Findings.
    """
    if not chain:
        return []
        
    findings = []
    hop_count = len(chain) - 1 # -1 because the first one is the original URL
    
    if hop_count > 6:
        findings.append(Finding(
            check="redirect_chain_length",
            category=CheckCategory.REDIRECT,
            severity=Severity.HIGH,
            description="Extremely long redirect chain",
            evidence=f"{hop_count} hops"
        ))
    elif hop_count > 3:
        findings.append(Finding(
            check="redirect_chain_length",
            category=CheckCategory.REDIRECT,
            severity=Severity.MEDIUM,
            description="Long redirect chain",
            evidence=f"{hop_count} hops"
        ))
        
    # Re-run static checks on intermediate hops (done externally if required, or we could import them here,
    # but the prompt says: "Re-run structural, unicode, and heuristic checks on every hop URL beyond the first."
    # To avoid circular dependency, we import them globally inside the function)
    import url_analyzer.checks.structural as c_struct
    import url_analyzer.checks.unicode as c_uni
    import url_analyzer.checks.heuristic as c_heuri
    
    first_url_parsed = parsed_fn(chain[0]["url"])
    first_domain = first_url_parsed.domain
    
    for i, hop in enumerate(chain[1:], start=1):
        hop_url = hop["url"]
        p = parsed_fn(hop_url)
        findings.extend(c_struct.run_all(p))
        findings.extend(c_uni.run_all(p))
        findings.extend(c_heuri.run_all(p))
        
    if hop_count > 0:
        last_url_parsed = parsed_fn(chain[-1]["url"])
        if first_domain and last_url_parsed.domain and first_domain != last_url_parsed.domain:
            findings.append(Finding(
                check="redirect_domain_change",
                category=CheckCategory.REDIRECT,
                severity=Severity.HIGH,
                description="Final destination domain differs from original domain",
                evidence=f"Original: {first_domain}, Final: {last_url_parsed.domain}"
            ))
            
    return findings
