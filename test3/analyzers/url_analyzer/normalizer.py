"""URL normalization and parsing."""
from __future__ import annotations

import logging
import re
import unicodedata
import urllib.parse
from contextlib import suppress

import tldextract

from url_analyzer.models import ParsedURL

logger = logging.getLogger(__name__)

# Zero-width characters to strip
ZERO_WIDTH_CHARS = re.compile(r"[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]")


def normalize_url(raw: str) -> str:
    """
    Normalize a raw URL string.
    
    Args:
        raw: The raw URL string.
        
    Returns:
        The normalized URL string.
    """
    # 1. Strip whitespace and zero-width chars
    url = raw.strip()
    url = ZERO_WIDTH_CHARS.sub("", url)

    # 2. Prepend http:// if no scheme
    lower_raw = url.lower()
    if not lower_raw.startswith(("http://", "https://")):
        url = "http://" + url

    # 3. Unquote until stable (max 10 iterations)
    for _ in range(10):
        unquoted = urllib.parse.unquote(url)
        if unquoted == url:
            break
        url = unquoted

    # 4. Lowercase scheme and netloc only
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    
    # Reconstruct
    url = urllib.parse.urlunparse((
        scheme,
        netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))

    # 5. NFKC normalization
    url = unicodedata.normalize("NFKC", url)

    return url


def parse_url(url: str) -> ParsedURL:
    """
    Parse a URL into its components.
    
    Args:
        url: The normalized URL string.
        
    Returns:
        A ParsedURL object.
    """
    parsed = urllib.parse.urlparse(url)
    extract_result = tldextract.extract(url)

    port = None
    with suppress(ValueError):
        port = parsed.port

    return ParsedURL(
        raw=url,
        scheme=parsed.scheme,
        hostname=parsed.hostname or "",
        subdomain=extract_result.subdomain or "",
        domain=extract_result.domain or "",
        suffix=extract_result.suffix or "",
        path=parsed.path,
        query=parsed.query,
        fragment=parsed.fragment,
        params=urllib.parse.parse_qs(parsed.query),
        port=port
    )

if __name__ == "__main__":
    test_urls = [
        "   HTTPS://EXAMPLE.COM/PATH%20?A=1  ",
        "example.com",
        "http://\u200bexample.com",
        "http://%2525example.com"
    ]
    for test_url in test_urls:
        norm = normalize_url(test_url)
        print(f"Raw: {test_url!r}")
        print(f"Norm: {norm!r}")
        print(f"Parsed: {parse_url(norm)}")
        print("-" * 40)
