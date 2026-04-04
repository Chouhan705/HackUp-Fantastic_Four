"""Models and dataclasses for the URL analyzer."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class Severity(int, Enum):
    """Findings severity levels with associated scoring."""
    INFO = 5
    LOW = 15
    MEDIUM = 25
    HIGH = 40
    CRITICAL = 60


class CheckCategory(str, Enum):
    """Categories of URL checks."""
    STRUCTURAL = "STRUCTURAL"
    UNICODE = "UNICODE"
    HEURISTIC = "HEURISTIC"
    ENCODING = "ENCODING"
    REDIRECT = "REDIRECT"
    TLS = "TLS"
    REPUTATION = "REPUTATION"


@dataclass(frozen=True)
class Finding:
    """A single finding from a check."""
    check: str
    category: CheckCategory
    severity: Severity
    description: str
    evidence: str


@dataclass
class AnalysisConfig:
    """Configuration for the analysis."""
    resolve_redirects: bool = True
    check_tls: bool = True
    check_domain_age: bool = True
    google_api_key: str | None = None
    virustotal_api_key: str | None = None
    maxmind_db_path: str | None = None
    timeout_seconds: float = 5.0
    max_redirect_hops: int = 10
    cache_ttl_seconds: int = 3600


@dataclass(frozen=True)
class ParsedURL:
    """Components of a parsed URL."""
    raw: str
    scheme: str
    hostname: str
    subdomain: str
    domain: str
    suffix: str
    path: str
    query: str
    fragment: str
    params: dict[str, list[str]]
    port: int | None


@dataclass(frozen=True)
class AnalysisResult:
    """Overall result of the analysis."""
    url: str
    normalized_url: str
    score: int
    verdict: str
    findings: list[Finding]
    redirect_chain: list[str]
    analysis_time_ms: float
