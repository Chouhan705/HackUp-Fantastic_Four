"""Models and dataclasses for the URL analyzer."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import logging

logger = logging.getLogger(__name__)


class Severity(int, Enum):
    INFO = 5
    LOW = 15
    MEDIUM = 25
    HIGH = 40
    CRITICAL = 60


class CheckCategory(str, Enum):
    STRUCTURAL = "STRUCTURAL"
    UNICODE = "UNICODE"
    HEURISTIC = "HEURISTIC"
    ENCODING = "ENCODING"
    REDIRECT = "REDIRECT"
    TLS = "TLS"
    REPUTATION = "REPUTATION"
    BEHAVIOR = "BEHAVIOR"


@dataclass(frozen=True)
class Finding:
    check: str
    category: CheckCategory
    severity: Severity
    description: str
    evidence: str


@dataclass
class AnalysisConfig:
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
class Signal:
    id: str
    name: str
    category: str
    severity: str
    weight: int
    confidence: float
    evidence: str


@dataclass(frozen=True)
class AnalysisResult:
    id: str
    session_id: str | None
    parent_id: str | None
    type: str
    source: str
    timestamp: str
    input: str
    normalized_url: str
    iocs: dict[str, Any]
    infrastructure: dict[str, Any]
    features: dict[str, Any]
    signals: list[Signal]
    graph: dict[str, list[dict[str, str]]]
    attack_type: list[str]
    attack_story: str
    score: int
    verdict: str
    confidence: float
    findings: list[Finding]
    analysis_time_ms: float
