"""Tests for the URL Analyzer checks."""
import pytest
from unittest.mock import AsyncMock, patch

from url_analyzer.models import AnalysisConfig
from url_analyzer.normalizer import parse_url, normalize_url
import url_analyzer.checks.structural as c_struct
import url_analyzer.checks.unicode as c_uni
import url_analyzer.checks.heuristic as c_heuri
import url_analyzer.checks.encoding as c_enc

# Test cases from the prompt
pytestmark = pytest.mark.asyncio


def test_ip_host():
    url = "http://192.168.1.1/login"
    p = parse_url(url)
    finding = c_struct.check_ip_host(p)
    assert finding is not None
    assert finding.check == "ip_host"


def test_credentials_in_url():
    url = "http://user@google.com@evil.com"
    p = parse_url(url)
    finding = c_struct.check_credentials_in_url(p)
    assert finding is not None
    assert finding.check == "credentials_in_url"


def test_brand_in_subdomain():
    url = "http://paypal.evil.com"
    p = parse_url(url)
    finding = c_struct.check_brand_in_subdomain(p)
    assert finding is not None
    assert finding.check == "brand_in_subdomain"


def test_typosquat():
    url = "http://gooogle.com"
    p = parse_url(url)
    finding = c_heuri.check_typosquat(p)
    assert finding is not None
    assert finding.check == "typosquat"


def test_idn_encoded():
    url = "http://xn--pple-43d.com"
    p = parse_url(url)
    finding = c_uni.check_punycode(p)
    assert finding is not None
    assert finding.check == "punycode"


def test_encoded_hostname():
    url = "http://google.com%2eevil.com"
    p = parse_url(url)
    finding = c_enc.check_encoded_hostname(p)
    assert finding is not None
    assert finding.check == "encoded_hostname"


def test_phishing_keywords():
    url = "http://secure-login-verify-account.com"
    p = parse_url(url)
    finding = c_struct.check_phishing_keywords(p)
    assert finding is not None
    assert finding.check == "phishing_keywords"


def test_url_shortener():
    url = "http://bit.ly/3xYz"
    p = parse_url(url)
    finding = c_heuri.check_url_shortener(p)
    assert finding is not None
    assert finding.check == "url_shortener"


def test_dangerous_scheme():
    url = "data:text/html,<script>"
    p = parse_url(url)
    finding = c_struct.check_dangerous_scheme(p)
    assert finding is not None
    assert finding.check == "dangerous_scheme"


def test_subdomain_depth():
    url = "http://a.b.c.d.e.com"
    p = parse_url(url)
    finding = c_struct.check_subdomain_depth(p)
    assert finding is not None
    assert finding.check == "subdomain_depth"


def test_hyphen_abuse():
    url = "http://pay-pal-secure-login.com"
    p = parse_url(url)
    finding = c_struct.check_hyphen_abuse(p)
    assert finding is not None
    assert finding.check == "hyphen_abuse"


def test_clean_url():
    url = "http://normal-site.com"
    p = parse_url(url)
    
    findings = []
    findings.extend(c_struct.run_all(p))
    findings.extend(c_uni.run_all(p))
    findings.extend(c_heuri.run_all(p))
    findings.extend(c_enc.run_all(p))
    
    assert len(findings) == 0


@patch("url_analyzer.checks.reputation.check_openphish", new_callable=AsyncMock)
async def test_reputation_mock(mock_openphish):
    from url_analyzer.models import Finding, CheckCategory, Severity
    mock_openphish.return_value = Finding(
        "openphish", CheckCategory.REPUTATION, Severity.CRITICAL, "found", "found"
    )
    import url_analyzer.checks.reputation as c_rep
    
    p = parse_url(normalize_url("http://phish.com"))
    c = AnalysisConfig(resolve_redirects=False, check_tls=False, check_domain_age=False)
    findings = await c_rep.run_all(p, c)
    
    # Due to concurrent execution we should have the openphish finding manually returned
    assert any(f.check == "openphish" for f in findings)
