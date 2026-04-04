import math
from collections import Counter
from url_analyzer.models import Finding, ParsedURL

def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    p, lns = Counter(s), float(len(s))
    return -sum(count/lns * math.log2(count/lns) for count in p.values())

def build_features(parsed: ParsedURL, findings: list[Finding], redirect_chain: list) -> dict:
    features = {
        "has_punycode": False,
        "has_mixed_script": False,
        "domain_age_days": None,
        "domain_age_available": False,
        "tls_cert_age_days": None,
        "tls_cert_age_available": False,
        "uses_ip_as_host": False,
        "has_credentials_in_url": False,
        "entropy_score": calculate_entropy(parsed.hostname),
        "url_length": len(parsed.raw),
        "num_subdomains": len(parsed.subdomain.split('.')) if parsed.subdomain else 0,
        "redirect_depth": len(redirect_chain),
        "tls_self_signed": False,
        "has_open_redirect_param": False
    }
    
    for f in findings:
        if f.check == "punycode": features["has_punycode"] = True
        elif f.check == "mixed_script": features["has_mixed_script"] = True
        elif f.check == "ip_host": features["uses_ip_as_host"] = True
        elif f.check == "credentials_in_url": features["has_credentials_in_url"] = True
        elif f.check == "tls_self_signed": features["tls_self_signed"] = True
        elif f.check == "open_redirect": features["has_open_redirect_param"] = True
        elif f.check == "domain_age":
            try:
                features["domain_age_days"] = int(f.evidence.split()[0].strip())
                features["domain_age_available"] = True
            except (ValueError, IndexError):
                pass
        elif f.check == "tls_cert_age":
            try:
                features["tls_cert_age_days"] = int(f.evidence.split()[0].strip())
                features["tls_cert_age_available"] = True
            except (ValueError, IndexError):
                pass

    return features
