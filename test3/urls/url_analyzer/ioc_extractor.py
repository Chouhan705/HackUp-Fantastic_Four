import re
from url_analyzer.models import Finding, ParsedURL

EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
URL_ENCODED_REGEX = re.compile(r'(%[0-9A-Fa-f]{2})+')

def extract_iocs(parsed: ParsedURL, findings: list[Finding], redirect_urls: list) -> dict:
    domains = set()
    if parsed.domain and parsed.suffix:
        domains.add(f"{parsed.domain}.{parsed.suffix}")
    if parsed.hostname and not re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.hostname):
        domains.add(parsed.hostname)
        
    ips = set()
    if parsed.hostname and re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.hostname):
        ips.add(parsed.hostname)

    for f in findings:
        if f.check == "ip_host" and f.evidence:
            ips.add(f.evidence)

    urls = {parsed.raw}
    for ru in redirect_urls:
        if isinstance(ru, dict) and "url" in ru:
            urls.add(ru["url"])
        elif isinstance(ru, str):
            urls.add(ru)

    potential_emails = set(EMAIL_REGEX.findall(parsed.raw))
    
    credential_injection = set()
    emails = set()
    
    # Differentiate typical auth vs email injection.
    if "@" in parsed.raw:
        # A crude check, if @ is before the domain in the hostname segment:
        try:
            auth_part = parsed.raw.split("://")[1].split("@")[0]
            credential_injection.add(f"{auth_part}@{parsed.hostname}")
        except IndexError:
            credential_injection.update(potential_emails)
    else:
        emails = potential_emails
        
    suspicious_query_params = set()
    for param_name, param_values in parsed.params.items():
        lower_name = param_name.lower()
        if "session" in lower_name or "token" in lower_name or "login" in lower_name or "auth" in lower_name:
            suspicious_query_params.add(f"{param_name}={param_values[0] if param_values else ''}")

    encoded_segments = set()
    for match in URL_ENCODED_REGEX.finditer(parsed.path + parsed.query):
        encoded_segments.add(match.group(0))

    return {
        "domains": list(domains),
        "ips": list(ips),
        "urls": list(urls),
        "emails": list(emails),
        "hashes": [],
        "patterns": {
            "credential_injection": list(credential_injection),
            "suspicious_query_params": list(suspicious_query_params),
            "encoded_segments": list(encoded_segments)
        }
    }
