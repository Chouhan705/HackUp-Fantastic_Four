# Phishing & Malware URL Analyzer

A production-grade Python system designed to analyze URLs and detect phishing attempts, malware distribution, obfuscation techniques, and overall malicious intent. It combines pure static heuristic analysis with dynamic reputation lookups and TLS certificate inspections to provide a comprehensive security verdict.

---

## 🔍 How the Analysis Works

The analysis pipeline operates in four main stages:

1. **Normalization & Parsing**:
   - Strips whitespace and zero-width characters.
   - Prepends missing HTTP/HTTPS schemes.
   - Repeatedly unquotes (URL-decodes) the string to defeat double/triple-encoding bypasses.
   - Applies NFKC Unicode normalization.
   - Parses the URL into distinct components (scheme, hostname, subdomain, exact domain, path, query parameters) using standard libraries and `tldextract`.

2. **Static Checks (Fast & Synchronous)**:
   - **Structural**: Inspects for IP hostnames, credential passing (`user:pass@`), suspicious ports, deep subdomains, path mimicry, excessive length, hyphen abuse, open redirect parameters, and phishing keywords.
   - **Unicode**: Checks for IDN (Punycode) usage, mixed-script characters (e.g., mixing Cyrillic and Latin), and known confusable homograph characters.
   - **Heuristic**: Detects typosquatting against known major brands (using Levenshtein distance), URL shortener usage, and high entropy (random looking) domain labels (DGA indicators).
   - **Encoding**: Flags double URL encoding, encoded hostnames, null bytes, and decimal/octal IP address representations.

3. **Dynamic Checks (Async I/O)**:
   - **Reputation**: Concurrently queries WHOIS (domain age), DNS (MX records), GeoIP location (high-risk countries), and integrates with multiple threat intelligence feeds.
   - **TLS/SSL**: Inspects certificate health, scanning for self-signed certificates, newly issued certificates (< 30 days), soon-to-expire certificates, hostname mismatches, and untrusted CAs.
   - **Redirect Resolution**: Actively traces HTTP 3xx, meta refresh, and JavaScript location assignments to evaluate the final destination.

4. **Scoring Engine**:
   - Groups findings by category and assigns weights based on severity (`INFO`=5, `LOW`=15, `MEDIUM`=25, `HIGH`=40, `CRITICAL`=60).
   - Caps category scores to prevent double-penalizing the same underlying signal.
   - Clamps the final score to a 0-100 scale and assigns a definitive verdict (`CLEAN`, `LOW RISK`, `SUSPICIOUS`, or `DANGEROUS`).

---

## 🛠️ Resources & Threat Feeds Used

### Services Requiring API Keys
These services require you to provide keys via a `.env` file or CLI flags. **Graceful Degradation:** If an API key or path is absent, the system does not crash. It will simply skip that specific module's checks while continuing to analyze the rest of the URL structure:

- **Google Safe Browsing** (`URL_ANALYZER_GSB_KEY`): Checks for known Malware, Social Engineering, and Potentially Harmful Applications. (Free up to 10k requests/day).
- **VirusTotal** (`URL_ANALYZER_VT_KEY`): Submits URLs to ~70 external antivirus engines and domain blocklisting services. (Free community tier: 4 reqs/min).
- **MaxMind GeoLite2** (`URL_ANALYZER_MAXMIND_PATH`): Offline geolocation database (`.mmdb`) mapping IPs to countries to flag bulletproof or high-risk hosting regions. *(Note: MaxMind releases updates to these free databases every Tuesday. It is recommended to automate a weekly re-download to maintain geographic accuracy).*

### Free Services (No Keys Required)
- **OpenPhish**: Pulls and automatically caches their free plain-text list of active phishing URLs.
- **URLhaus (abuse.ch)**: Queries their JSON API to identify URLs currently distributing malware.
- **DNS / WHOIS**: Native queries performed locally to calculate domain age and check mail exchange records.

*Note: All external network calls are wrapped in an asynchronous TTL Cache to reduce latency and prevent rate-limiting.*

---

## 🚀 Installation & Setup

1. **Create a virtual environment & install dependencies**:
    ```bash
    python -m venv .venv
    # Windows: .\.venv\Scripts\Activate.ps1
    # Linux/Mac: source .venv/bin/activate
    pip install -r requirements.txt
    ```

2. **Configure Environment Variables**:
   Copy `.env.example` to `.env` in your project root and populate your keys:
    ```env
    URL_ANALYZER_GSB_KEY=your_google_key
    URL_ANALYZER_VT_KEY=your_virustotal_key
    URL_ANALYZER_MAXMIND_PATH=C:\opt\maxmind
    ```

## 🧪 Testing

The codebase includes a full `pytest` suite simulating inputs across modules. Once set up, just execute:

```bash
python -m pytest tests/
```

---

## 💻 Usage (Inputs & Outputs)

The tool can be accessed via a Command Line Interface (CLI) or a REST API.

### Command Line Interface

**Input**: The primary input is the raw URL string. You can optionally toggle TLS, redirects, or output formats.
```bash
python -m url_analyzer.cli analyze "https://paypal.com@evil.com"
```

**Common Flags**:
- `--json`: Output raw JSON blocks instead of tabular results.
- `--no-tls`: Skip active network TLS verification checks entirely.
- `--no-redirects`: Don't actively trace HTTP 3xx or JS locations.
- `--timeout [FLOAT]`: Override the default 5.0-second socket/request limit for each network task.

**Output**: A colored summary table detailing the final verdict, score, and all security findings.
```text
Verdict: DANGEROUS
Score: 100/100

Findings:
Severity   | Category     | Check                     | Evidence
--------------------------------------------------------------------------------
CRITICAL   | STRUCTURAL   | credentials_in_url        | paypal.com@evil.com
CRITICAL   | REPUTATION   | virustotal                | 8 malicious hits
HIGH       | TLS          | tls_cert_age              | 2 days old

Analysis time: 1.60s
```

You can also request raw JSON output:
```bash
python -m url_analyzer.cli analyze "https://paypal.com@evil.com" --json
```

### REST API (FastAPI)

Start the server:
```bash
uvicorn url_analyzer.api:app --reload
```

**Input**: A JSON payload to `POST /analyze`.
```json
{
  "url": "http://xn--pple-43d.com",
  "config": {
    "resolve_redirects": true,
    "check_tls": true,
    "timeout_seconds": 5.0
  }
}
```

**Output**: A structured JSON response containing the full `AnalysisResult`.

*Note: The API limits incoming traffic to 10 requests per second per IP using a sliding window. Abuse will receive an HTTP 429 (`Rate limit exceeded`) string with a standard `Retry-After` header.*
```json
{
  "url": "http://xn--pple-43d.com",
  "normalized_url": "http://xn--pple-43d.com",
  "score": 85,
  "verdict": "DANGEROUS",
  "findings": [
    {
      "check": "punycode",
      "category": "UNICODE",
      "severity": 40,
      "description": "Punycode (IDN) used in hostname",
      "evidence": "xn--pple-43d.com"
    }
  ],
  "redirect_chain": [],
  "analysis_time_ms": 845.2
}
```
