# Prompt: Build a Production-Grade Python URL Phishing & Malware Detection System

## Role

You are a senior Python engineer and cybersecurity specialist. Your task is to produce
a complete, clean, well-structured Python codebase for a URL analysis system that
detects phishing, malware distribution, and suspicious URL patterns.

---

## Absolute Code Quality Rules

Apply these rules throughout every file without exception:

- Python 3.11+. Use `asyncio` for all I/O-bound operations.
- Every module has a module-level docstring.
- Every public function and class has a Google-style docstring (Args, Returns, Raises).
- Type-annotate every function signature (use `from __future__ import annotations`).
- Use `dataclasses` or `pydantic` models for all structured data — no raw dicts.
- No magic numbers. Every constant is a named module-level variable with a comment.
- All network calls have explicit timeouts and try/except with specific exception types.
- No bare `except:` or `except Exception:` — catch the narrowest exception possible.
- Group imports: stdlib → third-party → local, separated by blank lines.
- Max line length: 100 characters.
- Every file must be runnable standalone with a `if __name__ == "__main__":` demo block
  where appropriate.

---

## Project Layout

Generate all files listed below. Each file must be complete — no placeholder comments
like `# TODO` or `# implement this`.

```
url_analyzer/
├── __init__.py
├── models.py          # All dataclasses / enums
├── normalizer.py      # URL normalization and parsing
├── checks/
│   ├── __init__.py
│   ├── structural.py  # Fast, pure static checks
│   ├── unicode.py     # IDN, homograph, script mixing
│   ├── heuristic.py   # Keyword, brand, typosquat, entropy
│   ├── encoding.py    # Obfuscation and encoding abuse
│   ├── redirect.py    # Redirect chain resolver
│   ├── tls.py         # TLS certificate inspection
│   └── reputation.py  # DNS, WHOIS, external APIs
├── scorer.py          # Scoring engine
├── cache.py           # TTL caching layer
├── analyzer.py        # Orchestrator (asyncio.gather)
├── cli.py             # Click-based CLI
└── api.py             # FastAPI REST endpoint
```

---

## File Specifications

### `models.py`

Define the following using `dataclasses` with `frozen=True` unless noted:

```
Severity(Enum)      — INFO | LOW | MEDIUM | HIGH | CRITICAL
                      Each member carries an integer score attribute:
                      INFO=5, LOW=15, MEDIUM=25, HIGH=40, CRITICAL=60

CheckCategory(Enum) — STRUCTURAL | UNICODE | HEURISTIC | ENCODING
                      | REDIRECT | TLS | REPUTATION

Finding(dataclass, frozen)
    check: str
    category: CheckCategory
    severity: Severity
    description: str
    evidence: str

AnalysisConfig(dataclass, not frozen)
    resolve_redirects: bool = True
    check_tls: bool = True
    check_domain_age: bool = True
    google_api_key: str | None = None
    virustotal_api_key: str | None = None
    maxmind_db_path: str | None = None
    # Note: OpenPhish and URLhaus require no API key — always enabled
    timeout_seconds: float = 5.0
    max_redirect_hops: int = 10
    cache_ttl_seconds: int = 3600

ParsedURL(dataclass, frozen)
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

AnalysisResult(dataclass, frozen)
    url: str
    normalized_url: str
    score: int            # 0–100
    verdict: str          # CLEAN | LOW RISK | SUSPICIOUS | DANGEROUS
    findings: list[Finding]
    redirect_chain: list[str]
    analysis_time_ms: float
```

---

### `normalizer.py`

Implement two functions:

**`normalize_url(raw: str) -> str`**

Steps, in this exact order:
1. Strip all whitespace and the following zero-width characters:
   U+200B, U+200C, U+200D, U+FEFF, U+00AD, U+2060, U+180E
2. If no `http://` or `https://` scheme is present (case-insensitive), prepend `http://`
3. Repeatedly call `urllib.parse.unquote` until the output stabilises (max 10 iterations).
   This catches double- and triple-encoded URLs.
4. Lowercase only the scheme and netloc components (preserve path case).
5. Apply `unicodedata.normalize('NFKC', ...)` to the entire URL.
6. Return the result.

**`parse_url(url: str) -> ParsedURL`**

Use `tldextract.extract` for domain/subdomain/suffix splitting.
Use `urllib.parse.urlparse` for all other components.
Use `urllib.parse.parse_qs` for query parameters.
Return a `ParsedURL` dataclass. Never raise — return empty strings for missing parts.

---

### `checks/structural.py`

All functions are synchronous and pure (no I/O). Each returns `Finding | None` unless
noted. Import `Finding`, `Severity`, `CheckCategory` from `models`.

Implement:

1. **`check_ip_host(parsed)`** — Flag raw IPv4 and IPv6 hostnames. HIGH.

2. **`check_credentials_in_url(parsed)`** — Flag userinfo in netloc
   (e.g. `http://google.com@evil.com`). CRITICAL.

3. **`check_port_abuse(parsed)`** — Flag these specific ports:
   `{8080, 8443, 4443, 9999, 1337, 4444, 6666, 6667}`. MEDIUM.

4. **`check_subdomain_depth(parsed)`** — Flag subdomains with 4 or more labels. MEDIUM.

5. **`check_path_url_mimicry(parsed)`** — Flag when `http://` or `https://` appears
   inside the path component. HIGH.

6. **`check_dangerous_scheme(parsed)`** — Flag `data:` and `javascript:` schemes. CRITICAL.

7. **`check_url_length(parsed)`** — Flag URLs longer than 75 chars as LOW,
   longer than 150 chars as MEDIUM. Return the highest applicable finding.

8. **`check_hyphen_abuse(parsed)`** — Flag domains containing 3 or more hyphens. MEDIUM.
   Rationale: `pay-pal-secure-login.com` is a common phishing pattern.

9. **`check_brand_in_subdomain(parsed)`** — Use the same BRANDS list as typosquat checks.
   Flag when any brand name appears in the subdomain but the domain itself is NOT that brand.
   Example: `paypal.evil.com` → subdomain contains "paypal", domain is "evil". HIGH.

10. **`check_phishing_keywords(parsed)`** — Check the hostname and path (lowercased) for
    these keywords: `login`, `signin`, `sign-in`, `secure`, `verify`, `account`,
    `update`, `confirm`, `banking`, `credential`, `password`, `authenticate`,
    `validation`, `recover`, `suspend`, `limited`, `unusual`, `billing`.
    Flag on 2+ keyword matches as MEDIUM, 1 match as LOW.
    Return a single finding listing all matched keywords in evidence.

11. **`check_open_redirect(parsed)`** — Check query params against this list:
    `redirect, redirect_uri, redirect_url, url, uri, next, goto, return,
     returnurl, return_url, target, link, forward, dest, destination,
     continue, back, location, out, view, to`
    Flag when any param value starts with `http://`, `https://`, `//`, or `javascript:`. HIGH.

12. **`run_all(parsed) -> list[Finding]`** — Call all checks above, collect non-None results.

---

### `checks/unicode.py`

All synchronous and pure.

**`CONFUSABLES: dict[str, list[str]]`** — Map of ASCII chars to Unicode lookalikes.
Populate with at minimum these characters and their Cyrillic, Greek, and Armenian
lookalikes. Use Unicode code points in comments for auditing:

```
'a': ['\u0430', '\u0251', '\u03B1']      # Cyrillic а, Latin alpha, Greek alpha
'b': ['\u0432', '\u0253']                # Cyrillic в (approx), Latin b with hook
'c': ['\u0441', '\u03F2']                # Cyrillic с, Greek lunate sigma
'd': ['\u0501', '\u0257']                # Coptic d, Latin d with hook
'e': ['\u0435', '\u0454', '\u03B5']      # Cyrillic е, Ukrainian є, Greek epsilon
'g': ['\u0261']                          # Latin script small g
'h': ['\u04BB']                          # Cyrillic h
'i': ['\u0456', '\u04CF', '\u1D0B']     # Cyrillic і, Cyrillic ӏ, small capital I
'j': ['\u0458']                          # Cyrillic ј
'k': ['\u03BA']                          # Greek kappa
'l': ['\u04CF', '\u217C', '\u1C93']     # Cyrillic ӏ, Roman numeral l, etc
'm': ['\u217F', '\u1D0D']               # Roman small m, small capital M
'n': ['\u0578', '\u03B7']               # Armenian n, Greek eta
'o': ['\u03BF', '\u043E', '\u0D20']     # Greek omicron, Cyrillic о, Malayalam
'p': ['\u0440', '\u03C1']               # Cyrillic р, Greek rho
'q': ['\u0566']                          # Armenian q
'r': ['\u0433']                          # Cyrillic г (approximate)
's': ['\u0455', '\u0509']               # Cyrillic ѕ, Coptic s
't': ['\u0442', '\u03C4']               # Cyrillic т, Greek tau
'u': ['\u03C5', '\u0446']               # Greek upsilon, Cyrillic ц (approximate)
'v': ['\u03BD', '\u05D8']               # Greek nu, Hebrew tet (approximate)
'w': ['\u0461', '\u051D']               # Omega, Coptic
'x': ['\u0445', '\u03C7']               # Cyrillic х, Greek chi
'y': ['\u0443', '\u03B3']               # Cyrillic у, Greek gamma
'z': ['\u0225']                          # Latin z with hook
```

Implement:

1. **`check_punycode(parsed) -> Finding | None`** — Flag `xn--` in hostname. HIGH.

2. **`check_mixed_script(parsed) -> Finding | None`** — Iterate characters in hostname.
   Classify each alpha character as LATIN, CYRILLIC, GREEK, ARMENIAN, ARABIC,
   HEBREW, or OTHER using `unicodedata.name`. Flag if two or more distinct scripts
   are present. CRITICAL.

3. **`check_confusable_chars(parsed) -> Finding | None`** — Check every character in
   hostname against CONFUSABLES. Return first hit with the Unicode code point in evidence.
   CRITICAL.

4. **`run_all(parsed) -> list[Finding]`**

---

### `checks/heuristic.py`

**`BRANDS: list[str]`** — Include at minimum:
`google, paypal, amazon, apple, microsoft, facebook, netflix, instagram,
linkedin, twitter, chase, wellsfargo, bankofamerica, steam, discord, dropbox,
github, coinbase, binance, robinhood, spotify, apple, adobe, docusign,
dhl, fedex, usps, irs, outlook, office365, onedrive, sharepoint`

1. **`check_typosquat(parsed) -> Finding | None`**
   - Use `Levenshtein.distance` (from the `Levenshtein` package).
   - Skip if the domain exactly matches a brand (legitimate).
   - Flag if edit distance ≤ 2 from any brand. CRITICAL.
   - Include the brand name and edit distance in evidence.

2. **`check_url_shortener(parsed) -> Finding | None`**
   SHORTENERS set must include: `bit.ly, tinyurl.com, t.co, goo.gl, ow.ly,
   buff.ly, short.link, rebrand.ly, cutt.ly, is.gd, v.gd, tiny.cc, shorte.st,
   adf.ly, bc.vc, cli.re, s.id, bl.ink, snip.ly, rb.gy, lnkd.in, youtu.be`
   Flag if hostname is in SHORTENERS or ends with `.{shortener}`. MEDIUM.

3. **`check_entropy(parsed) -> Finding | None`**
   Calculate Shannon entropy of the domain label (excluding TLD).
   Formula: `H = -sum(p * log2(p) for each unique char frequency)`
   Flag if entropy > 4.0 as LOW (random-looking domain names indicate DGA malware).
   Include the calculated entropy value in evidence.

4. **`run_all(parsed) -> list[Finding]`**

---

### `checks/encoding.py`

1. **`check_double_encoding(parsed) -> Finding | None`**
   Flag if `%25` appears in the raw URL (percent-encoding of `%`). HIGH.

2. **`check_encoded_hostname(parsed) -> Finding | None`**
   Flag if any percent-encoded character (`%[0-9a-fA-F]{2}`) appears in the hostname.
   CRITICAL.

3. **`check_null_byte(parsed) -> Finding | None`**
   Flag if `%00` or `\x00` appears anywhere. CRITICAL.

4. **`check_decimal_ip(parsed) -> Finding | None`**
   Flag if hostname is a pure decimal number (e.g. `http://1249763845/path`).
   This is a dotless decimal IP representation. CRITICAL.
   Evidence should show the converted IP address.

5. **`check_octal_ip(parsed) -> Finding | None`**
   Flag if the hostname consists of octal octets (e.g. `0177.0.0.01`). CRITICAL.

6. **`run_all(parsed) -> list[Finding]`**

---

### `checks/redirect.py`

Implement an async redirect resolver that follows all redirect types.

**`resolve_redirect_chain(url, config) -> list[dict]`** — async.

Each hop dict contains: `url: str`, `status: int | None`, `redirect_type: str`, `error: str | None`.
`redirect_type` is one of: `http_3xx`, `meta_refresh`, `js_location`, `terminal`, `error`.

Implementation requirements:
- Use `aiohttp.ClientSession` with the timeout from config.
- Disable automatic redirects (`allow_redirects=False`).
- On each response:
  1. Record the hop.
  2. Check for HTTP 301/302/303/307/308 → follow `Location` header.
  3. If status 200, fetch the response body (max 50KB) and:
     a. Parse with `html.parser` via `BeautifulSoup` — look for
        `<meta http-equiv="refresh" content="...">` and extract the URL.
        Flag as `meta_refresh`.
     b. Scan for `window.location` and `location.href` assignments in `<script>` tags
        with a simple regex. Flag as `js_location`.
  4. Stop when no redirect is detected, or `max_redirect_hops` is reached,
     or an error occurs.
- Use `urllib.parse.urljoin` to resolve relative redirect URLs.
- Set `User-Agent` to `Mozilla/5.0 (compatible; PhishDetect/1.0)`.

**`check_redirect_chain(chain, parsed_fn) -> list[Finding]`** — synchronous post-processor.

Accepts the chain list and a function `parsed_fn(url) -> ParsedURL`.
- Flag chains longer than 3 hops as MEDIUM, longer than 6 as HIGH.
- Re-run structural, unicode, and heuristic checks on every hop URL beyond the first.
- Flag when the final destination domain differs from the original domain. HIGH.

---

### `checks/tls.py`

Implement using `ssl` (stdlib) and `OpenSSL` (pyOpenSSL). All functions are async.

**`fetch_tls_info(hostname, port=443, timeout=5.0) -> dict`** — async.

Return a dict with:
```
{
  'subject_cn': str,
  'issuer_org': str,
  'not_before': datetime,
  'not_after': datetime,
  'is_self_signed': bool,
  'san_domains': list[str],
  'cert_age_days': int,        # days since not_before
  'days_until_expiry': int,
}
```

Use `asyncio.get_event_loop().run_in_executor` to wrap the blocking `ssl` call.

**`check_tls(parsed, config) -> list[Finding]`** — async.

Call `fetch_tls_info` and then:
1. Flag if `is_self_signed` → HIGH.
2. Flag if `cert_age_days < 30` → HIGH (newly issued cert is a phishing signal).
3. Flag if `days_until_expiry < 7` → MEDIUM.
4. Flag if `subject_cn` does not match the hostname (wildcard-aware comparison) → CRITICAL.
5. Flag if the issuer org is not in a hardcoded set of known trusted CAs → LOW
   (evidence: the actual issuer org name).
   Known CAs set must include at minimum: DigiCert, Let's Encrypt, Sectigo, GlobalSign,
   GoDaddy, Comodo, Amazon, Microsoft, Google, Entrust, Thawte, GeoTrust.

On any connection error, return an empty list (the check is optional and best-effort).

---

### `checks/reputation.py`

All functions are async. Accept `config: AnalysisConfig` where needed.

1. **`check_domain_age(domain, config) -> Finding | None`**
   - Use the `whois` library (wrap with `asyncio.get_event_loop().run_in_executor`).
   - Handle `creation_date` being a list (take the earliest date).
   - Flag if age < 7 days → CRITICAL; < 30 days → HIGH; < 90 days → MEDIUM.
   - On any error (WHOIS rate limit, redacted, NXDomain), return None silently.

2. **`check_dns_mx(domain, config) -> Finding | None`**
   - Use `aiodns` or `dns.resolver` wrapped in executor.
   - Query for MX records using `dns.resolver.NoAnswer` (not `NXDOMAIN`) to detect
     "domain exists but has no MX". Flag as LOW.
   - `NXDOMAIN` means the domain doesn't exist at all — flag that as HIGH.

3. **`check_google_safe_browsing(url, config) -> Finding | None`**
   - Skip if `config.google_api_key` is None.
   - POST to `https://safebrowsing.googleapis.com/v4/threatMatches:find`.
   - Include threat types: MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION.
   - Flag if any match is returned → CRITICAL.

4. **`check_virustotal(url, config) -> Finding | None`**
   - Skip if `config.virustotal_api_key` is None.
   - Step 1: POST the URL to `https://www.virustotal.com/api/v3/urls` to submit for analysis.
     Use `base64.urlsafe_b64encode(url.encode()).rstrip(b'=').decode()` as the URL ID.
   - Step 2: GET `https://www.virustotal.com/api/v3/urls/{url_id}` to retrieve results.
   - If `last_analysis_stats.malicious > 2` → CRITICAL.
   - If `last_analysis_stats.suspicious > 3` → HIGH.
   - Handle 404 (URL not yet in VT) gracefully by returning None after the POST attempt.

5. **`check_openphish(url, config) -> Finding | None`**
   - No API key required. OpenPhish publishes a free plain-text feed.
   - On first call (or after cache TTL expires), fetch the feed from
     `https://openphish.com/feed.txt` with a 10-second timeout.
   - Cache the full set of URLs under key `openphish:feed` using the TTL cache.
   - Normalise both the candidate URL and each feed entry with `normalize_url`
     before comparing, then do an exact-match lookup in the cached set.
   - Flag if the URL is present in the feed → CRITICAL.
   - Evidence: `"URL found in OpenPhish feed"`.
   - On any network error, log a warning and return None (best-effort).

6. **`check_urlhaus(url, config) -> Finding | None`**
   - No API key required. URLhaus (abuse.ch) offers a free JSON lookup API.
   - POST to `https://urlhaus-api.abuse.ch/v1/url/` with form field `url=<url>`.
   - Cache results under key `urlhaus:{sha256_of_url}`.
   - If `query_status == "is_listed"` → CRITICAL.
     Evidence: include the `threat` field from the response (e.g. `malware_download`).
   - If `query_status == "no_results"` → return None.
   - On HTTP error or timeout, log a warning and return None.

7. **`check_geoip(parsed, config) -> Finding | None`**
   - Skip if `config.maxmind_db_path` is None.
   - Use `geoip2.database.Reader` to look up the hostname's resolved IP.
   - Resolve the hostname to an IP first using `socket.getaddrinfo` (in executor).
   - Flag if the country is in this high-risk set:
     `{'RU', 'CN', 'KP', 'IR', 'NG', 'RO', 'UA', 'BY', 'VN', 'PK'}` → LOW.
     Note in the docstring that this is a probabilistic signal, not a determination.
   - Also use `geoip2` ASN database if available to flag known bulletproof hosting ASNs.

8. **`run_all(parsed, config) -> list[Finding]`** — async, runs checks concurrently
   with `asyncio.gather(*tasks, return_exceptions=True)`. Filter out exceptions from results.

---

### `cache.py`

Implement a generic async-safe TTL cache.

```python
class TTLCache:
    """In-memory TTL cache with async-safe get/set."""

    def __init__(self, ttl_seconds: int) -> None: ...

    async def get(self, key: str) -> Any | None: ...
    async def set(self, key: str, value: Any) -> None: ...
    async def invalidate(self, key: str) -> None: ...
    async def clear(self) -> None: ...
```

- Store entries as `(value, expiry_timestamp)` tuples.
- `get` returns None if the key is missing or expired.
- Use `asyncio.Lock` for all mutations.
- Cache keys for the reputation module should be namespaced:
  `dns:{domain}`, `whois:{domain}`, `tls:{hostname}`, `vt:{url_hash}`, `gsb:{url_hash}`

Expose a module-level singleton: `cache = TTLCache(ttl_seconds=3600)`.
The `analyzer.py` orchestrator passes the cache into each check that supports it.

---

### `scorer.py`

**`SEVERITY_WEIGHTS: dict[Severity, int]`**
```
INFO=5, LOW=15, MEDIUM=25, HIGH=40, CRITICAL=60
```

**`CATEGORY_CAPS: dict[CheckCategory, int]`**
```
STRUCTURAL=60, UNICODE=60, HEURISTIC=50, ENCODING=60,
REDIRECT=40, TLS=50, REPUTATION=80
```
Cap the contribution of each category before summing to prevent double-penalising
the same underlying signal.

**`score(findings: list[Finding]) -> tuple[int, str]`**

Algorithm:
1. Group findings by `CheckCategory`.
2. For each category, sum `SEVERITY_WEIGHTS[f.severity]` for all findings.
3. Cap each category's sum at `CATEGORY_CAPS[category]`.
4. Sum capped scores across categories.
5. Clamp total to 100.
6. Determine verdict:
   - 0–9: `CLEAN`
   - 10–29: `LOW RISK`
   - 30–59: `SUSPICIOUS`
   - 60–100: `DANGEROUS`
7. Return `(total_score, verdict)`.

---

### `analyzer.py`

**`async def analyze(url: str, config: AnalysisConfig | None = None) -> AnalysisResult`**

Orchestration steps:
1. Record start time.
2. `normalized = normalize_url(url)`
3. `parsed = parse_url(normalized)`
4. Collect all static (sync) findings using `run_all` from:
   - `checks.structural`
   - `checks.unicode`
   - `checks.heuristic`
   - `checks.encoding`
5. Build a list of async tasks conditionally:
   - `checks.reputation.run_all` (always)
   - `checks.tls.check_tls` (if `config.check_tls`)
   - `checks.redirect.resolve_redirect_chain` (if `config.resolve_redirects`)
6. Await all async tasks with `asyncio.gather(*tasks, return_exceptions=True)`.
   Log exceptions as warnings; do not surface them to the caller.
7. If redirect chain was resolved, run `check_redirect_chain`.
8. Aggregate all findings, call `scorer.score`, record elapsed time.
9. Return `AnalysisResult`.

---

### `cli.py`

Use the `click` library.

```
url-analyzer analyze <URL> [OPTIONS]

Options:
  --json              Output raw JSON instead of coloured table
  --no-redirects      Skip redirect chain resolution
  --no-tls            Skip TLS certificate checks
  --timeout FLOAT     Per-request timeout in seconds [default: 5.0]
  --gsb-key TEXT      Google Safe Browsing API key
  --vt-key TEXT       VirusTotal API key
  --maxmind PATH      Path to MaxMind GeoLite2 DB directory
```

Default output (non-JSON) must:
- Print the verdict on one line with colour: green=CLEAN, yellow=LOW RISK,
  orange=SUSPICIOUS, red=DANGEROUS. Use `click.style`.
- Print score as `Score: 42/100`.
- Print a table of findings: `Severity | Category | Check | Evidence`.
- Sort findings by severity descending.
- Print `Analysis time: 1.23s` at the bottom.

---

### `api.py`

Use `FastAPI`.

```
POST /analyze
Body: { "url": "...", "config": { ... } }   (config fields are all optional)
Response: AnalysisResult serialised to JSON
```

```
GET /health
Response: { "status": "ok" }
```

- Use `pydantic` models for request/response bodies.
- Handle validation errors with a 422 response.
- Run `analyzer.analyze` with `asyncio` (FastAPI handles the event loop).
- Include a rate limiter: max 10 requests per second per IP using a simple
  in-memory sliding window. Return 429 with `Retry-After` header on breach.

---

## API Keys Reference

The system uses three external services that require credentials, and two that are
completely free with no registration.

---

### Services requiring API keys

#### 1. Google Safe Browsing
- **Key name in config:** `google_api_key`
- **CLI flag:** `--gsb-key`
- **Cost:** Free up to 10,000 requests/day
- **How to get:**
  1. Go to https://console.cloud.google.com
  2. Create a project (or select an existing one)
  3. Enable the "Safe Browsing API" from the API Library
  4. Go to Credentials → Create Credentials → API Key
  5. Restrict the key to the Safe Browsing API only (recommended)
- **Endpoint used:** `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=<KEY>`
- **Rate limit:** 10,000 requests/day on the free tier

---

#### 2. VirusTotal
- **Key name in config:** `virustotal_api_key`
- **CLI flag:** `--vt-key`
- **Cost:** Free community tier available
- **How to get:**
  1. Register at https://www.virustotal.com/gui/join-us
  2. After sign-in, go to your profile → API Key
  3. Copy the 64-character hex key
- **Rate limit (free tier):** 4 requests/minute, 500 requests/day
- **Header used:** `x-apikey: <KEY>` on all requests
- **Endpoints used:**
  - POST `https://www.virustotal.com/api/v3/urls`  (submit URL)
  - GET  `https://www.virustotal.com/api/v3/urls/{id}` (fetch result)

---

#### 3. MaxMind GeoLite2 (Geo-IP + ASN)
- **Key name in config:** `maxmind_db_path`  (path to the downloaded `.mmdb` file, not a key string)
- **CLI flag:** `--maxmind`
- **Cost:** Free (GeoLite2 databases — not GeoIP2 commercial)
- **How to get:**
  1. Register at https://www.maxmind.com/en/geolite2/signup
  2. After sign-in, go to Account → Manage License Keys → Generate new license key
  3. Download the databases using your license key:
     ```
     # GeoLite2 City (country + city)
     https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=<KEY>&suffix=tar.gz
     # GeoLite2 ASN (autonomous system number)
     https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=<KEY>&suffix=tar.gz
     ```
  4. Extract both `.mmdb` files into a single directory and pass that directory path as
     `maxmind_db_path`. The code expects:
     - `<path>/GeoLite2-City.mmdb`
     - `<path>/GeoLite2-ASN.mmdb`
- **Note:** The license key itself is only needed for downloading — it is never used at runtime.
  The `.mmdb` files work fully offline.
- **Update cadence:** MaxMind updates GeoLite2 every Tuesday. Set up a weekly cron job
  to re-download if freshness matters.

---

### Services requiring NO credentials

#### OpenPhish
- Completely free, no registration, no key.
- The code fetches `https://openphish.com/feed.txt` and caches it.
- Feed updates roughly every 12 hours; the TTL cache handles refresh automatically.

#### URLhaus (abuse.ch)
- Completely free, no registration, no key.
- API endpoint: `https://urlhaus-api.abuse.ch/v1/url/`
- Rate limit: generous free tier; no authentication required.

---

### Environment variable pattern (recommended)

Rather than hard-coding keys in config, instruct users to set these environment variables
and load them in `analyzer.py` as fallbacks when config fields are None:

```
URL_ANALYZER_GSB_KEY=...
URL_ANALYZER_VT_KEY=...
URL_ANALYZER_MAXMIND_PATH=/opt/maxmind/
```

---

## Dependencies

Generate a complete `requirements.txt`:

```
aiohttp>=3.9
aiodns>=3.1
beautifulsoup4>=4.12
click>=8.1
dnspython>=2.4
fastapi>=0.110
geoip2>=4.7
Levenshtein>=0.25
pyOpenSSL>=24.0
python-whois>=0.9
requests>=2.31
tldextract>=5.1
uvicorn>=0.28
validators>=0.28
```

---

## Tests

Generate `tests/test_checks.py` using `pytest` and `pytest-asyncio`.

Include at minimum one test per check function. Use these concrete test cases:

| URL | Expected check triggered |
|-----|--------------------------|
| `http://192.168.1.1/login` | `ip_host` |
| `http://user@google.com@evil.com` | `credentials_in_url` |
| `http://paypal.evil.com` | `brand_in_subdomain` |
| `http://gooogle.com` | `typosquat` |
| `http://xn--pple-43d.com` | `idn_encoded` |
| `http://google.com%2eevil.com` | `encoded_hostname` |
| `http://secure-login-verify-account.com` | `phishing_keywords` |
| `http://bit.ly/3xYz` | `url_shortener` |
| `data:text/html,<script>` | `dangerous_scheme` |
| `http://a.b.c.d.e.com` | `subdomain_depth` |
| `http://pay-pal-secure-login.com` | `hyphen_abuse` |
| `http://normal-site.com` | no findings / CLEAN |

Mock all network calls. Use `unittest.mock.AsyncMock` for async functions.

---

## Final Instructions

- Output all files in full. Do not truncate any file.
- Do not output any commentary between files — just the files with their paths as headers.
- If a dependency is used, it must be in `requirements.txt`.
- If a constant is shared between modules, define it once in `models.py` and import it.
- Use `logging.getLogger(__name__)` in every module. Do not use `print` outside `cli.py`.
- The `cache.py` singleton must be imported and used in `reputation.py` — wrap every
  external API call and every DNS/WHOIS lookup with a cache read-before-fetch pattern.
