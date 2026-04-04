# Phishing Detector — Chrome Extension + MIME Parser

Two components. Drop the extension into Chrome, drop the parser into your FastAPI backend.

---

## Project Structure

```
phishing-detector/
├── extension/
│   ├── manifest.json
│   ├── background/
│   │   └── service_worker.js      # OAuth + Gmail API + backend relay
│   ├── content/
│   │   ├── content.js             # Gmail watcher + sidebar injector
│   │   └── sidebar.css            # Shadow DOM host reset
│   ├── popup/
│   │   ├── popup.html
│   │   └── popup.js
│   └── icons/                     # Add icon16.png, icon48.png, icon128.png
│
└── parser/
    ├── mime_parser.py             # Raw email decoder + MIME walker
    └── scan_route.py              # FastAPI /scan endpoint
```

---

## Chrome Extension Setup

### 1. Google Cloud Project

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create a project → Enable **Gmail API**
3. OAuth consent screen → External → add scope `gmail.readonly`
4. Credentials → **OAuth 2.0 Client ID** → Chrome Extension
   - Set your extension ID (get it from `chrome://extensions` after loading unpacked)
5. Copy the Client ID into `manifest.json` → `oauth2.client_id`

### 2. Backend URL

In `background/service_worker.js`, set:
```js
const BACKEND_URL = "https://your-backend.example.com";
```

### 3. Load in Chrome

1. Go to `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked** → select the `extension/` folder
4. Pin the extension → click it → hit **Connect Gmail Account**

---

## Backend (Parser) Setup

### Requirements

```bash
pip install fastapi uvicorn
# No extra deps — mime_parser.py uses only Python stdlib
```

### Wire into FastAPI

```python
# main.py
from fastapi import FastAPI
from parser.scan_route import router

app = FastAPI()
app.include_router(router)
```

```bash
uvicorn main:app --reload
```

### Wire your engines

In `scan_route.py`, uncomment and replace the stub engine calls:
```python
url_result, nlp_result, header_result = await asyncio.gather(
    url_analyze(parsed.urls),
    nlp_analyze(parsed.text_body, parsed.html_body),
    header_analyze(parsed.auth, parsed.sender, parsed.headers),
)
```

Each engine receives clean, pre-extracted data from `ParsedEmail`:
- `parsed.urls`        → list of all URLs from body + hrefs
- `parsed.text_body`   → plain text body
- `parsed.html_body`   → raw HTML body
- `parsed.auth`        → SPF / DKIM / DMARC results
- `parsed.sender`      → From / Reply-To / domain mismatch flag
- `parsed.headers`     → full headers dict

### CLI test the parser

```bash
# Paste a base64url raw string directly
python -m parser.mime_parser "SGVsbG8gV29ybGQ..."

# Or from a file
python -m parser.mime_parser --file raw_email.b64
```

---

## Data Flow

```
Gmail UI → content.js detects email open
         → user clicks "Scan"
         → service_worker.js fetches raw email via Gmail API
         → POST /scan { message_id, raw_email }
         → mime_parser.py decodes + parses MIME
         → your engines get clean extracted data
         → weighted verdict JSON returned
         → sidebar renders score + signals
```

---

## What the parser extracts

| Field | Description |
|---|---|
| `text_body` | Decoded plain text from all `text/plain` parts |
| `html_body` | Raw HTML from all `text/html` parts |
| `urls` | Deduplicated list of all http/https URLs |
| `headers` | Full headers dict (lowercase keys) |
| `auth.spf` | `pass` / `fail` / `softfail` / `neutral` / `none` |
| `auth.dkim` | `pass` / `fail` / `none` |
| `auth.dmarc` | `pass` / `fail` / `none` |
| `sender.from_address` | Parsed From email |
| `sender.from_domain` | Domain of From address |
| `sender.reply_to` | Reply-To address if present |
| `sender.reply_to_mismatch` | `True` if Reply-To domain ≠ From domain |
| `attachments` | List of `{filename, content_type, size_bytes}` |
