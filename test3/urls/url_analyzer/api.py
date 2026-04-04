"""FastAPI REST endpoint for URL Analyzer."""
import time
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

from url_analyzer.analyzer import analyze
from url_analyzer.models import AnalysisConfig

app = FastAPI(title="URL Analyzer API", version="1.0.0")

# Simple Sliding Window Rate Limiter
RATE_LIMIT = 10
RATE_LIMIT_WINDOW = 1.0 # seconds
requests_windows: Dict[str, list[float]] = {}


class AnalyzerConfigRequest(BaseModel):
    resolve_redirects: bool = True
    check_tls: bool = True
    check_domain_age: bool = True
    google_api_key: str | None = None
    virustotal_api_key: str | None = None
    maxmind_db_path: str | None = None
    timeout_seconds: float = Field(5.0, ge=1.0, le=30.0)


class AnalyzeRequest(BaseModel):
    url: str
    config: AnalyzerConfigRequest = Field(default_factory=AnalyzerConfigRequest)


@app.middleware("http")
async def rate_limiter(request: Request, call_next):
    """Rate limit to 10 requests per second per IP."""
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    
    if client_ip not in requests_windows:
        requests_windows[client_ip] = []
        
    # Clean up old window records
    requests_windows[client_ip] = [t for t in requests_windows[client_ip] if now - t < RATE_LIMIT_WINDOW]
    
    if len(requests_windows[client_ip]) >= RATE_LIMIT:
        response = Response(content="Rate limit exceeded", status_code=429)
        response.headers["Retry-After"] = "1"
        return response
        
    requests_windows[client_ip].append(now)
    
    response = await call_next(request)
    return response


@app.post("/analyze")
async def analyze_endpoint(request: AnalyzeRequest) -> Any:
    """Analyze a URL."""
    try:
        config_dict = request.config.model_dump()
        c = AnalysisConfig(**config_dict)
        result = await analyze(request.url, c)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {"status": "ok"}
