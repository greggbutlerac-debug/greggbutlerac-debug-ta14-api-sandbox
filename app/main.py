from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

try:
    import redis
except ImportError:  # pragma: no cover
    redis = None

from .engine import (
    API_VERSION,
    PUBLIC_BOUNDARY,
    TA14_CHAIN,
    chain_status,
    decision_matrix,
    evaluate_evidence_payload,
    evaluate_execution_payload,
    make_meta,
)
from .rate_limit import ApiIdentity, ApiKeyRegistry, SandboxRateLimiter, make_usage_store
from .models import (
    AuthorityCheckRequest,
    ChainSpecResponse,
    ContinuityCheckRequest,
    Decision,
    DecisionMatrixResponse,
    EvaluateEvidenceRequest,
    EvaluateExecutionRequest,
    EvaluationResponse,
    ProcurementScreenRequest,
    PublicBoundaryResponse,
    ReviewabilityRecordRequest,
    RouteRiskClass,
)

APP_NAME = "TA-14 Admissible Execution API Sandbox"

MAX_BODY_BYTES = int(os.getenv("TA14_MAX_BODY_BYTES", "200000"))
API_KEY_REGISTRY = ApiKeyRegistry()
RATE_LIMIT_ENABLED = os.getenv("TA14_RATE_LIMIT_ENABLED", "true").lower() == "true"
RATE_LIMITER = SandboxRateLimiter(make_usage_store())
AUDIT_LOG_ENABLED = os.getenv("TA14_AUDIT_LOG", "false").lower() == "true"
AUDIT_LOG_PATH = os.getenv("TA14_AUDIT_LOG_PATH", "./ta14_audit_log.jsonl")
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "*")


class UsageAnalytics:
    """Privacy-preserving aggregate API usage analytics.

    Stores only aggregate counts by day, endpoint, decision, and plan.
    It does not store request bodies, IP addresses, API keys, or identities.
    Redis is used when TA14_REDIS_URL/REDIS_URL is configured; otherwise
    the dashboard remains available with in-memory counts that reset on deploy.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._memory: dict[str, dict[str, int]] = {}
        self._redis = None
        url = (os.getenv("TA14_REDIS_URL") or os.getenv("REDIS_URL") or "").strip()
        if url and redis is not None:
            try:
                client = redis.Redis.from_url(url, decode_responses=True)
                client.ping()
                self._redis = client
            except Exception:
                self._redis = None

    @staticmethod
    def _day(now: datetime | None = None) -> str:
        return (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d")

    @staticmethod
    def _fields(endpoint: str, decision: str, plan: str) -> list[str]:
        return [
            "total",
            f"decision:{decision}",
            f"endpoint:{endpoint}",
            f"plan:{plan}",
        ]

    def record(self, endpoint: str, decision: str, plan: str) -> None:
        day = self._day()
        fields = self._fields(endpoint, decision, plan)
        if self._redis is not None:
            pipe = self._redis.pipeline()
            for key in ("ta14:stats:all", f"ta14:stats:day:{day}"):
                for field in fields:
                    pipe.hincrby(key, field, 1)
            pipe.expire(f"ta14:stats:day:{day}", 60 * 60 * 24 * 120)
            pipe.execute()
            return

        with self._lock:
            for key in ("all", f"day:{day}"):
                bucket = self._memory.setdefault(key, {})
                for field in fields:
                    bucket[field] = bucket.get(field, 0) + 1

    def _read_bucket(self, key: str) -> dict[str, int]:
        if self._redis is not None:
            raw = self._redis.hgetall(key)
            return {str(k): int(v) for k, v in raw.items()}
        with self._lock:
            return dict(self._memory.get(key.replace("ta14:stats:", ""), {}))

    @staticmethod
    def _group(bucket: dict[str, int], prefix: str) -> dict[str, int]:
        return {
            key[len(prefix):]: value
            for key, value in bucket.items()
            if key.startswith(prefix)
        }

    def snapshot(self) -> dict:
        day = self._day()
        all_time = self._read_bucket("ta14:stats:all" if self._redis is not None else "all")
        today = self._read_bucket(
            f"ta14:stats:day:{day}" if self._redis is not None else f"day:{day}"
        )
        return {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "storage": "persistent" if self._redis is not None else "in_memory",
            "privacy": "Aggregate counts only. No request bodies, IP addresses, API keys, or identities are exposed.",
            "all_time": {
                "total": all_time.get("total", 0),
                "decisions": self._group(all_time, "decision:"),
                "endpoints": self._group(all_time, "endpoint:"),
                "plans": self._group(all_time, "plan:"),
            },
            "today": {
                "date_utc": day,
                "total": today.get("total", 0),
                "decisions": self._group(today, "decision:"),
                "endpoints": self._group(today, "endpoint:"),
                "plans": self._group(today, "plan:"),
            },
        }


USAGE_ANALYTICS = UsageAnalytics()


def _usage_plan(x_api_key: str | None) -> str:
    if not x_api_key:
        return "anonymous_sandbox"
    identity = API_KEY_REGISTRY.resolve(x_api_key)
    return identity.plan if identity else "invalid_key"


def _record_usage(endpoint: str, decision: Decision, x_api_key: str | None) -> None:
    try:
        USAGE_ANALYTICS.record(endpoint, decision.value, _usage_plan(x_api_key))
    except Exception:
        # Analytics must never interrupt the evaluation API.
        pass


app = FastAPI(
    title=APP_NAME,
    version=API_VERSION,
    description=(
        "Public sandbox/reference API for TA-14 admissible execution evaluation. "
        "This sandbox classifies submitted routes as ALLOW, HOLD, DENY, or ESCALATE. "
        "It is not legal advice, compliance certification, safety certification, "
        "production approval, or a warranty."
    ),
    docs_url="/docs",
    redoc_url=None,
    openapi_url="/openapi.json",
    contact={
        "name": "TA-14",
        "email": "ta14admissibleexecution@gmail.com",
    },
)

allow_origins = [origin.strip() for origin in CORS_ALLOW_ORIGINS.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def _chain_text() -> str:
    return " → ".join(TA14_CHAIN)


def _client_id(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _is_metered_route(request: Request) -> bool:
    return request.method == "POST" and request.url.path.startswith("/v1/")


def _resolve_identity(request: Request) -> ApiIdentity:
    raw_key = request.headers.get("x-api-key")
    if raw_key:
        identity = API_KEY_REGISTRY.resolve(raw_key)
        if identity is None:
            raise HTTPException(status_code=401, detail="Missing or invalid API key.")
        return identity
    return ApiIdentity(
        subject=f"ip:{_client_id(request)}",
        plan="anonymous_sandbox",
        monthly_limit=None,
        authenticated=False,
    )


def _require_api_key(x_api_key: str | None) -> None:
    # Public sandbox calls may omit a key. If a key is supplied, it must be valid.
    if x_api_key and API_KEY_REGISTRY.resolve(x_api_key) is None:
        raise HTTPException(status_code=401, detail="Missing or invalid API key.")


def _redact(value):
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            lower = key.lower()
            if any(secret in lower for secret in ["api_key", "password", "secret", "token", "authorization"]):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact(item)
        return redacted
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _audit(endpoint: str, request_id: str, payload: dict, decision: str | None = None) -> None:
    if not AUDIT_LOG_ENABLED:
        return

    record = {
        "timestamp_utc": make_meta(request_id).timestamp_utc,
        "request_id": request_id,
        "endpoint": endpoint,
        "decision": decision,
        "payload": _redact(payload),
    }

    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


@app.middleware("http")
async def sandbox_middleware(request: Request, call_next: Callable):
    request_id = request.headers.get("x-request-id") or str(uuid4())

    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={
                "meta": make_meta(request_id).model_dump(),
                "error": "Request body too large.",
                "max_body_bytes": MAX_BODY_BYTES,
            },
        )

    rate_result = None
    try:
        if RATE_LIMIT_ENABLED and _is_metered_route(request):
            identity = _resolve_identity(request)
            rate_result = RATE_LIMITER.check(identity)
            if not rate_result.allowed:
                response = JSONResponse(
                    status_code=429,
                    content={
                        "meta": make_meta(request_id).model_dump(),
                        "error": "The free TA-14 sandbox allowance has been used.",
                        "code": "SANDBOX_QUOTA_EXHAUSTED",
                        "plan": rate_result.plan,
                        "limit_scope": rate_result.scope,
                        "next_step": "Request API Readiness, Partner API, or institutional scope for continued use.",
                        "request_url": "https://ta14-architecture.netlify.app/request-evaluation",
                    },
                )
            else:
                response = await call_next(request)
        else:
            response = await call_next(request)
    except HTTPException as exc:
        response = JSONResponse(
            status_code=exc.status_code,
            content={
                "meta": make_meta(request_id).model_dump(),
                "error": exc.detail,
            },
        )

    if rate_result is not None:
        response.headers["X-RateLimit-Limit"] = str(rate_result.limit)
        response.headers["X-RateLimit-Remaining"] = str(rate_result.remaining)
        response.headers["X-RateLimit-Reset"] = str(rate_result.reset_epoch)
        response.headers["X-RateLimit-Scope"] = rate_result.scope
        response.headers["X-RateLimit-Plan"] = rate_result.plan

    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    request_id = request.headers.get("x-request-id") or str(uuid4())
    return JSONResponse(
        status_code=422,
        content={
            "meta": make_meta(request_id).model_dump(),
            "error": "Validation failed.",
            "details": exc.errors(),
        },
    )


def _shell(title: str, subtitle: str, body: str) -> str:
    chain = _chain_text()
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{title}</title>
  <meta name="description" content="{subtitle}" />
  <style>
    :root {{
      --black:#020617;
      --blue:#2563eb;
      --sky:#0ea5e9;
      --cyan:#06b6d4;
      --violet:#7c3aed;
      --emerald:#10b981;
      --amber:#f59e0b;
      --rose:#f43f5e;
      --white:#ffffff;
      --muted:#94a3b8;
      --glass:rgba(255,255,255,.075);
      --glass2:rgba(255,255,255,.12);
      --line:rgba(255,255,255,.15);
      --shadow:0 34px 120px rgba(0,0,0,.35);
      --max:1240px;
    }}

    * {{ box-sizing:border-box; }}
    html {{ scroll-behavior:smooth; }}
    body {{
      margin:0;
      min-height:100vh;
      font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
      color:#e5eefc;
      line-height:1.62;
      background:
        radial-gradient(circle at 8% 0%, rgba(37,99,235,.38), transparent 34rem),
        radial-gradient(circle at 92% 4%, rgba(124,58,237,.34), transparent 34rem),
        radial-gradient(circle at 50% 62%, rgba(6,182,212,.16), transparent 42rem),
        linear-gradient(135deg,#020617 0%,#0f172a 52%,#111827 100%);
      overflow-x:hidden;
    }}

    body:before {{
      content:"";
      position:fixed;
      inset:0;
      z-index:-2;
      background:
        linear-gradient(rgba(255,255,255,.045) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.045) 1px, transparent 1px);
      background-size:42px 42px;
      mask-image:linear-gradient(180deg,rgba(0,0,0,.86),rgba(0,0,0,.10));
      pointer-events:none;
    }}

    body:after {{
      content:"";
      position:fixed;
      inset:0;
      z-index:-1;
      background:
        radial-gradient(circle at 20% 20%, rgba(255,255,255,.08), transparent 26rem),
        radial-gradient(circle at 80% 18%, rgba(255,255,255,.05), transparent 22rem);
      pointer-events:none;
    }}

    a {{ color:inherit; }}
    code {{
      font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;
    }}

    .wrap {{ max-width:var(--max); margin:0 auto; padding:28px 22px 70px; }}

    .nav {{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:18px;
      padding:8px 0 28px;
    }}

    .brand {{
      display:flex;
      flex-direction:column;
      text-decoration:none;
      line-height:1.1;
    }}

    .brand strong {{
      color:#fff;
      font-size:1.05rem;
      font-weight:950;
      letter-spacing:-.04em;
    }}

    .brand span {{
      color:#93c5fd;
      font-size:.82rem;
      font-weight:900;
      margin-top:5px;
    }}

    .navlinks {{
      display:flex;
      flex-wrap:wrap;
      align-items:center;
      justify-content:flex-end;
      gap:10px;
    }}

    .navlinks a {{
      text-decoration:none;
      color:#dbeafe;
      border:1px solid rgba(255,255,255,.14);
      background:rgba(255,255,255,.065);
      border-radius:999px;
      padding:9px 13px;
      font-size:.88rem;
      font-weight:900;
    }}

    .navlinks a:hover {{ background:rgba(255,255,255,.14); color:#fff; }}

    .hero {{
      position:relative;
      overflow:hidden;
      border:1px solid rgba(255,255,255,.14);
      border-radius:46px;
      background:
        radial-gradient(circle at 15% 18%, rgba(37,99,235,.42), transparent 31rem),
        radial-gradient(circle at 85% 12%, rgba(124,58,237,.34), transparent 32rem),
        radial-gradient(circle at 52% 100%, rgba(6,182,212,.20), transparent 35rem),
        rgba(255,255,255,.055);
      box-shadow:var(--shadow);
      backdrop-filter:blur(18px);
      padding:clamp(30px,6vw,74px);
    }}

    .hero:after {{
      content:"";
      position:absolute;
      width:560px;
      height:560px;
      right:-260px;
      top:-250px;
      border-radius:999px;
      background:radial-gradient(circle,rgba(255,255,255,.18),transparent 64%);
      pointer-events:none;
    }}

    .hero-grid {{
      position:relative;
      z-index:1;
      display:grid;
      grid-template-columns:1.08fr .92fr;
      gap:38px;
      align-items:center;
    }}

    .eyebrow {{
      display:inline-flex;
      align-items:center;
      gap:9px;
      color:#bae6fd;
      background:rgba(14,165,233,.12);
      border:1px solid rgba(186,230,253,.22);
      border-radius:999px;
      padding:8px 12px;
      font-size:.76rem;
      font-weight:950;
      letter-spacing:.14em;
      text-transform:uppercase;
      margin:0 0 18px;
    }}

    .pulse {{
      display:inline-block;
      width:9px;
      height:9px;
      border-radius:50%;
      background:#22c55e;
      box-shadow:0 0 0 0 rgba(34,197,94,.65);
      animation:pulse 1.8s infinite;
    }}

    @keyframes pulse {{
      0% {{ box-shadow:0 0 0 0 rgba(34,197,94,.65); }}
      70% {{ box-shadow:0 0 0 12px rgba(34,197,94,0); }}
      100% {{ box-shadow:0 0 0 0 rgba(34,197,94,0); }}
    }}

    h1 {{
      margin:0 0 22px;
      color:#fff;
      font-size:clamp(3.1rem,7vw,7rem);
      line-height:.86;
      letter-spacing:-.085em;
      text-wrap:balance;
    }}

    h2 {{
      margin:0 0 14px;
      color:#fff;
      font-size:clamp(2rem,4.2vw,3.4rem);
      line-height:1;
      letter-spacing:-.065em;
      text-wrap:balance;
    }}

    h3 {{
      margin:0 0 10px;
      color:#fff;
      font-size:1.2rem;
      letter-spacing:-.03em;
    }}

    p {{ margin:0 0 18px; }}

    .lead {{
      max-width:880px;
      color:#dbeafe;
      font-size:clamp(1.08rem,2vw,1.32rem);
      line-height:1.75;
      margin:0 0 28px;
    }}

    .hero-actions,.cta-row {{
      display:flex;
      flex-wrap:wrap;
      gap:13px;
      margin-top:28px;
    }}

    .btn {{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      min-height:52px;
      padding:14px 20px;
      border-radius:999px;
      text-decoration:none;
      font-weight:950;
      transition:transform .16s ease, background .16s ease, border-color .16s ease;
    }}

    .btn:hover {{ transform:translateY(-2px); }}

    .btn.primary {{
      color:#020617;
      background:#fff;
      border:1px solid #fff;
      box-shadow:0 18px 45px rgba(255,255,255,.16);
    }}

    .btn.secondary {{
      color:#fff;
      background:rgba(255,255,255,.07);
      border:1px solid rgba(255,255,255,.22);
    }}

    .btn.blue {{
      color:#fff;
      background:linear-gradient(135deg,var(--blue),var(--violet));
      border:1px solid rgba(255,255,255,.12);
      box-shadow:0 18px 45px rgba(37,99,235,.22);
    }}

    .panel,.card,.codebox {{
      border:1px solid rgba(255,255,255,.14);
      background:rgba(255,255,255,.075);
      backdrop-filter:blur(14px);
      box-shadow:0 18px 55px rgba(0,0,0,.22);
    }}

    .panel {{
      border-radius:34px;
      padding:26px;
      box-shadow:inset 0 1px 0 rgba(255,255,255,.12), 0 18px 55px rgba(0,0,0,.22);
    }}

    .panel p {{ color:#cbd5e1; }}

    .chain {{
      margin-top:22px;
      color:#dff7ff;
      font-weight:950;
      line-height:1.8;
    }}

    .status-grid {{
      display:grid;
      grid-template-columns:repeat(2,minmax(0,1fr));
      gap:12px;
      margin-top:18px;
    }}

    .status {{
      border:1px solid rgba(255,255,255,.12);
      background:rgba(255,255,255,.07);
      border-radius:18px;
      padding:15px;
    }}

    .status strong {{
      display:block;
      color:#fff;
      font-size:1rem;
      margin-bottom:3px;
    }}

    .status span {{
      color:#cbd5e1;
      font-size:.9rem;
    }}

    section {{ margin-top:72px; }}

    .section-head {{
      display:grid;
      grid-template-columns:1fr auto;
      align-items:end;
      gap:24px;
      margin-bottom:24px;
    }}

    .section-head p {{
      max-width:850px;
      color:#cbd5e1;
      font-size:1.05rem;
    }}

    .pill {{
      border:1px solid rgba(255,255,255,.16);
      background:rgba(255,255,255,.08);
      border-radius:999px;
      padding:10px 14px;
      color:#dbeafe;
      font-weight:950;
      white-space:nowrap;
    }}

    .grid {{
      display:grid;
      gap:18px;
    }}

    .grid.two {{ grid-template-columns:repeat(2,minmax(0,1fr)); }}
    .grid.three {{ grid-template-columns:repeat(3,minmax(0,1fr)); }}
    .grid.four {{ grid-template-columns:repeat(4,minmax(0,1fr)); }}

    .card {{
      position:relative;
      overflow:hidden;
      border-radius:26px;
      padding:24px;
    }}

    .card:after {{
      content:"";
      position:absolute;
      width:150px;
      height:150px;
      right:-60px;
      bottom:-70px;
      border-radius:999px;
      background:radial-gradient(circle,rgba(56,189,248,.14),transparent 70%);
      pointer-events:none;
    }}

    .card p,.card li {{
      position:relative;
      z-index:1;
      color:#cbd5e1;
    }}

    .card ul {{
      position:relative;
      z-index:1;
      margin:0;
      padding-left:20px;
      color:#cbd5e1;
    }}

    .num {{
      display:inline-flex;
      width:42px;
      height:42px;
      align-items:center;
      justify-content:center;
      border-radius:14px;
      background:linear-gradient(135deg,var(--blue),var(--violet));
      color:#fff;
      font-weight:950;
      margin-bottom:16px;
    }}

    .decision {{
      font-size:1.9rem;
      font-weight:1000;
      letter-spacing:-.055em;
      margin-bottom:7px;
    }}

    .allow {{ color:#86efac; }}
    .hold {{ color:#fcd34d; }}
    .deny {{ color:#fda4af; }}
    .escalate {{ color:#c4b5fd; }}

    .codebox {{
      border-radius:28px;
      padding:22px;
      overflow:auto;
      background:rgba(2,6,23,.72);
    }}

    pre {{
      margin:0;
      color:#dbeafe;
      font-size:.92rem;
      line-height:1.7;
      white-space:pre-wrap;
    }}

    .endpoint-list {{
      display:grid;
      gap:11px;
    }}

    .endpoint {{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:14px;
      border:1px solid rgba(255,255,255,.12);
      background:rgba(255,255,255,.07);
      border-radius:18px;
      padding:13px 15px;
    }}

    .endpoint code {{
      color:#fff;
      font-weight:950;
    }}

    .method {{
      display:inline-flex;
      min-width:58px;
      justify-content:center;
      border-radius:999px;
      padding:5px 9px;
      font-size:.73rem;
      font-weight:950;
      background:rgba(37,99,235,.18);
      color:#bfdbfe;
      border:1px solid rgba(147,197,253,.22);
    }}

    .chain-map {{
      display:flex;
      flex-wrap:wrap;
      gap:10px;
      margin-top:22px;
    }}

    .node {{
      display:inline-flex;
      align-items:center;
      gap:9px;
      border:1px solid rgba(255,255,255,.16);
      background:rgba(255,255,255,.08);
      border-radius:999px;
      padding:9px 12px;
      font-weight:950;
      color:#fff;
      box-shadow:0 10px 30px rgba(0,0,0,.16);
      font-size:.92rem;
    }}

    .node small {{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      width:24px;
      height:24px;
      border-radius:999px;
      background:#020617;
      color:#bae6fd;
      font-size:.72rem;
      border:1px solid rgba(255,255,255,.18);
    }}

    .footer {{
      margin-top:70px;
      border-top:1px solid rgba(255,255,255,.12);
      padding-top:26px;
      color:#94a3b8;
      display:flex;
      flex-wrap:wrap;
      justify-content:space-between;
      gap:18px;
    }}

    .footer strong {{ color:#fff; }}
    .footer a {{ text-decoration:none; color:#dbeafe; font-weight:900; }}

    @media(max-width:980px) {{
      .hero-grid,.grid.two,.grid.three,.grid.four,.section-head {{ grid-template-columns:1fr; }}
      .pill {{ justify-self:start; }}
    }}

    @media(max-width:680px) {{
      .nav {{ align-items:flex-start; flex-direction:column; }}
      .navlinks {{ justify-content:flex-start; }}
      .hero {{ border-radius:30px; padding:24px; }}
      h1 {{ letter-spacing:-.065em; }}
      .status-grid {{ grid-template-columns:1fr; }}
      .endpoint {{ align-items:flex-start; flex-direction:column; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <nav class="nav">
      <a class="brand" href="/">
        <strong>TA-14 API Sandbox</strong>
        <span>No admissible chain. No admissible execution.</span>
      </a>
      <div class="navlinks">
        <a href="/">Home</a>
        <a href="/chain">24-Link Chain</a>
        <a href="/decision-matrix">Decision Matrix</a>
        <a href="/api-reference">API Reference</a>
        <a href="/stats">Usage Dashboard</a>
        <a href="/boundary">Boundary</a>
        <a href="/docs">Interactive Tester</a>
      </div>
    </nav>
    {body}
    <footer class="footer">
      <div>
        <strong>TA-14 Admissible Execution API Sandbox</strong><br />
        {chain}
      </div>
      <div>
        <a href="mailto:ta14admissibleexecution@gmail.com">ta14admissibleexecution@gmail.com</a>
      </div>
    </footer>
  </div>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def root():
    body = f"""
    <main>
      <section class="hero">
        <div class="hero-grid">
          <div>
            <p class="eyebrow"><span class="pulse"></span> Live Public Sandbox · API v{API_VERSION}</p>
            <h1>What does TA-14 actually stop?</h1>
            <p class="lead">
              TA-14 stops an action from becoming consequence when the submitted route
              lacks the evidence, continuity, authority, legitimacy, binding, or commit
              required to proceed.
            </p>
            <div class="hero-actions">
              <a class="btn primary" href="#payment-demo">See the $500,000 Payment Demo</a>
              <a class="btn secondary" href="/docs">Open Interactive Tester</a>
              <a class="btn blue" href="/chain">View the 24-Link Chain</a>
            </div>
          </div>

          <aside class="panel">
            <p class="eyebrow">The simple answer</p>
            <h2>TA-14 stops unsupported execution.</h2>
            <p>
              An AI system may have credentials, access, policy permission, and technical
              capability. That does not prove it has an admissible route to act.
            </p>
            <div class="status-grid">
              <div class="status"><strong>Missing authority</strong><span>HOLD or ESCALATE</span></div>
              <div class="status"><strong>Broken continuity</strong><span>HOLD</span></div>
              <div class="status"><strong>Unsafe condition</strong><span>DENY</span></div>
              <div class="status"><strong>Complete chain</strong><span>ALLOW</span></div>
            </div>
          </aside>
        </div>
      </section>

      <section id="payment-demo">
        <div class="section-head">
          <div>
            <p class="eyebrow">Demonstration 01</p>
            <h2>An AI agent attempts to release $500,000.</h2>
            <p>
              The payment record exists. The agent identity is known. The transaction is technically
              possible. But the approving authority is not valid for this amount.
            </p>
          </div>
          <span class="pill">Consequence: funds released</span>
        </div>

        <div class="grid two">
          <article class="card">
            <h3>What the ordinary workflow sees</h3>
            <div class="endpoint-list">
              <div class="endpoint"><span>Identity verified</span><strong class="allow">PASS</strong></div>
              <div class="endpoint"><span>Payment record present</span><strong class="allow">PASS</strong></div>
              <div class="endpoint"><span>API access available</span><strong class="allow">PASS</strong></div>
              <div class="endpoint"><span>Manager approval submitted</span><strong class="allow">PASS</strong></div>
            </div>
            <p style="margin-top:18px">
              A conventional authorization workflow may allow the payment because the agent can access
              the payment system and a manager approval exists.
            </p>
          </article>

          <article class="card">
            <h3>What TA-14 sees</h3>
            <div class="endpoint-list">
              <div class="endpoint"><span>Reality and record</span><strong class="allow">PRESENT</strong></div>
              <div class="endpoint"><span>Identity continuity</span><strong class="allow">PRESENT</strong></div>
              <div class="endpoint"><span>Authority scope</span><strong class="deny">FAILED</strong></div>
              <div class="endpoint"><span>Binding before commit</span><strong class="hold">INCOMPLETE</strong></div>
            </div>
            <div style="margin-top:22px">
              <div class="decision hold">HOLD</div>
              <p>
                Execution must not proceed because the approving authority is not admissible for a
                $500,000 consequence.
              </p>
            </div>
          </article>
        </div>

        <div class="cta-row">
          <a class="btn primary" href="/docs#/Evaluation/evaluate_execution_v1_evaluate_execution_post">
            Run This Route in the API
          </a>
          <a class="btn secondary" href="/decision-matrix">Why TA-14 Returned HOLD</a>
        </div>
      </section>

      <section>
        <div class="section-head">
          <div>
            <p class="eyebrow">Three preventable consequences</p>
            <h2>TA-14 evaluates the route before the action matters.</h2>
            <p>
              These examples show the problem in ordinary language. The sandbox remains available
              for developers who want the full chain status and machine-readable response.
            </p>
          </div>
          <span class="pill">ALLOW / HOLD / DENY / ESCALATE</span>
        </div>

        <div class="grid three">
          <article class="card">
            <span class="num">1</span>
            <h3>Unauthorized payment</h3>
            <div class="decision hold">HOLD</div>
            <p>
              The system can release the money, but the authority source does not cover the amount
              or consequence.
            </p>
          </article>

          <article class="card">
            <span class="num">2</span>
            <h3>Unsafe building action</h3>
            <div class="decision deny">DENY</div>
            <p>
              Automation attempts to begin an occupied event while environmental conditions remain
              unsafe or unresolved.
            </p>
          </article>

          <article class="card">
            <span class="num">3</span>
            <h3>High-impact institutional action</h3>
            <div class="decision escalate">ESCALATE</div>
            <p>
              Evidence may exist, but legal, human, safety, or institutional standing requires
              qualified review before consequence.
            </p>
          </article>
        </div>
      </section>

      <section>
        <div class="section-head">
          <div>
            <p class="eyebrow">The governing question</p>
            <h2>Can the system prove why it was allowed to act?</h2>
            <p>
              TA-14 does not ask only whether the AI can perform the action. It evaluates whether
              the submitted chain is sufficient for that action to become an admissible consequence.
            </p>
          </div>
        </div>

        <div class="panel">
          <div class="grid four">
            <div>
              <h3>Evidence</h3>
              <p>Is the supporting record preserved, governed, and sufficient?</p>
            </div>
            <div>
              <h3>Authority</h3>
              <p>Does the actor have legitimate authority for this exact action?</p>
            </div>
            <div>
              <h3>Binding and commit</h3>
              <p>Is the consequence properly attached before execution begins?</p>
            </div>
            <div>
              <h3>Outcome and memory</h3>
              <p>Can the result be reviewed, preserved, and carried into the future chain?</p>
            </div>
          </div>
        </div>

        <div class="cta-row">
          <a class="btn primary" href="/docs">Test a Route</a>
          <a class="btn secondary" href="/api-reference">Read the API Reference</a>
          <a class="btn secondary" href="/boundary">Read the Public Boundary</a>
        </div>
      </section>
    </main>
    """
    return _shell(
        "What Does TA-14 Stop? | TA-14 API Sandbox",
        "See how TA-14 holds, denies, or escalates unsupported execution before action becomes consequence.",
        body,
    )


@app.get("/chain", response_class=HTMLResponse, include_in_schema=False)
def visual_chain():
    nodes = "".join(
        f'<span class="node"><small>{idx:02d}</small>{name}</span>'
        for idx, name in enumerate(TA14_CHAIN, start=1)
    )
    body = f"""
    <main>
      <section class="hero">
        <div class="hero-grid">
          <div>
            <p class="eyebrow"><span class="pulse"></span> Visual 24-link chain map</p>
            <h1>The route must hold before execution matters.</h1>
            <p class="lead">
              TA-14 reviews the full dependency chain beneath consequence-bearing execution.
              The final action is not the only issue. Reality, evidence, truth, reliance,
              authority, binding, commit, execution, outcome, memory, and future chain all matter.
            </p>
            <div class="hero-actions">
              <a class="btn primary" href="/docs">Test the API</a>
              <a class="btn secondary" href="/decision-matrix">View Decision Matrix</a>
              <a class="btn blue" href="/api-reference">API Reference</a>
            </div>
          </div>
          <aside class="panel">
            <p class="eyebrow">Core doctrine</p>
            <h2>No admissible chain. No admissible execution.</h2>
            <p>
              A route can fail before the action. A system can be authorized to access resources
              and still not be admissible enough to become consequence.
            </p>
            <div class="status-grid">
              <div class="status"><strong>24 links</strong><span>Full public TA-14 chain</span></div>
              <div class="status"><strong>Before action</strong><span>Pre-consequence evaluation</span></div>
            </div>
          </aside>
        </div>
      </section>

      <section>
        <div class="section-head">
          <div>
            <p class="eyebrow">TA-14 full chain</p>
            <h2>From reality to future chain.</h2>
            <p>
              This is the human-readable chain map. Raw JSON remains available at
              <code>/v1/chain-spec</code> for integrations and developer tooling.
            </p>
          </div>
          <span class="pill">24 chain links</span>
        </div>
        <div class="card">
          <div class="chain-map">{nodes}</div>
        </div>
      </section>

      <section>
        <div class="grid three">
          <article class="card">
            <span class="num">1</span>
            <h3>Reality to truth</h3>
            <p>Reality, record, continuity, evidence governance, admissible evidence, and admissible truth establish the route’s factual spine.</p>
          </article>
          <article class="card">
            <span class="num">2</span>
            <h3>Reliance to commit</h3>
            <p>Reliance, authority, legitimacy, consequence formation, attachment, binding reality, binding, commit reality, and commit govern permission to matter.</p>
          </article>
          <article class="card">
            <span class="num">3</span>
            <h3>Execution to future chain</h3>
            <p>Execution reality, admissible non-occurrence, prevented consequence, execution, outcome reality, outcome, new reality, memory, and future chain preserve consequence.</p>
          </article>
        </div>
      </section>
    </main>
    """
    return _shell("TA-14 24-Link Chain Map", "Human-readable TA-14 24-link admissible execution chain map.", body)


@app.get("/decision-matrix", response_class=HTMLResponse, include_in_schema=False)
def decision_matrix_page():
    matrix = decision_matrix()
    body = f"""
    <main>
      <section class="hero">
        <div class="hero-grid">
          <div>
            <p class="eyebrow"><span class="pulse"></span> Decision matrix</p>
            <h1>ALLOW is not the default. It is earned.</h1>
            <p class="lead">
              The TA-14 sandbox classifies submitted routes as ALLOW, HOLD, DENY, or ESCALATE.
              This page is the human-readable version of the raw JSON decision matrix.
            </p>
            <div class="hero-actions">
              <a class="btn primary" href="/docs">Open Interactive Tester</a>
              <a class="btn secondary" href="/chain">Visual 24-Link Chain</a>
              <a class="btn blue" href="/api-reference">API Reference</a>
            </div>
          </div>
          <aside class="panel">
            <p class="eyebrow">Boundary rule</p>
            <h2>Capability is not clearance.</h2>
            <p>
              The question is not merely whether a system can act. The question is whether the route
              is admissible enough to become consequence.
            </p>
          </aside>
        </div>
      </section>

      <section>
        <div class="grid four">
          <article class="card">
            <div class="decision allow">ALLOW</div>
            <p>{matrix["ALLOW"]}</p>
          </article>
          <article class="card">
            <div class="decision hold">HOLD</div>
            <p>{matrix["HOLD"]}</p>
          </article>
          <article class="card">
            <div class="decision deny">DENY</div>
            <p>{matrix["DENY"]}</p>
          </article>
          <article class="card">
            <div class="decision escalate">ESCALATE</div>
            <p>{matrix["ESCALATE"]}</p>
          </article>
        </div>
      </section>

      <section>
        <div class="section-head">
          <div>
            <p class="eyebrow">Raw endpoint remains available</p>
            <h2>Developer JSON is still there.</h2>
            <p>
              Integrations can still read the raw matrix at <code>/v1/decision-matrix</code>.
              Human visitors should use this visual page.
            </p>
          </div>
          <a class="btn secondary" href="/v1/decision-matrix">Open Raw JSON</a>
        </div>
      </section>
    </main>
    """
    return _shell("TA-14 Decision Matrix", "Human-readable ALLOW / HOLD / DENY / ESCALATE matrix.", body)


@app.get("/api-reference", response_class=HTMLResponse, include_in_schema=False)
def api_reference_page():
    body = """
    <main>
      <section class="hero">
        <div class="hero-grid">
          <div>
            <p class="eyebrow"><span class="pulse"></span> Human-readable API reference</p>
            <h1>Readable for people. Structured for machines.</h1>
            <p class="lead">
              This page explains the public sandbox without forcing visitors into raw OpenAPI JSON.
              Developers can still use the interactive tester and the machine-readable OpenAPI contract.
            </p>
            <div class="hero-actions">
              <a class="btn primary" href="/docs">Open Interactive Tester</a>
              <a class="btn secondary" href="/chain">View 24-Link Chain</a>
              <a class="btn blue" href="/openapi.json">Raw OpenAPI JSON</a>
            </div>
          </div>
          <aside class="panel">
            <p class="eyebrow">Public API status</p>
            <h2>Live sandbox. Bounded use.</h2>
            <p>
              Public testing is available. Production use, signed evaluations, persistent audit storage,
              client-specific rules, billing, and partner integrations require written scope.
            </p>
          </aside>
        </div>
      </section>

      <section>
        <div class="section-head">
          <div>
            <p class="eyebrow">System endpoints</p>
            <h2>Check status and specification.</h2>
          </div>
          <span class="pill">GET endpoints</span>
        </div>
        <div class="grid two">
          <article class="card">
            <div class="endpoint-list">
              <div class="endpoint"><span><span class="method">GET</span> <code>/health</code></span><span>Returns health and sandbox mode.</span></div>
              <div class="endpoint"><span><span class="method">GET</span> <code>/version</code></span><span>Returns API version and service name.</span></div>
              <div class="endpoint"><span><span class="method">GET</span> <code>/v1/chain-spec</code></span><span>Raw 24-link TA-14 chain JSON.</span></div>
            </div>
          </article>
          <article class="card">
            <div class="endpoint-list">
              <div class="endpoint"><span><span class="method">GET</span> <code>/v1/decision-matrix</code></span><span>Raw decision matrix JSON.</span></div>
              <div class="endpoint"><span><span class="method">GET</span> <code>/v1/public-boundary</code></span><span>Official non-claim boundary JSON.</span></div>
              <div class="endpoint"><span><span class="method">GET</span> <code>/openapi.json</code></span><span>Machine-readable OpenAPI contract.</span></div>
            </div>
          </article>
        </div>
      </section>

      <section>
        <div class="section-head">
          <div>
            <p class="eyebrow">Evaluation endpoints</p>
            <h2>Submit routes for sandbox classification.</h2>
            <p>
              POST endpoints return response metadata, decision, chain status, failed links,
              warnings, reason, next step, public boundary, and the TA-14 chain.
            </p>
          </div>
          <span class="pill">POST endpoints</span>
        </div>
        <div class="grid three">
          <article class="card">
            <h3><code>/v1/evaluate-execution</code></h3>
            <p>Evaluates a proposed consequence-bearing execution route.</p>
          </article>
          <article class="card">
            <h3><code>/v1/evaluate-evidence</code></h3>
            <p>Evaluates whether an evidence claim is sufficiently governed, preserved, continuous, admissible, truthful, and reviewable.</p>
          </article>
          <article class="card">
            <h3><code>/v1/check-authority</code></h3>
            <p>Evaluates authority source, authority scope, and legitimacy for a proposed action.</p>
          </article>
          <article class="card">
            <h3><code>/v1/validate-continuity</code></h3>
            <p>Evaluates record preservation, sequence completeness, chain of custody, and explained gaps.</p>
          </article>
          <article class="card">
            <h3><code>/v1/reviewability-record</code></h3>
            <p>Determines whether a submitted entity has a recognizable reviewability surface.</p>
          </article>
          <article class="card">
            <h3><code>/v1/procurement-screen</code></h3>
            <p>Evaluates AI procurement or vendor routes before deployment reliance.</p>
          </article>
        </div>
      </section>
    </main>
    """
    return _shell("TA-14 API Reference", "Human-readable API reference for the TA-14 public sandbox.", body)


@app.get("/boundary", response_class=HTMLResponse, include_in_schema=False)
def boundary_page():
    body = """
    <main>
      <section class="hero">
        <div class="hero-grid">
          <div>
            <p class="eyebrow"><span class="pulse"></span> Public boundary</p>
            <h1>Live does not mean unbounded.</h1>
            <p class="lead">
              The TA-14 public API sandbox is live, but it is a bounded reference implementation.
              It demonstrates admissible execution evaluation without certifying, approving, or guaranteeing any submitted route.
            </p>
            <div class="hero-actions">
              <a class="btn primary" href="/v1/public-boundary">Raw Boundary JSON</a>
              <a class="btn secondary" href="/api-reference">API Reference</a>
              <a class="btn blue" href="/docs">Interactive Tester</a>
            </div>
          </div>
          <aside class="panel">
            <p class="eyebrow">Correct claim</p>
            <h2>Public sandbox. Not production approval.</h2>
            <p>
              TA-14 classifies submitted routes as ALLOW, HOLD, DENY, or ESCALATE based on submitted chain state.
            </p>
          </aside>
        </div>
      </section>

      <section>
        <div class="grid three">
          <article class="card">
            <span class="num">1</span>
            <h3>What it is</h3>
            <p>A public reference API for admissible execution evaluation and route classification.</p>
          </article>
          <article class="card">
            <span class="num">2</span>
            <h3>What it is not</h3>
            <p>Not legal advice, compliance certification, safety certification, production approval, or a warranty.</p>
          </article>
          <article class="card">
            <span class="num">3</span>
            <h3>Production boundary</h3>
            <p>Enterprise use requires written scope, client-specific rules, signed responses, persistent audit storage, and security review.</p>
          </article>
        </div>
      </section>
    </main>
    """
    return _shell("TA-14 Public API Boundary", "Human-readable boundary page for the TA-14 API Sandbox.", body)


@app.get("/v1/usage-stats", tags=["System"], summary="Public aggregate API usage statistics")
def usage_stats():
    return USAGE_ANALYTICS.snapshot()


@app.get("/stats", response_class=HTMLResponse, include_in_schema=False)
def stats_page():
    body = r"""
<section class="hero">
  <div class="hero-grid">
    <div>
      <p class="eyebrow"><span class="pulse"></span> Live public activity</p>
      <h1>TA-14 Usage Dashboard</h1>
      <p class="lead">Aggregate activity from the public admissible-execution sandbox. The dashboard shows how often the API is evaluated and how routes are classified without exposing request bodies, IP addresses, API keys, identities, or private evidence.</p>
      <div class="hero-actions">
        <a class="btn primary" href="/docs">Run an evaluation</a>
        <a class="btn secondary" href="/v1/usage-stats">View raw statistics</a>
      </div>
    </div>
    <div class="panel">
      <h3>Public transparency boundary</h3>
      <p>These numbers are informational activity counts. They are not certifications, production approvals, legal findings, or evidence that every submitted claim was independently authenticated.</p>
      <div class="chain">No request content is displayed. No individual user is identified.</div>
    </div>
  </div>
</section>

<section>
  <div class="section-head">
    <div>
      <h2>Sandbox activity</h2>
      <p>Automatically refreshed from the running API.</p>
    </div>
    <span class="pill" id="storage-pill">Loading…</span>
  </div>
  <div class="grid four">
    <div class="card"><div class="num">Σ</div><h3>All-time evaluations</h3><div class="decision" id="all-total">0</div><p>Recorded since analytics became active.</p></div>
    <div class="card"><div class="num">24h</div><h3>Today</h3><div class="decision" id="today-total">0</div><p>UTC-day evaluation count.</p></div>
    <div class="card"><div class="num">↗</div><h3>Most-used route</h3><div class="decision" id="top-endpoint" style="font-size:1.15rem">—</div><p id="top-endpoint-count">No activity yet.</p></div>
    <div class="card"><div class="num">◎</div><h3>Last refresh</h3><div class="decision" id="last-refresh" style="font-size:1.15rem">—</div><p>Dashboard refreshes every 30 seconds.</p></div>
  </div>
</section>

<section>
  <div class="section-head"><div><h2>Decision distribution</h2><p>How submitted routes have been classified by the public sandbox.</p></div></div>
  <div class="grid four">
    <div class="card"><div class="decision allow" id="allow-count">0</div><h3>ALLOW</h3><p>Submitted conditions satisfied the sandbox rules for the declared scope.</p></div>
    <div class="card"><div class="decision hold" id="hold-count">0</div><h3>HOLD</h3><p>Evidence, continuity, authority, or context remained incomplete.</p></div>
    <div class="card"><div class="decision deny" id="deny-count">0</div><h3>DENY</h3><p>The submitted route failed a condition that should prevent execution.</p></div>
    <div class="card"><div class="decision escalate" id="escalate-count">0</div><h3>ESCALATE</h3><p>The route required human, institutional, legal, safety, or partner review.</p></div>
  </div>
</section>

<section>
  <div class="section-head"><div><h2>Endpoint activity</h2><p>Aggregate use across the six public evaluation routes.</p></div></div>
  <div class="panel"><div class="endpoint-list" id="endpoint-list"><div class="endpoint"><code>No activity recorded yet.</code></div></div></div>
</section>

<script>
  const esc = (value) => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
  const number = value => new Intl.NumberFormat().format(value || 0);

  function topEntry(object) {
    const entries = Object.entries(object || {});
    return entries.sort((a,b) => b[1] - a[1])[0] || null;
  }

  async function refreshStats() {
    try {
      const response = await fetch('/v1/usage-stats', {cache:'no-store'});
      const data = await response.json();
      const all = data.all_time || {};
      const today = data.today || {};
      const decisions = all.decisions || {};
      document.getElementById('all-total').textContent = number(all.total);
      document.getElementById('today-total').textContent = number(today.total);
      document.getElementById('allow-count').textContent = number(decisions.ALLOW);
      document.getElementById('hold-count').textContent = number(decisions.HOLD);
      document.getElementById('deny-count').textContent = number(decisions.DENY);
      document.getElementById('escalate-count').textContent = number(decisions.ESCALATE);
      document.getElementById('storage-pill').textContent = data.storage === 'persistent' ? 'Persistent counters' : 'Live counters · reset on deploy';
      document.getElementById('last-refresh').textContent = new Date(data.generated_at_utc).toLocaleTimeString();

      const top = topEntry(all.endpoints);
      document.getElementById('top-endpoint').textContent = top ? top[0].replace('/v1/','') : '—';
      document.getElementById('top-endpoint-count').textContent = top ? `${number(top[1])} evaluations` : 'No activity yet.';

      const list = document.getElementById('endpoint-list');
      const endpoints = Object.entries(all.endpoints || {}).sort((a,b) => b[1]-a[1]);
      list.innerHTML = endpoints.length ? endpoints.map(([name,count]) => `<div class="endpoint"><code>${esc(name)}</code><span class="pill">${number(count)} evaluations</span></div>`).join('') : '<div class="endpoint"><code>No activity recorded yet.</code></div>';
    } catch (error) {
      document.getElementById('storage-pill').textContent = 'Dashboard temporarily unavailable';
    }
  }
  refreshStats();
  setInterval(refreshStats, 30000);
</script>
"""
    return HTMLResponse(_shell("TA-14 Usage Dashboard", "Public aggregate API sandbox activity", body))


@app.get("/health", tags=["System"], summary="Health check")
def health(x_request_id: str | None = Header(default=None)):
    return {
        "meta": make_meta(x_request_id).model_dump(),
        "status": "healthy",
        "mode": os.getenv("TA14_MODE", "sandbox"),
    }


@app.get("/version", tags=["System"], summary="API version")
def version(x_request_id: str | None = Header(default=None)):
    return {
        "meta": make_meta(x_request_id).model_dump(),
        "api_version": API_VERSION,
        "name": APP_NAME,
    }


@app.get(
    "/v1/chain-spec",
    response_model=ChainSpecResponse,
    tags=["Specification"],
    summary="Raw 24-link chain specification",
)
def chain_spec(x_request_id: str | None = Header(default=None)):
    return ChainSpecResponse(
        meta=make_meta(x_request_id),
        chain=TA14_CHAIN,
        decisions=[decision.value for decision in Decision],
        public_boundary=PUBLIC_BOUNDARY,
    )


@app.get(
    "/v1/decision-matrix",
    response_model=DecisionMatrixResponse,
    tags=["Specification"],
    summary="Raw decision matrix",
)
def get_decision_matrix(x_request_id: str | None = Header(default=None)):
    return DecisionMatrixResponse(
        meta=make_meta(x_request_id),
        matrix=decision_matrix(),
    )


@app.get(
    "/v1/public-boundary",
    response_model=PublicBoundaryResponse,
    tags=["Boundary"],
    summary="Public non-claim boundary",
)
def public_boundary(x_request_id: str | None = Header(default=None)):
    return PublicBoundaryResponse(
        meta=make_meta(x_request_id),
        public_claim=(
            "TA-14 has a public API sandbox for admissible execution evaluation. "
            "It classifies submitted execution routes as ALLOW, HOLD, DENY, or ESCALATE "
            "based on submitted chain state."
        ),
        non_claims=[
            "Not legal advice.",
            "Not compliance certification.",
            "Not safety certification.",
            "Not production approval.",
            "Not a warranty that execution is safe, lawful, or complete.",
            "Not enterprise production enforcement unless separately agreed in writing.",
        ],
        use_boundary=PUBLIC_BOUNDARY,
    )


@app.post(
    "/v1/evaluate-execution",
    response_model=EvaluationResponse,
    tags=["Evaluation"],
    summary="Evaluate an execution route",
)
def evaluate_execution(
    payload: EvaluateExecutionRequest,
    x_api_key: str | None = Header(default=None),
    x_request_id: str | None = Header(default=None),
):
    _require_api_key(x_api_key)
    decision, failed, warnings, reason, next_step = evaluate_execution_payload(payload)
    _audit("/v1/evaluate-execution", x_request_id or str(uuid4()), payload.model_dump(), decision.value)
    _record_usage("/v1/evaluate-execution", decision, x_api_key)
    return EvaluationResponse(
        meta=make_meta(x_request_id),
        decision=decision,
        chain_status=chain_status(decision),
        failed_links=failed,
        warnings=warnings,
        reason=reason,
        next_step=next_step,
        boundary=PUBLIC_BOUNDARY,
        ta14_chain=TA14_CHAIN,
    )


@app.post(
    "/v1/evaluate-evidence",
    response_model=EvaluationResponse,
    tags=["Evaluation"],
    summary="Evaluate an evidence claim",
)
def evaluate_evidence(
    payload: EvaluateEvidenceRequest,
    x_api_key: str | None = Header(default=None),
    x_request_id: str | None = Header(default=None),
):
    _require_api_key(x_api_key)
    decision, failed, warnings, reason, next_step = evaluate_evidence_payload(payload)
    _audit("/v1/evaluate-evidence", x_request_id or str(uuid4()), payload.model_dump(), decision.value)
    _record_usage("/v1/evaluate-evidence", decision, x_api_key)
    return EvaluationResponse(
        meta=make_meta(x_request_id),
        decision=decision,
        chain_status=chain_status(decision),
        failed_links=failed,
        warnings=warnings,
        reason=reason,
        next_step=next_step,
        boundary=PUBLIC_BOUNDARY,
        ta14_chain=TA14_CHAIN,
    )


@app.post(
    "/v1/check-authority",
    response_model=EvaluationResponse,
    tags=["Evaluation"],
    summary="Check authority and legitimacy",
)
def check_authority(
    payload: AuthorityCheckRequest,
    x_api_key: str | None = Header(default=None),
    x_request_id: str | None = Header(default=None),
):
    _require_api_key(x_api_key)

    failed = []
    warnings = []

    if not payload.authority_source:
        failed.append("Authority")
    if not payload.authority_in_scope:
        failed.append("Authority Scope")
    if not payload.legitimacy_clear:
        failed.append("Legitimacy")

    if failed and payload.risk_class in [RouteRiskClass.HIGH, RouteRiskClass.CRITICAL]:
        decision = Decision.ESCALATE
        reason = "High-risk authority route requires escalation before execution."
        next_step = "Escalate for authority and legitimacy review."
    elif failed:
        decision = Decision.HOLD
        reason = "Authority is incomplete for the declared action."
        next_step = "Hold execution until authority source, scope, and legitimacy are clear."
    else:
        decision = Decision.ALLOW
        reason = "Authority source, scope, and legitimacy are sufficient for the sandbox request."
        next_step = "Proceed only within declared authority scope."

    _audit("/v1/check-authority", x_request_id or str(uuid4()), payload.model_dump(), decision.value)
    _record_usage("/v1/check-authority", decision, x_api_key)
    return EvaluationResponse(
        meta=make_meta(x_request_id),
        decision=decision,
        chain_status=chain_status(decision),
        failed_links=failed,
        warnings=warnings,
        reason=reason,
        next_step=next_step,
        boundary=PUBLIC_BOUNDARY,
        ta14_chain=TA14_CHAIN,
    )


@app.post(
    "/v1/validate-continuity",
    response_model=EvaluationResponse,
    tags=["Evaluation"],
    summary="Validate record continuity",
)
def validate_continuity(
    payload: ContinuityCheckRequest,
    x_api_key: str | None = Header(default=None),
    x_request_id: str | None = Header(default=None),
):
    _require_api_key(x_api_key)

    failed = []
    warnings = []

    if not payload.record_preserved:
        failed.append("Record")
    if not payload.sequence_complete:
        failed.append("Continuity")
    if not payload.chain_of_custody_clear:
        failed.append("Evidence Governance")
    if payload.gaps_identified and not payload.gaps_explained:
        failed.append("Admissible Truth")

    if failed:
        decision = Decision.HOLD
        reason = "Continuity is incomplete for the submitted route."
        next_step = "Hold execution until sequence, preservation, custody, and gap explanations are complete."
    else:
        decision = Decision.ALLOW
        reason = "Continuity is sufficient for the submitted sandbox route."
        next_step = "Preserve the continuity record and proceed only within declared scope."

    _audit("/v1/validate-continuity", x_request_id or str(uuid4()), payload.model_dump(), decision.value)
    _record_usage("/v1/validate-continuity", decision, x_api_key)
    return EvaluationResponse(
        meta=make_meta(x_request_id),
        decision=decision,
        chain_status=chain_status(decision),
        failed_links=failed,
        warnings=warnings,
        reason=reason,
        next_step=next_step,
        boundary=PUBLIC_BOUNDARY,
        ta14_chain=TA14_CHAIN,
    )


@app.post(
    "/v1/reviewability-record",
    response_model=EvaluationResponse,
    tags=["Evaluation"],
    summary="Create a reviewability record",
)
def reviewability_record(
    payload: ReviewabilityRecordRequest,
    x_api_key: str | None = Header(default=None),
    x_request_id: str | None = Header(default=None),
):
    _require_api_key(x_api_key)

    failed = []
    warnings = []

    if not payload.materials_available:
        failed.append("Record")
        warnings.append("No materials list was submitted.")

    if len(payload.claim_or_function) < 20:
        warnings.append("Claim or function may be too short for meaningful review.")

    if len(payload.consequence_question) < 20:
        warnings.append("Consequence question may be too short for meaningful review.")

    decision = Decision.HOLD if failed else Decision.ALLOW
    reason = (
        "The entity has a recognizable review surface, but materials are incomplete."
        if failed
        else "The entity has a recognizable reviewability surface for sandbox intake."
    )
    next_step = (
        "Submit materials before reviewability can be completed."
        if failed
        else "Proceed to Reviewability Check, Governance Desk Review, or scoped review."
    )

    _audit("/v1/reviewability-record", x_request_id or str(uuid4()), payload.model_dump(), decision.value)
    _record_usage("/v1/reviewability-record", decision, x_api_key)
    return EvaluationResponse(
        meta=make_meta(x_request_id),
        decision=decision,
        chain_status=chain_status(decision),
        failed_links=failed,
        warnings=warnings,
        reason=reason,
        next_step=next_step,
        boundary=PUBLIC_BOUNDARY,
        ta14_chain=TA14_CHAIN,
    )


@app.post(
    "/v1/procurement-screen",
    response_model=EvaluationResponse,
    tags=["Procurement"],
    summary="Screen an AI procurement route",
)
def procurement_screen(
    payload: ProcurementScreenRequest,
    x_api_key: str | None = Header(default=None),
    x_request_id: str | None = Header(default=None),
):
    _require_api_key(x_api_key)
    decision, failed, warnings, reason, next_step = evaluate_execution_payload(payload)

    if payload.risk_class in [RouteRiskClass.HIGH, RouteRiskClass.CRITICAL] and decision == Decision.ALLOW:
        decision = Decision.ESCALATE
        warnings.append("High-risk procurement route should receive buyer-side review before deployment.")
        reason = "Procurement route is high risk and should be escalated before consequence-bearing deployment."
        next_step = "Escalate to AI Procurement Admissibility Review."

    _audit("/v1/procurement-screen", x_request_id or str(uuid4()), payload.model_dump(), decision.value)
    _record_usage("/v1/procurement-screen", decision, x_api_key)
    return EvaluationResponse(
        meta=make_meta(x_request_id),
        decision=decision,
        chain_status=chain_status(decision),
        failed_links=failed,
        warnings=warnings,
        reason=reason,
        next_step=next_step,
        boundary=PUBLIC_BOUNDARY,
        ta14_chain=TA14_CHAIN,
    )
