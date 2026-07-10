from __future__ import annotations

import json
import os
import time
from collections import defaultdict, deque
from typing import Callable
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

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
)

APP_NAME = "TA-14 Admissible Execution API Sandbox"

MAX_BODY_BYTES = int(os.getenv("TA14_MAX_BODY_BYTES", "200000"))
API_KEY = os.getenv("TA14_API_KEY")
RATE_LIMIT_ENABLED = os.getenv("TA14_RATE_LIMIT_ENABLED", "false").lower() == "true"
RATE_LIMIT_MAX = int(os.getenv("TA14_RATE_LIMIT_MAX", "60"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("TA14_RATE_LIMIT_WINDOW_SECONDS", "60"))
AUDIT_LOG_ENABLED = os.getenv("TA14_AUDIT_LOG", "false").lower() == "true"
AUDIT_LOG_PATH = os.getenv("TA14_AUDIT_LOG_PATH", "./ta14_audit_log.jsonl")
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "*")

_request_windows: dict[str, deque[float]] = defaultdict(deque)


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
    redoc_url="/redoc",
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


def _client_id(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _check_rate_limit(request: Request) -> None:
    if not RATE_LIMIT_ENABLED:
        return

    now = time.time()
    client = _client_id(request)
    window = _request_windows[client]

    while window and now - window[0] > RATE_LIMIT_WINDOW_SECONDS:
        window.popleft()

    if len(window) >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Sandbox rate limit exceeded.")

    window.append(now)


def _require_api_key(x_api_key: str | None) -> None:
    if API_KEY and x_api_key != API_KEY:
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

    try:
        _check_rate_limit(request)
        response: Response = await call_next(request)
    except HTTPException as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "meta": make_meta(request_id).model_dump(),
                "error": exc.detail,
            },
        )

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


@app.get("/", response_class=HTMLResponse, tags=["Public Sandbox"])
def root():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>TA-14 API Sandbox | Admissible Execution</title>
  <meta name="description" content="TA-14 Admissible Execution API Sandbox — a live public reference API for evaluating consequence-bearing AI, automation, evidence, authority, and runtime execution routes before action becomes consequence." />
  <style>
    :root{
      --black:#020617;
      --ink:#0f172a;
      --muted:#64748b;
      --line:rgba(226,232,240,.24);
      --white:#ffffff;
      --blue:#2563eb;
      --cyan:#06b6d4;
      --violet:#7c3aed;
      --emerald:#10b981;
      --amber:#f59e0b;
      --rose:#f43f5e;
      --glass:rgba(255,255,255,.08);
      --glass-2:rgba(255,255,255,.12);
      --shadow:0 34px 120px rgba(0,0,0,.35);
      --max:1220px;
    }

    *{box-sizing:border-box}
    html{scroll-behavior:smooth}
    body{
      margin:0;
      font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
      color:#e5eefc;
      background:
        radial-gradient(circle at 12% 6%, rgba(37,99,235,.34), transparent 30rem),
        radial-gradient(circle at 88% 0%, rgba(124,58,237,.32), transparent 32rem),
        radial-gradient(circle at 50% 70%, rgba(6,182,212,.16), transparent 36rem),
        linear-gradient(135deg,#020617 0%,#0f172a 52%,#111827 100%);
      min-height:100vh;
      line-height:1.6;
      overflow-x:hidden;
    }

    body:before{
      content:"";
      position:fixed;
      inset:0;
      background:
        linear-gradient(rgba(255,255,255,.045) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.045) 1px, transparent 1px);
      background-size:42px 42px;
      mask-image:linear-gradient(180deg,rgba(0,0,0,.78),rgba(0,0,0,.12));
      pointer-events:none;
      z-index:-1;
    }

    a{color:inherit}
    .wrap{max-width:var(--max);margin:0 auto;padding:28px 22px 70px}

    .nav{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:18px;
      padding:8px 0 28px;
    }

    .brand{
      display:flex;
      flex-direction:column;
      text-decoration:none;
      line-height:1.1;
    }
    .brand strong{
      color:#fff;
      font-size:1.05rem;
      font-weight:950;
      letter-spacing:-.04em;
    }
    .brand span{
      color:#93c5fd;
      font-size:.82rem;
      font-weight:900;
      margin-top:5px;
    }

    .navlinks{
      display:flex;
      flex-wrap:wrap;
      align-items:center;
      justify-content:flex-end;
      gap:10px;
    }
    .navlinks a{
      text-decoration:none;
      color:#cbd5e1;
      border:1px solid rgba(255,255,255,.12);
      background:rgba(255,255,255,.06);
      border-radius:999px;
      padding:9px 13px;
      font-size:.88rem;
      font-weight:900;
    }
    .navlinks a:hover{background:rgba(255,255,255,.13);color:#fff}

    .hero{
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
    }

    .hero:after{
      content:"";
      position:absolute;
      width:520px;
      height:520px;
      right:-240px;
      top:-220px;
      border-radius:999px;
      background:radial-gradient(circle,rgba(255,255,255,.18),transparent 64%);
      pointer-events:none;
    }

    .hero-grid{
      position:relative;
      z-index:1;
      display:grid;
      grid-template-columns:1.08fr .92fr;
      gap:38px;
      align-items:center;
    }

    .eyebrow{
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
    }

    .pulse{
      display:inline-block;
      width:9px;
      height:9px;
      border-radius:50%;
      background:#22c55e;
      box-shadow:0 0 0 0 rgba(34,197,94,.65);
      animation:pulse 1.8s infinite;
    }

    @keyframes pulse{
      0%{box-shadow:0 0 0 0 rgba(34,197,94,.65)}
      70%{box-shadow:0 0 0 12px rgba(34,197,94,0)}
      100%{box-shadow:0 0 0 0 rgba(34,197,94,0)}
    }

    h1{
      margin:0 0 22px;
      color:#fff;
      font-size:clamp(3.2rem,7.5vw,7.15rem);
      line-height:.86;
      letter-spacing:-.085em;
      text-wrap:balance;
    }

    .lead{
      max-width:850px;
      color:#dbeafe;
      font-size:clamp(1.08rem,2vw,1.32rem);
      line-height:1.75;
      margin:0 0 28px;
    }

    .hero-actions,.cta-row{
      display:flex;
      flex-wrap:wrap;
      gap:13px;
      margin-top:28px;
    }

    .btn{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      min-height:52px;
      padding:14px 20px;
      border-radius:999px;
      text-decoration:none;
      font-weight:950;
      transition:transform .16s ease, background .16s ease, border-color .16s ease;
    }
    .btn:hover{transform:translateY(-2px)}
    .btn.primary{
      color:#020617;
      background:#fff;
      border:1px solid #fff;
      box-shadow:0 18px 45px rgba(255,255,255,.16);
    }
    .btn.secondary{
      color:#fff;
      background:rgba(255,255,255,.07);
      border:1px solid rgba(255,255,255,.22);
    }
    .btn.blue{
      color:#fff;
      background:linear-gradient(135deg,var(--blue),var(--violet));
      border:1px solid rgba(255,255,255,.12);
      box-shadow:0 18px 45px rgba(37,99,235,.22);
    }

    .panel{
      border:1px solid rgba(255,255,255,.14);
      border-radius:34px;
      background:rgba(255,255,255,.08);
      backdrop-filter:blur(14px);
      padding:26px;
      box-shadow:inset 0 1px 0 rgba(255,255,255,.12);
    }
    .panel h2{
      color:#fff;
      margin:0 0 12px;
      font-size:clamp(1.85rem,3.2vw,2.65rem);
      line-height:1;
      letter-spacing:-.055em;
    }
    .panel p{color:#cbd5e1;margin:0 0 18px}

    .status-grid{
      display:grid;
      grid-template-columns:repeat(2,minmax(0,1fr));
      gap:12px;
      margin-top:18px;
    }
    .status{
      border:1px solid rgba(255,255,255,.12);
      background:rgba(255,255,255,.07);
      border-radius:18px;
      padding:15px;
    }
    .status strong{
      display:block;
      color:#fff;
      font-size:1rem;
      margin-bottom:3px;
    }
    .status span{
      color:#cbd5e1;
      font-size:.9rem;
    }

    .chain{
      margin-top:22px;
      color:#dff7ff;
      font-weight:950;
      line-height:1.8;
    }

    section{margin-top:72px}
    .section-head{
      display:grid;
      grid-template-columns:1fr auto;
      align-items:end;
      gap:24px;
      margin-bottom:24px;
    }
    .section-head h2{
      margin:0 0 12px;
      color:#fff;
      font-size:clamp(2rem,4.4vw,3.5rem);
      line-height:1;
      letter-spacing:-.065em;
    }
    .section-head p{
      margin:0;
      max-width:830px;
      color:#cbd5e1;
      font-size:1.05rem;
    }
    .pill{
      border:1px solid rgba(255,255,255,.16);
      background:rgba(255,255,255,.08);
      border-radius:999px;
      padding:10px 14px;
      color:#dbeafe;
      font-weight:950;
      white-space:nowrap;
    }

    .grid{
      display:grid;
      gap:18px;
    }
    .grid.three{grid-template-columns:repeat(3,minmax(0,1fr))}
    .grid.four{grid-template-columns:repeat(4,minmax(0,1fr))}
    .grid.two{grid-template-columns:repeat(2,minmax(0,1fr))}

    .card{
      position:relative;
      overflow:hidden;
      border:1px solid rgba(255,255,255,.12);
      border-radius:26px;
      padding:24px;
      background:rgba(255,255,255,.075);
      box-shadow:0 16px 50px rgba(0,0,0,.18);
      backdrop-filter:blur(12px);
    }
    .card:after{
      content:"";
      position:absolute;
      width:150px;
      height:150px;
      right:-60px;
      bottom:-70px;
      border-radius:999px;
      background:radial-gradient(circle,rgba(56,189,248,.14),transparent 70%);
      pointer-events:none;
    }
    .card h3{
      position:relative;
      z-index:1;
      color:#fff;
      margin:0 0 10px;
      font-size:1.18rem;
      letter-spacing:-.03em;
    }
    .card p,.card li{
      position:relative;
      z-index:1;
      color:#cbd5e1;
      margin:0;
    }
    .card ul{padding-left:20px;margin:0;color:#cbd5e1}
    .num{
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
    }

    .decision{
      font-size:1.8rem;
      font-weight:1000;
      letter-spacing:-.05em;
      margin-bottom:6px;
    }
    .allow{color:#86efac}
    .hold{color:#fcd34d}
    .deny{color:#fda4af}
    .escalate{color:#c4b5fd}

    .codebox{
      border:1px solid rgba(255,255,255,.14);
      background:rgba(2,6,23,.7);
      border-radius:28px;
      padding:22px;
      overflow:auto;
      box-shadow:0 18px 55px rgba(0,0,0,.24);
    }
    pre{
      margin:0;
      color:#dbeafe;
      font-size:.92rem;
      line-height:1.7;
      white-space:pre-wrap;
    }
    code{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace}

    .endpoint-list{
      display:grid;
      gap:11px;
    }
    .endpoint{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:14px;
      border:1px solid rgba(255,255,255,.12);
      background:rgba(255,255,255,.07);
      border-radius:18px;
      padding:13px 15px;
    }
    .endpoint code{
      color:#fff;
      font-weight:950;
    }
    .method{
      display:inline-flex;
      min-width:54px;
      justify-content:center;
      border-radius:999px;
      padding:5px 9px;
      font-size:.73rem;
      font-weight:950;
      background:rgba(37,99,235,.18);
      color:#bfdbfe;
      border:1px solid rgba(147,197,253,.22);
    }

    .footer{
      margin-top:70px;
      border-top:1px solid rgba(255,255,255,.12);
      padding-top:26px;
      color:#94a3b8;
      display:flex;
      flex-wrap:wrap;
      justify-content:space-between;
      gap:18px;
    }
    .footer strong{color:#fff}
    .footer a{text-decoration:none;color:#dbeafe;font-weight:900}

    @media(max-width:980px){
      .hero-grid,.grid.two,.grid.three,.grid.four,.section-head{grid-template-columns:1fr}
      .pill{justify-self:start}
    }

    @media(max-width:680px){
      .nav{align-items:flex-start;flex-direction:column}
      .navlinks{justify-content:flex-start}
      .hero{border-radius:30px;padding:24px}
      h1{letter-spacing:-.065em}
      .status-grid{grid-template-columns:1fr}
      .endpoint{align-items:flex-start;flex-direction:column}
    }
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
        <a href="/docs">Interactive Docs</a>
        <a href="/redoc">ReDoc</a>
        <a href="/openapi.json">OpenAPI</a>
        <a href="/v1/public-boundary">Boundary</a>
      </div>
    </nav>

    <main>
      <section class="hero">
        <div class="hero-grid">
          <div>
            <p class="eyebrow"><span class="pulse"></span> Live Public Sandbox · API v0.3.0</p>
            <h1>Govern the route before action becomes consequence.</h1>
            <p class="lead">
              TA-14 Admissible Execution API Sandbox is a live public reference API for evaluating
              consequence-bearing AI, automation, evidence, authority, procurement, and runtime routes
              before they are allowed to matter.
            </p>
            <div class="hero-actions">
              <a class="btn primary" href="/docs">Open Interactive API Docs</a>
              <a class="btn secondary" href="/v1/chain-spec">View Chain Spec</a>
              <a class="btn secondary" href="/v1/decision-matrix">Decision Matrix</a>
              <a class="btn blue" href="/openapi.json">OpenAPI JSON</a>
            </div>
          </div>

          <aside class="panel">
            <p class="eyebrow">The TA-14 answer</p>
            <h2>Authorization is not admissibility.</h2>
            <p>
              An agent can have identity, credentials, approved APIs, logs, and policy permission —
              and still lack the admissible chain required to become consequence.
            </p>
            <div class="chain">
              Reality → Record → Continuity → Evidence → Reliance → Authority → Legitimacy → Binding → Commit → Execution → Outcome → Memory
            </div>
            <div class="status-grid">
              <div class="status"><strong>Live</strong><span>Public sandbox endpoint</span></div>
              <div class="status"><strong>OpenAPI 3.1</strong><span>Machine-readable contract</span></div>
              <div class="status"><strong>4 decisions</strong><span>ALLOW / HOLD / DENY / ESCALATE</span></div>
              <div class="status"><strong>Bounded</strong><span>Reference use, not certification</span></div>
            </div>
          </aside>
        </div>
      </section>

      <section>
        <div class="section-head">
          <div>
            <p class="eyebrow">Decision boundary</p>
            <h2>Capability is not clearance.</h2>
            <p>
              The API classifies submitted routes through a deterministic sandbox engine.
              It does not approve systems. It shows whether the submitted chain is sufficient
              to allow, hold, deny, or escalate the route inside the declared sandbox scope.
            </p>
          </div>
          <span class="pill">Sandbox/reference only</span>
        </div>

        <div class="grid four">
          <article class="card">
            <div class="decision allow">ALLOW</div>
            <p>The submitted route satisfies the sandbox chain conditions for its declared scope.</p>
          </article>
          <article class="card">
            <div class="decision hold">HOLD</div>
            <p>The route may be valid, but evidence, continuity, authority, or reviewability is incomplete.</p>
          </article>
          <article class="card">
            <div class="decision deny">DENY</div>
            <p>The route is outside scope, lacks legitimate authority, or fails core admissibility conditions.</p>
          </article>
          <article class="card">
            <div class="decision escalate">ESCALATE</div>
            <p>The route requires human, institutional, legal, safety, or partner review before consequence.</p>
          </article>
        </div>
      </section>

      <section>
        <div class="section-head">
          <div>
            <p class="eyebrow">Public endpoints</p>
            <h2>Built for builders, buyers, and reviewers.</h2>
            <p>
              Use the interactive docs to test the API. Use OpenAPI to inspect the contract.
              Use the boundary endpoint to preserve the public non-claim language.
            </p>
          </div>
          <span class="pill">Try it live</span>
        </div>

        <div class="grid two">
          <div class="card">
            <h3>Core endpoints</h3>
            <div class="endpoint-list">
              <div class="endpoint"><span><span class="method">GET</span> <code>/health</code></span><span>Service health</span></div>
              <div class="endpoint"><span><span class="method">GET</span> <code>/version</code></span><span>API version</span></div>
              <div class="endpoint"><span><span class="method">GET</span> <code>/v1/chain-spec</code></span><span>TA-14 chain</span></div>
              <div class="endpoint"><span><span class="method">GET</span> <code>/v1/decision-matrix</code></span><span>Decision logic</span></div>
              <div class="endpoint"><span><span class="method">GET</span> <code>/v1/public-boundary</code></span><span>Public boundary</span></div>
            </div>
          </div>

          <div class="card">
            <h3>Evaluation endpoints</h3>
            <div class="endpoint-list">
              <div class="endpoint"><span><span class="method">POST</span> <code>/v1/evaluate-execution</code></span><span>Execution route</span></div>
              <div class="endpoint"><span><span class="method">POST</span> <code>/v1/evaluate-evidence</code></span><span>Evidence claim</span></div>
              <div class="endpoint"><span><span class="method">POST</span> <code>/v1/check-authority</code></span><span>Authority scope</span></div>
              <div class="endpoint"><span><span class="method">POST</span> <code>/v1/validate-continuity</code></span><span>Record continuity</span></div>
              <div class="endpoint"><span><span class="method">POST</span> <code>/v1/procurement-screen</code></span><span>Vendor screen</span></div>
            </div>
          </div>
        </div>
      </section>

      <section>
        <div class="section-head">
          <div>
            <p class="eyebrow">Example request</p>
            <h2>Submit a route. Get a gate decision.</h2>
            <p>
              This example shows a high-risk AI procurement route with a continuity gap.
              The sandbox should hold or escalate before consequence-bearing approval.
            </p>
          </div>
          <span class="pill">Copy / paste into /docs</span>
        </div>

        <div class="codebox">
<pre><code>{
  "route_name": "AI procurement agent vendor approval route",
  "proposed_action": "Approve a vendor for pilot deployment",
  "risk_class": "high",
  "reality_valid": true,
  "record_preserved": true,
  "continuity_intact": false,
  "evidence_sufficient": true,
  "reliance_justified": false,
  "authority_source": "Department manager approval policy",
  "authority_in_scope": true,
  "legitimacy_clear": true,
  "consequence_defined": "The vendor may enter an enterprise pilot and influence procurement reliance.",
  "binding_clear": true,
  "commit_point_known": true,
  "execution_reversible": false,
  "outcome_reviewable": true,
  "human_review_available": true,
  "metadata": {
    "example": true,
    "domain": "AI procurement"
  }
}</code></pre>
        </div>

        <div class="cta-row">
          <a class="btn primary" href="/docs#/default/evaluate_execution_v1_evaluate_execution_post">Test Evaluate Execution</a>
          <a class="btn secondary" href="/v1/public-boundary">Read Public Boundary</a>
        </div>
      </section>

      <section>
        <div class="section-head">
          <div>
            <p class="eyebrow">Public boundary</p>
            <h2>Live does not mean unbounded.</h2>
            <p>
              This public sandbox demonstrates TA-14 admissible execution evaluation. It does not certify,
              approve, legally validate, production-clear, or guarantee any submitted route.
            </p>
          </div>
          <span class="pill">Protected claim language</span>
        </div>

        <div class="grid three">
          <article class="card">
            <span class="num">1</span>
            <h3>What it is</h3>
            <p>A public reference API for classifying submitted routes as ALLOW, HOLD, DENY, or ESCALATE based on submitted chain state.</p>
          </article>
          <article class="card">
            <span class="num">2</span>
            <h3>What it is not</h3>
            <p>Not legal advice, compliance certification, safety certification, production approval, or a warranty.</p>
          </article>
          <article class="card">
            <span class="num">3</span>
            <h3>What comes next</h3>
            <p>Enterprise use requires written scope, client-specific rules, signed responses, security review, persistent logs, and partner integration.</p>
          </article>
        </div>
      </section>

      <footer class="footer">
        <div>
          <strong>TA-14 Admissible Execution API Sandbox</strong><br />
          Reality → Record → Continuity → Evidence → Reliance → Authority → Legitimacy → Binding → Commit → Execution → Outcome → Memory
        </div>
        <div>
          <a href="mailto:ta14admissibleexecution@gmail.com">ta14admissibleexecution@gmail.com</a>
        </div>
      </footer>
    </main>
  </div>
</body>
</html>
    """


@app.get("/health", tags=["System"])
def health(x_request_id: str | None = Header(default=None)):
    return {
        "meta": make_meta(x_request_id).model_dump(),
        "status": "healthy",
        "mode": os.getenv("TA14_MODE", "sandbox"),
    }


@app.get("/version", tags=["System"])
def version(x_request_id: str | None = Header(default=None)):
    return {
        "meta": make_meta(x_request_id).model_dump(),
        "api_version": API_VERSION,
        "name": APP_NAME,
    }


@app.get("/v1/chain-spec", response_model=ChainSpecResponse, tags=["Specification"])
def chain_spec(x_request_id: str | None = Header(default=None)):
    return ChainSpecResponse(
        meta=make_meta(x_request_id),
        chain=TA14_CHAIN,
        decisions=[decision.value for decision in Decision],
        public_boundary=PUBLIC_BOUNDARY,
    )


@app.get("/v1/decision-matrix", response_model=DecisionMatrixResponse, tags=["Specification"])
def get_decision_matrix(x_request_id: str | None = Header(default=None)):
    return DecisionMatrixResponse(
        meta=make_meta(x_request_id),
        matrix=decision_matrix(),
    )


@app.get("/v1/public-boundary", response_model=PublicBoundaryResponse, tags=["Boundary"])
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


@app.post("/v1/evaluate-execution", response_model=EvaluationResponse, tags=["Evaluation"])
def evaluate_execution(
    payload: EvaluateExecutionRequest,
    x_api_key: str | None = Header(default=None),
    x_request_id: str | None = Header(default=None),
):
    _require_api_key(x_api_key)
    decision, failed, warnings, reason, next_step = evaluate_execution_payload(payload)
    _audit("/v1/evaluate-execution", x_request_id or str(uuid4()), payload.model_dump(), decision.value)
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


@app.post("/v1/evaluate-evidence", response_model=EvaluationResponse, tags=["Evaluation"])
def evaluate_evidence(
    payload: EvaluateEvidenceRequest,
    x_api_key: str | None = Header(default=None),
    x_request_id: str | None = Header(default=None),
):
    _require_api_key(x_api_key)
    decision, failed, warnings, reason, next_step = evaluate_evidence_payload(payload)
    _audit("/v1/evaluate-evidence", x_request_id or str(uuid4()), payload.model_dump(), decision.value)
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


@app.post("/v1/check-authority", response_model=EvaluationResponse, tags=["Evaluation"])
def check_authority(
    payload: AuthorityCheckRequest,
    x_api_key: str | None = Header(default=None),
    x_request_id: str | None = Header(default=None),
):
    _require_api_key(x_api_key)

    failed = []
    warnings = []

    if not payload.authority_source:
        failed.append("authority_source")
    if not payload.authority_in_scope:
        failed.append("authority_scope")
    if not payload.legitimacy_clear:
        failed.append("legitimacy")

    if failed and payload.risk_class in ["high", "critical"]:
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


@app.post("/v1/validate-continuity", response_model=EvaluationResponse, tags=["Evaluation"])
def validate_continuity(
    payload: ContinuityCheckRequest,
    x_api_key: str | None = Header(default=None),
    x_request_id: str | None = Header(default=None),
):
    _require_api_key(x_api_key)

    failed = []
    warnings = []

    if not payload.record_preserved:
        failed.append("record_preserved")
    if not payload.sequence_complete:
        failed.append("sequence_complete")
    if not payload.chain_of_custody_clear:
        failed.append("chain_of_custody_clear")
    if payload.gaps_identified and not payload.gaps_explained:
        failed.append("gaps_explained")

    if failed:
        decision = Decision.HOLD
        reason = "Continuity is incomplete for the submitted route."
        next_step = "Hold execution until sequence, preservation, custody, and gap explanations are complete."
    else:
        decision = Decision.ALLOW
        reason = "Continuity is sufficient for the submitted sandbox route."
        next_step = "Preserve the continuity record and proceed only within declared scope."

    _audit("/v1/validate-continuity", x_request_id or str(uuid4()), payload.model_dump(), decision.value)
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


@app.post("/v1/reviewability-record", response_model=EvaluationResponse, tags=["Evaluation"])
def reviewability_record(
    payload: ReviewabilityRecordRequest,
    x_api_key: str | None = Header(default=None),
    x_request_id: str | None = Header(default=None),
):
    _require_api_key(x_api_key)

    failed = []
    warnings = []

    if not payload.materials_available:
        failed.append("materials_available")
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


@app.post("/v1/procurement-screen", response_model=EvaluationResponse, tags=["Procurement"])
def procurement_screen(
    payload: ProcurementScreenRequest,
    x_api_key: str | None = Header(default=None),
    x_request_id: str | None = Header(default=None),
):
    _require_api_key(x_api_key)
    decision, failed, warnings, reason, next_step = evaluate_execution_payload(payload)

    if payload.risk_class in ["high", "critical"] and decision == Decision.ALLOW:
        decision = Decision.ESCALATE
        warnings.append("High-risk procurement route should receive buyer-side review before deployment.")
        reason = "Procurement route is high risk and should be escalated before consequence-bearing deployment."
        next_step = "Escalate to AI Procurement Admissibility Review."

    _audit("/v1/procurement-screen", x_request_id or str(uuid4()), payload.model_dump(), decision.value)
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
