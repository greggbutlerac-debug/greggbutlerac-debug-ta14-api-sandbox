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
from fastapi.responses import JSONResponse

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


@app.get("/")
def root(x_request_id: str | None = Header(default=None)):
    return {
        "meta": make_meta(x_request_id).model_dump(),
        "name": APP_NAME,
        "status": "ok",
        "docs": "/docs",
        "boundary": PUBLIC_BOUNDARY,
    }


@app.get("/health")
def health(x_request_id: str | None = Header(default=None)):
    return {
        "meta": make_meta(x_request_id).model_dump(),
        "status": "healthy",
        "mode": os.getenv("TA14_MODE", "sandbox"),
    }


@app.get("/version")
def version(x_request_id: str | None = Header(default=None)):
    return {
        "meta": make_meta(x_request_id).model_dump(),
        "api_version": API_VERSION,
        "name": APP_NAME,
    }


@app.get("/v1/chain-spec", response_model=ChainSpecResponse)
def chain_spec(x_request_id: str | None = Header(default=None)):
    return ChainSpecResponse(
        meta=make_meta(x_request_id),
        chain=TA14_CHAIN,
        decisions=[decision.value for decision in Decision],
        public_boundary=PUBLIC_BOUNDARY,
    )


@app.get("/v1/decision-matrix", response_model=DecisionMatrixResponse)
def get_decision_matrix(x_request_id: str | None = Header(default=None)):
    return DecisionMatrixResponse(
        meta=make_meta(x_request_id),
        matrix=decision_matrix(),
    )


@app.get("/v1/public-boundary", response_model=PublicBoundaryResponse)
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


@app.post("/v1/evaluate-execution", response_model=EvaluationResponse)
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


@app.post("/v1/evaluate-evidence", response_model=EvaluationResponse)
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


@app.post("/v1/check-authority", response_model=EvaluationResponse)
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


@app.post("/v1/validate-continuity", response_model=EvaluationResponse)
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


@app.post("/v1/reviewability-record", response_model=EvaluationResponse)
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


@app.post("/v1/procurement-screen", response_model=EvaluationResponse)
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
