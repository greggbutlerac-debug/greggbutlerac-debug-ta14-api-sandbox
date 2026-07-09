from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from uuid import uuid4

from .models import Decision, ResponseMeta, RouteRiskClass

API_VERSION = "0.3.0"

TA14_CHAIN = [
    "reality",
    "record",
    "continuity",
    "evidence",
    "reliance",
    "authority",
    "legitimacy",
    "binding",
    "commit",
    "execution",
    "outcome",
    "memory",
]

PUBLIC_BOUNDARY = (
    "TA-14 API Sandbox is a reference evaluation layer. It is not legal advice, "
    "compliance certification, safety certification, production approval, or a warranty."
)


def make_meta(request_id: str | None = None) -> ResponseMeta:
    return ResponseMeta(
        request_id=request_id or str(uuid4()),
        api_version=API_VERSION,
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        mode="sandbox",
    )


def decision_matrix() -> Dict[str, str]:
    return {
        "ALLOW": "The submitted route satisfies the required sandbox chain conditions for its scope.",
        "HOLD": "The submitted route may be valid, but evidence, context, continuity, authority, or reviewability is incomplete.",
        "DENY": "The submitted route is outside scope, lacks legitimate authority, or fails core admissibility conditions.",
        "ESCALATE": "The submitted route requires human, institutional, legal, safety, or partner review before consequence.",
    }


def _risk_value(risk_class: RouteRiskClass) -> int:
    return {
        RouteRiskClass.LOW: 1,
        RouteRiskClass.MODERATE: 2,
        RouteRiskClass.HIGH: 3,
        RouteRiskClass.CRITICAL: 4,
    }[risk_class]


def evaluate_execution_payload(payload: Any) -> Tuple[Decision, List[str], List[str], str, str]:
    failed: List[str] = []
    warnings: List[str] = []

    checks = {
        "reality": payload.reality_valid,
        "record": payload.record_preserved,
        "continuity": payload.continuity_intact,
        "evidence": payload.evidence_sufficient,
        "reliance": payload.reliance_justified,
        "authority_scope": bool(payload.authority_source) and payload.authority_in_scope,
        "legitimacy": payload.legitimacy_clear,
        "binding": payload.binding_clear,
        "commit": payload.commit_point_known,
        "outcome": payload.outcome_reviewable,
    }

    for name, passed in checks.items():
        if not passed:
            failed.append(name)

    if not payload.consequence_defined:
        failed.append("consequence_defined")

    if not payload.execution_reversible and payload.commit_point_known is False:
        warnings.append("Execution is described as irreversible, but the commit point is not known.")

    risk = _risk_value(payload.risk_class)

    if risk >= 3 and not payload.human_review_available:
        warnings.append("High-risk route has no available human review path.")

    if risk == 4 and ("authority_scope" in failed or "consequence_defined" in failed):
        decision = Decision.ESCALATE
        reason = "Critical route lacks authority scope or consequence definition."
        next_step = "Escalate for institutional review before execution."
        return decision, failed, warnings, reason, next_step

    if "authority_scope" in failed and risk >= 3:
        decision = Decision.ESCALATE
        reason = "High-risk route lacks sufficient authority source or authority scope."
        next_step = "Escalate for authority review and scope confirmation."
        return decision, failed, warnings, reason, next_step

    core_failures = {"reality", "record", "continuity", "evidence"}
    if core_failures.intersection(failed):
        decision = Decision.HOLD
        reason = "The route has upstream admissibility gaps before execution."
        next_step = "Hold execution and complete the missing reality, record, continuity, or evidence requirements."
        return decision, failed, warnings, reason, next_step

    if "legitimacy" in failed or "binding" in failed or "commit" in failed:
        decision = Decision.HOLD
        reason = "The route has permission, binding, or commit gaps before consequence."
        next_step = "Hold execution until legitimacy, binding, and commit conditions are clarified."
        return decision, failed, warnings, reason, next_step

    if "outcome" in failed:
        decision = Decision.HOLD
        reason = "The route may act, but outcome reviewability is incomplete."
        next_step = "Define outcome reviewability before allowing execution."
        return decision, failed, warnings, reason, next_step

    decision = Decision.ALLOW
    reason = "The submitted sandbox chain conditions are satisfied for the declared scope."
    next_step = "Proceed only within the submitted scope and preserve the reviewability record."
    return decision, failed, warnings, reason, next_step


def evaluate_evidence_payload(payload: Any) -> Tuple[Decision, List[str], List[str], str, str]:
    failed: List[str] = []
    warnings: List[str] = []

    checks = {
        "source_known": payload.source_known,
        "record_preserved": payload.record_preserved,
        "continuity_intact": payload.continuity_intact,
        "tamper_resistant": payload.tamper_resistant,
        "independently_reviewable": payload.independently_reviewable,
        "linked_to_consequence": payload.linked_to_consequence,
    }

    for name, passed in checks.items():
        if not passed:
            failed.append(name)

    if "source_known" in failed or "record_preserved" in failed or "continuity_intact" in failed:
        return (
            Decision.HOLD,
            failed,
            warnings,
            "The evidence claim has upstream record or continuity gaps.",
            "Hold reliance until source, record preservation, and continuity are established.",
        )

    if "independently_reviewable" in failed:
        warnings.append("Evidence exists but is not independently reviewable.")
        return (
            Decision.HOLD,
            failed,
            warnings,
            "The evidence is not sufficiently reviewable for reliance.",
            "Create an independently reviewable evidence record.",
        )

    if "linked_to_consequence" in failed:
        return (
            Decision.HOLD,
            failed,
            warnings,
            "The evidence is not clearly linked to a consequence-bearing decision.",
            "Define the consequence relationship before relying on the evidence.",
        )

    return (
        Decision.ALLOW,
        failed,
        warnings,
        "The evidence claim satisfies the sandbox evidence conditions.",
        "Preserve the evidence record and proceed only within the declared scope.",
    )


def chain_status(decision: Decision) -> str:
    if decision == Decision.ALLOW:
        return "admissible_for_declared_sandbox_scope"
    if decision == Decision.ESCALATE:
        return "requires_escalation_before_execution"
    if decision == Decision.DENY:
        return "not_admissible_for_execution"
    return "hold_before_execution"
