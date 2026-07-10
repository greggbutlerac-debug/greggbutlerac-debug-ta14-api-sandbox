from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .models import Decision, ResponseMeta, RouteRiskClass

API_VERSION = "0.3.0"

TA14_CHAIN = [
    "Reality",
    "Record",
    "Continuity",
    "Evidence Governance",
    "Admissible Evidence",
    "Admissible Truth",
    "Reliance",
    "Authority",
    "Legitimacy",
    "Consequence Formation",
    "Attachment / Assent",
    "Binding Reality",
    "Binding",
    "Commit Reality",
    "Commit",
    "Execution Reality",
    "Admissible Non-Occurrence",
    "Prevented Consequence",
    "Execution",
    "Outcome Reality",
    "Outcome",
    "New Reality",
    "Memory",
    "Future Chain",
]

PUBLIC_BOUNDARY = (
    "The TA-14 API Sandbox is a public reference and demonstration layer for "
    "admissible execution evaluation. It classifies submitted routes as ALLOW, "
    "HOLD, DENY, or ESCALATE based on submitted chain state. It is not legal "
    "advice, compliance certification, safety certification, production approval, "
    "or a warranty. Production use, signed evaluations, persistent audit storage, "
    "client-specific rules, billing, security review, private deployment, and "
    "partner integrations require written scope."
)


def make_meta(request_id: str | None = None) -> ResponseMeta:
    return ResponseMeta(
        request_id=request_id or str(uuid4()),
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        api_version=API_VERSION,
    )


def _risk_value(value: Any) -> str:
    if isinstance(value, RouteRiskClass):
        return value.value
    return str(value).lower()


def decision_matrix() -> dict[str, str]:
    return {
        "ALLOW": (
            "The submitted route satisfies the sandbox chain conditions for its "
            "declared scope. ALLOW does not mean legal approval, safety approval, "
            "production certification, or enterprise authorization."
        ),
        "HOLD": (
            "The submitted route may be valid, but one or more chain links are "
            "incomplete, unclear, weak, unpreserved, or not yet reviewable. "
            "Execution should not proceed until the gap is resolved."
        ),
        "DENY": (
            "The submitted route fails a core admissibility condition, is outside "
            "declared scope, lacks legitimate authority, or lacks enough chain "
            "integrity to support consequence-bearing action."
        ),
        "ESCALATE": (
            "The submitted route involves risk, ambiguity, irreversibility, "
            "institutional consequence, safety exposure, legal sensitivity, or "
            "governance uncertainty requiring human, institutional, legal, safety, "
            "or partner review before consequence."
        ),
    }


def chain_status(decision: Decision) -> str:
    if decision == Decision.ALLOW:
        return "Chain sufficient for sandbox allowance within declared scope."
    if decision == Decision.HOLD:
        return "Chain incomplete. Execution should be held before consequence."
    if decision == Decision.DENY:
        return "Chain failed. Execution should not proceed."
    if decision == Decision.ESCALATE:
        return "Chain requires escalation before consequence-bearing execution."
    return "Unknown chain status."


def evaluate_execution_payload(payload) -> tuple[Decision, list[str], list[str], str, str]:
    failed: list[str] = []
    warnings: list[str] = []

    risk = _risk_value(payload.risk_class)

    if not payload.reality_valid:
        failed.append("Reality")
    if not payload.record_preserved:
        failed.append("Record")
    if not payload.continuity_intact:
        failed.append("Continuity")
    if not payload.evidence_sufficient:
        failed.append("Admissible Evidence")
    if not payload.reliance_justified:
        failed.append("Reliance")
    if not payload.authority_source:
        failed.append("Authority")
    if not payload.authority_in_scope:
        failed.append("Authority Scope")
    if not payload.legitimacy_clear:
        failed.append("Legitimacy")
    if not payload.consequence_defined:
        failed.append("Consequence Formation")
    if not payload.binding_clear:
        failed.append("Binding")
    if not payload.commit_point_known:
        failed.append("Commit")
    if not payload.outcome_reviewable:
        failed.append("Outcome / Memory")

    if not payload.execution_reversible:
        warnings.append(
            "Execution is not clearly reversible. Consequence-bearing routes may require escalation."
        )

    if not payload.human_review_available and risk in {"high", "critical"}:
        warnings.append(
            "Human review is not available for a high-risk or critical route."
        )

    if failed:
        if "Authority" in failed or "Authority Scope" in failed or "Legitimacy" in failed:
            decision = Decision.DENY
            reason = (
                "The route fails authority, scope, or legitimacy conditions. "
                "A consequence-bearing action should not proceed."
            )
            next_step = (
                "Deny execution until authority source, authority scope, and legitimacy are established."
            )
            return decision, failed, warnings, reason, next_step

        if risk in {"high", "critical"}:
            decision = Decision.ESCALATE
            reason = (
                "The route contains chain gaps inside a high-risk or critical execution context."
            )
            next_step = (
                "Escalate for TA-14 review, institutional review, legal/safety review, or partner review before execution."
            )
            return decision, failed, warnings, reason, next_step

        decision = Decision.HOLD
        reason = (
            "The route contains incomplete chain links. Execution should be held before consequence."
        )
        next_step = (
            "Resolve the failed chain links and resubmit the route for sandbox evaluation."
        )
        return decision, failed, warnings, reason, next_step

    if risk in {"critical"}:
        decision = Decision.ESCALATE
        reason = (
            "The chain appears complete, but critical-risk execution should receive escalation before consequence."
        )
        next_step = (
            "Escalate to scoped review before using the route for real-world consequence."
        )
        return decision, failed, warnings, reason, next_step

    if risk in {"high"} and not payload.human_review_available:
        decision = Decision.ESCALATE
        reason = (
            "The route appears complete, but high-risk execution without human review should be escalated."
        )
        next_step = (
            "Add human review or obtain scoped governance review before consequence."
        )
        return decision, failed, warnings, reason, next_step

    decision = Decision.ALLOW
    reason = (
        "The submitted route satisfies the sandbox chain conditions for its declared scope."
    )
    next_step = (
        "Proceed only within declared scope and preserve the resulting execution, outcome, memory, and future-chain record."
    )
    return decision, failed, warnings, reason, next_step


def evaluate_evidence_payload(payload) -> tuple[Decision, list[str], list[str], str, str]:
    failed: list[str] = []
    warnings: list[str] = []

    if not payload.source_known:
        failed.append("Evidence Governance")
    if not payload.record_preserved:
        failed.append("Record")
    if not payload.continuity_intact:
        failed.append("Continuity")
    if not payload.tamper_resistant:
        failed.append("Admissible Evidence")
    if not payload.independently_reviewable:
        failed.append("Admissible Truth")
    if not payload.linked_to_consequence:
        failed.append("Consequence Formation")

    if len(payload.evidence_claim) < 20:
        warnings.append("Evidence claim may be too short for meaningful review.")

    if failed:
        decision = Decision.HOLD
        reason = (
            "The submitted evidence claim is not yet admissible enough for reliance."
        )
        next_step = (
            "Resolve evidence governance, preservation, continuity, reviewability, and consequence-link gaps before reliance."
        )
        return decision, failed, warnings, reason, next_step

    decision = Decision.ALLOW
    reason = (
        "The submitted evidence claim satisfies the sandbox evidence conditions for declared reliance."
    )
    next_step = (
        "Preserve the evidence record and bind it only to the declared consequence context."
    )
    return decision, failed, warnings, reason, next_step
