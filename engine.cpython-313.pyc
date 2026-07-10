from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Decision(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


class RouteRiskClass(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ResponseMeta(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "request_id": "8f5a6c44-4e5f-4a52-9fd3-2df0f6c1b6d9",
                "timestamp_utc": "2026-07-09T20:14:00.000000+00:00",
                "api_version": "0.3.0",
            }
        }
    )

    request_id: str = Field(
        ...,
        description="Unique request identifier returned with each sandbox response.",
    )
    timestamp_utc: str = Field(
        ...,
        description="UTC timestamp generated when the sandbox response is created.",
    )
    api_version: str = Field(
        ...,
        description="Version of the TA-14 public API sandbox.",
    )


class EvaluateExecutionRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "route_name": "AI procurement agent vendor approval route",
                "proposed_action": "Approve a vendor for pilot deployment",
                "risk_class": "high",
                "reality_valid": True,
                "record_preserved": True,
                "continuity_intact": False,
                "evidence_sufficient": True,
                "reliance_justified": False,
                "authority_source": "Department manager approval policy",
                "authority_in_scope": True,
                "legitimacy_clear": True,
                "consequence_defined": "The vendor may enter an enterprise pilot and influence procurement reliance.",
                "binding_clear": True,
                "commit_point_known": True,
                "execution_reversible": False,
                "outcome_reviewable": True,
                "human_review_available": True,
                "metadata": {
                    "example": True,
                    "domain": "AI procurement",
                    "submitted_by": "public sandbox tester",
                },
            }
        }
    )

    route_name: str = Field(
        ...,
        min_length=3,
        max_length=180,
        description="Human-readable name for the route being evaluated.",
        examples=["AI procurement agent vendor approval route"],
    )
    proposed_action: str = Field(
        ...,
        min_length=5,
        max_length=500,
        description="The specific consequence-bearing action the system, agent, workflow, or organization wants to take.",
        examples=["Approve a vendor for pilot deployment"],
    )
    risk_class: RouteRiskClass = Field(
        ...,
        description="Declared risk class of the route. High and critical routes may require escalation even when the submitted chain appears complete.",
        examples=["high"],
    )
    reality_valid: bool = Field(
        ...,
        description="Whether the submitted route is grounded in a valid present-state reality rather than assumption, hallucination, stale context, or incomplete condition.",
        examples=[True],
    )
    record_preserved: bool = Field(
        ...,
        description="Whether the relevant record exists, is preserved, and can be reviewed later.",
        examples=[True],
    )
    continuity_intact: bool = Field(
        ...,
        description="Whether the route preserves sequence, custody, context, and continuity from reality through proposed execution.",
        examples=[False],
    )
    evidence_sufficient: bool = Field(
        ...,
        description="Whether the submitted evidence is sufficient for the declared action and risk context.",
        examples=[True],
    )
    reliance_justified: bool = Field(
        ...,
        description="Whether the system, agent, buyer, reviewer, or institution is justified in relying on the submitted evidence and route state.",
        examples=[False],
    )
    authority_source: str = Field(
        ...,
        max_length=300,
        description="The policy, role, contract, law, instruction, governance rule, or institutional source claimed as authority for the proposed action.",
        examples=["Department manager approval policy"],
    )
    authority_in_scope: bool = Field(
        ...,
        description="Whether the claimed authority actually covers this action, route, domain, risk class, and consequence.",
        examples=[True],
    )
    legitimacy_clear: bool = Field(
        ...,
        description="Whether the route has clear legitimacy beyond mere access, technical permission, or credentialed authorization.",
        examples=[True],
    )
    consequence_defined: str = Field(
        ...,
        min_length=10,
        max_length=800,
        description="The foreseeable consequence if the route is allowed to proceed.",
        examples=["The vendor may enter an enterprise pilot and influence procurement reliance."],
    )
    binding_clear: bool = Field(
        ...,
        description="Whether the route has a clear binding point where submitted reality, evidence, authority, and action become attached.",
        examples=[True],
    )
    commit_point_known: bool = Field(
        ...,
        description="Whether the route has a known commit point where the action becomes consequence-bearing or difficult to reverse.",
        examples=[True],
    )
    execution_reversible: bool = Field(
        ...,
        description="Whether the execution can be reversed without material consequence, reliance, harm, lock-in, or institutional exposure.",
        examples=[False],
    )
    outcome_reviewable: bool = Field(
        ...,
        description="Whether the outcome can be reviewed after execution with enough preserved record, continuity, evidence, and memory.",
        examples=[True],
    )
    human_review_available: bool = Field(
        ...,
        description="Whether qualified human review is available before execution or escalation.",
        examples=[True],
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional contextual metadata. Do not submit secrets, credentials, personal health information, financial account numbers, or confidential client data to the public sandbox.",
        examples=[
            {
                "example": True,
                "domain": "AI procurement",
                "submitted_by": "public sandbox tester",
            }
        ],
    )


class EvaluateEvidenceRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "evidence_name": "Vendor model audit packet",
                "evidence_claim": "The vendor claims the agent route is fully auditable and safe for procurement approval.",
                "source_known": True,
                "record_preserved": True,
                "continuity_intact": False,
                "tamper_resistant": True,
                "independently_reviewable": False,
                "linked_to_consequence": True,
                "metadata": {
                    "example": True,
                    "domain": "evidence review",
                },
            }
        }
    )

    evidence_name: str = Field(
        ...,
        min_length=3,
        max_length=180,
        description="Human-readable name for the evidence packet, artifact, claim, record, or submission.",
        examples=["Vendor model audit packet"],
    )
    evidence_claim: str = Field(
        ...,
        min_length=5,
        max_length=1000,
        description="The claim being made from, about, or through the submitted evidence.",
        examples=["The vendor claims the agent route is fully auditable and safe for procurement approval."],
    )
    source_known: bool = Field(
        ...,
        description="Whether the source of the evidence is known and attributable.",
        examples=[True],
    )
    record_preserved: bool = Field(
        ...,
        description="Whether the evidence record is preserved and reviewable.",
        examples=[True],
    )
    continuity_intact: bool = Field(
        ...,
        description="Whether custody, sequence, and context continuity are intact.",
        examples=[False],
    )
    tamper_resistant: bool = Field(
        ...,
        description="Whether the evidence is protected against alteration, substitution, or unverifiable reconstruction.",
        examples=[True],
    )
    independently_reviewable: bool = Field(
        ...,
        description="Whether a qualified reviewer can independently examine the evidence and its relationship to the claim.",
        examples=[False],
    )
    linked_to_consequence: bool = Field(
        ...,
        description="Whether the evidence is clearly linked to the consequence-bearing action or reliance decision.",
        examples=[True],
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional evidence metadata. Do not submit secrets, credentials, personal health information, financial account numbers, or confidential client data to the public sandbox.",
        examples=[
            {
                "example": True,
                "domain": "evidence review",
            }
        ],
    )


class AuthorityCheckRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action_name": "Approve autonomous refund above threshold",
                "risk_class": "high",
                "authority_source": "Customer operations refund policy",
                "authority_in_scope": False,
                "legitimacy_clear": True,
                "metadata": {
                    "example": True,
                    "domain": "customer operations",
                },
            }
        }
    )

    action_name: str = Field(
        ...,
        min_length=3,
        max_length=180,
        description="Name of the proposed action requiring authority review.",
        examples=["Approve autonomous refund above threshold"],
    )
    risk_class: RouteRiskClass = Field(
        ...,
        description="Declared risk class of the authority route.",
        examples=["high"],
    )
    authority_source: str = Field(
        ...,
        max_length=300,
        description="Claimed source of authority for the action.",
        examples=["Customer operations refund policy"],
    )
    authority_in_scope: bool = Field(
        ...,
        description="Whether the claimed authority covers the proposed action, domain, risk level, and consequence.",
        examples=[False],
    )
    legitimacy_clear: bool = Field(
        ...,
        description="Whether legitimacy is clear beyond access, credentials, or technical permission.",
        examples=[True],
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional authority metadata. Do not submit secrets or confidential client data to the public sandbox.",
        examples=[
            {
                "example": True,
                "domain": "customer operations",
            }
        ],
    )


class ContinuityCheckRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "record_name": "Agent approval event log",
                "record_preserved": True,
                "sequence_complete": False,
                "chain_of_custody_clear": True,
                "gaps_identified": True,
                "gaps_explained": False,
                "metadata": {
                    "example": True,
                    "domain": "runtime audit",
                },
            }
        }
    )

    record_name: str = Field(
        ...,
        min_length=3,
        max_length=180,
        description="Name of the record, route, log, event packet, or evidence sequence being checked.",
        examples=["Agent approval event log"],
    )
    record_preserved: bool = Field(
        ...,
        description="Whether the record exists and has been preserved.",
        examples=[True],
    )
    sequence_complete: bool = Field(
        ...,
        description="Whether the relevant event sequence is complete enough to support review.",
        examples=[False],
    )
    chain_of_custody_clear: bool = Field(
        ...,
        description="Whether custody, control, source, and handling are clear.",
        examples=[True],
    )
    gaps_identified: bool = Field(
        ...,
        description="Whether any continuity gaps have been identified.",
        examples=[True],
    )
    gaps_explained: bool = Field(
        ...,
        description="Whether identified gaps are explained well enough for review.",
        examples=[False],
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional continuity metadata. Do not submit secrets or confidential client data to the public sandbox.",
        examples=[
            {
                "example": True,
                "domain": "runtime audit",
            }
        ],
    )


class ReviewabilityRecordRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "entity_name": "AI vendor procurement workflow",
                "claim_or_function": "The workflow reviews vendors and recommends whether a pilot should be approved.",
                "consequence_question": "Should this workflow be allowed to influence enterprise procurement decisions before formal review?",
                "materials_available": True,
                "materials_summary": "Public product page, workflow description, sample audit output, and policy summary.",
                "metadata": {
                    "example": True,
                    "domain": "reviewability intake",
                },
            }
        }
    )

    entity_name: str = Field(
        ...,
        min_length=3,
        max_length=180,
        description="Name of the entity, system, workflow, agent, vendor route, or claim surface being reviewed.",
        examples=["AI vendor procurement workflow"],
    )
    claim_or_function: str = Field(
        ...,
        min_length=5,
        max_length=1000,
        description="The claim, function, route, product behavior, or governance assertion to be reviewed.",
        examples=["The workflow reviews vendors and recommends whether a pilot should be approved."],
    )
    consequence_question: str = Field(
        ...,
        min_length=5,
        max_length=1000,
        description="The consequence question that determines why reviewability matters.",
        examples=["Should this workflow be allowed to influence enterprise procurement decisions before formal review?"],
    )
    materials_available: bool = Field(
        ...,
        description="Whether enough materials are available to begin a meaningful reviewability check.",
        examples=[True],
    )
    materials_summary: str | None = Field(
        default=None,
        max_length=1000,
        description="Optional summary of the materials available for review.",
        examples=["Public product page, workflow description, sample audit output, and policy summary."],
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional reviewability metadata. Do not submit secrets or confidential client data to the public sandbox.",
        examples=[
            {
                "example": True,
                "domain": "reviewability intake",
            }
        ],
    )


class ProcurementScreenRequest(EvaluateExecutionRequest):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "route_name": "Enterprise AI vendor pilot approval",
                "proposed_action": "Approve an AI vendor for a live enterprise pilot",
                "risk_class": "high",
                "reality_valid": True,
                "record_preserved": True,
                "continuity_intact": True,
                "evidence_sufficient": True,
                "reliance_justified": True,
                "authority_source": "Procurement review committee charter",
                "authority_in_scope": True,
                "legitimacy_clear": True,
                "consequence_defined": "The vendor will influence operational decisions during a live enterprise pilot.",
                "binding_clear": True,
                "commit_point_known": True,
                "execution_reversible": False,
                "outcome_reviewable": True,
                "human_review_available": True,
                "metadata": {
                    "example": True,
                    "domain": "AI procurement",
                    "buyer_side_review": True,
                },
            }
        }
    )


class ChainSpecResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "meta": {
                    "request_id": "8f5a6c44-4e5f-4a52-9fd3-2df0f6c1b6d9",
                    "timestamp_utc": "2026-07-09T20:14:00.000000+00:00",
                    "api_version": "0.3.0",
                },
                "chain": [
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
                ],
                "decisions": ["ALLOW", "HOLD", "DENY", "ESCALATE"],
                "public_boundary": "The TA-14 API Sandbox is a public reference and demonstration layer.",
            }
        }
    )

    meta: ResponseMeta = Field(
        ...,
        description="Response metadata.",
    )
    chain: list[str] = Field(
        ...,
        description="The public 24-link TA-14 admissible execution chain.",
    )
    decisions: list[str] = Field(
        ...,
        description="Supported sandbox decisions.",
    )
    public_boundary: str = Field(
        ...,
        description="Public boundary language for sandbox use.",
    )


class DecisionMatrixResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "meta": {
                    "request_id": "8f5a6c44-4e5f-4a52-9fd3-2df0f6c1b6d9",
                    "timestamp_utc": "2026-07-09T20:14:00.000000+00:00",
                    "api_version": "0.3.0",
                },
                "matrix": {
                    "ALLOW": "The submitted route satisfies the sandbox chain conditions for its declared scope.",
                    "HOLD": "The submitted route may be valid, but one or more chain links are incomplete.",
                    "DENY": "The submitted route fails a core admissibility condition.",
                    "ESCALATE": "The submitted route requires human, institutional, legal, safety, or partner review before consequence.",
                },
            }
        }
    )

    meta: ResponseMeta = Field(
        ...,
        description="Response metadata.",
    )
    matrix: dict[str, str] = Field(
        ...,
        description="Human-readable explanation of each supported sandbox decision.",
    )


class PublicBoundaryResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "meta": {
                    "request_id": "8f5a6c44-4e5f-4a52-9fd3-2df0f6c1b6d9",
                    "timestamp_utc": "2026-07-09T20:14:00.000000+00:00",
                    "api_version": "0.3.0",
                },
                "public_claim": "TA-14 has a public API sandbox for admissible execution evaluation.",
                "non_claims": [
                    "Not legal advice.",
                    "Not compliance certification.",
                    "Not safety certification.",
                    "Not production approval.",
                    "Not a warranty.",
                ],
                "use_boundary": "The TA-14 API Sandbox is a public reference and demonstration layer.",
            }
        }
    )

    meta: ResponseMeta = Field(
        ...,
        description="Response metadata.",
    )
    public_claim: str = Field(
        ...,
        description="Safe public claim for the TA-14 API Sandbox.",
    )
    non_claims: list[str] = Field(
        ...,
        description="Explicit non-claims for public sandbox use.",
    )
    use_boundary: str = Field(
        ...,
        description="Boundary language governing sandbox interpretation.",
    )


class EvaluationResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "meta": {
                    "request_id": "8f5a6c44-4e5f-4a52-9fd3-2df0f6c1b6d9",
                    "timestamp_utc": "2026-07-09T20:14:00.000000+00:00",
                    "api_version": "0.3.0",
                },
                "decision": "ESCALATE",
                "chain_status": "Chain requires escalation before consequence-bearing execution.",
                "failed_links": ["Continuity", "Reliance"],
                "warnings": [
                    "Execution is not clearly reversible. Consequence-bearing routes may require escalation."
                ],
                "reason": "The route contains chain gaps inside a high-risk or critical execution context.",
                "next_step": "Escalate for TA-14 review, institutional review, legal/safety review, or partner review before execution.",
                "boundary": "The TA-14 API Sandbox is a public reference and demonstration layer.",
                "ta14_chain": [
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
                ],
            }
        }
    )

    meta: ResponseMeta = Field(
        ...,
        description="Response metadata.",
    )
    decision: Decision = Field(
        ...,
        description="Sandbox classification for the submitted route.",
    )
    chain_status: str = Field(
        ...,
        description="Plain-language status of the chain after evaluation.",
    )
    failed_links: list[str] = Field(
        default_factory=list,
        description="TA-14 chain links or route conditions that failed or need attention.",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Additional warnings that may require review, even when the route is not denied.",
    )
    reason: str = Field(
        ...,
        description="Primary reason for the sandbox decision.",
    )
    next_step: str = Field(
        ...,
        description="Recommended next step before reliance, binding, commit, execution, or production use.",
    )
    boundary: str = Field(
        ...,
        description="Public sandbox boundary language.",
    )
    ta14_chain: list[str] = Field(
        ...,
        description="The public 24-link TA-14 chain returned with evaluation responses.",
    )
