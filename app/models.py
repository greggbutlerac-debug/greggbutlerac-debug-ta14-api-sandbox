from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class Decision(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


class RouteRiskClass(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class BaseSandboxRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    route_name: str = Field(..., min_length=2, max_length=160)
    proposed_action: str = Field(..., min_length=2, max_length=500)
    risk_class: RouteRiskClass = RouteRiskClass.MODERATE

    reality_valid: bool = False
    record_preserved: bool = False
    continuity_intact: bool = False
    evidence_sufficient: bool = False
    reliance_justified: bool = False
    authority_source: Optional[str] = Field(default=None, max_length=240)
    authority_in_scope: bool = False
    legitimacy_clear: bool = False
    consequence_defined: Optional[str] = Field(default=None, max_length=500)
    binding_clear: bool = False
    commit_point_known: bool = False
    execution_reversible: bool = True
    outcome_reviewable: bool = False
    human_review_available: bool = True

    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvaluateExecutionRequest(BaseSandboxRequest):
    pass


class EvaluateEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_name: str = Field(..., min_length=2, max_length=160)
    evidence_claim: str = Field(..., min_length=2, max_length=500)
    source_known: bool = False
    record_preserved: bool = False
    continuity_intact: bool = False
    tamper_resistant: bool = False
    independently_reviewable: bool = False
    linked_to_consequence: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AuthorityCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str = Field(..., min_length=2, max_length=160)
    proposed_action: str = Field(..., min_length=2, max_length=500)
    authority_source: Optional[str] = Field(default=None, max_length=240)
    authority_in_scope: bool = False
    legitimacy_clear: bool = False
    human_review_available: bool = True
    risk_class: RouteRiskClass = RouteRiskClass.MODERATE


class ContinuityCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    route_name: str = Field(..., min_length=2, max_length=160)
    record_preserved: bool = False
    sequence_complete: bool = False
    chain_of_custody_clear: bool = False
    gaps_identified: bool = False
    gaps_explained: bool = False


class ReviewabilityRecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    submitted_entity: str = Field(..., min_length=2, max_length=240)
    submitted_url: Optional[str] = Field(default=None, max_length=500)
    claim_or_function: str = Field(..., min_length=2, max_length=700)
    consequence_question: str = Field(..., min_length=2, max_length=700)
    materials_available: List[str] = Field(default_factory=list)


class ProcurementScreenRequest(BaseSandboxRequest):
    vendor_name: str = Field(..., min_length=2, max_length=180)
    procurement_stage: str = Field(default="screen", max_length=120)


class ResponseMeta(BaseModel):
    request_id: str
    api_version: str
    timestamp_utc: str
    mode: str = "sandbox"


class EvaluationResponse(BaseModel):
    meta: ResponseMeta
    decision: Decision
    chain_status: str
    failed_links: List[str]
    warnings: List[str]
    reason: str
    next_step: str
    boundary: str
    ta14_chain: List[str]


class ChainSpecResponse(BaseModel):
    meta: ResponseMeta
    chain: List[str]
    decisions: List[str]
    public_boundary: str


class DecisionMatrixResponse(BaseModel):
    meta: ResponseMeta
    matrix: Dict[str, str]


class PublicBoundaryResponse(BaseModel):
    meta: ResponseMeta
    public_claim: str
    non_claims: List[str]
    use_boundary: str
