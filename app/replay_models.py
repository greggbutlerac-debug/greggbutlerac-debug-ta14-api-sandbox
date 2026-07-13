"""
TA-14 Independent Route Replay Standard
=======================================

Canonical data models for preserving and independently verifying a
consequence-bearing route from evidence through outcome.

This module is additive. It does not change the existing public sandbox
decision engine until imported by later implementation files.

Core route:

Reality -> Record -> Continuity -> Admissibility -> Binding ->
Commit -> Execution -> Outcome -> Preserved Proof

Public boundary:

These models provide a technical structure for route preservation and
verification. They do not constitute legal advice, compliance certification,
safety certification, production approval, or a warranty that any execution
is lawful, safe, complete, or appropriate.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


class StrictModel(BaseModel):
    """
    Base model for replay-standard records.

    Unknown fields are rejected so an independently replayed package cannot
    silently introduce undeclared state.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        use_enum_values=False,
        str_strip_whitespace=True,
    )


class ReplayDecision(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


class IntegrityStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    UNVERIFIED = "UNVERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    NOT_VERIFIED = "NOT_VERIFIED"


class AuthorityStatus(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    SUSPENDED = "SUSPENDED"
    UNKNOWN = "UNKNOWN"


class RouteEventType(str, Enum):
    ROUTE_CREATED = "ROUTE_CREATED"
    EVIDENCE_REGISTERED = "EVIDENCE_REGISTERED"
    AUTHORITY_REGISTERED = "AUTHORITY_REGISTERED"
    RULESET_BOUND = "RULESET_BOUND"
    DETERMINATION_ISSUED = "DETERMINATION_ISSUED"
    ROUTE_BOUND = "ROUTE_BOUND"
    COMMIT_AUTHORIZED = "COMMIT_AUTHORIZED"
    EXECUTION_STARTED = "EXECUTION_STARTED"
    EXECUTION_COMPLETED = "EXECUTION_COMPLETED"
    EXECUTION_BLOCKED = "EXECUTION_BLOCKED"
    OUTCOME_RECORDED = "OUTCOME_RECORDED"
    DIVERGENCE_RECORDED = "DIVERGENCE_RECORDED"
    ROUTE_REVOKED = "ROUTE_REVOKED"
    ROUTE_EXPIRED = "ROUTE_EXPIRED"
    PACKAGE_SEALED = "PACKAGE_SEALED"
    PACKAGE_VERIFIED = "PACKAGE_VERIFIED"


class HashAlgorithm(str, Enum):
    SHA256 = "SHA-256"
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"


class SignatureAlgorithm(str, Enum):
    ED25519 = "Ed25519"
    ECDSA_P256_SHA256 = "ECDSA-P256-SHA256"
    RSA_PSS_SHA256 = "RSA-PSS-SHA256"


# ---------------------------------------------------------------------------
# Cryptographic and provenance records
# ---------------------------------------------------------------------------


class DigestRecord(StrictModel):
    algorithm: HashAlgorithm = HashAlgorithm.SHA256
    value: str = Field(
        ...,
        min_length=32,
        description="Lowercase hexadecimal digest of canonical content.",
    )

    @field_validator("value")
    @classmethod
    def validate_hex_digest(cls, value: str) -> str:
        normalized = value.lower()

        if any(character not in "0123456789abcdef" for character in normalized):
            raise ValueError("Digest value must contain hexadecimal characters only.")

        expected_lengths = {
            HashAlgorithm.SHA256: 64,
            HashAlgorithm.SHA384: 96,
            HashAlgorithm.SHA512: 128,
        }

        # The algorithm field is not reliably available inside this validator
        # across all Pydantic execution paths, so supported digest lengths are
        # checked here. Exact algorithm-to-length matching is checked by the
        # cryptographic service when the package is created or verified.
        if len(normalized) not in expected_lengths.values():
            raise ValueError(
                "Digest must be 64, 96, or 128 hexadecimal characters."
            )

        return normalized


class SignatureRecord(StrictModel):
    signature_id: UUID = Field(default_factory=uuid4)
    algorithm: SignatureAlgorithm
    key_id: str = Field(..., min_length=1, max_length=200)
    public_key_fingerprint: DigestRecord
    signed_digest: DigestRecord
    signature_base64: str = Field(..., min_length=20)
    signed_at: datetime = Field(default_factory=utc_now)
    signer: str = Field(..., min_length=1, max_length=300)
    certificate_chain: List[str] = Field(default_factory=list)
    verification_status: VerificationStatus = VerificationStatus.NOT_VERIFIED
    verification_message: Optional[str] = None


class SourceIdentity(StrictModel):
    source_id: str = Field(..., min_length=1, max_length=300)
    source_type: str = Field(..., min_length=1, max_length=200)
    system_name: str = Field(..., min_length=1, max_length=300)
    system_version: Optional[str] = Field(default=None, max_length=200)
    organization: Optional[str] = Field(default=None, max_length=300)
    environment: Optional[str] = Field(default=None, max_length=100)
    endpoint_or_location: Optional[str] = Field(default=None, max_length=1000)
    authenticated: bool = False
    authentication_method: Optional[str] = Field(default=None, max_length=200)
    attestation_reference: Optional[str] = Field(default=None, max_length=1000)


class CustodyEvent(StrictModel):
    event_id: UUID = Field(default_factory=uuid4)
    occurred_at: datetime = Field(default_factory=utc_now)
    actor: str = Field(..., min_length=1, max_length=300)
    action: str = Field(..., min_length=1, max_length=300)
    system: Optional[str] = Field(default=None, max_length=300)
    location: Optional[str] = Field(default=None, max_length=1000)
    previous_digest: Optional[DigestRecord] = None
    resulting_digest: DigestRecord
    notes: Optional[str] = Field(default=None, max_length=4000)


# ---------------------------------------------------------------------------
# Evidence records
# ---------------------------------------------------------------------------


class EvidenceValidity(StrictModel):
    observed_at: datetime
    valid_from: datetime
    valid_until: Optional[datetime] = None
    maximum_age_seconds: Optional[int] = Field(default=None, ge=0)
    refresh_required: bool = False
    refresh_condition: Optional[str] = Field(default=None, max_length=2000)

    @field_validator("valid_until")
    @classmethod
    def valid_until_must_be_after_valid_from(
        cls,
        value: Optional[datetime],
        info: Any,
    ) -> Optional[datetime]:
        if value is None:
            return value

        valid_from = info.data.get("valid_from")

        if valid_from is not None and value <= valid_from:
            raise ValueError("valid_until must be later than valid_from.")

        return value


class EvidenceObject(StrictModel):
    evidence_id: UUID = Field(default_factory=uuid4)
    evidence_type: str = Field(..., min_length=1, max_length=200)
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = Field(default=None, max_length=8000)

    source: SourceIdentity
    validity: EvidenceValidity

    content_digest: DigestRecord
    canonicalization_method: str = Field(
        default="TA14-JCS-1",
        min_length=1,
        max_length=100,
        description=(
            "Method used to canonicalize evidence metadata or content before hashing."
        ),
    )

    media_type: Optional[str] = Field(default=None, max_length=200)
    byte_length: Optional[int] = Field(default=None, ge=0)
    storage_reference: Optional[str] = Field(default=None, max_length=2000)
    encrypted: bool = False
    redacted: bool = False

    provenance_complete: bool = False
    independently_retrievable: bool = False
    tamper_evident: bool = False

    custody_history: List[CustodyEvent] = Field(default_factory=list)
    supporting_evidence_ids: List[UUID] = Field(default_factory=list)
    conflicts_with_evidence_ids: List[UUID] = Field(default_factory=list)

    attestation: Optional[SignatureRecord] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvidenceIndexEntry(StrictModel):
    evidence_id: UUID
    evidence_type: str
    title: str
    content_digest: DigestRecord
    source_id: str
    observed_at: datetime
    valid_until: Optional[datetime] = None
    storage_reference: Optional[str] = None
    included_in_package: bool = False
    redacted: bool = False


class EvidenceIndex(StrictModel):
    index_version: str = "1.0.0"
    generated_at: datetime = Field(default_factory=utc_now)
    entries: List[EvidenceIndexEntry] = Field(default_factory=list)
    index_digest: Optional[DigestRecord] = None


# ---------------------------------------------------------------------------
# Authority and jurisdiction
# ---------------------------------------------------------------------------


class AuthorityScope(StrictModel):
    permitted_actions: List[str] = Field(default_factory=list)
    prohibited_actions: List[str] = Field(default_factory=list)
    jurisdictions: List[str] = Field(default_factory=list)
    systems: List[str] = Field(default_factory=list)
    resource_limits: Dict[str, Any] = Field(default_factory=dict)
    conditions: List[str] = Field(default_factory=list)


class AuthorityRecord(StrictModel):
    authority_id: UUID = Field(default_factory=uuid4)
    principal_id: str = Field(..., min_length=1, max_length=300)
    principal_type: str = Field(..., min_length=1, max_length=100)
    issuer: str = Field(..., min_length=1, max_length=300)

    granted_at: datetime
    valid_from: datetime
    valid_until: Optional[datetime] = None
    revoked_at: Optional[datetime] = None

    status: AuthorityStatus = AuthorityStatus.UNKNOWN
    delegation_chain: List[str] = Field(default_factory=list)
    scope: AuthorityScope

    authority_document_digest: Optional[DigestRecord] = None
    storage_reference: Optional[str] = Field(default=None, max_length=2000)
    attestation: Optional[SignatureRecord] = None

    @field_validator("valid_until")
    @classmethod
    def authority_expiry_after_start(
        cls,
        value: Optional[datetime],
        info: Any,
    ) -> Optional[datetime]:
        if value is None:
            return value

        valid_from = info.data.get("valid_from")

        if valid_from is not None and value <= valid_from:
            raise ValueError("Authority valid_until must be later than valid_from.")

        return value


class JurisdictionRecord(StrictModel):
    jurisdiction_id: str = Field(..., min_length=1, max_length=200)
    name: str = Field(..., min_length=1, max_length=300)
    applicable: bool = True
    basis: str = Field(..., min_length=1, max_length=4000)
    requirements: List[str] = Field(default_factory=list)
    conflicts: List[str] = Field(default_factory=list)
    human_review_required: bool = False
    evidence_references: List[UUID] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Ruleset and predicate evaluation
# ---------------------------------------------------------------------------


class RuleReference(StrictModel):
    rule_id: str = Field(..., min_length=1, max_length=200)
    rule_version: str = Field(..., min_length=1, max_length=100)
    title: str = Field(..., min_length=1, max_length=500)
    rule_digest: DigestRecord
    source_reference: Optional[str] = Field(default=None, max_length=2000)


class RulesetRecord(StrictModel):
    ruleset_id: str = Field(..., min_length=1, max_length=200)
    ruleset_version: str = Field(..., min_length=1, max_length=100)
    architecture_version: str = Field(..., min_length=1, max_length=100)
    effective_from: datetime
    effective_until: Optional[datetime] = None
    ruleset_digest: DigestRecord
    rules: List[RuleReference] = Field(default_factory=list)
    signed_by: Optional[SignatureRecord] = None


class PredicateResult(StrictModel):
    predicate_id: str = Field(..., min_length=1, max_length=200)
    link_number: int = Field(..., ge=1, le=24)
    link_name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=2000)

    satisfied: bool
    required: bool = True
    observed_value: Any = None
    expected_value: Any = None

    evidence_ids: List[UUID] = Field(default_factory=list)
    authority_ids: List[UUID] = Field(default_factory=list)
    rule_ids: List[str] = Field(default_factory=list)

    evaluated_at: datetime = Field(default_factory=utc_now)
    evaluator_version: str = Field(..., min_length=1, max_length=100)
    reason: str = Field(..., min_length=1, max_length=4000)


class ChainLinkState(StrictModel):
    link_number: int = Field(..., ge=1, le=24)
    link_name: str = Field(..., min_length=1, max_length=200)
    satisfied: bool
    required: bool = True
    status: Literal["PASS", "FAIL", "HOLD", "NOT_EVALUATED"]
    predicate_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[UUID] = Field(default_factory=list)
    reason: str = Field(..., min_length=1, max_length=4000)


# ---------------------------------------------------------------------------
# Proposed action and route manifest
# ---------------------------------------------------------------------------


class ProposedAction(StrictModel):
    action_id: UUID = Field(default_factory=uuid4)
    action_type: str = Field(..., min_length=1, max_length=200)
    actor_id: str = Field(..., min_length=1, max_length=300)
    target: str = Field(..., min_length=1, max_length=1000)

    description: str = Field(..., min_length=1, max_length=8000)
    parameters: Dict[str, Any] = Field(default_factory=dict)

    requested_at: datetime = Field(default_factory=utc_now)
    requested_execution_time: Optional[datetime] = None

    consequence_class: str = Field(..., min_length=1, max_length=200)
    reversible: bool
    maximum_impact: Optional[str] = Field(default=None, max_length=2000)

    action_digest: Optional[DigestRecord] = None


class RouteManifest(StrictModel):
    manifest_version: str = "1.0.0"

    route_id: UUID = Field(default_factory=uuid4)
    request_id: UUID = Field(default_factory=uuid4)
    correlation_id: Optional[str] = Field(default=None, max_length=300)

    created_at: datetime = Field(default_factory=utc_now)
    expires_at: Optional[datetime] = None

    architecture_name: str = "TA-14 Admissible Execution Architecture"
    architecture_version: str = Field(..., min_length=1, max_length=100)

    proposed_action: ProposedAction
    evidence_ids: List[UUID] = Field(default_factory=list)
    authority_ids: List[UUID] = Field(default_factory=list)
    jurisdiction_ids: List[str] = Field(default_factory=list)

    ruleset_id: str = Field(..., min_length=1, max_length=200)
    ruleset_version: str = Field(..., min_length=1, max_length=100)
    ruleset_digest: DigestRecord

    chain_links: List[ChainLinkState] = Field(default_factory=list)
    predicates: List[PredicateResult] = Field(default_factory=list)

    input_digest: DigestRecord
    manifest_digest: Optional[DigestRecord] = None

    re_evaluation_required_when: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("chain_links")
    @classmethod
    def chain_link_numbers_must_be_unique(
        cls,
        value: List[ChainLinkState],
    ) -> List[ChainLinkState]:
        link_numbers = [link.link_number for link in value]

        if len(link_numbers) != len(set(link_numbers)):
            raise ValueError("Route manifest contains duplicate chain-link numbers.")

        return sorted(value, key=lambda item: item.link_number)


# ---------------------------------------------------------------------------
# Determination, binding, and commit
# ---------------------------------------------------------------------------


class DeterminationReceipt(StrictModel):
    receipt_version: str = "1.0.0"
    receipt_id: UUID = Field(default_factory=uuid4)
    route_id: UUID
    request_id: UUID

    decision: ReplayDecision
    issued_at: datetime = Field(default_factory=utc_now)
    valid_until: Optional[datetime] = None

    reasons: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    failed_predicate_ids: List[str] = Field(default_factory=list)
    satisfied_predicate_ids: List[str] = Field(default_factory=list)

    required_actions: List[str] = Field(default_factory=list)
    escalation_destination: Optional[str] = Field(default=None, max_length=500)

    manifest_digest: DigestRecord
    determination_digest: Optional[DigestRecord] = None
    signature: Optional[SignatureRecord] = None

    independently_replayable: bool = False


class BindingCondition(StrictModel):
    condition_id: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=3000)
    required: bool = True
    expected_value: Any = None
    evidence_ids: List[UUID] = Field(default_factory=list)
    rule_ids: List[str] = Field(default_factory=list)


class BindingReceipt(StrictModel):
    binding_id: UUID = Field(default_factory=uuid4)
    route_id: UUID
    determination_receipt_id: UUID

    bound_at: datetime = Field(default_factory=utc_now)
    bound_by: str = Field(..., min_length=1, max_length=300)

    action_digest: DigestRecord
    evidence_index_digest: DigestRecord
    authority_digest: DigestRecord
    ruleset_digest: DigestRecord
    determination_digest: DigestRecord

    conditions: List[BindingCondition] = Field(default_factory=list)
    binding_digest: Optional[DigestRecord] = None
    signature: Optional[SignatureRecord] = None


class CommitReceipt(StrictModel):
    commit_id: UUID = Field(default_factory=uuid4)
    route_id: UUID
    binding_id: UUID

    authorized_at: datetime = Field(default_factory=utc_now)
    authorized_by: str = Field(..., min_length=1, max_length=300)
    valid_until: datetime

    single_use: bool = True
    execution_audience: str = Field(..., min_length=1, max_length=500)
    execution_nonce: str = Field(..., min_length=16, max_length=500)

    bound_action_digest: DigestRecord
    bound_binding_digest: DigestRecord

    commit_digest: Optional[DigestRecord] = None
    signature: Optional[SignatureRecord] = None

    consumed_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = Field(default=None, max_length=3000)


# ---------------------------------------------------------------------------
# Execution and outcome
# ---------------------------------------------------------------------------


class ExecutionReceipt(StrictModel):
    execution_id: UUID = Field(default_factory=uuid4)
    route_id: UUID
    commit_id: UUID

    executor_id: str = Field(..., min_length=1, max_length=300)
    execution_system: str = Field(..., min_length=1, max_length=300)
    execution_system_version: Optional[str] = Field(default=None, max_length=100)

    started_at: datetime
    completed_at: Optional[datetime] = None

    status: Literal[
        "STARTED",
        "COMPLETED",
        "FAILED",
        "BLOCKED",
        "CANCELLED",
        "PARTIAL",
    ]

    submitted_action_digest: DigestRecord
    bound_action_digest: DigestRecord
    action_binding_matched: bool

    result_digest: Optional[DigestRecord] = None
    result_reference: Optional[str] = Field(default=None, max_length=2000)

    exception_codes: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

    execution_digest: Optional[DigestRecord] = None
    signature: Optional[SignatureRecord] = None


class DivergenceRecord(StrictModel):
    divergence_id: UUID = Field(default_factory=uuid4)
    route_id: UUID
    detected_at: datetime = Field(default_factory=utc_now)

    category: str = Field(..., min_length=1, max_length=200)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    description: str = Field(..., min_length=1, max_length=8000)

    expected_state: Any = None
    observed_state: Any = None

    evidence_ids: List[UUID] = Field(default_factory=list)
    requires_re_evaluation: bool = True
    requires_escalation: bool = False
    remediation_actions: List[str] = Field(default_factory=list)


class OutcomeRecord(StrictModel):
    outcome_id: UUID = Field(default_factory=uuid4)
    route_id: UUID
    execution_id: UUID

    observed_at: datetime = Field(default_factory=utc_now)
    observer_id: str = Field(..., min_length=1, max_length=300)
    observation_system: str = Field(..., min_length=1, max_length=300)

    intended_outcome: str = Field(..., min_length=1, max_length=8000)
    observed_outcome: str = Field(..., min_length=1, max_length=8000)

    consequence_matched: bool
    remained_within_binding_conditions: bool
    authority_remained_valid: bool
    evidence_remained_valid: bool

    outcome_evidence_ids: List[UUID] = Field(default_factory=list)
    divergences: List[DivergenceRecord] = Field(default_factory=list)

    outcome_digest: Optional[DigestRecord] = None
    signature: Optional[SignatureRecord] = None


# ---------------------------------------------------------------------------
# Tamper-evident event ledger
# ---------------------------------------------------------------------------


class LedgerEvent(StrictModel):
    sequence: int = Field(..., ge=1)
    event_id: UUID = Field(default_factory=uuid4)
    route_id: UUID
    event_type: RouteEventType

    occurred_at: datetime = Field(default_factory=utc_now)
    actor: str = Field(..., min_length=1, max_length=300)

    object_type: str = Field(..., min_length=1, max_length=200)
    object_id: str = Field(..., min_length=1, max_length=300)
    object_digest: DigestRecord

    previous_event_digest: Optional[DigestRecord] = None
    event_digest: Optional[DigestRecord] = None

    metadata: Dict[str, Any] = Field(default_factory=dict)
    signature: Optional[SignatureRecord] = None


class LedgerRecord(StrictModel):
    ledger_version: str = "1.0.0"
    route_id: UUID
    created_at: datetime = Field(default_factory=utc_now)
    events: List[LedgerEvent] = Field(default_factory=list)
    root_digest: Optional[DigestRecord] = None
    final_event_digest: Optional[DigestRecord] = None
    sealed_at: Optional[datetime] = None
    seal_signature: Optional[SignatureRecord] = None

    @field_validator("events")
    @classmethod
    def ledger_sequences_must_be_contiguous(
        cls,
        value: List[LedgerEvent],
    ) -> List[LedgerEvent]:
        if not value:
            return value

        sorted_events = sorted(value, key=lambda event: event.sequence)
        actual = [event.sequence for event in sorted_events]
        expected = list(range(1, len(sorted_events) + 1))

        if actual != expected:
            raise ValueError(
                "Ledger event sequence must begin at 1 and remain contiguous."
            )

        return sorted_events


# ---------------------------------------------------------------------------
# Replay package and independent verification
# ---------------------------------------------------------------------------


class PackageFileRecord(StrictModel):
    path: str = Field(..., min_length=1, max_length=1000)
    media_type: str = Field(..., min_length=1, max_length=200)
    byte_length: int = Field(..., ge=0)
    digest: DigestRecord
    required: bool = True
    encrypted: bool = False
    redacted: bool = False


class ReplayPackageManifest(StrictModel):
    package_standard: str = "TA-14 Independent Route Replay Standard"
    package_version: str = "1.0.0"

    package_id: UUID = Field(default_factory=uuid4)
    route_id: UUID
    created_at: datetime = Field(default_factory=utc_now)
    created_by: str = Field(..., min_length=1, max_length=300)

    files: List[PackageFileRecord] = Field(default_factory=list)
    package_digest: Optional[DigestRecord] = None
    signature: Optional[SignatureRecord] = None

    contains_sensitive_material: bool = False
    encryption_description: Optional[str] = Field(default=None, max_length=2000)
    disclosure_limitations: List[str] = Field(default_factory=list)


class VerificationCheck(StrictModel):
    check_id: str = Field(..., min_length=1, max_length=200)
    name: str = Field(..., min_length=1, max_length=500)
    status: VerificationStatus
    message: str = Field(..., min_length=1, max_length=4000)
    expected: Any = None
    observed: Any = None
    related_object_ids: List[str] = Field(default_factory=list)


class IndependentVerificationReport(StrictModel):
    report_standard: str = "TA-14 Independent Route Verification Report"
    report_version: str = "1.0.0"

    report_id: UUID = Field(default_factory=uuid4)
    package_id: UUID
    route_id: UUID

    verifier_name: str = Field(..., min_length=1, max_length=300)
    verifier_version: str = Field(..., min_length=1, max_length=100)
    verified_at: datetime = Field(default_factory=utc_now)

    overall_status: VerificationStatus
    original_decision: ReplayDecision

    package_integrity: IntegrityStatus
    signature_integrity: IntegrityStatus
    ledger_integrity: IntegrityStatus
    evidence_integrity: IntegrityStatus
    authority_at_commit: IntegrityStatus
    ruleset_integrity: IntegrityStatus
    action_binding: IntegrityStatus
    commit_integrity: IntegrityStatus
    execution_correspondence: IntegrityStatus
    outcome_correspondence: IntegrityStatus

    checks: List[VerificationCheck] = Field(default_factory=list)
    failures: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

    independently_replayable: bool = False
    report_digest: Optional[DigestRecord] = None
    signature: Optional[SignatureRecord] = None


class CompleteRouteReplayRecord(StrictModel):
    """
    In-memory representation of a complete governed route.

    Package-generation services will serialize these components into separate
    canonical files so an outside verifier does not need to trust the TA-14
    dashboard or operator.
    """

    route_manifest: RouteManifest
    evidence_index: EvidenceIndex
    evidence_objects: List[EvidenceObject] = Field(default_factory=list)

    authority_records: List[AuthorityRecord] = Field(default_factory=list)
    jurisdiction_records: List[JurisdictionRecord] = Field(default_factory=list)
    ruleset: RulesetRecord

    determination: DeterminationReceipt
    binding: Optional[BindingReceipt] = None
    commit: Optional[CommitReceipt] = None
    execution: Optional[ExecutionReceipt] = None
    outcome: Optional[OutcomeRecord] = None

    ledger: LedgerRecord
    package_manifest: Optional[ReplayPackageManifest] = None
    verification_report: Optional[IndependentVerificationReport] = None
