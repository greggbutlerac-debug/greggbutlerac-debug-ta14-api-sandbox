"""
Tests for the TA-14 Independent Route Replay receipt-construction layer.

These tests verify:

- signed determination receipt creation;
- failed-predicate protection;
- escalation requirements;
- exact action, evidence, authority, and ruleset binding;
- short-lived commit authorization;
- single-use commit consumption;
- commit revocation;
- execution-to-binding correspondence;
- outcome verification;
- divergence requirements;
- route consistency;
- receipt signature verification.
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.replay_crypto import (
    digest_object,
    digest_text,
    secure_digest_equal,
)
from app.replay_models import (
    AuthorityRecord,
    AuthorityScope,
    AuthorityStatus,
    BindingCondition,
    ChainLinkState,
    DigestRecord,
    DivergenceRecord,
    EvidenceIndex,
    EvidenceIndexEntry,
    HashAlgorithm,
    PredicateResult,
    ProposedAction,
    ReplayDecision,
    RouteManifest,
    RulesetRecord,
)
from app.replay_receipts import (
    ReceiptConstructionError,
    create_binding_receipt,
    create_commit_receipt,
    create_determination_receipt,
    create_execution_receipt,
    create_outcome_record,
    mark_commit_consumed,
    revoke_commit_receipt,
)
from app.replay_signing import (
    generate_key_pair,
    verify_object_signature,
)


FIXED_TIME = datetime(
    2026,
    7,
    14,
    14,
    0,
    0,
    tzinfo=timezone.utc,
)

SIGNER = "TA-14 Receipt Test Signer"


def fixed_digest(
    character: str,
) -> DigestRecord:
    """Create a deterministic valid SHA-256 digest fixture."""

    return DigestRecord(
        algorithm=HashAlgorithm.SHA256,
        value=character * 64,
    )


def build_action() -> ProposedAction:
    """Create a proposed action with a deterministic action digest."""

    action = ProposedAction(
        action_type="synthetic-funds-transfer",
        actor_id="agent-credit-engine-001",
        target="synthetic-beneficiary-account",
        description=(
            "Transfer a synthetic amount under a controlled replay test."
        ),
        parameters={
            "amount": 2500000,
            "currency": "EUR",
        },
        requested_at=FIXED_TIME,
        requested_execution_time=(
            FIXED_TIME + timedelta(minutes=5)
        ),
        consequence_class="financial",
        reversible=False,
        maximum_impact="Synthetic test exposure only.",
    )

    return action.model_copy(
        update={
            "action_digest": digest_object(action),
        }
    )


def build_ruleset() -> RulesetRecord:
    """Create a versioned deterministic ruleset fixture."""

    return RulesetRecord(
        ruleset_id="ta14-test-ruleset",
        ruleset_version="1.0.0",
        architecture_version="24-link-test-1.0.0",
        effective_from=(
            FIXED_TIME - timedelta(days=1)
        ),
        effective_until=(
            FIXED_TIME + timedelta(days=30)
        ),
        ruleset_digest=digest_text(
            "ta14-test-ruleset-1.0.0"
        ),
        rules=[],
        signed_by=None,
    )


def build_predicate(
    *,
    satisfied: bool = True,
) -> PredicateResult:
    """Create a route predicate fixture."""

    return PredicateResult(
        predicate_id="authority-current",
        link_number=8,
        link_name="Authority",
        description=(
            "The execution authority must remain active and in scope."
        ),
        satisfied=satisfied,
        required=True,
        observed_value=(
            "ACTIVE"
            if satisfied
            else "EXPIRED"
        ),
        expected_value="ACTIVE",
        evidence_ids=[],
        authority_ids=[],
        rule_ids=["AUTHORITY-CURRENT"],
        evaluated_at=FIXED_TIME,
        evaluator_version="test-engine-1.0.0",
        reason=(
            "Authority is active."
            if satisfied
            else "Authority has expired."
        ),
    )


def build_chain_link(
    *,
    satisfied: bool = True,
) -> ChainLinkState:
    """Create a chain-link state matching the predicate fixture."""

    return ChainLinkState(
        link_number=8,
        link_name="Authority",
        satisfied=satisfied,
        required=True,
        status=(
            "PASS"
            if satisfied
            else "FAIL"
        ),
        predicate_ids=["authority-current"],
        evidence_ids=[],
        reason=(
            "Authority requirement passed."
            if satisfied
            else "Authority requirement failed."
        ),
    )


def build_route_manifest(
    *,
    predicate_satisfied: bool = True,
) -> RouteManifest:
    """Create a route manifest with its deterministic manifest digest."""

    action = build_action()
    ruleset = build_ruleset()

    manifest = RouteManifest(
        route_id=uuid4(),
        request_id=uuid4(),
        correlation_id="receipt-test-001",
        created_at=FIXED_TIME,
        expires_at=(
            FIXED_TIME + timedelta(minutes=30)
        ),
        architecture_version="24-link-test-1.0.0",
        proposed_action=action,
        evidence_ids=[],
        authority_ids=[],
        jurisdiction_ids=["DE"],
        ruleset_id=ruleset.ruleset_id,
        ruleset_version=ruleset.ruleset_version,
        ruleset_digest=ruleset.ruleset_digest,
        chain_links=[
            build_chain_link(
                satisfied=predicate_satisfied
            )
        ],
        predicates=[
            build_predicate(
                satisfied=predicate_satisfied
            )
        ],
        input_digest=digest_text(
            "receipt-test-input"
        ),
        re_evaluation_required_when=[
            "Evidence expires.",
            "Authority changes.",
            "Action parameters change.",
        ],
        metadata={
            "scenario": "synthetic-receipt-test",
        },
    )

    return manifest.model_copy(
        update={
            "manifest_digest": digest_object(
                manifest
            ),
        }
    )


def build_evidence_index() -> EvidenceIndex:
    """Create a deterministic evidence index fixture."""

    evidence_id = uuid4()

    index = EvidenceIndex(
        generated_at=FIXED_TIME,
        entries=[
            EvidenceIndexEntry(
                evidence_id=evidence_id,
                evidence_type="synthetic-authority-record",
                title="Active deployment authority",
                content_digest=digest_text(
                    "active-authority-record"
                ),
                source_id="synthetic-authority-registry",
                observed_at=FIXED_TIME,
                valid_until=(
                    FIXED_TIME + timedelta(hours=1)
                ),
                storage_reference=(
                    "urn:ta14:test:evidence:authority"
                ),
                included_in_package=True,
                redacted=False,
            )
        ],
    )

    return index.model_copy(
        update={
            "index_digest": digest_object(index),
        }
    )


def build_authority_record() -> AuthorityRecord:
    """Create an active authority record fixture."""

    return AuthorityRecord(
        authority_id=uuid4(),
        principal_id="agent-credit-engine-001",
        principal_type="AI_AGENT",
        issuer="Synthetic Europa Bank Board",
        granted_at=(
            FIXED_TIME - timedelta(days=30)
        ),
        valid_from=(
            FIXED_TIME - timedelta(days=30)
        ),
        valid_until=(
            FIXED_TIME + timedelta(days=30)
        ),
        revoked_at=None,
        status=AuthorityStatus.ACTIVE,
        delegation_chain=[
            "Board",
            "Chief Risk Officer",
            "Credit Automation Authority",
        ],
        scope=AuthorityScope(
            permitted_actions=[
                "synthetic-funds-transfer"
            ],
            prohibited_actions=[],
            jurisdictions=["DE"],
            systems=["synthetic-credit-engine"],
            resource_limits={
                "maximum_amount_eur": 5000000,
            },
            conditions=[
                "Evidence must remain current.",
                "Action digest must remain unchanged.",
            ],
        ),
        authority_document_digest=digest_text(
            "synthetic-authority-document"
        ),
        storage_reference=(
            "urn:ta14:test:authority:active"
        ),
        attestation=None,
    )


def build_binding_condition() -> BindingCondition:
    """Create one execution binding condition."""

    return BindingCondition(
        condition_id="amount-limit",
        description=(
            "The executed amount must not exceed the authorized amount."
        ),
        required=True,
        expected_value={
            "maximum_amount_eur": 2500000,
        },
        evidence_ids=[],
        rule_ids=["AMOUNT-LIMIT"],
    )


def build_allow_chain(
    *,
    signed: bool = True,
):
    """
    Build a complete route through binding.

    Returns:
        route_manifest,
        evidence_index,
        ruleset,
        authority_record,
        determination,
        binding,
        key_pair
    """

    route_manifest = build_route_manifest()
    evidence_index = build_evidence_index()
    ruleset = build_ruleset()
    authority_record = build_authority_record()

    key_pair = (
        generate_key_pair()
        if signed
        else None
    )

    determination = create_determination_receipt(
        route_manifest=route_manifest,
        decision=ReplayDecision.ALLOW,
        reasons=[
            "All required predicates passed.",
        ],
        issued_at=FIXED_TIME,
        valid_until=(
            FIXED_TIME + timedelta(minutes=20)
        ),
        independently_replayable=True,
        key_pair=key_pair,
        signer=(
            SIGNER
            if signed
            else None
        ),
    )

    binding = create_binding_receipt(
        route_manifest=route_manifest,
        evidence_index=evidence_index,
        ruleset=ruleset,
        determination=determination,
        authority_records=[
            authority_record
        ],
        conditions=[
            build_binding_condition()
        ],
        bound_by="ta14-binding-service",
        bound_at=(
            FIXED_TIME + timedelta(minutes=1)
        ),
        key_pair=key_pair,
        signer=(
            SIGNER
            if signed
            else None
        ),
    )

    return (
        route_manifest,
        evidence_index,
        ruleset,
        authority_record,
        determination,
        binding,
        key_pair,
    )


def test_create_signed_allow_determination() -> None:
    """A valid route must produce a signed ALLOW receipt."""

    route_manifest = build_route_manifest()
    key_pair = generate_key_pair()

    determination = create_determination_receipt(
        route_manifest=route_manifest,
        decision=ReplayDecision.ALLOW,
        reasons=[
            "All required predicates passed.",
        ],
        issued_at=FIXED_TIME,
        valid_until=(
            FIXED_TIME + timedelta(minutes=20)
        ),
        independently_replayable=True,
        key_pair=key_pair,
        signer=SIGNER,
    )

    assert determination.decision == ReplayDecision.ALLOW
    assert determination.determination_digest is not None
    assert determination.signature is not None
    assert determination.failed_predicate_ids == []
    assert determination.satisfied_predicate_ids == [
        "authority-current"
    ]

    result = verify_object_signature(
        determination,
        determination.signature,
        public_key=key_pair.public_key,
    )

    assert result.valid is True


def test_allow_rejects_failed_predicates() -> None:
    """ALLOW must never be issued when a required predicate failed."""

    route_manifest = build_route_manifest(
        predicate_satisfied=False
    )

    with pytest.raises(
        ReceiptConstructionError,
        match="ALLOW determination cannot contain failed predicates",
    ):
        create_determination_receipt(
            route_manifest=route_manifest,
            decision=ReplayDecision.ALLOW,
            reasons=[
                "Incorrect attempt to allow.",
            ],
            issued_at=FIXED_TIME,
        )


def test_escalate_requires_destination() -> None:
    """ESCALATE must identify where the route is sent."""

    route_manifest = build_route_manifest(
        predicate_satisfied=False
    )

    with pytest.raises(
        ReceiptConstructionError,
        match="ESCALATE requires an escalation_destination",
    ):
        create_determination_receipt(
            route_manifest=route_manifest,
            decision=ReplayDecision.ESCALATE,
            reasons=[
                "Authority requires human review.",
            ],
            issued_at=FIXED_TIME,
        )


def test_escalate_receipt_preserves_destination() -> None:
    """A valid escalation receipt must preserve its destination."""

    route_manifest = build_route_manifest(
        predicate_satisfied=False
    )

    determination = create_determination_receipt(
        route_manifest=route_manifest,
        decision=ReplayDecision.ESCALATE,
        reasons=[
            "Authority requires human review.",
        ],
        escalation_destination=(
            "Chief Risk Officer Review Queue"
        ),
        issued_at=FIXED_TIME,
    )

    assert (
        determination.escalation_destination
        == "Chief Risk Officer Review Queue"
    )

    assert determination.failed_predicate_ids == [
        "authority-current"
    ]


def test_binding_is_signed_and_matches_dependencies() -> None:
    """Binding must preserve exact action and determination digests."""

    (
        route_manifest,
        evidence_index,
        ruleset,
        authority_record,
        determination,
        binding,
        key_pair,
    ) = build_allow_chain()

    assert key_pair is not None
    assert binding.binding_digest is not None
    assert binding.signature is not None

    assert secure_digest_equal(
        binding.action_digest,
        route_manifest.proposed_action.action_digest,
    )

    assert secure_digest_equal(
        binding.evidence_index_digest,
        evidence_index.index_digest,
    )

    assert secure_digest_equal(
        binding.ruleset_digest,
        ruleset.ruleset_digest,
    )

    assert secure_digest_equal(
        binding.determination_digest,
        determination.determination_digest,
    )

    result = verify_object_signature(
        binding,
        binding.signature,
        public_key=key_pair.public_key,
    )

    assert result.valid is True

    assert authority_record.status == AuthorityStatus.ACTIVE


def test_non_allow_determination_cannot_be_bound() -> None:
    """HOLD, DENY, and ESCALATE cannot authorize execution binding."""

    route_manifest = build_route_manifest(
        predicate_satisfied=False
    )

    determination = create_determination_receipt(
        route_manifest=route_manifest,
        decision=ReplayDecision.HOLD,
        reasons=[
            "Authority is not currently valid.",
        ],
        issued_at=FIXED_TIME,
    )

    with pytest.raises(
        ReceiptConstructionError,
        match="Only an ALLOW determination may be bound",
    ):
        create_binding_receipt(
            route_manifest=route_manifest,
            evidence_index=build_evidence_index(),
            ruleset=build_ruleset(),
            determination=determination,
            authority_records=[
                build_authority_record()
            ],
            conditions=[
                build_binding_condition()
            ],
            bound_by="ta14-binding-service",
            bound_at=(
                FIXED_TIME + timedelta(minutes=1)
            ),
        )


def test_expired_determination_cannot_be_bound() -> None:
    """Binding must fail after determination validity expires."""

    route_manifest = build_route_manifest()

    determination = create_determination_receipt(
        route_manifest=route_manifest,
        decision=ReplayDecision.ALLOW,
        reasons=[
            "All predicates passed.",
        ],
        issued_at=FIXED_TIME,
        valid_until=(
            FIXED_TIME + timedelta(minutes=2)
        ),
    )

    with pytest.raises(
        ReceiptConstructionError,
        match="Determination expired before binding",
    ):
        create_binding_receipt(
            route_manifest=route_manifest,
            evidence_index=build_evidence_index(),
            ruleset=build_ruleset(),
            determination=determination,
            authority_records=[
                build_authority_record()
            ],
            conditions=[
                build_binding_condition()
            ],
            bound_by="ta14-binding-service",
            bound_at=(
                FIXED_TIME + timedelta(minutes=3)
            ),
        )


def test_commit_receipt_is_signed_and_short_lived() -> None:
    """A binding must produce a signed, time-limited commit receipt."""

    (
        _route_manifest,
        _evidence_index,
        _ruleset,
        _authority_record,
        _determination,
        binding,
        key_pair,
    ) = build_allow_chain()

    assert key_pair is not None

    commit = create_commit_receipt(
        binding=binding,
        authorized_by="ta14-commit-service",
        execution_audience=(
            "synthetic-credit-engine"
        ),
        authorized_at=(
            FIXED_TIME + timedelta(minutes=2)
        ),
        valid_until=(
            FIXED_TIME + timedelta(minutes=7)
        ),
        execution_nonce=(
            "synthetic-fixed-nonce-0001"
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    assert commit.commit_digest is not None
    assert commit.signature is not None
    assert commit.single_use is True
    assert commit.consumed_at is None
    assert commit.revoked_at is None

    result = verify_object_signature(
        commit,
        commit.signature,
        public_key=key_pair.public_key,
    )

    assert result.valid is True


def test_commit_validity_must_extend_beyond_authorization() -> None:
    """A commit cannot expire at or before authorization."""

    (
        _route_manifest,
        _evidence_index,
        _ruleset,
        _authority_record,
        _determination,
        binding,
        _key_pair,
    ) = build_allow_chain(
        signed=False
    )

    with pytest.raises(
        ReceiptConstructionError,
        match="valid_until must be later than authorized_at",
    ):
        create_commit_receipt(
            binding=binding,
            authorized_by="ta14-commit-service",
            execution_audience=(
                "synthetic-credit-engine"
            ),
            authorized_at=FIXED_TIME,
            valid_until=FIXED_TIME,
        )


def test_single_use_commit_can_only_be_consumed_once() -> None:
    """A single-use commitment must reject duplicate consumption."""

    (
        _route_manifest,
        _evidence_index,
        _ruleset,
        _authority_record,
        _determination,
        binding,
        _key_pair,
    ) = build_allow_chain(
        signed=False
    )

    commit = create_commit_receipt(
        binding=binding,
        authorized_by="ta14-commit-service",
        execution_audience=(
            "synthetic-credit-engine"
        ),
        authorized_at=(
            FIXED_TIME + timedelta(minutes=2)
        ),
        valid_until=(
            FIXED_TIME + timedelta(minutes=7)
        ),
        execution_nonce=(
            "synthetic-fixed-nonce-0002"
        ),
    )

    consumed = mark_commit_consumed(
        commit,
        consumed_at=(
            FIXED_TIME + timedelta(minutes=3)
        ),
    )

    assert consumed.consumed_at == (
        FIXED_TIME + timedelta(minutes=3)
    )

    assert consumed.commit_digest is not None

    with pytest.raises(
        ReceiptConstructionError,
        match="already been consumed",
    ):
        mark_commit_consumed(
            consumed,
            consumed_at=(
                FIXED_TIME + timedelta(minutes=4)
            ),
        )


def test_unused_commit_can_be_revoked() -> None:
    """An unused commit may be revoked with a preserved reason."""

    (
        _route_manifest,
        _evidence_index,
        _ruleset,
        _authority_record,
        _determination,
        binding,
        _key_pair,
    ) = build_allow_chain(
        signed=False
    )

    commit = create_commit_receipt(
        binding=binding,
        authorized_by="ta14-commit-service",
        execution_audience=(
            "synthetic-credit-engine"
        ),
        authorized_at=(
            FIXED_TIME + timedelta(minutes=2)
        ),
        valid_until=(
            FIXED_TIME + timedelta(minutes=7)
        ),
        execution_nonce=(
            "synthetic-fixed-nonce-0003"
        ),
    )

    revoked = revoke_commit_receipt(
        commit,
        reason=(
            "Authority was withdrawn before execution."
        ),
        revoked_at=(
            FIXED_TIME + timedelta(minutes=3)
        ),
    )

    assert revoked.revoked_at is not None
    assert (
        revoked.revocation_reason
        == "Authority was withdrawn before execution."
    )

    assert revoked.commit_digest is not None


def test_revoked_commit_cannot_authorize_execution() -> None:
    """Execution must fail when the governing commit was revoked."""

    (
        route_manifest,
        _evidence_index,
        _ruleset,
        _authority_record,
        _determination,
        binding,
        _key_pair,
    ) = build_allow_chain(
        signed=False
    )

    commit = create_commit_receipt(
        binding=binding,
        authorized_by="ta14-commit-service",
        execution_audience=(
            "synthetic-credit-engine"
        ),
        authorized_at=(
            FIXED_TIME + timedelta(minutes=2)
        ),
        valid_until=(
            FIXED_TIME + timedelta(minutes=7)
        ),
        execution_nonce=(
            "synthetic-fixed-nonce-0004"
        ),
    )

    revoked = revoke_commit_receipt(
        commit,
        reason="Execution route withdrawn.",
        revoked_at=(
            FIXED_TIME + timedelta(minutes=3)
        ),
    )

    with pytest.raises(
        ReceiptConstructionError,
        match="revoked commit receipt cannot authorize execution",
    ):
        create_execution_receipt(
            commit=revoked,
            executor_id="agent-credit-engine-001",
            execution_system=(
                "synthetic-credit-engine"
            ),
            submitted_action_digest=(
                route_manifest.proposed_action.action_digest
            ),
            status="BLOCKED",
            started_at=(
                FIXED_TIME + timedelta(minutes=4)
            ),
            completed_at=(
                FIXED_TIME + timedelta(
                    minutes=4,
                    seconds=1,
                )
            ),
        )


def test_completed_execution_requires_matching_action() -> None:
    """A changed action cannot be recorded as completed."""

    (
        _route_manifest,
        _evidence_index,
        _ruleset,
        _authority_record,
        _determination,
        binding,
        _key_pair,
    ) = build_allow_chain(
        signed=False
    )

    commit = create_commit_receipt(
        binding=binding,
        authorized_by="ta14-commit-service",
        execution_audience=(
            "synthetic-credit-engine"
        ),
        authorized_at=(
            FIXED_TIME + timedelta(minutes=2)
        ),
        valid_until=(
            FIXED_TIME + timedelta(minutes=7)
        ),
        execution_nonce=(
            "synthetic-fixed-nonce-0005"
        ),
    )

    consumed = mark_commit_consumed(
        commit,
        consumed_at=(
            FIXED_TIME + timedelta(minutes=3)
        ),
    )

    with pytest.raises(
        ReceiptConstructionError,
        match="mismatched action cannot be recorded as COMPLETED",
    ):
        create_execution_receipt(
            commit=consumed,
            executor_id="agent-credit-engine-001",
            execution_system=(
                "synthetic-credit-engine"
            ),
            submitted_action_digest=fixed_digest("f"),
            status="COMPLETED",
            started_at=(
                FIXED_TIME + timedelta(minutes=3)
            ),
            completed_at=(
                FIXED_TIME + timedelta(
                    minutes=3,
                    seconds=2,
                )
            ),
        )


def test_complete_signed_execution_and_outcome_chain() -> None:
    """A valid route must produce signed execution and outcome records."""

    (
        route_manifest,
        _evidence_index,
        _ruleset,
        _authority_record,
        _determination,
        binding,
        key_pair,
    ) = build_allow_chain()

    assert key_pair is not None

    commit = create_commit_receipt(
        binding=binding,
        authorized_by="ta14-commit-service",
        execution_audience=(
            "synthetic-credit-engine"
        ),
        authorized_at=(
            FIXED_TIME + timedelta(minutes=2)
        ),
        valid_until=(
            FIXED_TIME + timedelta(minutes=7)
        ),
        execution_nonce=(
            "synthetic-fixed-nonce-0006"
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    consumed = mark_commit_consumed(
        commit,
        consumed_at=(
            FIXED_TIME + timedelta(minutes=3)
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    execution = create_execution_receipt(
        commit=consumed,
        executor_id="agent-credit-engine-001",
        execution_system=(
            "synthetic-credit-engine"
        ),
        execution_system_version="1.0.0",
        submitted_action_digest=(
            route_manifest.proposed_action.action_digest
        ),
        status="COMPLETED",
        started_at=(
            FIXED_TIME + timedelta(minutes=3)
        ),
        completed_at=(
            FIXED_TIME + timedelta(
                minutes=3,
                seconds=2,
            )
        ),
        result_digest=digest_text(
            "synthetic-transfer-completed"
        ),
        result_reference=(
            "urn:ta14:test:execution:001"
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    assert execution.action_binding_matched is True
    assert execution.execution_digest is not None
    assert execution.signature is not None

    execution_verification = verify_object_signature(
        execution,
        execution.signature,
        public_key=key_pair.public_key,
    )

    assert execution_verification.valid is True

    outcome = create_outcome_record(
        execution=execution,
        observer_id="synthetic-ledger-observer",
        observation_system=(
            "synthetic-settlement-ledger"
        ),
        intended_outcome=(
            "The authorized synthetic transfer is completed once."
        ),
        observed_outcome=(
            "The authorized synthetic transfer completed once."
        ),
        consequence_matched=True,
        remained_within_binding_conditions=True,
        authority_remained_valid=True,
        evidence_remained_valid=True,
        observed_at=(
            FIXED_TIME + timedelta(minutes=4)
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    assert outcome.outcome_digest is not None
    assert outcome.signature is not None
    assert outcome.divergences == []

    outcome_verification = verify_object_signature(
        outcome,
        outcome.signature,
        public_key=key_pair.public_key,
    )

    assert outcome_verification.valid is True


def test_mismatched_outcome_requires_divergence() -> None:
    """A consequence mismatch must preserve a divergence record."""

    (
        route_manifest,
        _evidence_index,
        _ruleset,
        _authority_record,
        _determination,
        binding,
        _key_pair,
    ) = build_allow_chain(
        signed=False
    )

    commit = create_commit_receipt(
        binding=binding,
        authorized_by="ta14-commit-service",
        execution_audience=(
            "synthetic-credit-engine"
        ),
        authorized_at=(
            FIXED_TIME + timedelta(minutes=2)
        ),
        valid_until=(
            FIXED_TIME + timedelta(minutes=7)
        ),
        execution_nonce=(
            "synthetic-fixed-nonce-0007"
        ),
    )

    consumed = mark_commit_consumed(
        commit,
        consumed_at=(
            FIXED_TIME + timedelta(minutes=3)
        ),
    )

    execution = create_execution_receipt(
        commit=consumed,
        executor_id="agent-credit-engine-001",
        execution_system=(
            "synthetic-credit-engine"
        ),
        submitted_action_digest=(
            route_manifest.proposed_action.action_digest
        ),
        status="COMPLETED",
        started_at=(
            FIXED_TIME + timedelta(minutes=3)
        ),
        completed_at=(
            FIXED_TIME + timedelta(
                minutes=3,
                seconds=2,
            )
        ),
    )

    with pytest.raises(
        ReceiptConstructionError,
        match="mismatched consequence requires at least one divergence",
    ):
        create_outcome_record(
            execution=execution,
            observer_id="synthetic-ledger-observer",
            observation_system=(
                "synthetic-settlement-ledger"
            ),
            intended_outcome=(
                "One authorized transfer."
            ),
            observed_outcome=(
                "Two transfers were observed."
            ),
            consequence_matched=False,
            remained_within_binding_conditions=False,
            authority_remained_valid=True,
            evidence_remained_valid=True,
            observed_at=(
                FIXED_TIME + timedelta(minutes=4)
            ),
        )


def test_mismatched_outcome_with_divergence_is_preserved() -> None:
    """A divergence record must explain the observed consequence mismatch."""

    (
        route_manifest,
        _evidence_index,
        _ruleset,
        _authority_record,
        _determination,
        binding,
        _key_pair,
    ) = build_allow_chain(
        signed=False
    )

    commit = create_commit_receipt(
        binding=binding,
        authorized_by="ta14-commit-service",
        execution_audience=(
            "synthetic-credit-engine"
        ),
        authorized_at=(
            FIXED_TIME + timedelta(minutes=2)
        ),
        valid_until=(
            FIXED_TIME + timedelta(minutes=7)
        ),
        execution_nonce=(
            "synthetic-fixed-nonce-0008"
        ),
    )

    consumed = mark_commit_consumed(
        commit,
        consumed_at=(
            FIXED_TIME + timedelta(minutes=3)
        ),
    )

    execution = create_execution_receipt(
        commit=consumed,
        executor_id="agent-credit-engine-001",
        execution_system=(
            "synthetic-credit-engine"
        ),
        submitted_action_digest=(
            route_manifest.proposed_action.action_digest
        ),
        status="COMPLETED",
        started_at=(
            FIXED_TIME + timedelta(minutes=3)
        ),
        completed_at=(
            FIXED_TIME + timedelta(
                minutes=3,
                seconds=2,
            )
        ),
    )

    divergence = DivergenceRecord(
        route_id=execution.route_id,
        detected_at=(
            FIXED_TIME + timedelta(minutes=4)
        ),
        category="DUPLICATE_EXECUTION",
        severity="CRITICAL",
        description=(
            "Two consequences were observed for a single-use commit."
        ),
        expected_state={
            "transfer_count": 1,
        },
        observed_state={
            "transfer_count": 2,
        },
        evidence_ids=[],
        requires_re_evaluation=True,
        requires_escalation=True,
        remediation_actions=[
            "Freeze the execution route.",
            "Escalate to independent review.",
        ],
    )

    outcome = create_outcome_record(
        execution=execution,
        observer_id="synthetic-ledger-observer",
        observation_system=(
            "synthetic-settlement-ledger"
        ),
        intended_outcome=(
            "One authorized transfer."
        ),
        observed_outcome=(
            "Two transfers were observed."
        ),
        consequence_matched=False,
        remained_within_binding_conditions=False,
        authority_remained_valid=True,
        evidence_remained_valid=True,
        divergences=[
            divergence
        ],
        observed_at=(
            FIXED_TIME + timedelta(minutes=4)
        ),
    )

    assert outcome.consequence_matched is False
    assert len(outcome.divergences) == 1
    assert (
        outcome.divergences[0].category
        == "DUPLICATE_EXECUTION"
    )

    assert outcome.outcome_digest is not None


def test_outcome_cannot_precede_execution_completion() -> None:
    """Outcome observation cannot occur before execution completion."""

    (
        route_manifest,
        _evidence_index,
        _ruleset,
        _authority_record,
        _determination,
        binding,
        _key_pair,
    ) = build_allow_chain(
        signed=False
    )

    commit = create_commit_receipt(
        binding=binding,
        authorized_by="ta14-commit-service",
        execution_audience=(
            "synthetic-credit-engine"
        ),
        authorized_at=(
            FIXED_TIME + timedelta(minutes=2)
        ),
        valid_until=(
            FIXED_TIME + timedelta(minutes=7)
        ),
        execution_nonce=(
            "synthetic-fixed-nonce-0009"
        ),
    )

    consumed = mark_commit_consumed(
        commit,
        consumed_at=(
            FIXED_TIME + timedelta(minutes=3)
        ),
    )

    execution = create_execution_receipt(
        commit=consumed,
        executor_id="agent-credit-engine-001",
        execution_system=(
            "synthetic-credit-engine"
        ),
        submitted_action_digest=(
            route_manifest.proposed_action.action_digest
        ),
        status="COMPLETED",
        started_at=(
            FIXED_TIME + timedelta(minutes=3)
        ),
        completed_at=(
            FIXED_TIME + timedelta(minutes=4)
        ),
    )

    with pytest.raises(
        ReceiptConstructionError,
        match="cannot precede execution completion",
    ):
        create_outcome_record(
            execution=execution,
            observer_id="synthetic-ledger-observer",
            observation_system=(
                "synthetic-settlement-ledger"
            ),
            intended_outcome="One transfer.",
            observed_outcome="One transfer.",
            consequence_matched=True,
            remained_within_binding_conditions=True,
            authority_remained_valid=True,
            evidence_remained_valid=True,
            observed_at=(
                FIXED_TIME + timedelta(
                    minutes=3,
                    seconds=30,
                )
            ),
        )
