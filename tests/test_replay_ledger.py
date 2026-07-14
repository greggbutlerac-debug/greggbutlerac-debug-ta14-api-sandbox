"""
Tests for the TA-14 Independent Route Replay append-only ledger.

These tests verify:

- empty ledger creation;
- ordered event appends;
- route consistency;
- deterministic event digests;
- signed ledger events;
- hash linkage;
- tamper detection;
- root and final digest validation;
- ledger sealing;
- seal signature verification;
- rejection of post-seal writes;
- rejection of invalid sequence and predecessor state.
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.replay_crypto import (
    digest_object,
    digest_text,
    secure_digest_equal,
    verify_ledger_chain,
)
from app.replay_ledger import (
    LedgerConstructionError,
    append_commit_authorized,
    append_determination_issued,
    append_execution,
    append_outcome_recorded,
    append_route_bound,
    append_route_created,
    create_ledger,
    create_ledger_event,
    seal_ledger,
    verify_ledger_record,
)
from app.replay_models import (
    BindingCondition,
    ChainLinkState,
    EvidenceIndex,
    PredicateResult,
    ProposedAction,
    ReplayDecision,
    RouteEventType,
    RouteManifest,
    RulesetRecord,
)
from app.replay_receipts import (
    create_binding_receipt,
    create_commit_receipt,
    create_determination_receipt,
    create_execution_receipt,
    create_outcome_record,
    mark_commit_consumed,
)
from app.replay_signing import (
    generate_key_pair,
    verify_object_signature,
)


FIXED_TIME = datetime(
    2026,
    7,
    14,
    16,
    0,
    0,
    tzinfo=timezone.utc,
)

SIGNER = "TA-14 Ledger Test Signer"


def build_action() -> ProposedAction:
    """Create a deterministic proposed action fixture."""

    action = ProposedAction(
        action_type="synthetic-governed-transfer",
        actor_id="agent-001",
        target="synthetic-target",
        description="Execute one bounded synthetic transfer.",
        parameters={
            "amount": 1000,
            "currency": "USD",
        },
        requested_at=FIXED_TIME,
        requested_execution_time=(
            FIXED_TIME + timedelta(minutes=5)
        ),
        consequence_class="financial",
        reversible=False,
        maximum_impact="Synthetic test only.",
    )

    return action.model_copy(
        update={
            "action_digest": digest_object(action),
        }
    )


def build_ruleset() -> RulesetRecord:
    """Create a deterministic ruleset fixture."""

    return RulesetRecord(
        ruleset_id="ta14-ledger-test-ruleset",
        ruleset_version="1.0.0",
        architecture_version="24-link-test-1.0.0",
        effective_from=(
            FIXED_TIME - timedelta(days=1)
        ),
        effective_until=(
            FIXED_TIME + timedelta(days=30)
        ),
        ruleset_digest=digest_text(
            "ta14-ledger-test-ruleset"
        ),
        rules=[],
        signed_by=None,
    )


def build_route_manifest(
    *,
    route_id=None,
) -> RouteManifest:
    """Create a route manifest with a deterministic digest."""

    resolved_route_id = route_id or uuid4()
    ruleset = build_ruleset()

    predicate = PredicateResult(
        predicate_id="authority-valid",
        link_number=8,
        link_name="Authority",
        description="Authority must remain valid.",
        satisfied=True,
        required=True,
        observed_value="ACTIVE",
        expected_value="ACTIVE",
        evidence_ids=[],
        authority_ids=[],
        rule_ids=["AUTHORITY-VALID"],
        evaluated_at=FIXED_TIME,
        evaluator_version="ledger-test-engine-1.0.0",
        reason="Authority is active.",
    )

    link = ChainLinkState(
        link_number=8,
        link_name="Authority",
        satisfied=True,
        required=True,
        status="PASS",
        predicate_ids=["authority-valid"],
        evidence_ids=[],
        reason="Authority requirement passed.",
    )

    manifest = RouteManifest(
        route_id=resolved_route_id,
        request_id=uuid4(),
        correlation_id="ledger-test-001",
        created_at=FIXED_TIME,
        expires_at=(
            FIXED_TIME + timedelta(minutes=30)
        ),
        architecture_version="24-link-test-1.0.0",
        proposed_action=build_action(),
        evidence_ids=[],
        authority_ids=[],
        jurisdiction_ids=["US"],
        ruleset_id=ruleset.ruleset_id,
        ruleset_version=ruleset.ruleset_version,
        ruleset_digest=ruleset.ruleset_digest,
        chain_links=[link],
        predicates=[predicate],
        input_digest=digest_text(
            "ledger-test-input"
        ),
        re_evaluation_required_when=[
            "Authority changes.",
            "Action changes.",
        ],
        metadata={
            "scenario": "ledger-test",
        },
    )

    return manifest.model_copy(
        update={
            "manifest_digest": digest_object(manifest),
        }
    )


def build_receipt_chain():
    """
    Build a complete signed route from determination through outcome.
    """

    key_pair = generate_key_pair()
    route_manifest = build_route_manifest()
    ruleset = build_ruleset()

    evidence_index = EvidenceIndex(
        generated_at=FIXED_TIME,
        entries=[],
    ).model_copy(
        update={
            "index_digest": digest_object(
                EvidenceIndex(
                    generated_at=FIXED_TIME,
                    entries=[],
                )
            )
        }
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
        signer=SIGNER,
    )

    binding = create_binding_receipt(
        route_manifest=route_manifest,
        evidence_index=evidence_index,
        ruleset=ruleset,
        determination=determination,
        authority_records=[],
        conditions=[
            BindingCondition(
                condition_id="exact-action",
                description=(
                    "The submitted action digest must remain unchanged."
                ),
                required=True,
                expected_value=(
                    route_manifest.proposed_action.action_digest.value
                ),
                evidence_ids=[],
                rule_ids=["EXACT-ACTION"],
            )
        ],
        bound_by="ta14-binding-service",
        bound_at=(
            FIXED_TIME + timedelta(minutes=1)
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    commit = create_commit_receipt(
        binding=binding,
        authorized_by="ta14-commit-service",
        execution_audience="synthetic-executor",
        authorized_at=(
            FIXED_TIME + timedelta(minutes=2)
        ),
        valid_until=(
            FIXED_TIME + timedelta(minutes=7)
        ),
        execution_nonce="ledger-test-nonce-0001",
        key_pair=key_pair,
        signer=SIGNER,
    )

    consumed_commit = mark_commit_consumed(
        commit,
        consumed_at=(
            FIXED_TIME + timedelta(minutes=3)
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    execution = create_execution_receipt(
        commit=consumed_commit,
        executor_id="agent-001",
        execution_system="synthetic-executor",
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
            "synthetic-execution-result"
        ),
        result_reference=(
            "urn:ta14:test:execution:ledger"
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    outcome = create_outcome_record(
        execution=execution,
        observer_id="synthetic-observer",
        observation_system="synthetic-outcome-system",
        intended_outcome="One bounded synthetic transfer.",
        observed_outcome="One bounded synthetic transfer.",
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

    return {
        "key_pair": key_pair,
        "route_manifest": route_manifest,
        "determination": determination,
        "binding": binding,
        "commit": consumed_commit,
        "execution": execution,
        "outcome": outcome,
    }


def test_create_empty_ledger() -> None:
    """A new ledger must be open and contain no events."""

    route_id = uuid4()

    ledger = create_ledger(
        route_id=route_id,
        created_at=FIXED_TIME,
    )

    assert ledger.route_id == route_id
    assert ledger.events == []
    assert ledger.root_digest is None
    assert ledger.final_event_digest is None
    assert ledger.sealed_at is None
    assert ledger.seal_signature is None
    assert verify_ledger_record(ledger)


def test_first_event_must_not_have_previous_digest() -> None:
    """Sequence one must never reference a predecessor."""

    with pytest.raises(
        LedgerConstructionError,
        match="first ledger event cannot contain a previous digest",
    ):
        create_ledger_event(
            sequence=1,
            route_id=uuid4(),
            event_type=RouteEventType.ROUTE_CREATED,
            actor="test-actor",
            object_type="route_manifest",
            object_id="route-001",
            object_digest=digest_text("route"),
            previous_event_digest=digest_text("previous"),
            occurred_at=FIXED_TIME,
        )


def test_later_event_requires_previous_digest() -> None:
    """Every event after sequence one must reference its predecessor."""

    with pytest.raises(
        LedgerConstructionError,
        match="requires previous_event_digest",
    ):
        create_ledger_event(
            sequence=2,
            route_id=uuid4(),
            event_type=RouteEventType.DETERMINATION_ISSUED,
            actor="test-actor",
            object_type="determination_receipt",
            object_id="determination-001",
            object_digest=digest_text("determination"),
            previous_event_digest=None,
            occurred_at=FIXED_TIME,
        )


def test_route_created_is_first_event() -> None:
    """The route manifest must become the root ledger event."""

    route_manifest = build_route_manifest()

    ledger = create_ledger(
        route_id=route_manifest.route_id,
        created_at=FIXED_TIME,
    )

    ledger = append_route_created(
        ledger,
        route_manifest=route_manifest,
        actor="ta14-route-service",
    )

    assert len(ledger.events) == 1
    assert ledger.events[0].sequence == 1
    assert (
        ledger.events[0].event_type
        == RouteEventType.ROUTE_CREATED
    )
    assert ledger.events[0].previous_event_digest is None
    assert ledger.events[0].event_digest is not None

    assert secure_digest_equal(
        ledger.root_digest,
        ledger.events[0].event_digest,
    )

    assert secure_digest_equal(
        ledger.final_event_digest,
        ledger.events[0].event_digest,
    )

    assert verify_ledger_record(ledger)


def test_route_created_cannot_be_appended_twice() -> None:
    """A ledger cannot contain two route-root events."""

    route_manifest = build_route_manifest()

    ledger = create_ledger(
        route_id=route_manifest.route_id,
        created_at=FIXED_TIME,
    )

    ledger = append_route_created(
        ledger,
        route_manifest=route_manifest,
        actor="ta14-route-service",
    )

    with pytest.raises(
        LedgerConstructionError,
        match="must be the first ledger event",
    ):
        append_route_created(
            ledger,
            route_manifest=route_manifest,
            actor="ta14-route-service",
        )


def test_cross_route_object_is_rejected() -> None:
    """An object from another route must not enter the ledger."""

    first_manifest = build_route_manifest()
    second_manifest = build_route_manifest()

    ledger = create_ledger(
        route_id=first_manifest.route_id,
        created_at=FIXED_TIME,
    )

    with pytest.raises(
        LedgerConstructionError,
        match="belongs to a different route",
    ):
        append_route_created(
            ledger,
            route_manifest=second_manifest,
            actor="ta14-route-service",
        )


def test_complete_receipt_chain_builds_valid_ledger() -> None:
    """A full governed route must form one valid hash-linked history."""

    chain = build_receipt_chain()

    route_manifest = chain["route_manifest"]

    ledger = create_ledger(
        route_id=route_manifest.route_id,
        created_at=FIXED_TIME,
    )

    ledger = append_route_created(
        ledger,
        route_manifest=route_manifest,
        actor="ta14-route-service",
    )

    ledger = append_determination_issued(
        ledger,
        determination=chain["determination"],
        actor="ta14-determination-service",
    )

    ledger = append_route_bound(
        ledger,
        binding=chain["binding"],
        actor="ta14-binding-service",
    )

    ledger = append_commit_authorized(
        ledger,
        commit=chain["commit"],
        actor="ta14-commit-service",
    )

    ledger = append_execution(
        ledger,
        execution=chain["execution"],
        actor="synthetic-executor",
    )

    ledger = append_outcome_recorded(
        ledger,
        outcome=chain["outcome"],
        actor="synthetic-observer",
    )

    assert len(ledger.events) == 6

    assert [
        event.sequence
        for event in ledger.events
    ] == [1, 2, 3, 4, 5, 6]

    assert [
        event.event_type
        for event in ledger.events
    ] == [
        RouteEventType.ROUTE_CREATED,
        RouteEventType.DETERMINATION_ISSUED,
        RouteEventType.ROUTE_BOUND,
        RouteEventType.COMMIT_AUTHORIZED,
        RouteEventType.EXECUTION_COMPLETED,
        RouteEventType.OUTCOME_RECORDED,
    ]

    assert verify_ledger_chain(ledger.events)
    assert verify_ledger_record(ledger)

    for index, event in enumerate(
        ledger.events
    ):
        assert event.event_digest is not None

        if index == 0:
            assert event.previous_event_digest is None
        else:
            previous_event = ledger.events[
                index - 1
            ]

            assert secure_digest_equal(
                event.previous_event_digest,
                previous_event.event_digest,
            )


def test_signed_events_verify_independently() -> None:
    """Every signed ledger event must verify with the public key."""

    chain = build_receipt_chain()
    key_pair = chain["key_pair"]
    route_manifest = chain["route_manifest"]

    ledger = create_ledger(
        route_id=route_manifest.route_id,
        created_at=FIXED_TIME,
    )

    ledger = append_route_created(
        ledger,
        route_manifest=route_manifest,
        actor="ta14-route-service",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_determination_issued(
        ledger,
        determination=chain["determination"],
        actor="ta14-determination-service",
        key_pair=key_pair,
        signer=SIGNER,
    )

    for event in ledger.events:
        assert event.signature is not None

        result = verify_object_signature(
            event,
            event.signature,
            public_key=key_pair.public_key,
        )

        assert result.valid is True


def test_event_tampering_breaks_ledger_verification() -> None:
    """Changing a preserved ledger event must invalidate the chain."""

    chain = build_receipt_chain()
    route_manifest = chain["route_manifest"]

    ledger = create_ledger(
        route_id=route_manifest.route_id,
        created_at=FIXED_TIME,
    )

    ledger = append_route_created(
        ledger,
        route_manifest=route_manifest,
        actor="ta14-route-service",
    )

    ledger = append_determination_issued(
        ledger,
        determination=chain["determination"],
        actor="ta14-determination-service",
    )

    tampered_event = ledger.events[0].model_copy(
        update={
            "actor": "unauthorized-actor",
        }
    )

    tampered_ledger = ledger.model_copy(
        update={
            "events": [
                tampered_event,
                ledger.events[1],
            ]
        }
    )

    assert not verify_ledger_chain(
        tampered_ledger.events
    )

    assert not verify_ledger_record(
        tampered_ledger
    )


def test_wrong_root_digest_fails_verification() -> None:
    """Stored root digest must match the first event digest."""

    route_manifest = build_route_manifest()

    ledger = create_ledger(
        route_id=route_manifest.route_id,
        created_at=FIXED_TIME,
    )

    ledger = append_route_created(
        ledger,
        route_manifest=route_manifest,
        actor="ta14-route-service",
    )

    altered = ledger.model_copy(
        update={
            "root_digest": digest_text(
                "wrong-root"
            ),
        }
    )

    assert not verify_ledger_record(altered)


def test_wrong_final_digest_fails_verification() -> None:
    """Stored final digest must match the last event digest."""

    chain = build_receipt_chain()
    route_manifest = chain["route_manifest"]

    ledger = create_ledger(
        route_id=route_manifest.route_id,
        created_at=FIXED_TIME,
    )

    ledger = append_route_created(
        ledger,
        route_manifest=route_manifest,
        actor="ta14-route-service",
    )

    ledger = append_determination_issued(
        ledger,
        determination=chain["determination"],
        actor="ta14-determination-service",
    )

    altered = ledger.model_copy(
        update={
            "final_event_digest": digest_text(
                "wrong-final"
            ),
        }
    )

    assert not verify_ledger_record(altered)


def test_open_ledger_can_be_sealed() -> None:
    """A valid non-empty ledger must support deterministic sealing."""

    chain = build_receipt_chain()
    route_manifest = chain["route_manifest"]

    ledger = create_ledger(
        route_id=route_manifest.route_id,
        created_at=FIXED_TIME,
    )

    ledger = append_route_created(
        ledger,
        route_manifest=route_manifest,
        actor="ta14-route-service",
    )

    sealed = seal_ledger(
        ledger,
        sealed_at=(
            FIXED_TIME + timedelta(minutes=1)
        ),
    )

    assert sealed.sealed_at == (
        FIXED_TIME + timedelta(minutes=1)
    )

    assert sealed.seal_signature is None
    assert verify_ledger_record(sealed)


def test_signed_ledger_seal_verifies() -> None:
    """The final ledger seal must verify with the signer public key."""

    chain = build_receipt_chain()
    key_pair = chain["key_pair"]
    route_manifest = chain["route_manifest"]

    ledger = create_ledger(
        route_id=route_manifest.route_id,
        created_at=FIXED_TIME,
    )

    ledger = append_route_created(
        ledger,
        route_manifest=route_manifest,
        actor="ta14-route-service",
    )

    sealed = seal_ledger(
        ledger,
        sealed_at=(
            FIXED_TIME + timedelta(minutes=1)
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    assert sealed.seal_signature is not None

    result = verify_object_signature(
        sealed,
        sealed.seal_signature,
        public_key=key_pair.public_key,
    )

    assert result.valid is True


def test_empty_ledger_cannot_be_sealed() -> None:
    """An empty ledger has no route history to seal."""

    ledger = create_ledger(
        route_id=uuid4(),
        created_at=FIXED_TIME,
    )

    with pytest.raises(
        LedgerConstructionError,
        match="empty ledger cannot be sealed",
    ):
        seal_ledger(
            ledger,
            sealed_at=FIXED_TIME,
        )


def test_seal_cannot_precede_final_event() -> None:
    """Ledger sealing cannot occur before the final preserved event."""

    route_manifest = build_route_manifest()

    ledger = create_ledger(
        route_id=route_manifest.route_id,
        created_at=FIXED_TIME,
    )

    ledger = append_route_created(
        ledger,
        route_manifest=route_manifest,
        actor="ta14-route-service",
    )

    with pytest.raises(
        LedgerConstructionError,
        match="cannot precede the final ledger event",
    ):
        seal_ledger(
            ledger,
            sealed_at=(
                FIXED_TIME - timedelta(seconds=1)
            ),
        )


def test_sealed_ledger_rejects_new_events() -> None:
    """No route event may be appended after the ledger is sealed."""

    chain = build_receipt_chain()
    route_manifest = chain["route_manifest"]

    ledger = create_ledger(
        route_id=route_manifest.route_id,
        created_at=FIXED_TIME,
    )

    ledger = append_route_created(
        ledger,
        route_manifest=route_manifest,
        actor="ta14-route-service",
    )

    sealed = seal_ledger(
        ledger,
        sealed_at=(
            FIXED_TIME + timedelta(minutes=1)
        ),
    )

    with pytest.raises(
        LedgerConstructionError,
        match="sealed ledger cannot accept additional events",
    ):
        append_determination_issued(
            sealed,
            determination=chain["determination"],
            actor="ta14-determination-service",
        )
