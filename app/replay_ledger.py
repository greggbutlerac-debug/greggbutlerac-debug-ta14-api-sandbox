"""
TA-14 Independent Route Replay Standard
Append-only, hash-linked replay ledger.

Purpose
-------
This module converts separate route records into one ordered and
tamper-evident event history.

The ledger preserves:

- route creation;
- evidence registration;
- authority registration;
- ruleset binding;
- determination issuance;
- route binding;
- commit authorization;
- execution;
- outcome;
- divergence;
- package sealing;
- independent verification.

Each event contains:

- a strict sequence number;
- the governed route ID;
- the object type and object ID;
- the digest of the preserved object;
- the digest of the previous ledger event;
- its own deterministic event digest;
- an optional Ed25519 signature.

Any alteration to an earlier event breaks the chain from that point forward.

This module is additive and does not alter existing public sandbox endpoints.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional, Sequence
from uuid import UUID

from .replay_crypto import (
    apply_ledger_event_digest,
    digest_object,
    secure_digest_equal,
    verify_ledger_chain,
)
from .replay_models import (
    DigestRecord,
    LedgerEvent,
    LedgerRecord,
    RouteEventType,
)
from .replay_signing import (
    Ed25519KeyPair,
    sign_object,
)


class LedgerConstructionError(ValueError):
    """Raised when a replay ledger cannot be constructed safely."""


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


def _require_aware_datetime(
    value: datetime,
    *,
    field_name: str,
) -> datetime:
    """Reject timestamps that do not contain an explicit timezone."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise LedgerConstructionError(
            f"{field_name} must be timezone-aware."
        )

    return value


def _require_nonempty_text(
    value: str,
    *,
    field_name: str,
) -> str:
    """Validate and normalize required text fields."""

    normalized = value.strip()

    if not normalized:
        raise LedgerConstructionError(
            f"{field_name} must not be empty."
        )

    return normalized


def _require_same_route(
    expected_route_id: UUID,
    observed_route_id: UUID,
    *,
    object_name: str,
) -> None:
    """Require an event object to belong to the same route."""

    if expected_route_id != observed_route_id:
        raise LedgerConstructionError(
            f"{object_name} belongs to a different route."
        )


def _event_object_id(
    value: Any,
    *,
    explicit_object_id: Optional[str] = None,
) -> str:
    """
    Resolve the preserved object's stable identifier.

    Explicit identifiers take priority. Otherwise known model identifier
    fields are inspected in deterministic order.
    """

    if explicit_object_id is not None:
        return _require_nonempty_text(
            explicit_object_id,
            field_name="object_id",
        )

    candidate_fields = (
        "package_id",
        "report_id",
        "outcome_id",
        "execution_id",
        "commit_id",
        "binding_id",
        "receipt_id",
        "authority_id",
        "evidence_id",
        "route_id",
        "request_id",
        "ruleset_id",
    )

    for field_name in candidate_fields:
        candidate = getattr(
            value,
            field_name,
            None,
        )

        if candidate is not None:
            return str(candidate)

    raise LedgerConstructionError(
        "Unable to determine a stable object_id. "
        "Provide explicit_object_id."
    )


def _event_route_id(
    value: Any,
    *,
    explicit_route_id: Optional[UUID] = None,
) -> UUID:
    """Resolve the governed route ID from an object or explicit argument."""

    if explicit_route_id is not None:
        return explicit_route_id

    route_id = getattr(
        value,
        "route_id",
        None,
    )

    if route_id is None:
        raise LedgerConstructionError(
            "Unable to determine route_id from the preserved object."
        )

    return route_id


def _event_timestamp(
    value: Any,
    *,
    explicit_occurred_at: Optional[datetime] = None,
) -> datetime:
    """
    Resolve an event timestamp from an explicit value or known model fields.
    """

    if explicit_occurred_at is not None:
        return _require_aware_datetime(
            explicit_occurred_at,
            field_name="occurred_at",
        )

    candidate_fields = (
        "verified_at",
        "sealed_at",
        "observed_at",
        "completed_at",
        "started_at",
        "consumed_at",
        "revoked_at",
        "authorized_at",
        "bound_at",
        "issued_at",
        "created_at",
        "generated_at",
        "effective_from",
        "granted_at",
    )

    for field_name in candidate_fields:
        candidate = getattr(
            value,
            field_name,
            None,
        )

        if candidate is not None:
            return _require_aware_datetime(
                candidate,
                field_name=field_name,
            )

    return utc_now()


def _sign_ledger_event(
    event: LedgerEvent,
    *,
    key_pair: Optional[Ed25519KeyPair],
    signer: Optional[str],
) -> LedgerEvent:
    """Apply an optional Ed25519 signature to a digested ledger event."""

    if key_pair is None:
        return event

    if signer is None:
        raise LedgerConstructionError(
            "signer is required when key_pair is provided."
        )

    signature = sign_object(
        event,
        key_pair=key_pair,
        signer=signer,
    )

    return event.model_copy(
        update={
            "signature": signature,
        }
    )


def create_ledger(
    *,
    route_id: UUID,
    created_at: Optional[datetime] = None,
) -> LedgerRecord:
    """
    Create an empty append-only ledger for one governed route.
    """

    resolved_created_at = created_at or utc_now()

    _require_aware_datetime(
        resolved_created_at,
        field_name="created_at",
    )

    return LedgerRecord(
        route_id=route_id,
        created_at=resolved_created_at,
        events=[],
        root_digest=None,
        final_event_digest=None,
        sealed_at=None,
        seal_signature=None,
    )


def create_ledger_event(
    *,
    sequence: int,
    route_id: UUID,
    event_type: RouteEventType,
    actor: str,
    object_type: str,
    object_id: str,
    object_digest: DigestRecord,
    previous_event_digest: Optional[DigestRecord],
    occurred_at: Optional[datetime] = None,
    metadata: Optional[dict[str, Any]] = None,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> LedgerEvent:
    """
    Create, digest, and optionally sign one ledger event.
    """

    if sequence < 1:
        raise LedgerConstructionError(
            "Ledger sequence must begin at 1."
        )

    resolved_occurred_at = occurred_at or utc_now()

    _require_aware_datetime(
        resolved_occurred_at,
        field_name="occurred_at",
    )

    if sequence == 1 and previous_event_digest is not None:
        raise LedgerConstructionError(
            "The first ledger event cannot contain a previous digest."
        )

    if sequence > 1 and previous_event_digest is None:
        raise LedgerConstructionError(
            "Every ledger event after sequence 1 requires "
            "previous_event_digest."
        )

    event = LedgerEvent(
        sequence=sequence,
        route_id=route_id,
        event_type=event_type,
        occurred_at=resolved_occurred_at,
        actor=_require_nonempty_text(
            actor,
            field_name="actor",
        ),
        object_type=_require_nonempty_text(
            object_type,
            field_name="object_type",
        ),
        object_id=_require_nonempty_text(
            object_id,
            field_name="object_id",
        ),
        object_digest=object_digest,
        previous_event_digest=previous_event_digest,
        metadata=metadata or {},
    )

    digested = apply_ledger_event_digest(event)

    return _sign_ledger_event(
        digested,
        key_pair=key_pair,
        signer=signer,
    )


def append_event(
    ledger: LedgerRecord,
    *,
    event_type: RouteEventType,
    actor: str,
    object_type: str,
    preserved_object: Any,
    object_id: Optional[str] = None,
    occurred_at: Optional[datetime] = None,
    metadata: Optional[dict[str, Any]] = None,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> LedgerRecord:
    """
    Append one preserved object to an open replay ledger.

    The object's digest is calculated canonically. The new event links to the
    exact digest of the previous event.
    """

    if ledger.sealed_at is not None:
        raise LedgerConstructionError(
            "A sealed ledger cannot accept additional events."
        )

    resolved_route_id = _event_route_id(
        preserved_object,
        explicit_route_id=ledger.route_id,
    )

    _require_same_route(
        ledger.route_id,
        resolved_route_id,
        object_name=object_type,
    )

    resolved_object_id = _event_object_id(
        preserved_object,
        explicit_object_id=object_id,
    )

    resolved_occurred_at = _event_timestamp(
        preserved_object,
        explicit_occurred_at=occurred_at,
    )

    object_digest = digest_object(
        preserved_object
    )

    previous_digest = (
        ledger.events[-1].event_digest
        if ledger.events
        else None
    )

    if ledger.events and previous_digest is None:
        raise LedgerConstructionError(
            "The current final ledger event has no event digest."
        )

    event = create_ledger_event(
        sequence=len(ledger.events) + 1,
        route_id=ledger.route_id,
        event_type=event_type,
        actor=actor,
        object_type=object_type,
        object_id=resolved_object_id,
        object_digest=object_digest,
        previous_event_digest=previous_digest,
        occurred_at=resolved_occurred_at,
        metadata=metadata,
        key_pair=key_pair,
        signer=signer,
    )

    updated_events = [
        *ledger.events,
        event,
    ]

    root_digest = updated_events[0].event_digest
    final_event_digest = updated_events[-1].event_digest

    updated = ledger.model_copy(
        update={
            "events": updated_events,
            "root_digest": root_digest,
            "final_event_digest": final_event_digest,
        }
    )

    if not verify_ledger_chain(updated.events):
        raise LedgerConstructionError(
            "Ledger chain failed verification after append."
        )

    return updated


def append_route_created(
    ledger: LedgerRecord,
    *,
    route_manifest: Any,
    actor: str,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> LedgerRecord:
    """Append the route manifest as the first ledger event."""

    if ledger.events:
        raise LedgerConstructionError(
            "ROUTE_CREATED must be the first ledger event."
        )

    return append_event(
        ledger,
        event_type=RouteEventType.ROUTE_CREATED,
        actor=actor,
        object_type="route_manifest",
        preserved_object=route_manifest,
        metadata={
            "stage": "route",
        },
        key_pair=key_pair,
        signer=signer,
    )


def append_evidence_registered(
    ledger: LedgerRecord,
    *,
    evidence_object: Any,
    actor: str,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> LedgerRecord:
    """Append a preserved evidence object."""

    return append_event(
        ledger,
        event_type=RouteEventType.EVIDENCE_REGISTERED,
        actor=actor,
        object_type="evidence_object",
        preserved_object=evidence_object,
        metadata={
            "stage": "evidence",
        },
        key_pair=key_pair,
        signer=signer,
    )


def append_authority_registered(
    ledger: LedgerRecord,
    *,
    authority_record: Any,
    actor: str,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> LedgerRecord:
    """Append an authority record."""

    return append_event(
        ledger,
        event_type=RouteEventType.AUTHORITY_REGISTERED,
        actor=actor,
        object_type="authority_record",
        preserved_object=authority_record,
        metadata={
            "stage": "authority",
        },
        key_pair=key_pair,
        signer=signer,
    )


def append_ruleset_bound(
    ledger: LedgerRecord,
    *,
    ruleset: Any,
    actor: str,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> LedgerRecord:
    """Append the exact ruleset used for determination."""

    return append_event(
        ledger,
        event_type=RouteEventType.RULESET_BOUND,
        actor=actor,
        object_type="ruleset_record",
        preserved_object=ruleset,
        object_id=getattr(
            ruleset,
            "ruleset_id",
            None,
        ),
        metadata={
            "stage": "ruleset",
        },
        key_pair=key_pair,
        signer=signer,
    )


def append_determination_issued(
    ledger: LedgerRecord,
    *,
    determination: Any,
    actor: str,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> LedgerRecord:
    """Append an admissibility determination receipt."""

    return append_event(
        ledger,
        event_type=RouteEventType.DETERMINATION_ISSUED,
        actor=actor,
        object_type="determination_receipt",
        preserved_object=determination,
        metadata={
            "stage": "determination",
            "decision": str(
                getattr(
                    determination,
                    "decision",
                    "",
                )
            ),
        },
        key_pair=key_pair,
        signer=signer,
    )


def append_route_bound(
    ledger: LedgerRecord,
    *,
    binding: Any,
    actor: str,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> LedgerRecord:
    """Append an action-and-condition binding receipt."""

    return append_event(
        ledger,
        event_type=RouteEventType.ROUTE_BOUND,
        actor=actor,
        object_type="binding_receipt",
        preserved_object=binding,
        metadata={
            "stage": "binding",
        },
        key_pair=key_pair,
        signer=signer,
    )


def append_commit_authorized(
    ledger: LedgerRecord,
    *,
    commit: Any,
    actor: str,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> LedgerRecord:
    """Append a commit authorization receipt."""

    return append_event(
        ledger,
        event_type=RouteEventType.COMMIT_AUTHORIZED,
        actor=actor,
        object_type="commit_receipt",
        preserved_object=commit,
        metadata={
            "stage": "commit",
            "single_use": bool(
                getattr(
                    commit,
                    "single_use",
                    False,
                )
            ),
        },
        key_pair=key_pair,
        signer=signer,
    )


def append_execution(
    ledger: LedgerRecord,
    *,
    execution: Any,
    actor: str,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> LedgerRecord:
    """Append an execution receipt using the matching event classification."""

    status = str(
        getattr(
            execution,
            "status",
            "",
        )
    ).upper()

    if status == "STARTED":
        event_type = RouteEventType.EXECUTION_STARTED
    elif status == "BLOCKED":
        event_type = RouteEventType.EXECUTION_BLOCKED
    else:
        event_type = RouteEventType.EXECUTION_COMPLETED

    return append_event(
        ledger,
        event_type=event_type,
        actor=actor,
        object_type="execution_receipt",
        preserved_object=execution,
        metadata={
            "stage": "execution",
            "status": status,
            "action_binding_matched": bool(
                getattr(
                    execution,
                    "action_binding_matched",
                    False,
                )
            ),
        },
        key_pair=key_pair,
        signer=signer,
    )


def append_outcome_recorded(
    ledger: LedgerRecord,
    *,
    outcome: Any,
    actor: str,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> LedgerRecord:
    """Append an outcome record."""

    return append_event(
        ledger,
        event_type=RouteEventType.OUTCOME_RECORDED,
        actor=actor,
        object_type="outcome_record",
        preserved_object=outcome,
        metadata={
            "stage": "outcome",
            "consequence_matched": bool(
                getattr(
                    outcome,
                    "consequence_matched",
                    False,
                )
            ),
        },
        key_pair=key_pair,
        signer=signer,
    )


def append_divergences(
    ledger: LedgerRecord,
    *,
    divergences: Sequence[Any],
    actor: str,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> LedgerRecord:
    """
    Append each divergence as a separate replay event.
    """

    updated = ledger

    for divergence in divergences:
        updated = append_event(
            updated,
            event_type=RouteEventType.DIVERGENCE_RECORDED,
            actor=actor,
            object_type="divergence_record",
            preserved_object=divergence,
            metadata={
                "stage": "divergence",
                "category": str(
                    getattr(
                        divergence,
                        "category",
                        "",
                    )
                ),
                "severity": str(
                    getattr(
                        divergence,
                        "severity",
                        "",
                    )
                ),
            },
            key_pair=key_pair,
            signer=signer,
        )

    return updated


def seal_ledger(
    ledger: LedgerRecord,
    *,
    sealed_at: Optional[datetime] = None,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> LedgerRecord:
    """
    Seal an open replay ledger.

    The seal signature attests to the complete LedgerRecord state before the
    seal signature itself is attached.
    """

    if ledger.sealed_at is not None:
        raise LedgerConstructionError(
            "Ledger has already been sealed."
        )

    if not ledger.events:
        raise LedgerConstructionError(
            "An empty ledger cannot be sealed."
        )

    if not verify_ledger_chain(ledger.events):
        raise LedgerConstructionError(
            "Ledger chain is invalid and cannot be sealed."
        )

    resolved_sealed_at = sealed_at or utc_now()

    _require_aware_datetime(
        resolved_sealed_at,
        field_name="sealed_at",
    )

    last_event_time = ledger.events[-1].occurred_at

    if resolved_sealed_at < last_event_time:
        raise LedgerConstructionError(
            "sealed_at cannot precede the final ledger event."
        )

    final_digest = ledger.events[-1].event_digest
    root_digest = ledger.events[0].event_digest

    if final_digest is None or root_digest is None:
        raise LedgerConstructionError(
            "Ledger events must contain calculated digests before sealing."
        )

    sealed = ledger.model_copy(
        update={
            "root_digest": root_digest,
            "final_event_digest": final_digest,
            "sealed_at": resolved_sealed_at,
            "seal_signature": None,
        }
    )

    if key_pair is None:
        return sealed

    if signer is None:
        raise LedgerConstructionError(
            "signer is required when key_pair is provided."
        )

    seal_signature = sign_object(
        sealed,
        key_pair=key_pair,
        signer=signer,
    )

    return sealed.model_copy(
        update={
            "seal_signature": seal_signature,
        }
    )


def verify_ledger_record(
    ledger: LedgerRecord,
) -> bool:
    """
    Verify a ledger's event chain and stored root/final digests.
    """

    if not verify_ledger_chain(ledger.events):
        return False

    if not ledger.events:
        return (
            ledger.root_digest is None
            and ledger.final_event_digest is None
        )

    observed_root = ledger.events[0].event_digest
    observed_final = ledger.events[-1].event_digest

    if observed_root is None or observed_final is None:
        return False

    if ledger.root_digest is None:
        return False

    if ledger.final_event_digest is None:
        return False

    if not secure_digest_equal(
        ledger.root_digest,
        observed_root,
    ):
        return False

    if not secure_digest_equal(
        ledger.final_event_digest,
        observed_final,
    ):
        return False

    return True
