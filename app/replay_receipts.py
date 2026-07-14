"""
TA-14 Independent Route Replay Standard
Signed receipt construction for governed execution routes.

Purpose
-------
This module creates the formal records that connect an admissibility
determination to a specific action and its resulting consequence.

The receipt sequence is:

Determination
    -> Binding
    -> Commit
    -> Execution
    -> Outcome

Each receipt:

- references the same governed route;
- contains a deterministic cryptographic digest;
- can be signed with the tested Ed25519 signing service;
- preserves the state required for independent replay;
- rejects inconsistent route, action, timing, and dependency relationships.

This module is additive and does not alter existing public sandbox endpoints.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Iterable, Optional, Sequence
from uuid import UUID

from .replay_crypto import (
    digest_named_objects,
    digest_object,
    secure_digest_equal,
)
from .replay_models import (
    BindingCondition,
    BindingReceipt,
    CommitReceipt,
    DeterminationReceipt,
    DigestRecord,
    DivergenceRecord,
    EvidenceIndex,
    ExecutionReceipt,
    OutcomeRecord,
    ReplayDecision,
    RouteManifest,
    RulesetRecord,
)
from .replay_signing import (
    Ed25519KeyPair,
    sign_object,
)


class ReceiptConstructionError(ValueError):
    """Raised when a replay receipt cannot be constructed safely."""


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
        raise ReceiptConstructionError(
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
        raise ReceiptConstructionError(
            f"{field_name} must not be empty."
        )

    return normalized


def _require_same_route(
    expected_route_id: UUID,
    observed_route_id: UUID,
    *,
    object_name: str,
) -> None:
    """Ensure all receipts belong to the same governed route."""

    if expected_route_id != observed_route_id:
        raise ReceiptConstructionError(
            f"{object_name} belongs to a different route."
        )


def _require_matching_digest(
    first: DigestRecord,
    second: DigestRecord,
    *,
    field_name: str,
) -> None:
    """Require two cryptographic digest records to match."""

    if not secure_digest_equal(first, second):
        raise ReceiptConstructionError(
            f"{field_name} digest does not match."
        )


def _unique_text_values(
    values: Iterable[str],
) -> list[str]:
    """Normalize text values while preserving first-seen order."""

    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        item = value.strip()

        if not item or item in seen:
            continue

        normalized.append(item)
        seen.add(item)

    return normalized


def _digest_and_sign_determination(
    receipt: DeterminationReceipt,
    *,
    key_pair: Optional[Ed25519KeyPair],
    signer: Optional[str],
) -> DeterminationReceipt:
    """Populate a determination digest and optional signature."""

    determination_digest = digest_object(receipt)

    completed = receipt.model_copy(
        update={
            "determination_digest": determination_digest,
        }
    )

    if key_pair is None:
        return completed

    if signer is None:
        raise ReceiptConstructionError(
            "signer is required when key_pair is provided."
        )

    signature = sign_object(
        completed,
        key_pair=key_pair,
        signer=signer,
    )

    return completed.model_copy(
        update={
            "signature": signature,
        }
    )


def _digest_and_sign_binding(
    receipt: BindingReceipt,
    *,
    key_pair: Optional[Ed25519KeyPair],
    signer: Optional[str],
) -> BindingReceipt:
    """Populate a binding digest and optional signature."""

    binding_digest = digest_object(receipt)

    completed = receipt.model_copy(
        update={
            "binding_digest": binding_digest,
        }
    )

    if key_pair is None:
        return completed

    if signer is None:
        raise ReceiptConstructionError(
            "signer is required when key_pair is provided."
        )

    signature = sign_object(
        completed,
        key_pair=key_pair,
        signer=signer,
    )

    return completed.model_copy(
        update={
            "signature": signature,
        }
    )


def _digest_and_sign_commit(
    receipt: CommitReceipt,
    *,
    key_pair: Optional[Ed25519KeyPair],
    signer: Optional[str],
) -> CommitReceipt:
    """Populate a commit digest and optional signature."""

    commit_digest = digest_object(receipt)

    completed = receipt.model_copy(
        update={
            "commit_digest": commit_digest,
        }
    )

    if key_pair is None:
        return completed

    if signer is None:
        raise ReceiptConstructionError(
            "signer is required when key_pair is provided."
        )

    signature = sign_object(
        completed,
        key_pair=key_pair,
        signer=signer,
    )

    return completed.model_copy(
        update={
            "signature": signature,
        }
    )


def _digest_and_sign_execution(
    receipt: ExecutionReceipt,
    *,
    key_pair: Optional[Ed25519KeyPair],
    signer: Optional[str],
) -> ExecutionReceipt:
    """Populate an execution digest and optional signature."""

    execution_digest = digest_object(receipt)

    completed = receipt.model_copy(
        update={
            "execution_digest": execution_digest,
        }
    )

    if key_pair is None:
        return completed

    if signer is None:
        raise ReceiptConstructionError(
            "signer is required when key_pair is provided."
        )

    signature = sign_object(
        completed,
        key_pair=key_pair,
        signer=signer,
    )

    return completed.model_copy(
        update={
            "signature": signature,
        }
    )


def _digest_and_sign_outcome(
    receipt: OutcomeRecord,
    *,
    key_pair: Optional[Ed25519KeyPair],
    signer: Optional[str],
) -> OutcomeRecord:
    """Populate an outcome digest and optional signature."""

    outcome_digest = digest_object(receipt)

    completed = receipt.model_copy(
        update={
            "outcome_digest": outcome_digest,
        }
    )

    if key_pair is None:
        return completed

    if signer is None:
        raise ReceiptConstructionError(
            "signer is required when key_pair is provided."
        )

    signature = sign_object(
        completed,
        key_pair=key_pair,
        signer=signer,
    )

    return completed.model_copy(
        update={
            "signature": signature,
        }
    )


def create_determination_receipt(
    *,
    route_manifest: RouteManifest,
    decision: ReplayDecision,
    reasons: Sequence[str],
    warnings: Sequence[str] = (),
    required_actions: Sequence[str] = (),
    escalation_destination: Optional[str] = None,
    issued_at: Optional[datetime] = None,
    valid_until: Optional[datetime] = None,
    independently_replayable: bool = False,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> DeterminationReceipt:
    """
    Create a deterministic admissibility determination receipt.

    Failed and satisfied predicate identifiers are derived directly from the
    route manifest so the receipt cannot silently contradict the evaluated
    predicate state.
    """

    resolved_issued_at = issued_at or utc_now()

    _require_aware_datetime(
        resolved_issued_at,
        field_name="issued_at",
    )

    if valid_until is not None:
        _require_aware_datetime(
            valid_until,
            field_name="valid_until",
        )

        if valid_until <= resolved_issued_at:
            raise ReceiptConstructionError(
                "valid_until must be later than issued_at."
            )

    if route_manifest.manifest_digest is None:
        raise ReceiptConstructionError(
            "Route manifest must contain manifest_digest "
            "before a determination receipt is created."
        )

    normalized_reasons = _unique_text_values(reasons)

    if not normalized_reasons:
        raise ReceiptConstructionError(
            "A determination receipt requires at least one reason."
        )

    failed_predicate_ids = [
        predicate.predicate_id
        for predicate in route_manifest.predicates
        if not predicate.satisfied
    ]

    satisfied_predicate_ids = [
        predicate.predicate_id
        for predicate in route_manifest.predicates
        if predicate.satisfied
    ]

    if decision == ReplayDecision.ALLOW and failed_predicate_ids:
        raise ReceiptConstructionError(
            "An ALLOW determination cannot contain failed predicates."
        )

    if (
        decision == ReplayDecision.ESCALATE
        and escalation_destination is None
    ):
        raise ReceiptConstructionError(
            "ESCALATE requires an escalation_destination."
        )

    if escalation_destination is not None:
        escalation_destination = _require_nonempty_text(
            escalation_destination,
            field_name="escalation_destination",
        )

    receipt = DeterminationReceipt(
        route_id=route_manifest.route_id,
        request_id=route_manifest.request_id,
        decision=decision,
        issued_at=resolved_issued_at,
        valid_until=valid_until,
        reasons=normalized_reasons,
        warnings=_unique_text_values(warnings),
        failed_predicate_ids=failed_predicate_ids,
        satisfied_predicate_ids=satisfied_predicate_ids,
        required_actions=_unique_text_values(
            required_actions
        ),
        escalation_destination=escalation_destination,
        manifest_digest=route_manifest.manifest_digest,
        independently_replayable=independently_replayable,
    )

    return _digest_and_sign_determination(
        receipt,
        key_pair=key_pair,
        signer=signer,
    )


def create_binding_receipt(
    *,
    route_manifest: RouteManifest,
    evidence_index: EvidenceIndex,
    ruleset: RulesetRecord,
    determination: DeterminationReceipt,
    authority_records: Sequence[object],
    conditions: Sequence[BindingCondition],
    bound_by: str,
    bound_at: Optional[datetime] = None,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> BindingReceipt:
    """
    Bind an ALLOW determination to the exact action, evidence, authority,
    ruleset, and execution conditions that may proceed.

    The binding receipt prevents an ALLOW decision from being reused for a
    materially different action or evidence state.
    """

    if determination.decision != ReplayDecision.ALLOW:
        raise ReceiptConstructionError(
            "Only an ALLOW determination may be bound for execution."
        )

    if determination.determination_digest is None:
        raise ReceiptConstructionError(
            "Determination must contain determination_digest."
        )

    if route_manifest.proposed_action.action_digest is None:
        raise ReceiptConstructionError(
            "Proposed action must contain action_digest."
        )

    if evidence_index.index_digest is None:
        raise ReceiptConstructionError(
            "Evidence index must contain index_digest."
        )

    _require_same_route(
        route_manifest.route_id,
        determination.route_id,
        object_name="Determination receipt",
    )

    _require_matching_digest(
        route_manifest.manifest_digest,
        determination.manifest_digest,
        field_name="Manifest",
    )

    _require_matching_digest(
        route_manifest.ruleset_digest,
        ruleset.ruleset_digest,
        field_name="Ruleset",
    )

    if determination.valid_until is not None:
        resolved_bound_at = bound_at or utc_now()

        if resolved_bound_at > determination.valid_until:
            raise ReceiptConstructionError(
                "Determination expired before binding."
            )
    else:
        resolved_bound_at = bound_at or utc_now()

    _require_aware_datetime(
        resolved_bound_at,
        field_name="bound_at",
    )

    normalized_bound_by = _require_nonempty_text(
        bound_by,
        field_name="bound_by",
    )

    if not conditions:
        raise ReceiptConstructionError(
            "Binding receipt requires at least one binding condition."
        )

    condition_ids = [
        condition.condition_id
        for condition in conditions
    ]

    if len(condition_ids) != len(set(condition_ids)):
        raise ReceiptConstructionError(
            "Binding condition identifiers must be unique."
        )

    authority_digest = digest_named_objects(
        {
            f"authority-{index + 1}": record
            for index, record in enumerate(authority_records)
        }
    )

    receipt = BindingReceipt(
        route_id=route_manifest.route_id,
        determination_receipt_id=determination.receipt_id,
        bound_at=resolved_bound_at,
        bound_by=normalized_bound_by,
        action_digest=(
            route_manifest.proposed_action.action_digest
        ),
        evidence_index_digest=evidence_index.index_digest,
        authority_digest=authority_digest,
        ruleset_digest=ruleset.ruleset_digest,
        determination_digest=(
            determination.determination_digest
        ),
        conditions=list(conditions),
    )

    return _digest_and_sign_binding(
        receipt,
        key_pair=key_pair,
        signer=signer,
    )


def create_commit_receipt(
    *,
    binding: BindingReceipt,
    authorized_by: str,
    execution_audience: str,
    valid_until: datetime,
    authorized_at: Optional[datetime] = None,
    single_use: bool = True,
    execution_nonce: Optional[str] = None,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> CommitReceipt:
    """
    Authorize a short-lived execution commitment against one exact binding.

    The commit receipt is designed to become invalid if:

    - the binding changes;
    - the action changes;
    - the execution audience changes;
    - the receipt expires;
    - the receipt is revoked;
    - a single-use receipt is consumed more than once.
    """

    if binding.binding_digest is None:
        raise ReceiptConstructionError(
            "Binding receipt must contain binding_digest."
        )

    resolved_authorized_at = authorized_at or utc_now()

    _require_aware_datetime(
        resolved_authorized_at,
        field_name="authorized_at",
    )

    _require_aware_datetime(
        valid_until,
        field_name="valid_until",
    )

    if valid_until <= resolved_authorized_at:
        raise ReceiptConstructionError(
            "Commit valid_until must be later than authorized_at."
        )

    normalized_authorized_by = _require_nonempty_text(
        authorized_by,
        field_name="authorized_by",
    )

    normalized_audience = _require_nonempty_text(
        execution_audience,
        field_name="execution_audience",
    )

    resolved_nonce = execution_nonce or secrets.token_urlsafe(32)

    if len(resolved_nonce) < 16:
        raise ReceiptConstructionError(
            "execution_nonce must contain at least 16 characters."
        )

    receipt = CommitReceipt(
        route_id=binding.route_id,
        binding_id=binding.binding_id,
        authorized_at=resolved_authorized_at,
        authorized_by=normalized_authorized_by,
        valid_until=valid_until,
        single_use=single_use,
        execution_audience=normalized_audience,
        execution_nonce=resolved_nonce,
        bound_action_digest=binding.action_digest,
        bound_binding_digest=binding.binding_digest,
    )

    return _digest_and_sign_commit(
        receipt,
        key_pair=key_pair,
        signer=signer,
    )


def mark_commit_consumed(
    commit: CommitReceipt,
    *,
    consumed_at: Optional[datetime] = None,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> CommitReceipt:
    """
    Mark a commit receipt as consumed.

    A single-use commit may only be consumed once.
    """

    if commit.revoked_at is not None:
        raise ReceiptConstructionError(
            "A revoked commit receipt cannot be consumed."
        )

    if commit.consumed_at is not None:
        raise ReceiptConstructionError(
            "Commit receipt has already been consumed."
        )

    resolved_consumed_at = consumed_at or utc_now()

    _require_aware_datetime(
        resolved_consumed_at,
        field_name="consumed_at",
    )

    if resolved_consumed_at < commit.authorized_at:
        raise ReceiptConstructionError(
            "consumed_at cannot precede authorized_at."
        )

    if resolved_consumed_at > commit.valid_until:
        raise ReceiptConstructionError(
            "Commit receipt expired before consumption."
        )

    updated = commit.model_copy(
        update={
            "consumed_at": resolved_consumed_at,
            "commit_digest": None,
            "signature": None,
        }
    )

    return _digest_and_sign_commit(
        updated,
        key_pair=key_pair,
        signer=signer,
    )


def revoke_commit_receipt(
    commit: CommitReceipt,
    *,
    reason: str,
    revoked_at: Optional[datetime] = None,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> CommitReceipt:
    """Revoke an unused commit receipt and preserve the reason."""

    if commit.consumed_at is not None:
        raise ReceiptConstructionError(
            "A consumed commit receipt cannot be revoked retroactively."
        )

    if commit.revoked_at is not None:
        raise ReceiptConstructionError(
            "Commit receipt has already been revoked."
        )

    normalized_reason = _require_nonempty_text(
        reason,
        field_name="revocation reason",
    )

    resolved_revoked_at = revoked_at or utc_now()

    _require_aware_datetime(
        resolved_revoked_at,
        field_name="revoked_at",
    )

    if resolved_revoked_at < commit.authorized_at:
        raise ReceiptConstructionError(
            "revoked_at cannot precede authorized_at."
        )

    updated = commit.model_copy(
        update={
            "revoked_at": resolved_revoked_at,
            "revocation_reason": normalized_reason,
            "commit_digest": None,
            "signature": None,
        }
    )

    return _digest_and_sign_commit(
        updated,
        key_pair=key_pair,
        signer=signer,
    )


def create_execution_receipt(
    *,
    commit: CommitReceipt,
    executor_id: str,
    execution_system: str,
    submitted_action_digest: DigestRecord,
    status: str,
    started_at: datetime,
    completed_at: Optional[datetime] = None,
    execution_system_version: Optional[str] = None,
    result_digest: Optional[DigestRecord] = None,
    result_reference: Optional[str] = None,
    exception_codes: Sequence[str] = (),
    warnings: Sequence[str] = (),
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> ExecutionReceipt:
    """
    Record execution of the exact committed action.

    The action_binding_matched field is calculated cryptographically rather
    than supplied by the caller.
    """

    if commit.commit_digest is None:
        raise ReceiptConstructionError(
            "Commit receipt must contain commit_digest."
        )

    if commit.revoked_at is not None:
        raise ReceiptConstructionError(
            "A revoked commit receipt cannot authorize execution."
        )

    _require_aware_datetime(
        started_at,
        field_name="started_at",
    )

    if started_at < commit.authorized_at:
        raise ReceiptConstructionError(
            "Execution cannot begin before commit authorization."
        )

    if started_at > commit.valid_until:
        raise ReceiptConstructionError(
            "Execution began after the commit receipt expired."
        )

    if commit.single_use and commit.consumed_at is None:
        raise ReceiptConstructionError(
            "Single-use commit must be marked consumed before "
            "an execution receipt is created."
        )

    if completed_at is not None:
        _require_aware_datetime(
            completed_at,
            field_name="completed_at",
        )

        if completed_at < started_at:
            raise ReceiptConstructionError(
                "completed_at cannot precede started_at."
            )

    allowed_statuses = {
        "STARTED",
        "COMPLETED",
        "FAILED",
        "BLOCKED",
        "CANCELLED",
        "PARTIAL",
    }

    normalized_status = status.strip().upper()

    if normalized_status not in allowed_statuses:
        raise ReceiptConstructionError(
            f"Unsupported execution status: {status}"
        )

    if normalized_status == "STARTED" and completed_at is not None:
        raise ReceiptConstructionError(
            "STARTED execution cannot contain completed_at."
        )

    if normalized_status != "STARTED" and completed_at is None:
        raise ReceiptConstructionError(
            f"{normalized_status} execution requires completed_at."
        )

    binding_matched = secure_digest_equal(
        submitted_action_digest,
        commit.bound_action_digest,
    )

    if not binding_matched and normalized_status == "COMPLETED":
        raise ReceiptConstructionError(
            "A mismatched action cannot be recorded as COMPLETED."
        )

    receipt = ExecutionReceipt(
        route_id=commit.route_id,
        commit_id=commit.commit_id,
        executor_id=_require_nonempty_text(
            executor_id,
            field_name="executor_id",
        ),
        execution_system=_require_nonempty_text(
            execution_system,
            field_name="execution_system",
        ),
        execution_system_version=(
            execution_system_version.strip()
            if execution_system_version
            else None
        ),
        started_at=started_at,
        completed_at=completed_at,
        status=normalized_status,
        submitted_action_digest=submitted_action_digest,
        bound_action_digest=commit.bound_action_digest,
        action_binding_matched=binding_matched,
        result_digest=result_digest,
        result_reference=(
            result_reference.strip()
            if result_reference
            else None
        ),
        exception_codes=_unique_text_values(
            exception_codes
        ),
        warnings=_unique_text_values(warnings),
    )

    return _digest_and_sign_execution(
        receipt,
        key_pair=key_pair,
        signer=signer,
    )


def create_outcome_record(
    *,
    execution: ExecutionReceipt,
    observer_id: str,
    observation_system: str,
    intended_outcome: str,
    observed_outcome: str,
    consequence_matched: bool,
    remained_within_binding_conditions: bool,
    authority_remained_valid: bool,
    evidence_remained_valid: bool,
    outcome_evidence_ids: Sequence[UUID] = (),
    divergences: Sequence[DivergenceRecord] = (),
    observed_at: Optional[datetime] = None,
    key_pair: Optional[Ed25519KeyPair] = None,
    signer: Optional[str] = None,
) -> OutcomeRecord:
    """
    Record whether the real consequence matched the governed route.

    A technically completed execution is not treated as a valid outcome unless
    the consequence, binding conditions, authority, and evidence all remained
    valid.
    """

    if execution.execution_digest is None:
        raise ReceiptConstructionError(
            "Execution receipt must contain execution_digest."
        )

    if execution.status not in {
        "COMPLETED",
        "FAILED",
        "BLOCKED",
        "CANCELLED",
        "PARTIAL",
    }:
        raise ReceiptConstructionError(
            "Outcome cannot be recorded while execution is only STARTED."
        )

    resolved_observed_at = observed_at or utc_now()

    _require_aware_datetime(
        resolved_observed_at,
        field_name="observed_at",
    )

    if (
        execution.completed_at is not None
        and resolved_observed_at < execution.completed_at
    ):
        raise ReceiptConstructionError(
            "Outcome observation cannot precede execution completion."
        )

    normalized_divergences = list(divergences)

    if (
        consequence_matched
        and remained_within_binding_conditions
        and authority_remained_valid
        and evidence_remained_valid
        and normalized_divergences
    ):
        raise ReceiptConstructionError(
            "A fully conforming outcome cannot contain divergence records."
        )

    if not consequence_matched and not normalized_divergences:
        raise ReceiptConstructionError(
            "A mismatched consequence requires at least one divergence record."
        )

    receipt = OutcomeRecord(
        route_id=execution.route_id,
        execution_id=execution.execution_id,
        observed_at=resolved_observed_at,
        observer_id=_require_nonempty_text(
            observer_id,
            field_name="observer_id",
        ),
        observation_system=_require_nonempty_text(
            observation_system,
            field_name="observation_system",
        ),
        intended_outcome=_require_nonempty_text(
            intended_outcome,
            field_name="intended_outcome",
        ),
        observed_outcome=_require_nonempty_text(
            observed_outcome,
            field_name="observed_outcome",
        ),
        consequence_matched=consequence_matched,
        remained_within_binding_conditions=(
            remained_within_binding_conditions
        ),
        authority_remained_valid=authority_remained_valid,
        evidence_remained_valid=evidence_remained_valid,
        outcome_evidence_ids=list(outcome_evidence_ids),
        divergences=normalized_divergences,
    )

    return _digest_and_sign_outcome(
        receipt,
        key_pair=key_pair,
        signer=signer,
    )
