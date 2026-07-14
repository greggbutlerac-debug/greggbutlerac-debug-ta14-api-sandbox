"""
Tests for the TA-14 Independent Route Replay verifier.

These tests verify:

- successful independent verification of a complete package;
- human-readable verification summaries;
- canonical JSON verification-report output;
- file tamper detection;
- package-manifest signature failure;
- public-key substitution detection;
- route-identity mismatch detection;
- broken ledger detection;
- execution correspondence failure;
- outcome correspondence failure;
- missing required-file detection;
- invalid archive rejection;
- report overwrite protection.
"""

import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from app.replay_crypto import (
    canonical_json_bytes,
    digest_object,
    digest_text,
)
from app.replay_ledger import (
    append_commit_authorized,
    append_determination_issued,
    append_execution,
    append_outcome_recorded,
    append_route_bound,
    append_route_created,
    create_ledger,
    seal_ledger,
)
from app.replay_models import (
    BindingCondition,
    ChainLinkState,
    CompleteRouteReplayRecord,
    EvidenceIndex,
    IntegrityStatus,
    PredicateResult,
    ProposedAction,
    ReplayDecision,
    RouteManifest,
    RulesetRecord,
    VerificationStatus,
)
from app.replay_package import (
    build_replay_package,
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
    public_verification_bundle,
)
from app.replay_verify import (
    ReplayVerificationError,
    verification_summary,
    verify_and_write_report,
    verify_replay_package,
)


FIXED_TIME = datetime(
    2026,
    7,
    14,
    20,
    0,
    0,
    tzinfo=timezone.utc,
)

SIGNER = "TA-14 Independent Verifier Test Signer"
CREATED_BY = "TA-14 Independent Verifier Test Service"


def build_action() -> ProposedAction:
    """Create a deterministic proposed action fixture."""

    action = ProposedAction(
        action_type="synthetic-verifier-transfer",
        actor_id="synthetic-verifier-agent",
        target="synthetic-verifier-target",
        description=(
            "Execute one bounded synthetic transfer for verifier testing."
        ),
        parameters={
            "amount": 5000,
            "currency": "USD",
        },
        requested_at=FIXED_TIME,
        requested_execution_time=(
            FIXED_TIME + timedelta(minutes=5)
        ),
        consequence_class="financial",
        reversible=False,
        maximum_impact="Synthetic verification test only.",
    )

    return action.model_copy(
        update={
            "action_digest": digest_object(action),
        }
    )


def build_ruleset() -> RulesetRecord:
    """Create a deterministic ruleset fixture."""

    return RulesetRecord(
        ruleset_id="ta14-verifier-test-ruleset",
        ruleset_version="1.0.0",
        architecture_version="24-link-verifier-test-1.0.0",
        effective_from=(
            FIXED_TIME - timedelta(days=1)
        ),
        effective_until=(
            FIXED_TIME + timedelta(days=30)
        ),
        ruleset_digest=digest_text(
            "ta14-verifier-test-ruleset-artifact"
        ),
        rules=[],
        signed_by=None,
    )


def build_route_manifest() -> RouteManifest:
    """Create a deterministic route manifest fixture."""

    ruleset = build_ruleset()

    predicate = PredicateResult(
        predicate_id="verifier-authority-active",
        link_number=8,
        link_name="Authority",
        description=(
            "Synthetic execution authority must remain active."
        ),
        satisfied=True,
        required=True,
        observed_value="ACTIVE",
        expected_value="ACTIVE",
        evidence_ids=[],
        authority_ids=[],
        rule_ids=["VERIFIER-AUTHORITY-ACTIVE"],
        evaluated_at=FIXED_TIME,
        evaluator_version="verifier-test-engine-1.0.0",
        reason="Synthetic authority is active.",
    )

    chain_link = ChainLinkState(
        link_number=8,
        link_name="Authority",
        satisfied=True,
        required=True,
        status="PASS",
        predicate_ids=[
            "verifier-authority-active"
        ],
        evidence_ids=[],
        reason="Authority requirement passed.",
    )

    manifest = RouteManifest(
        route_id=uuid4(),
        request_id=uuid4(),
        correlation_id="verifier-test-001",
        created_at=FIXED_TIME,
        expires_at=(
            FIXED_TIME + timedelta(minutes=30)
        ),
        architecture_version=(
            "24-link-verifier-test-1.0.0"
        ),
        proposed_action=build_action(),
        evidence_ids=[],
        authority_ids=[],
        jurisdiction_ids=["US"],
        ruleset_id=ruleset.ruleset_id,
        ruleset_version=ruleset.ruleset_version,
        ruleset_digest=ruleset.ruleset_digest,
        chain_links=[
            chain_link
        ],
        predicates=[
            predicate
        ],
        input_digest=digest_text(
            "verifier-test-input"
        ),
        re_evaluation_required_when=[
            "Authority changes.",
            "Evidence expires.",
            "Action parameters change.",
        ],
        metadata={
            "scenario": "synthetic-verifier-test",
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
    """Create a deterministic empty evidence index."""

    index = EvidenceIndex(
        generated_at=FIXED_TIME,
        entries=[],
    )

    return index.model_copy(
        update={
            "index_digest": digest_object(index),
        }
    )


def build_complete_package(
    tmp_path: Path,
    *,
    filename: str = "valid-replay-package.zip",
) -> tuple[Path, CompleteRouteReplayRecord, object]:
    """
    Build one complete signed, sealed, and independently verifiable package.
    """

    key_pair = generate_key_pair()
    route_manifest = build_route_manifest()
    evidence_index = build_evidence_index()
    ruleset = build_ruleset()

    determination = create_determination_receipt(
        route_manifest=route_manifest,
        decision=ReplayDecision.ALLOW,
        reasons=[
            "All required synthetic predicates passed.",
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
                condition_id="verifier-exact-action",
                description=(
                    "The submitted execution action must match "
                    "the bound action digest."
                ),
                required=True,
                expected_value=(
                    route_manifest
                    .proposed_action
                    .action_digest
                    .value
                ),
                evidence_ids=[],
                rule_ids=[
                    "VERIFIER-EXACT-ACTION"
                ],
            )
        ],
        bound_by="ta14-verifier-binding-service",
        bound_at=(
            FIXED_TIME + timedelta(minutes=1)
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    commit = create_commit_receipt(
        binding=binding,
        authorized_by="ta14-verifier-commit-service",
        execution_audience="synthetic-verifier-executor",
        authorized_at=(
            FIXED_TIME + timedelta(minutes=2)
        ),
        valid_until=(
            FIXED_TIME + timedelta(minutes=7)
        ),
        execution_nonce="verifier-fixed-nonce-0001",
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
        executor_id="synthetic-verifier-agent",
        execution_system="synthetic-verifier-executor",
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
            "synthetic-verifier-execution-result"
        ),
        result_reference=(
            "urn:ta14:test:execution:verifier"
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    outcome = create_outcome_record(
        execution=execution,
        observer_id="synthetic-verifier-observer",
        observation_system="synthetic-verifier-outcome-system",
        intended_outcome=(
            "One bounded synthetic transfer is completed."
        ),
        observed_outcome=(
            "One bounded synthetic transfer was completed."
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

    ledger = create_ledger(
        route_id=route_manifest.route_id,
        created_at=FIXED_TIME,
    )

    ledger = append_route_created(
        ledger,
        route_manifest=route_manifest,
        actor="ta14-verifier-route-service",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_determination_issued(
        ledger,
        determination=determination,
        actor="ta14-verifier-determination-service",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_route_bound(
        ledger,
        binding=binding,
        actor="ta14-verifier-binding-service",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_commit_authorized(
        ledger,
        commit=consumed_commit,
        actor="ta14-verifier-commit-service",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_execution(
        ledger,
        execution=execution,
        actor="synthetic-verifier-executor",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_outcome_recorded(
        ledger,
        outcome=outcome,
        actor="synthetic-verifier-observer",
        key_pair=key_pair,
        signer=SIGNER,
    )

    sealed_ledger = seal_ledger(
        ledger,
        sealed_at=(
            FIXED_TIME + timedelta(minutes=5)
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    replay_record = CompleteRouteReplayRecord(
        route_manifest=route_manifest,
        evidence_index=evidence_index,
        evidence_objects=[],
        authority_records=[],
        jurisdiction_records=[],
        ruleset=ruleset,
        determination=determination,
        binding=binding,
        commit=consumed_commit,
        execution=execution,
        outcome=outcome,
        ledger=sealed_ledger,
        package_manifest=None,
        verification_report=None,
    )

    package_path = tmp_path / filename

    build_replay_package(
        replay_record=replay_record,
        output_path=package_path,
        key_pair=key_pair,
        signer=SIGNER,
        created_by=CREATED_BY,
        created_at=(
            FIXED_TIME + timedelta(minutes=6)
        ),
    )

    return package_path, replay_record, key_pair


def rewrite_zip_member(
    source_path: Path,
    output_path: Path,
    member_name: str,
    replacement: bytes | None,
) -> None:
    """
    Rewrite one ZIP archive member.

    Passing replacement=None removes the member.
    """

    with zipfile.ZipFile(
        source_path,
        mode="r",
    ) as source_archive:
        members = {
            name: source_archive.read(name)
            for name in source_archive.namelist()
            if name != member_name
        }

    if replacement is not None:
        members[member_name] = replacement

    with zipfile.ZipFile(
        output_path,
        mode="w",
        compression=zipfile.ZIP_STORED,
    ) as output_archive:
        for name in sorted(members):
            output_archive.writestr(
                name,
                members[name],
            )


def read_zip_json(
    package_path: Path,
    member_name: str,
) -> dict:
    """Read one JSON archive member."""

    with zipfile.ZipFile(
        package_path,
        mode="r",
    ) as archive:
        return json.loads(
            archive.read(
                member_name
            ).decode("utf-8")
        )


def test_valid_package_verifies_independently(
    tmp_path: Path,
) -> None:
    """A complete package must verify without trusting the dashboard."""

    package_path, replay_record, _key_pair = (
        build_complete_package(tmp_path)
    )

    report = verify_replay_package(
        package_path
    )

    assert (
        report.overall_status
        == VerificationStatus.VERIFIED
    )

    assert report.independently_replayable is True

    assert (
        report.original_decision
        == ReplayDecision.ALLOW
    )

    assert (
        report.route_id
        == replay_record.route_manifest.route_id
    )

    assert (
        report.package_integrity
        == IntegrityStatus.VALID
    )

    assert (
        report.signature_integrity
        == IntegrityStatus.VALID
    )

    assert (
        report.ledger_integrity
        == IntegrityStatus.VALID
    )

    assert (
        report.evidence_integrity
        == IntegrityStatus.VALID
    )

    assert (
        report.ruleset_integrity
        == IntegrityStatus.VALID
    )

    assert (
        report.action_binding
        == IntegrityStatus.VALID
    )

    assert (
        report.commit_integrity
        == IntegrityStatus.VALID
    )

    assert (
        report.execution_correspondence
        == IntegrityStatus.VALID
    )

    assert (
        report.outcome_correspondence
        == IntegrityStatus.VALID
    )

    assert report.failures == []
    assert report.warnings == []
    assert report.report_digest is not None


def test_verification_summary_contains_core_result(
    tmp_path: Path,
) -> None:
    """The human-readable summary must state the independent result."""

    package_path, _replay_record, _key_pair = (
        build_complete_package(tmp_path)
    )

    report = verify_replay_package(
        package_path
    )

    summary = verification_summary(report)

    assert (
        "TA-14 INDEPENDENT ROUTE VERIFICATION"
        in summary
    )

    assert "Overall status: VERIFIED" in summary
    assert "Original decision: ALLOW" in summary
    assert "Independently replayable: YES" in summary
    assert "Package integrity: VALID" in summary
    assert "Ledger integrity: VALID" in summary
    assert "Failures\n--------\n- None" in summary
    assert "Warnings\n--------\n- None" in summary


def test_verify_and_write_report_creates_json(
    tmp_path: Path,
) -> None:
    """Verification must support canonical report-file output."""

    package_path, replay_record, _key_pair = (
        build_complete_package(tmp_path)
    )

    report_path = (
        tmp_path
        / "verification-report.json"
    )

    report = verify_and_write_report(
        package_path=package_path,
        report_path=report_path,
        verifier_name="Independent Test Reviewer",
        verifier_version="1.0.0-test",
    )

    assert report_path.exists()
    assert report_path.is_file()

    saved = json.loads(
        report_path.read_text(
            encoding="utf-8"
        )
    )

    assert saved["overall_status"] == "VERIFIED"
    assert saved["independently_replayable"] is True

    assert saved["route_id"] == str(
        replay_record.route_manifest.route_id
    )

    assert (
        saved["verifier_name"]
        == "Independent Test Reviewer"
    )

    assert (
        saved["verifier_version"]
        == "1.0.0-test"
    )

    assert report.report_digest is not None


def test_report_refuses_overwrite_by_default(
    tmp_path: Path,
) -> None:
    """Existing verification reports must not be overwritten silently."""

    package_path, _replay_record, _key_pair = (
        build_complete_package(tmp_path)
    )

    report_path = (
        tmp_path
        / "existing-report.json"
    )

    report_path.write_text(
        "{}",
        encoding="utf-8",
    )

    with pytest.raises(
        ReplayVerificationError,
        match="Refusing to overwrite",
    ):
        verify_and_write_report(
            package_path=package_path,
            report_path=report_path,
        )


def test_report_can_overwrite_when_explicitly_enabled(
    tmp_path: Path,
) -> None:
    """Explicit overwrite permission must replace an existing report."""

    package_path, _replay_record, _key_pair = (
        build_complete_package(tmp_path)
    )

    report_path = (
        tmp_path
        / "replaceable-report.json"
    )

    report_path.write_text(
        "{}",
        encoding="utf-8",
    )

    report = verify_and_write_report(
        package_path=package_path,
        report_path=report_path,
        overwrite=True,
    )

    saved = json.loads(
        report_path.read_text(
            encoding="utf-8"
        )
    )

    assert saved["overall_status"] == "VERIFIED"
    assert report.independently_replayable is True


def test_tampered_route_manifest_is_detected(
    tmp_path: Path,
) -> None:
    """Changing the route manifest must fail package verification."""

    package_path, _replay_record, _key_pair = (
        build_complete_package(tmp_path)
    )

    manifest_data = read_zip_json(
        package_path,
        "route-manifest.json",
    )

    manifest_data["metadata"]["tampered"] = True

    tampered_path = (
        tmp_path
        / "tampered-route-manifest.zip"
    )

    rewrite_zip_member(
        package_path,
        tampered_path,
        "route-manifest.json",
        canonical_json_bytes(
            manifest_data
        ),
    )

    report = verify_replay_package(
        tampered_path
    )

    assert (
        report.overall_status
        == VerificationStatus.FAILED
    )

    assert report.independently_replayable is False

    assert (
        report.package_integrity
        == IntegrityStatus.INVALID
    )

    assert any(
        "route-manifest.json"
        in failure
        for failure in report.failures
    )


def test_substituted_public_key_is_detected(
    tmp_path: Path,
) -> None:
    """Replacing the public verification key must invalidate signatures."""

    package_path, _replay_record, _key_pair = (
        build_complete_package(tmp_path)
    )

    wrong_key_pair = generate_key_pair()

    wrong_bundle = public_verification_bundle(
        wrong_key_pair.public_key,
        signer="Unauthorized Substitute Signer",
        key_id=wrong_key_pair.key_id,
    )

    substituted_path = (
        tmp_path
        / "substituted-public-key.zip"
    )

    rewrite_zip_member(
        package_path,
        substituted_path,
        "public-verification-key.json",
        canonical_json_bytes(
            wrong_bundle
        ),
    )

    report = verify_replay_package(
        substituted_path
    )

    assert (
        report.overall_status
        == VerificationStatus.FAILED
    )

    assert report.independently_replayable is False

    assert (
        report.package_integrity
        == IntegrityStatus.INVALID
    )

    assert (
        report.signature_integrity
        == IntegrityStatus.INVALID
    )


def test_tampered_package_manifest_signature_is_detected(
    tmp_path: Path,
) -> None:
    """Changing the package-manifest signature must fail verification."""

    package_path, _replay_record, _key_pair = (
        build_complete_package(tmp_path)
    )

    package_manifest = read_zip_json(
        package_path,
        "package-manifest.json",
    )

    package_manifest[
        "signature"
    ][
        "signature_base64"
    ] = "A" * 88

    tampered_path = (
        tmp_path
        / "tampered-package-signature.zip"
    )

    rewrite_zip_member(
        package_path,
        tampered_path,
        "package-manifest.json",
        canonical_json_bytes(
            package_manifest
        ),
    )

    report = verify_replay_package(
        tampered_path
    )

    assert (
        report.overall_status
        == VerificationStatus.FAILED
    )

    assert (
        report.signature_integrity
        == IntegrityStatus.INVALID
    )

    assert report.independently_replayable is False

    assert any(
        "Package manifest signature verification failed"
        in failure
        for failure in report.failures
    )


def test_cross_route_determination_is_detected(
    tmp_path: Path,
) -> None:
    """A determination substituted from another route must fail verification."""

    package_path, _replay_record, _key_pair = (
        build_complete_package(tmp_path)
    )

    determination = read_zip_json(
        package_path,
        "determination.json",
    )

    determination["route_id"] = str(
        uuid4()
    )

    tampered_path = (
        tmp_path
        / "cross-route-determination.zip"
    )

    rewrite_zip_member(
        package_path,
        tampered_path,
        "determination.json",
        canonical_json_bytes(
            determination
        ),
    )

    report = verify_replay_package(
        tampered_path
    )

    assert (
        report.overall_status
        == VerificationStatus.FAILED
    )

    assert report.independently_replayable is False

    assert any(
        "determination belongs to a different route"
        in failure
        for failure in report.failures
    )


def test_broken_ledger_event_is_detected(
    tmp_path: Path,
) -> None:
    """Changing a ledger event must invalidate the ledger and package."""

    package_path, _replay_record, _key_pair = (
        build_complete_package(tmp_path)
    )

    ledger = read_zip_json(
        package_path,
        "ledger.json",
    )

    ledger["events"][0]["actor"] = (
        "unauthorized-ledger-actor"
    )

    tampered_path = (
        tmp_path
        / "broken-ledger.zip"
    )

    rewrite_zip_member(
        package_path,
        tampered_path,
        "ledger.json",
        canonical_json_bytes(
            ledger
        ),
    )

    report = verify_replay_package(
        tampered_path
    )

    assert (
        report.overall_status
        == VerificationStatus.FAILED
    )

    assert (
        report.ledger_integrity
        == IntegrityStatus.INVALID
    )

    assert report.independently_replayable is False


def test_execution_action_mismatch_is_detected(
    tmp_path: Path,
) -> None:
    """Changing the submitted execution digest must fail correspondence."""

    package_path, _replay_record, _key_pair = (
        build_complete_package(tmp_path)
    )

    execution = read_zip_json(
        package_path,
        "execution.json",
    )

    execution[
        "submitted_action_digest"
    ][
        "value"
    ] = "f" * 64

    tampered_path = (
        tmp_path
        / "execution-action-mismatch.zip"
    )

    rewrite_zip_member(
        package_path,
        tampered_path,
        "execution.json",
        canonical_json_bytes(
            execution
        ),
    )

    report = verify_replay_package(
        tampered_path
    )

    assert (
        report.overall_status
        == VerificationStatus.FAILED
    )

    assert (
        report.execution_correspondence
        == IntegrityStatus.INVALID
    )

    assert report.independently_replayable is False


def test_outcome_mismatch_is_detected(
    tmp_path: Path,
) -> None:
    """A preserved outcome mismatch must fail independent replay."""

    package_path, _replay_record, _key_pair = (
        build_complete_package(tmp_path)
    )

    outcome = read_zip_json(
        package_path,
        "outcome.json",
    )

    outcome["consequence_matched"] = False
    outcome[
        "remained_within_binding_conditions"
    ] = False

    tampered_path = (
        tmp_path
        / "outcome-mismatch.zip"
    )

    rewrite_zip_member(
        package_path,
        tampered_path,
        "outcome.json",
        canonical_json_bytes(
            outcome
        ),
    )

    report = verify_replay_package(
        tampered_path
    )

    assert (
        report.overall_status
        == VerificationStatus.FAILED
    )

    assert (
        report.outcome_correspondence
        == IntegrityStatus.INVALID
    )

    assert report.independently_replayable is False


def test_missing_required_file_is_reported(
    tmp_path: Path,
) -> None:
    """Removing a required package file must fail verification."""

    package_path, _replay_record, _key_pair = (
        build_complete_package(tmp_path)
    )

    missing_file_path = (
        tmp_path
        / "missing-evidence-index.zip"
    )

    rewrite_zip_member(
        package_path,
        missing_file_path,
        "evidence-index.json",
        None,
    )

    with pytest.raises(
        ReplayVerificationError,
        match="Required JSON document is missing",
    ):
        verify_replay_package(
            missing_file_path
        )


def test_invalid_archive_is_rejected(
    tmp_path: Path,
) -> None:
    """A non-ZIP file must not enter replay verification."""

    invalid_path = (
        tmp_path
        / "invalid-replay-package.zip"
    )

    invalid_path.write_text(
        "This is not a replay ZIP archive.",
        encoding="utf-8",
    )

    with pytest.raises(
        ReplayVerificationError,
        match="not a valid ZIP archive",
    ):
        verify_replay_package(
            invalid_path
        )


def test_parent_directory_traversal_is_rejected(
    tmp_path: Path,
) -> None:
    """Unsafe archive paths must be rejected before extraction."""

    malicious_path = (
        tmp_path
        / "malicious-replay-package.zip"
    )

    with zipfile.ZipFile(
        malicious_path,
        mode="w",
    ) as archive:
        archive.writestr(
            "../escaped.txt",
            "malicious-content",
        )

    with pytest.raises(
        ReplayVerificationError,
        match="parent-directory traversal",
    ):
        verify_replay_package(
            malicious_path
        )

    assert not (
        tmp_path
        / "escaped.txt"
    ).exists()
