"""
Tests for the TA-14 Independent Route Replay package exporter.

These tests verify:

- complete synthetic replay-package construction;
- required package members;
- canonical package-manifest contents;
- package-manifest signature verification;
- deterministic ZIP output;
- absence of private signing keys;
- file-digest correspondence;
- safe extraction;
- overwrite protection;
- rejection of unsealed ledgers;
- rejection of cross-route records;
- rejection of invalid ZIP archives;
- archive path-traversal protection.
"""

import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from app.replay_crypto import (
    digest_file,
    digest_object,
    digest_text,
    secure_digest_equal,
    verify_file_digest,
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
    PredicateResult,
    ProposedAction,
    ReplayDecision,
    ReplayPackageManifest,
    RouteManifest,
    RulesetRecord,
)
from app.replay_package import (
    ReplayPackageError,
    build_replay_package,
    extract_replay_package,
    inspect_package_members,
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
    load_public_key_pem,
    verify_object_signature,
)


FIXED_TIME = datetime(
    2026,
    7,
    14,
    18,
    0,
    0,
    tzinfo=timezone.utc,
)

SIGNER = "TA-14 Package Test Signer"
CREATED_BY = "TA-14 Replay Package Test Service"


EXPECTED_CORE_MEMBERS = {
    "README.txt",
    "binding.json",
    "commit.json",
    "determination.json",
    "evidence-index.json",
    "execution.json",
    "ledger.json",
    "ledger.jsonl",
    "outcome.json",
    "package-manifest.json",
    "public-verification-key.json",
    "route-manifest.json",
    "ruleset.json",
}


def build_action() -> ProposedAction:
    """Create a deterministic proposed action fixture."""

    action = ProposedAction(
        action_type="synthetic-package-transfer",
        actor_id="synthetic-agent-001",
        target="synthetic-account-001",
        description=(
            "Execute one bounded synthetic transfer for replay-package testing."
        ),
        parameters={
            "amount": 2500,
            "currency": "USD",
        },
        requested_at=FIXED_TIME,
        requested_execution_time=(
            FIXED_TIME + timedelta(minutes=5)
        ),
        consequence_class="financial",
        reversible=False,
        maximum_impact="Synthetic test consequence only.",
    )

    return action.model_copy(
        update={
            "action_digest": digest_object(action),
        }
    )


def build_ruleset() -> RulesetRecord:
    """Create a deterministic ruleset fixture."""

    return RulesetRecord(
        ruleset_id="ta14-package-test-ruleset",
        ruleset_version="1.0.0",
        architecture_version="24-link-package-test-1.0.0",
        effective_from=(
            FIXED_TIME - timedelta(days=1)
        ),
        effective_until=(
            FIXED_TIME + timedelta(days=30)
        ),
        ruleset_digest=digest_text(
            "ta14-package-test-ruleset-1.0.0"
        ),
        rules=[],
        signed_by=None,
    )


def build_route_manifest(
    *,
    route_id=None,
) -> RouteManifest:
    """Create a deterministic route manifest with its digest populated."""

    resolved_route_id = route_id or uuid4()
    ruleset = build_ruleset()

    predicate = PredicateResult(
        predicate_id="package-authority-valid",
        link_number=8,
        link_name="Authority",
        description=(
            "The synthetic execution authority must remain active."
        ),
        satisfied=True,
        required=True,
        observed_value="ACTIVE",
        expected_value="ACTIVE",
        evidence_ids=[],
        authority_ids=[],
        rule_ids=["PACKAGE-AUTHORITY-VALID"],
        evaluated_at=FIXED_TIME,
        evaluator_version="package-test-engine-1.0.0",
        reason="Synthetic authority is active.",
    )

    chain_link = ChainLinkState(
        link_number=8,
        link_name="Authority",
        satisfied=True,
        required=True,
        status="PASS",
        predicate_ids=[
            "package-authority-valid"
        ],
        evidence_ids=[],
        reason="Authority requirement passed.",
    )

    manifest = RouteManifest(
        route_id=resolved_route_id,
        request_id=uuid4(),
        correlation_id="package-test-001",
        created_at=FIXED_TIME,
        expires_at=(
            FIXED_TIME + timedelta(minutes=30)
        ),
        architecture_version="24-link-package-test-1.0.0",
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
            "package-test-input"
        ),
        re_evaluation_required_when=[
            "Authority changes.",
            "Evidence expires.",
            "Action parameters change.",
        ],
        metadata={
            "scenario": "synthetic-package-test",
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
    """Create an empty but cryptographically complete evidence index."""

    index = EvidenceIndex(
        generated_at=FIXED_TIME,
        entries=[],
    )

    return index.model_copy(
        update={
            "index_digest": digest_object(index),
        }
    )


def build_complete_replay_record():
    """
    Build one complete signed and sealed synthetic replay record.

    Returns:
        replay_record,
        key_pair
    """

    key_pair = generate_key_pair()
    route_manifest = build_route_manifest()
    ruleset = build_ruleset()
    evidence_index = build_evidence_index()

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
                condition_id="exact-action-binding",
                description=(
                    "The submitted action digest must remain unchanged."
                ),
                required=True,
                expected_value=(
                    route_manifest.proposed_action.action_digest.value
                ),
                evidence_ids=[],
                rule_ids=[
                    "EXACT-ACTION-BINDING"
                ],
            )
        ],
        bound_by="ta14-package-binding-service",
        bound_at=(
            FIXED_TIME + timedelta(minutes=1)
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    commit = create_commit_receipt(
        binding=binding,
        authorized_by="ta14-package-commit-service",
        execution_audience="synthetic-package-executor",
        authorized_at=(
            FIXED_TIME + timedelta(minutes=2)
        ),
        valid_until=(
            FIXED_TIME + timedelta(minutes=7)
        ),
        execution_nonce="package-test-fixed-nonce-0001",
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
        executor_id="synthetic-agent-001",
        execution_system="synthetic-package-executor",
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
            "synthetic-package-execution-result"
        ),
        result_reference=(
            "urn:ta14:test:execution:package"
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    outcome = create_outcome_record(
        execution=execution,
        observer_id="synthetic-package-observer",
        observation_system="synthetic-package-outcome-system",
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
        actor="ta14-package-route-service",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_determination_issued(
        ledger,
        determination=determination,
        actor="ta14-package-determination-service",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_route_bound(
        ledger,
        binding=binding,
        actor="ta14-package-binding-service",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_commit_authorized(
        ledger,
        commit=consumed_commit,
        actor="ta14-package-commit-service",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_execution(
        ledger,
        execution=execution,
        actor="synthetic-package-executor",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_outcome_recorded(
        ledger,
        outcome=outcome,
        actor="synthetic-package-observer",
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

    return replay_record, key_pair


def read_zip_json(
    package_path: Path,
    member_name: str,
) -> dict:
    """Read and parse one JSON document directly from a ZIP package."""

    with zipfile.ZipFile(
        package_path,
        mode="r",
    ) as archive:
        content = archive.read(
            member_name
        ).decode("utf-8")

    return json.loads(content)


def test_build_complete_replay_package(
    tmp_path: Path,
) -> None:
    """A complete route must produce a valid portable ZIP package."""

    replay_record, key_pair = build_complete_replay_record()

    output_path = (
        tmp_path
        / "ta14-route-replay.zip"
    )

    result = build_replay_package(
        replay_record=replay_record,
        output_path=output_path,
        key_pair=key_pair,
        signer=SIGNER,
        created_by=CREATED_BY,
        created_at=(
            FIXED_TIME + timedelta(minutes=6)
        ),
    )

    assert result.package_path == output_path
    assert output_path.exists()
    assert output_path.is_file()
    assert zipfile.is_zipfile(output_path)
    assert result.byte_length == output_path.stat().st_size
    assert result.file_count == len(EXPECTED_CORE_MEMBERS)
    assert len(result.package_digest) == 64


def test_package_contains_expected_members(
    tmp_path: Path,
) -> None:
    """The exported archive must contain all expected core files."""

    replay_record, key_pair = build_complete_replay_record()

    output_path = (
        tmp_path
        / "ta14-route-replay.zip"
    )

    build_replay_package(
        replay_record=replay_record,
        output_path=output_path,
        key_pair=key_pair,
        signer=SIGNER,
        created_by=CREATED_BY,
        created_at=(
            FIXED_TIME + timedelta(minutes=6)
        ),
    )

    members = set(
        inspect_package_members(
            output_path
        )
    )

    assert EXPECTED_CORE_MEMBERS == members


def test_package_manifest_is_signed_and_verifiable(
    tmp_path: Path,
) -> None:
    """The package manifest must verify using the included public key."""

    replay_record, key_pair = build_complete_replay_record()

    output_path = (
        tmp_path
        / "ta14-route-replay.zip"
    )

    build_replay_package(
        replay_record=replay_record,
        output_path=output_path,
        key_pair=key_pair,
        signer=SIGNER,
        created_by=CREATED_BY,
        created_at=(
            FIXED_TIME + timedelta(minutes=6)
        ),
    )

    manifest_data = read_zip_json(
        output_path,
        "package-manifest.json",
    )

    key_bundle = read_zip_json(
        output_path,
        "public-verification-key.json",
    )

    manifest = ReplayPackageManifest.model_validate(
        manifest_data
    )

    assert manifest.signature is not None
    assert manifest.package_digest is not None
    assert manifest.route_id == (
        replay_record.route_manifest.route_id
    )

    public_key = load_public_key_pem(
        key_bundle["public_key_pem"].encode(
            "ascii"
        )
    )

    verification = verify_object_signature(
        manifest,
        manifest.signature,
        public_key=public_key,
    )

    assert verification.valid is True


def test_every_manifest_file_digest_matches(
    tmp_path: Path,
) -> None:
    """Every file listed in the manifest must match its preserved digest."""

    replay_record, key_pair = build_complete_replay_record()

    output_path = (
        tmp_path
        / "ta14-route-replay.zip"
    )

    build_replay_package(
        replay_record=replay_record,
        output_path=output_path,
        key_pair=key_pair,
        signer=SIGNER,
        created_by=CREATED_BY,
        created_at=(
            FIXED_TIME + timedelta(minutes=6)
        ),
    )

    extraction_directory = (
        tmp_path
        / "extracted"
    )

    extract_replay_package(
        package_path=output_path,
        destination=extraction_directory,
    )

    manifest_data = json.loads(
        (
            extraction_directory
            / "package-manifest.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    manifest = ReplayPackageManifest.model_validate(
        manifest_data
    )

    for file_record in manifest.files:
        file_path = (
            extraction_directory
            / file_record.path
        )

        assert file_path.exists()

        assert verify_file_digest(
            file_path,
            file_record.digest,
        )


def test_package_contains_no_private_key_material(
    tmp_path: Path,
) -> None:
    """No private signing key may enter the replay package."""

    replay_record, key_pair = build_complete_replay_record()

    output_path = (
        tmp_path
        / "ta14-route-replay.zip"
    )

    build_replay_package(
        replay_record=replay_record,
        output_path=output_path,
        key_pair=key_pair,
        signer=SIGNER,
        created_by=CREATED_BY,
        created_at=(
            FIXED_TIME + timedelta(minutes=6)
        ),
    )

    with zipfile.ZipFile(
        output_path,
        mode="r",
    ) as archive:
        combined_content = b"\n".join(
            archive.read(name)
            for name in archive.namelist()
        )

    assert b"BEGIN PRIVATE KEY" not in combined_content
    assert b"ENCRYPTED PRIVATE KEY" not in combined_content
    assert b"PRIVATE KEY" not in combined_content


def test_package_output_is_deterministic(
    tmp_path: Path,
) -> None:
    """
    Identical replay records and timestamps must produce identical ZIP bytes.
    """

    replay_record, key_pair = build_complete_replay_record()

    first_path = (
        tmp_path
        / "first.zip"
    )

    second_path = (
        tmp_path
        / "second.zip"
    )

    created_at = (
        FIXED_TIME + timedelta(minutes=6)
    )

    first_result = build_replay_package(
        replay_record=replay_record,
        output_path=first_path,
        key_pair=key_pair,
        signer=SIGNER,
        created_by=CREATED_BY,
        created_at=created_at,
    )

    second_result = build_replay_package(
        replay_record=replay_record,
        output_path=second_path,
        key_pair=key_pair,
        signer=SIGNER,
        created_by=CREATED_BY,
        created_at=created_at,
    )

    first_digest = digest_file(first_path)
    second_digest = digest_file(second_path)

    assert secure_digest_equal(
        first_digest,
        second_digest,
    )

    assert (
        first_result.package_digest
        == second_result.package_digest
    )

    assert first_path.read_bytes() == second_path.read_bytes()


def test_package_refuses_overwrite_by_default(
    tmp_path: Path,
) -> None:
    """An existing replay package must not be overwritten silently."""

    replay_record, key_pair = build_complete_replay_record()

    output_path = (
        tmp_path
        / "existing.zip"
    )

    build_replay_package(
        replay_record=replay_record,
        output_path=output_path,
        key_pair=key_pair,
        signer=SIGNER,
        created_by=CREATED_BY,
        created_at=(
            FIXED_TIME + timedelta(minutes=6)
        ),
    )

    with pytest.raises(
        ReplayPackageError,
        match="Refusing to overwrite",
    ):
        build_replay_package(
            replay_record=replay_record,
            output_path=output_path,
            key_pair=key_pair,
            signer=SIGNER,
            created_by=CREATED_BY,
            created_at=(
                FIXED_TIME + timedelta(minutes=6)
            ),
        )


def test_package_can_overwrite_when_explicitly_enabled(
    tmp_path: Path,
) -> None:
    """Explicit overwrite permission must replace an existing package."""

    replay_record, key_pair = build_complete_replay_record()

    output_path = (
        tmp_path
        / "replaceable.zip"
    )

    output_path.write_bytes(
        b"not-a-valid-package"
    )

    result = build_replay_package(
        replay_record=replay_record,
        output_path=output_path,
        key_pair=key_pair,
        signer=SIGNER,
        created_by=CREATED_BY,
        created_at=(
            FIXED_TIME + timedelta(minutes=6)
        ),
        overwrite=True,
    )

    assert result.package_path == output_path
    assert zipfile.is_zipfile(output_path)


def test_output_path_must_end_in_zip(
    tmp_path: Path,
) -> None:
    """Replay packages must use the expected ZIP filename boundary."""

    replay_record, key_pair = build_complete_replay_record()

    with pytest.raises(
        ReplayPackageError,
        match="must end in .zip",
    ):
        build_replay_package(
            replay_record=replay_record,
            output_path=(
                tmp_path
                / "invalid-package.bin"
            ),
            key_pair=key_pair,
            signer=SIGNER,
            created_by=CREATED_BY,
            created_at=(
                FIXED_TIME + timedelta(minutes=6)
            ),
        )


def test_unsealed_ledger_is_rejected(
    tmp_path: Path,
) -> None:
    """A package cannot be created before the route ledger is sealed."""

    replay_record, key_pair = build_complete_replay_record()

    unsealed_ledger = replay_record.ledger.model_copy(
        update={
            "sealed_at": None,
            "seal_signature": None,
        }
    )

    incomplete_record = replay_record.model_copy(
        update={
            "ledger": unsealed_ledger,
        }
    )

    with pytest.raises(
        ReplayPackageError,
        match="Ledger must be sealed",
    ):
        build_replay_package(
            replay_record=incomplete_record,
            output_path=(
                tmp_path
                / "unsealed.zip"
            ),
            key_pair=key_pair,
            signer=SIGNER,
            created_by=CREATED_BY,
            created_at=(
                FIXED_TIME + timedelta(minutes=6)
            ),
        )


def test_cross_route_determination_is_rejected(
    tmp_path: Path,
) -> None:
    """All route-bearing records must belong to the same governed route."""

    replay_record, key_pair = build_complete_replay_record()

    foreign_determination = (
        replay_record.determination.model_copy(
            update={
                "route_id": uuid4(),
            }
        )
    )

    invalid_record = replay_record.model_copy(
        update={
            "determination": foreign_determination,
        }
    )

    with pytest.raises(
        ReplayPackageError,
        match="Determination receipt belongs to a different route",
    ):
        build_replay_package(
            replay_record=invalid_record,
            output_path=(
                tmp_path
                / "cross-route.zip"
            ),
            key_pair=key_pair,
            signer=SIGNER,
            created_by=CREATED_BY,
            created_at=(
                FIXED_TIME + timedelta(minutes=6)
            ),
        )


def test_safe_extraction_returns_destination(
    tmp_path: Path,
) -> None:
    """A valid package must extract into the requested directory."""

    replay_record, key_pair = build_complete_replay_record()

    output_path = (
        tmp_path
        / "safe-extraction.zip"
    )

    build_replay_package(
        replay_record=replay_record,
        output_path=output_path,
        key_pair=key_pair,
        signer=SIGNER,
        created_by=CREATED_BY,
        created_at=(
            FIXED_TIME + timedelta(minutes=6)
        ),
    )

    destination = (
        tmp_path
        / "safe-extraction"
    )

    extracted = extract_replay_package(
        package_path=output_path,
        destination=destination,
    )

    assert extracted == destination
    assert (
        destination
        / "package-manifest.json"
    ).exists()

    assert (
        destination
        / "README.txt"
    ).exists()


def test_extraction_refuses_existing_destination(
    tmp_path: Path,
) -> None:
    """Existing extraction directories must not be replaced silently."""

    replay_record, key_pair = build_complete_replay_record()

    output_path = (
        tmp_path
        / "existing-destination.zip"
    )

    build_replay_package(
        replay_record=replay_record,
        output_path=output_path,
        key_pair=key_pair,
        signer=SIGNER,
        created_by=CREATED_BY,
        created_at=(
            FIXED_TIME + timedelta(minutes=6)
        ),
    )

    destination = (
        tmp_path
        / "existing-destination"
    )

    destination.mkdir()

    with pytest.raises(
        ReplayPackageError,
        match="Extraction destination already exists",
    ):
        extract_replay_package(
            package_path=output_path,
            destination=destination,
        )


def test_invalid_zip_is_rejected(
    tmp_path: Path,
) -> None:
    """Inspection and extraction must reject non-ZIP files."""

    invalid_package = (
        tmp_path
        / "invalid.zip"
    )

    invalid_package.write_text(
        "This is not a ZIP archive.",
        encoding="utf-8",
    )

    with pytest.raises(
        ReplayPackageError,
        match="not a valid ZIP archive",
    ):
        inspect_package_members(
            invalid_package
        )

    with pytest.raises(
        ReplayPackageError,
        match="not a valid ZIP archive",
    ):
        extract_replay_package(
            package_path=invalid_package,
            destination=(
                tmp_path
                / "invalid-extraction"
            ),
        )


def test_extraction_rejects_parent_directory_traversal(
    tmp_path: Path,
) -> None:
    """Malicious archive members must not escape the extraction directory."""

    malicious_package = (
        tmp_path
        / "malicious.zip"
    )

    with zipfile.ZipFile(
        malicious_package,
        mode="w",
    ) as archive:
        archive.writestr(
            "../escaped.txt",
            "malicious-content",
        )

    destination = (
        tmp_path
        / "malicious-extraction"
    )

    escaped_target = (
        tmp_path
        / "escaped.txt"
    )

    with pytest.raises(
        ReplayPackageError,
        match="parent-directory traversal",
    ):
        extract_replay_package(
            package_path=malicious_package,
            destination=destination,
        )

    assert not escaped_target.exists()
    assert not destination.exists()


def test_manifest_does_not_list_itself(
    tmp_path: Path,
) -> None:
    """
    The signed manifest covers governed payload files, not its own bytes.

    The manifest and README are added after the governed payload file list
    has been calculated.
    """

    replay_record, key_pair = build_complete_replay_record()

    output_path = (
        tmp_path
        / "manifest-boundary.zip"
    )

    build_replay_package(
        replay_record=replay_record,
        output_path=output_path,
        key_pair=key_pair,
        signer=SIGNER,
        created_by=CREATED_BY,
        created_at=(
            FIXED_TIME + timedelta(minutes=6)
        ),
    )

    manifest_data = read_zip_json(
        output_path,
        "package-manifest.json",
    )

    listed_paths = {
        item["path"]
        for item in manifest_data["files"]
    }

    assert "package-manifest.json" not in listed_paths
    assert "README.txt" not in listed_paths

    assert "route-manifest.json" in listed_paths
    assert "ledger.json" in listed_paths
    assert "public-verification-key.json" in listed_paths
