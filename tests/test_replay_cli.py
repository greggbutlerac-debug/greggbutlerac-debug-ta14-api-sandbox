"""
Tests for the TA-14 Independent Route Replay command-line interface.

These tests verify:

- version output;
- replay-package inspection;
- JSON inspection output;
- successful verification output;
- JSON verification output;
- report and summary file creation;
- quiet mode;
- overwrite protection;
- verified exit code 0;
- failed or partial exit code 1;
- command and archive error exit code 2.
"""

import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from app.replay_cli import (
    CLI_NAME,
    CLI_VERSION,
    run,
)
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
    PredicateResult,
    ProposedAction,
    ReplayDecision,
    RouteManifest,
    RulesetRecord,
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
)


FIXED_TIME = datetime(
    2026,
    7,
    14,
    22,
    0,
    0,
    tzinfo=timezone.utc,
)

SIGNER = "TA-14 CLI Test Signer"
CREATED_BY = "TA-14 CLI Test Service"


def build_action() -> ProposedAction:
    """Create a deterministic action fixture."""

    action = ProposedAction(
        action_type="synthetic-cli-transfer",
        actor_id="synthetic-cli-agent",
        target="synthetic-cli-target",
        description=(
            "Execute one bounded synthetic transfer for CLI testing."
        ),
        parameters={
            "amount": 7500,
            "currency": "USD",
        },
        requested_at=FIXED_TIME,
        requested_execution_time=(
            FIXED_TIME + timedelta(minutes=5)
        ),
        consequence_class="financial",
        reversible=False,
        maximum_impact="Synthetic CLI test only.",
    )

    return action.model_copy(
        update={
            "action_digest": digest_object(action),
        }
    )


def build_ruleset() -> RulesetRecord:
    """Create a deterministic ruleset fixture."""

    return RulesetRecord(
        ruleset_id="ta14-cli-test-ruleset",
        ruleset_version="1.0.0",
        architecture_version="24-link-cli-test-1.0.0",
        effective_from=(
            FIXED_TIME - timedelta(days=1)
        ),
        effective_until=(
            FIXED_TIME + timedelta(days=30)
        ),
        ruleset_digest=digest_text(
            "ta14-cli-test-ruleset-artifact"
        ),
        rules=[],
        signed_by=None,
    )


def build_route_manifest() -> RouteManifest:
    """Create a deterministic route manifest fixture."""

    ruleset = build_ruleset()

    predicate = PredicateResult(
        predicate_id="cli-authority-active",
        link_number=8,
        link_name="Authority",
        description=(
            "Synthetic CLI execution authority must remain active."
        ),
        satisfied=True,
        required=True,
        observed_value="ACTIVE",
        expected_value="ACTIVE",
        evidence_ids=[],
        authority_ids=[],
        rule_ids=["CLI-AUTHORITY-ACTIVE"],
        evaluated_at=FIXED_TIME,
        evaluator_version="cli-test-engine-1.0.0",
        reason="Synthetic authority is active.",
    )

    chain_link = ChainLinkState(
        link_number=8,
        link_name="Authority",
        satisfied=True,
        required=True,
        status="PASS",
        predicate_ids=[
            "cli-authority-active"
        ],
        evidence_ids=[],
        reason="Authority requirement passed.",
    )

    manifest = RouteManifest(
        route_id=uuid4(),
        request_id=uuid4(),
        correlation_id="cli-test-001",
        created_at=FIXED_TIME,
        expires_at=(
            FIXED_TIME + timedelta(minutes=30)
        ),
        architecture_version="24-link-cli-test-1.0.0",
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
            "cli-test-input"
        ),
        re_evaluation_required_when=[
            "Authority changes.",
            "Evidence expires.",
            "Action parameters change.",
        ],
        metadata={
            "scenario": "synthetic-cli-test",
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


def build_valid_package(
    tmp_path: Path,
    *,
    filename: str = "cli-valid-package.zip",
) -> Path:
    """Build one complete valid replay package."""

    key_pair = generate_key_pair()
    route_manifest = build_route_manifest()
    evidence_index = build_evidence_index()
    ruleset = build_ruleset()

    determination = create_determination_receipt(
        route_manifest=route_manifest,
        decision=ReplayDecision.ALLOW,
        reasons=[
            "All required synthetic CLI predicates passed.",
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
                condition_id="cli-exact-action",
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
                    "CLI-EXACT-ACTION"
                ],
            )
        ],
        bound_by="ta14-cli-binding-service",
        bound_at=(
            FIXED_TIME + timedelta(minutes=1)
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    commit = create_commit_receipt(
        binding=binding,
        authorized_by="ta14-cli-commit-service",
        execution_audience="synthetic-cli-executor",
        authorized_at=(
            FIXED_TIME + timedelta(minutes=2)
        ),
        valid_until=(
            FIXED_TIME + timedelta(minutes=7)
        ),
        execution_nonce="cli-fixed-nonce-0001",
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
        executor_id="synthetic-cli-agent",
        execution_system="synthetic-cli-executor",
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
            "synthetic-cli-execution-result"
        ),
        result_reference=(
            "urn:ta14:test:execution:cli"
        ),
        key_pair=key_pair,
        signer=SIGNER,
    )

    outcome = create_outcome_record(
        execution=execution,
        observer_id="synthetic-cli-observer",
        observation_system="synthetic-cli-outcome-system",
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
        actor="ta14-cli-route-service",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_determination_issued(
        ledger,
        determination=determination,
        actor="ta14-cli-determination-service",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_route_bound(
        ledger,
        binding=binding,
        actor="ta14-cli-binding-service",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_commit_authorized(
        ledger,
        commit=consumed_commit,
        actor="ta14-cli-commit-service",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_execution(
        ledger,
        execution=execution,
        actor="synthetic-cli-executor",
        key_pair=key_pair,
        signer=SIGNER,
    )

    ledger = append_outcome_recorded(
        ledger,
        outcome=outcome,
        actor="synthetic-cli-observer",
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

    return package_path


def rewrite_zip_member(
    source_path: Path,
    output_path: Path,
    member_name: str,
    replacement: bytes,
) -> None:
    """Rewrite one ZIP member for failure-path testing."""

    with zipfile.ZipFile(
        source_path,
        mode="r",
    ) as source_archive:
        members = {
            name: source_archive.read(name)
            for name in source_archive.namelist()
        }

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


def test_version_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The version command must print the CLI identity."""

    exit_code = run(
        [
            "version",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert captured.out == (
        f"{CLI_NAME} {CLI_VERSION}\n"
    )


def test_inspect_lists_package_members(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Inspect must list archive members without verifying them."""

    package_path = build_valid_package(
        tmp_path
    )

    exit_code = run(
        [
            "inspect",
            str(package_path),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""

    assert "package-manifest.json" in captured.out
    assert "route-manifest.json" in captured.out
    assert "ledger.json" in captured.out
    assert "README.txt" in captured.out


def test_inspect_json_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Inspect --json must return a valid JSON list."""

    package_path = build_valid_package(
        tmp_path
    )

    exit_code = run(
        [
            "inspect",
            str(package_path),
            "--json",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""

    members = json.loads(
        captured.out
    )

    assert isinstance(
        members,
        list,
    )

    assert "package-manifest.json" in members
    assert "route-manifest.json" in members


def test_verify_valid_package_returns_exit_zero(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A valid independently replayable package must exit with code zero."""

    package_path = build_valid_package(
        tmp_path
    )

    exit_code = run(
        [
            "verify",
            str(package_path),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""

    assert (
        "TA-14 INDEPENDENT ROUTE VERIFICATION"
        in captured.out
    )

    assert "Overall status: VERIFIED" in captured.out
    assert "Original decision: ALLOW" in captured.out
    assert "Independently replayable: YES" in captured.out


def test_verify_json_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify --json must print the complete structured report."""

    package_path = build_valid_package(
        tmp_path
    )

    exit_code = run(
        [
            "verify",
            str(package_path),
            "--json",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""

    report = json.loads(
        captured.out
    )

    assert report["overall_status"] == "VERIFIED"
    assert report["original_decision"] == "ALLOW"
    assert report["independently_replayable"] is True
    assert report["failures"] == []
    assert report["warnings"] == []


def test_verify_writes_report_and_summary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI verification must write both requested artifacts."""

    package_path = build_valid_package(
        tmp_path
    )

    report_path = (
        tmp_path
        / "verification-report.json"
    )

    summary_path = (
        tmp_path
        / "verification-summary.txt"
    )

    exit_code = run(
        [
            "verify",
            str(package_path),
            "--report",
            str(report_path),
            "--summary",
            str(summary_path),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""

    assert report_path.exists()
    assert summary_path.exists()

    report = json.loads(
        report_path.read_text(
            encoding="utf-8"
        )
    )

    summary = summary_path.read_text(
        encoding="utf-8"
    )

    assert report["overall_status"] == "VERIFIED"
    assert report["independently_replayable"] is True

    assert "Overall status: VERIFIED" in summary
    assert "Independently replayable: YES" in summary


def test_quiet_mode_suppresses_stdout(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Quiet mode must preserve exit status while suppressing output."""

    package_path = build_valid_package(
        tmp_path
    )

    exit_code = run(
        [
            "verify",
            str(package_path),
            "--quiet",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == ""
    assert captured.err == ""


def test_existing_summary_requires_overwrite(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Existing summary output must not be silently replaced."""

    package_path = build_valid_package(
        tmp_path
    )

    summary_path = (
        tmp_path
        / "existing-summary.txt"
    )

    summary_path.write_text(
        "existing-content",
        encoding="utf-8",
    )

    exit_code = run(
        [
            "verify",
            str(package_path),
            "--summary",
            str(summary_path),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""

    assert (
        "Refusing to overwrite existing file"
        in captured.err
    )


def test_overwrite_replaces_existing_outputs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Explicit overwrite permission must replace report and summary files."""

    package_path = build_valid_package(
        tmp_path
    )

    report_path = (
        tmp_path
        / "replaceable-report.json"
    )

    summary_path = (
        tmp_path
        / "replaceable-summary.txt"
    )

    report_path.write_text(
        "{}",
        encoding="utf-8",
    )

    summary_path.write_text(
        "old-summary",
        encoding="utf-8",
    )

    exit_code = run(
        [
            "verify",
            str(package_path),
            "--report",
            str(report_path),
            "--summary",
            str(summary_path),
            "--overwrite",
            "--quiet",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == ""
    assert captured.err == ""

    report = json.loads(
        report_path.read_text(
            encoding="utf-8"
        )
    )

    summary = summary_path.read_text(
        encoding="utf-8"
    )

    assert report["overall_status"] == "VERIFIED"
    assert "Overall status: VERIFIED" in summary


def test_tampered_package_returns_exit_one(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A processed but failed package must exit with code one."""

    package_path = build_valid_package(
        tmp_path
    )

    with zipfile.ZipFile(
        package_path,
        mode="r",
    ) as archive:
        manifest = json.loads(
            archive.read(
                "route-manifest.json"
            ).decode("utf-8")
        )

    manifest["metadata"]["tampered"] = True

    tampered_path = (
        tmp_path
        / "cli-tampered-package.zip"
    )

    rewrite_zip_member(
        package_path,
        tampered_path,
        "route-manifest.json",
        canonical_json_bytes(
            manifest
        ),
    )

    exit_code = run(
        [
            "verify",
            str(tampered_path),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.err == ""

    assert "Overall status: FAILED" in captured.out
    assert "Independently replayable: NO" in captured.out


def test_invalid_archive_returns_exit_two(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Invalid archives must return command error exit code two."""

    invalid_path = (
        tmp_path
        / "invalid-cli-package.zip"
    )

    invalid_path.write_text(
        "not-a-valid-zip",
        encoding="utf-8",
    )

    exit_code = run(
        [
            "verify",
            str(invalid_path),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""

    assert (
        "not a valid ZIP archive"
        in captured.err
    )


def test_inspect_invalid_archive_returns_exit_two(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Inspect must also reject invalid archives with exit code two."""

    invalid_path = (
        tmp_path
        / "invalid-inspection-package.zip"
    )

    invalid_path.write_text(
        "not-a-valid-zip",
        encoding="utf-8",
    )

    exit_code = run(
        [
            "inspect",
            str(invalid_path),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""

    assert (
        "not a valid ZIP archive"
        in captured.err
    )


def test_missing_package_argument_is_argparse_error() -> None:
    """
    argparse must preserve its standard usage-error exit code.

    The run function cannot intercept parser termination because parsing occurs
    before command execution begins.
    """

    with pytest.raises(
        SystemExit
    ) as exc_info:
        run(
            [
                "verify",
            ]
        )

    assert exc_info.value.code == 2
