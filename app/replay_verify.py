"""
TA-14 Independent Route Replay Standard
Independent replay-package verification.

Purpose
-------
This module verifies a TA-14 replay package without relying on the TA-14
dashboard, original operator, or live decision engine.

The verifier checks:

- archive safety and required files;
- package-manifest structure;
- package-manifest signature;
- public-key fingerprint;
- every listed file digest;
- route consistency;
- route-manifest digest;
- evidence-index digest;
- determination digest and signature;
- binding digest and signature;
- commit digest and signature;
- execution digest and signature;
- outcome digest and signature;
- ruleset correspondence;
- action binding;
- determination-to-binding correspondence;
- binding-to-commit correspondence;
- commit-to-execution correspondence;
- execution-to-outcome correspondence;
- ledger hashes, sequence, root, final digest, and seal signature;
- ledger object correspondence;
- declared omissions, redactions, warnings, and divergence.

The verifier returns a structured IndependentVerificationReport and does not
require private key material.

Security boundary
-----------------
Verification proves that preserved records are internally consistent,
cryptographically intact, and signed by the included public key.

It does not independently prove that an external source told the truth unless
the source evidence was authenticated, included, or independently retrievable.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Optional, Sequence
from uuid import UUID

from pydantic import ValidationError

from .replay_crypto import (
    digest_named_objects,
    digest_object,
    secure_digest_equal,
    verify_file_digest,
    verify_ledger_chain,
    verify_object_digest,
)
from .replay_ledger import verify_ledger_record
from .replay_models import (
    BindingReceipt,
    CommitReceipt,
    DeterminationReceipt,
    EvidenceIndex,
    ExecutionReceipt,
    IndependentVerificationReport,
    IntegrityStatus,
    LedgerRecord,
    OutcomeRecord,
    ReplayDecision,
    ReplayPackageManifest,
    RouteManifest,
    RulesetRecord,
    VerificationCheck,
    VerificationStatus,
)
from .replay_package import ReplayPackageError
from .replay_signing import (
    KeyLoadingError,
    load_public_key_pem,
    public_key_fingerprint,
    verify_object_signature,
)


REQUIRED_PACKAGE_FILES = {
    "route-manifest.json",
    "evidence-index.json",
    "ruleset.json",
    "determination.json",
    "ledger.json",
    "ledger.jsonl",
    "public-verification-key.json",
    "package-manifest.json",
    "README.txt",
}

OPTIONAL_ROUTE_FILES = {
    "binding.json",
    "commit.json",
    "execution.json",
    "outcome.json",
}


class ReplayVerificationError(ValueError):
    """Raised when a replay package cannot be parsed or verified safely."""


class VerificationCollector:
    """
    Collect verification checks and derive the final verification status.
    """

    def __init__(self) -> None:
        self.checks: list[VerificationCheck] = []
        self.failures: list[str] = []
        self.warnings: list[str] = []

    def verified(
        self,
        *,
        check_id: str,
        name: str,
        message: str,
        expected: Any = None,
        observed: Any = None,
        related_object_ids: Sequence[str] = (),
    ) -> None:
        self.checks.append(
            VerificationCheck(
                check_id=check_id,
                name=name,
                status=VerificationStatus.VERIFIED,
                message=message,
                expected=expected,
                observed=observed,
                related_object_ids=list(related_object_ids),
            )
        )

    def failed(
        self,
        *,
        check_id: str,
        name: str,
        message: str,
        expected: Any = None,
        observed: Any = None,
        related_object_ids: Sequence[str] = (),
    ) -> None:
        self.checks.append(
            VerificationCheck(
                check_id=check_id,
                name=name,
                status=VerificationStatus.FAILED,
                message=message,
                expected=expected,
                observed=observed,
                related_object_ids=list(related_object_ids),
            )
        )
        self.failures.append(message)

    def partial(
        self,
        *,
        check_id: str,
        name: str,
        message: str,
        expected: Any = None,
        observed: Any = None,
        related_object_ids: Sequence[str] = (),
    ) -> None:
        self.checks.append(
            VerificationCheck(
                check_id=check_id,
                name=name,
                status=VerificationStatus.PARTIAL,
                message=message,
                expected=expected,
                observed=observed,
                related_object_ids=list(related_object_ids),
            )
        )
        self.warnings.append(message)

    def status(self) -> VerificationStatus:
        if self.failures:
            return VerificationStatus.FAILED

        if self.warnings:
            return VerificationStatus.PARTIAL

        return VerificationStatus.VERIFIED


def _read_json(
    root: Path,
    relative_path: str,
) -> Any:
    """Read one UTF-8 JSON document from an extracted package."""

    path = root / relative_path

    if not path.exists():
        raise ReplayVerificationError(
            f"Required JSON document is missing: {relative_path}"
        )

    if not path.is_file():
        raise ReplayVerificationError(
            f"Replay package path is not a file: {relative_path}"
        )

    try:
        return json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise ReplayVerificationError(
            f"Unable to parse JSON document: {relative_path}"
        ) from exc


def _safe_extract(
    package_path: Path,
    destination: Path,
) -> None:
    """Extract a ZIP archive while rejecting unsafe member paths."""

    if not package_path.exists():
        raise FileNotFoundError(
            f"Replay package does not exist: {package_path}"
        )

    if not package_path.is_file():
        raise ReplayVerificationError(
            f"Replay package path is not a file: {package_path}"
        )

    if not zipfile.is_zipfile(package_path):
        raise ReplayVerificationError(
            "Replay package is not a valid ZIP archive."
        )

    destination.mkdir(
        parents=True,
        exist_ok=False,
    )

    try:
        with zipfile.ZipFile(
            package_path,
            mode="r",
        ) as archive:
            for information in archive.infolist():
                member_path = Path(
                    information.filename
                )

                if member_path.is_absolute():
                    raise ReplayVerificationError(
                        "Replay package contains an absolute archive path."
                    )

                if ".." in member_path.parts:
                    raise ReplayVerificationError(
                        "Replay package contains parent-directory traversal."
                    )

                target = (
                    destination
                    / member_path
                ).resolve()

                root = destination.resolve()

                if (
                    target != root
                    and root not in target.parents
                ):
                    raise ReplayVerificationError(
                        "Replay package member escapes the extraction directory."
                    )

            archive.extractall(destination)

    except Exception:
        shutil.rmtree(
            destination,
            ignore_errors=True,
        )
        raise


def _parse_model(
    *,
    model_type: Any,
    data: Any,
    object_name: str,
) -> Any:
    """Parse one replay model and return a clear verification error."""

    try:
        return model_type.model_validate(data)
    except ValidationError as exc:
        raise ReplayVerificationError(
            f"{object_name} failed schema validation."
        ) from exc


def _optional_model(
    *,
    root: Path,
    relative_path: str,
    model_type: Any,
    object_name: str,
) -> Any | None:
    """Read and parse an optional replay document."""

    path = root / relative_path

    if not path.exists():
        return None

    return _parse_model(
        model_type=model_type,
        data=_read_json(
            root,
            relative_path,
        ),
        object_name=object_name,
    )


def _verify_stored_digest(
    *,
    collector: VerificationCollector,
    check_id: str,
    name: str,
    value: Any,
    stored_digest: Any,
    related_object_ids: Sequence[str] = (),
) -> IntegrityStatus:
    """Verify one model's stored canonical digest."""

    if stored_digest is None:
        collector.failed(
            check_id=check_id,
            name=name,
            message=f"{name} does not contain its required digest.",
            related_object_ids=related_object_ids,
        )
        return IntegrityStatus.INVALID

    if verify_object_digest(
        value,
        stored_digest,
    ):
        collector.verified(
            check_id=check_id,
            name=name,
            message=f"{name} digest is valid.",
            related_object_ids=related_object_ids,
        )
        return IntegrityStatus.VALID

    collector.failed(
        check_id=check_id,
        name=name,
        message=f"{name} digest verification failed.",
        related_object_ids=related_object_ids,
    )
    return IntegrityStatus.INVALID


def _verify_signature(
    *,
    collector: VerificationCollector,
    check_id: str,
    name: str,
    value: Any,
    signature: Any,
    public_key: Any,
    required: bool,
    related_object_ids: Sequence[str] = (),
) -> IntegrityStatus:
    """Verify one replay object's Ed25519 signature."""

    if signature is None:
        if required:
            collector.failed(
                check_id=check_id,
                name=name,
                message=f"{name} is missing its required signature.",
                related_object_ids=related_object_ids,
            )
            return IntegrityStatus.INVALID

        collector.partial(
            check_id=check_id,
            name=name,
            message=f"{name} is unsigned.",
            related_object_ids=related_object_ids,
        )
        return IntegrityStatus.UNVERIFIED

    result = verify_object_signature(
        value,
        signature,
        public_key=public_key,
    )

    if result.valid:
        collector.verified(
            check_id=check_id,
            name=name,
            message=f"{name} signature is valid.",
            related_object_ids=related_object_ids,
        )
        return IntegrityStatus.VALID

    collector.failed(
        check_id=check_id,
        name=name,
        message=(
            f"{name} signature verification failed: "
            f"{result.message}"
        ),
        related_object_ids=related_object_ids,
    )
    return IntegrityStatus.INVALID


def _verify_manifest_files(
    *,
    collector: VerificationCollector,
    root: Path,
    manifest: ReplayPackageManifest,
) -> IntegrityStatus:
    """Verify every file listed in the signed package manifest."""

    all_valid = True
    listed_paths: set[str] = set()

    for file_record in manifest.files:
        if file_record.path in listed_paths:
            collector.failed(
                check_id="package-file-duplicate",
                name="Package file uniqueness",
                message=(
                    "Package manifest contains a duplicate file path: "
                    f"{file_record.path}"
                ),
                observed=file_record.path,
            )
            all_valid = False
            continue

        listed_paths.add(file_record.path)

        file_path = root / file_record.path

        if not file_path.exists():
            collector.failed(
                check_id=f"file-present:{file_record.path}",
                name="Package file presence",
                message=(
                    "Manifest-listed file is missing: "
                    f"{file_record.path}"
                ),
                expected=file_record.path,
            )
            all_valid = False
            continue

        if not file_path.is_file():
            collector.failed(
                check_id=f"file-type:{file_record.path}",
                name="Package file type",
                message=(
                    "Manifest-listed path is not a file: "
                    f"{file_record.path}"
                ),
                observed=file_record.path,
            )
            all_valid = False
            continue

        observed_length = file_path.stat().st_size

        if observed_length != file_record.byte_length:
            collector.failed(
                check_id=f"file-length:{file_record.path}",
                name="Package file length",
                message=(
                    "File byte length does not match manifest: "
                    f"{file_record.path}"
                ),
                expected=file_record.byte_length,
                observed=observed_length,
            )
            all_valid = False

        if verify_file_digest(
            file_path,
            file_record.digest,
        ):
            collector.verified(
                check_id=f"file-digest:{file_record.path}",
                name="Package file digest",
                message=(
                    "File digest is valid: "
                    f"{file_record.path}"
                ),
                related_object_ids=[
                    file_record.path
                ],
            )
        else:
            collector.failed(
                check_id=f"file-digest:{file_record.path}",
                name="Package file digest",
                message=(
                    "File digest verification failed: "
                    f"{file_record.path}"
                ),
                related_object_ids=[
                    file_record.path
                ],
            )
            all_valid = False

        if file_record.redacted:
            collector.partial(
                check_id=f"file-redacted:{file_record.path}",
                name="Package disclosure",
                message=(
                    "Package file is declared redacted: "
                    f"{file_record.path}"
                ),
                related_object_ids=[
                    file_record.path
                ],
            )

        if file_record.encrypted:
            collector.partial(
                check_id=f"file-encrypted:{file_record.path}",
                name="Package disclosure",
                message=(
                    "Package file is declared encrypted: "
                    f"{file_record.path}"
                ),
                related_object_ids=[
                    file_record.path
                ],
            )

    observed_compound_digest = digest_named_objects(
        {
            file_record.path: {
                "media_type": file_record.media_type,
                "byte_length": file_record.byte_length,
                "digest": file_record.digest,
                "required": file_record.required,
                "encrypted": file_record.encrypted,
                "redacted": file_record.redacted,
            }
            for file_record in manifest.files
        }
    )

    if manifest.package_digest is None:
        collector.failed(
            check_id="package-payload-root",
            name="Package payload root",
            message="Package manifest does not contain package_digest.",
        )
        all_valid = False
    elif secure_digest_equal(
        observed_compound_digest,
        manifest.package_digest,
    ):
        collector.verified(
            check_id="package-payload-root",
            name="Package payload root",
            message="Package payload compound digest is valid.",
        )
    else:
        collector.failed(
            check_id="package-payload-root",
            name="Package payload root",
            message="Package payload compound digest is invalid.",
        )
        all_valid = False

    return (
        IntegrityStatus.VALID
        if all_valid
        else IntegrityStatus.INVALID
    )


def _verify_required_members(
    *,
    collector: VerificationCollector,
    root: Path,
) -> None:
    """Verify that required archive members are present."""

    observed = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }

    missing = sorted(
        REQUIRED_PACKAGE_FILES - observed
    )

    if missing:
        collector.failed(
            check_id="required-package-members",
            name="Required package members",
            message=(
                "Replay package is missing required files: "
                + ", ".join(missing)
            ),
            expected=sorted(REQUIRED_PACKAGE_FILES),
            observed=sorted(observed),
        )
        return

    collector.verified(
        check_id="required-package-members",
        name="Required package members",
        message="All required replay-package files are present.",
    )


def _verify_route_consistency(
    *,
    collector: VerificationCollector,
    route_manifest: RouteManifest,
    determination: DeterminationReceipt,
    binding: Optional[BindingReceipt],
    commit: Optional[CommitReceipt],
    execution: Optional[ExecutionReceipt],
    outcome: Optional[OutcomeRecord],
    ledger: LedgerRecord,
    package_manifest: ReplayPackageManifest,
) -> bool:
    """Verify that every route-bearing object belongs to one route."""

    route_id = route_manifest.route_id
    all_valid = True

    objects: list[tuple[str, Optional[UUID]]] = [
        (
            "determination",
            determination.route_id,
        ),
        (
            "binding",
            binding.route_id
            if binding is not None
            else None,
        ),
        (
            "commit",
            commit.route_id
            if commit is not None
            else None,
        ),
        (
            "execution",
            execution.route_id
            if execution is not None
            else None,
        ),
        (
            "outcome",
            outcome.route_id
            if outcome is not None
            else None,
        ),
        (
            "ledger",
            ledger.route_id,
        ),
        (
            "package_manifest",
            package_manifest.route_id,
        ),
    ]

    for object_name, observed_route_id in objects:
        if observed_route_id is None:
            continue

        if observed_route_id == route_id:
            collector.verified(
                check_id=f"route-id:{object_name}",
                name="Route identity",
                message=(
                    f"{object_name} belongs to the governed route."
                ),
                expected=str(route_id),
                observed=str(observed_route_id),
            )
        else:
            collector.failed(
                check_id=f"route-id:{object_name}",
                name="Route identity",
                message=(
                    f"{object_name} belongs to a different route."
                ),
                expected=str(route_id),
                observed=str(observed_route_id),
            )
            all_valid = False

    return all_valid


def _verify_dependency_correspondence(
    *,
    collector: VerificationCollector,
    route_manifest: RouteManifest,
    evidence_index: EvidenceIndex,
    ruleset: RulesetRecord,
    determination: DeterminationReceipt,
    binding: Optional[BindingReceipt],
    commit: Optional[CommitReceipt],
    execution: Optional[ExecutionReceipt],
    outcome: Optional[OutcomeRecord],
) -> tuple[
    IntegrityStatus,
    IntegrityStatus,
    IntegrityStatus,
    IntegrityStatus,
    IntegrityStatus,
]:
    """
    Verify binding, commit, execution, and outcome dependency correspondence.
    """

    ruleset_integrity = IntegrityStatus.VALID
    action_binding = IntegrityStatus.NOT_APPLICABLE
    commit_integrity = IntegrityStatus.NOT_APPLICABLE
    execution_correspondence = IntegrityStatus.NOT_APPLICABLE
    outcome_correspondence = IntegrityStatus.NOT_APPLICABLE

    if (
        route_manifest.ruleset_id
        == ruleset.ruleset_id
        and route_manifest.ruleset_version
        == ruleset.ruleset_version
        and secure_digest_equal(
            route_manifest.ruleset_digest,
            ruleset.ruleset_digest,
        )
    ):
        collector.verified(
            check_id="ruleset-correspondence",
            name="Ruleset correspondence",
            message=(
                "Ruleset identity, version, and digest match "
                "the route manifest."
            ),
        )
    else:
        collector.failed(
            check_id="ruleset-correspondence",
            name="Ruleset correspondence",
            message=(
                "Ruleset identity, version, or digest does not "
                "match the route manifest."
            ),
        )
        ruleset_integrity = IntegrityStatus.INVALID

    if route_manifest.manifest_digest is None:
        collector.failed(
            check_id="determination-manifest-binding",
            name="Determination manifest binding",
            message="Route manifest does not contain manifest_digest.",
        )
    elif secure_digest_equal(
        route_manifest.manifest_digest,
        determination.manifest_digest,
    ):
        collector.verified(
            check_id="determination-manifest-binding",
            name="Determination manifest binding",
            message=(
                "Determination is bound to the preserved route manifest."
            ),
        )
    else:
        collector.failed(
            check_id="determination-manifest-binding",
            name="Determination manifest binding",
            message=(
                "Determination manifest digest does not match "
                "the route manifest."
            ),
        )

    if binding is not None:
        action_binding = IntegrityStatus.VALID

        binding_checks = [
            (
                "binding-action",
                binding.action_digest,
                route_manifest.proposed_action.action_digest,
                "Binding action digest matches the proposed action.",
            ),
            (
                "binding-evidence-index",
                binding.evidence_index_digest,
                evidence_index.index_digest,
                "Binding evidence-index digest matches.",
            ),
            (
                "binding-ruleset",
                binding.ruleset_digest,
                ruleset.ruleset_digest,
                "Binding ruleset digest matches.",
            ),
            (
                "binding-determination",
                binding.determination_digest,
                determination.determination_digest,
                "Binding determination digest matches.",
            ),
        ]

        for (
            check_id,
            observed_digest,
            expected_digest,
            success_message,
        ) in binding_checks:
            if (
                observed_digest is not None
                and expected_digest is not None
                and secure_digest_equal(
                    observed_digest,
                    expected_digest,
                )
            ):
                collector.verified(
                    check_id=check_id,
                    name="Binding correspondence",
                    message=success_message,
                )
            else:
                collector.failed(
                    check_id=check_id,
                    name="Binding correspondence",
                    message=(
                        success_message.replace(
                            "matches",
                            "does not match",
                        )
                    ),
                )
                action_binding = IntegrityStatus.INVALID

        if (
            binding.determination_receipt_id
            == determination.receipt_id
        ):
            collector.verified(
                check_id="binding-receipt-reference",
                name="Binding receipt reference",
                message=(
                    "Binding references the preserved determination receipt."
                ),
            )
        else:
            collector.failed(
                check_id="binding-receipt-reference",
                name="Binding receipt reference",
                message=(
                    "Binding references a different determination receipt."
                ),
            )
            action_binding = IntegrityStatus.INVALID

    elif determination.decision == ReplayDecision.ALLOW:
        collector.partial(
            check_id="binding-present",
            name="Binding presence",
            message=(
                "ALLOW determination contains no binding receipt."
            ),
        )
        action_binding = IntegrityStatus.UNVERIFIED

    if commit is not None:
        commit_integrity = IntegrityStatus.VALID

        if binding is None:
            collector.failed(
                check_id="commit-binding-present",
                name="Commit binding",
                message=(
                    "Commit receipt exists without a binding receipt."
                ),
            )
            commit_integrity = IntegrityStatus.INVALID
        else:
            if commit.binding_id == binding.binding_id:
                collector.verified(
                    check_id="commit-binding-reference",
                    name="Commit binding",
                    message=(
                        "Commit references the preserved binding receipt."
                    ),
                )
            else:
                collector.failed(
                    check_id="commit-binding-reference",
                    name="Commit binding",
                    message=(
                        "Commit references a different binding receipt."
                    ),
                )
                commit_integrity = IntegrityStatus.INVALID

            if (
                binding.binding_digest is not None
                and secure_digest_equal(
                    commit.bound_binding_digest,
                    binding.binding_digest,
                )
            ):
                collector.verified(
                    check_id="commit-binding-digest",
                    name="Commit binding",
                    message=(
                        "Commit is cryptographically bound to the binding."
                    ),
                )
            else:
                collector.failed(
                    check_id="commit-binding-digest",
                    name="Commit binding",
                    message=(
                        "Commit binding digest does not match."
                    ),
                )
                commit_integrity = IntegrityStatus.INVALID

            if secure_digest_equal(
                commit.bound_action_digest,
                binding.action_digest,
            ):
                collector.verified(
                    check_id="commit-action-digest",
                    name="Commit action binding",
                    message=(
                        "Commit action digest matches the bound action."
                    ),
                )
            else:
                collector.failed(
                    check_id="commit-action-digest",
                    name="Commit action binding",
                    message=(
                        "Commit action digest does not match the bound action."
                    ),
                )
                commit_integrity = IntegrityStatus.INVALID

        if commit.revoked_at is not None:
            collector.failed(
                check_id="commit-revocation",
                name="Commit state",
                message="Commit receipt was revoked.",
                observed=commit.revocation_reason,
            )
            commit_integrity = IntegrityStatus.INVALID
        else:
            collector.verified(
                check_id="commit-revocation",
                name="Commit state",
                message="Commit receipt was not revoked.",
            )

        if commit.single_use:
            if commit.consumed_at is not None:
                collector.verified(
                    check_id="commit-consumption",
                    name="Commit state",
                    message=(
                        "Single-use commit contains a consumption timestamp."
                    ),
                )
            else:
                collector.partial(
                    check_id="commit-consumption",
                    name="Commit state",
                    message=(
                        "Single-use commit was not marked consumed."
                    ),
                )
                if commit_integrity == IntegrityStatus.VALID:
                    commit_integrity = IntegrityStatus.UNVERIFIED

    if execution is not None:
        execution_correspondence = IntegrityStatus.VALID

        if commit is None:
            collector.failed(
                check_id="execution-commit-present",
                name="Execution correspondence",
                message=(
                    "Execution receipt exists without a commit receipt."
                ),
            )
            execution_correspondence = IntegrityStatus.INVALID
        else:
            if execution.commit_id == commit.commit_id:
                collector.verified(
                    check_id="execution-commit-reference",
                    name="Execution correspondence",
                    message=(
                        "Execution references the preserved commit receipt."
                    ),
                )
            else:
                collector.failed(
                    check_id="execution-commit-reference",
                    name="Execution correspondence",
                    message=(
                        "Execution references a different commit receipt."
                    ),
                )
                execution_correspondence = IntegrityStatus.INVALID

            if secure_digest_equal(
                execution.bound_action_digest,
                commit.bound_action_digest,
            ):
                collector.verified(
                    check_id="execution-bound-action",
                    name="Execution correspondence",
                    message=(
                        "Execution bound-action digest matches the commit."
                    ),
                )
            else:
                collector.failed(
                    check_id="execution-bound-action",
                    name="Execution correspondence",
                    message=(
                        "Execution bound-action digest does not match "
                        "the commit."
                    ),
                )
                execution_correspondence = IntegrityStatus.INVALID

            if secure_digest_equal(
                execution.submitted_action_digest,
                commit.bound_action_digest,
            ):
                collector.verified(
                    check_id="execution-submitted-action",
                    name="Execution correspondence",
                    message=(
                        "Submitted execution action matches the committed action."
                    ),
                )
            else:
                collector.failed(
                    check_id="execution-submitted-action",
                    name="Execution correspondence",
                    message=(
                        "Submitted execution action does not match "
                        "the committed action."
                    ),
                )
                execution_correspondence = IntegrityStatus.INVALID

        if execution.action_binding_matched:
            collector.verified(
                check_id="execution-binding-flag",
                name="Execution correspondence",
                message=(
                    "Execution records a successful action-binding match."
                ),
            )
        else:
            collector.failed(
                check_id="execution-binding-flag",
                name="Execution correspondence",
                message=(
                    "Execution records an action-binding mismatch."
                ),
            )
            execution_correspondence = IntegrityStatus.INVALID

    if outcome is not None:
        outcome_correspondence = IntegrityStatus.VALID

        if execution is None:
            collector.failed(
                check_id="outcome-execution-present",
                name="Outcome correspondence",
                message=(
                    "Outcome record exists without an execution receipt."
                ),
            )
            outcome_correspondence = IntegrityStatus.INVALID
        elif outcome.execution_id == execution.execution_id:
            collector.verified(
                check_id="outcome-execution-reference",
                name="Outcome correspondence",
                message=(
                    "Outcome references the preserved execution receipt."
                ),
            )
        else:
            collector.failed(
                check_id="outcome-execution-reference",
                name="Outcome correspondence",
                message=(
                    "Outcome references a different execution receipt."
                ),
            )
            outcome_correspondence = IntegrityStatus.INVALID

        if outcome.consequence_matched:
            collector.verified(
                check_id="outcome-consequence",
                name="Outcome correspondence",
                message=(
                    "Observed consequence matched the intended outcome."
                ),
            )
        else:
            collector.failed(
                check_id="outcome-consequence",
                name="Outcome correspondence",
                message=(
                    "Observed consequence did not match the intended outcome."
                ),
            )
            outcome_correspondence = IntegrityStatus.INVALID

        if outcome.remained_within_binding_conditions:
            collector.verified(
                check_id="outcome-binding-conditions",
                name="Outcome correspondence",
                message=(
                    "Outcome remained within the binding conditions."
                ),
            )
        else:
            collector.failed(
                check_id="outcome-binding-conditions",
                name="Outcome correspondence",
                message=(
                    "Outcome left the binding conditions."
                ),
            )
            outcome_correspondence = IntegrityStatus.INVALID

        if outcome.authority_remained_valid:
            collector.verified(
                check_id="outcome-authority",
                name="Outcome correspondence",
                message=(
                    "Authority remained valid through outcome observation."
                ),
            )
        else:
            collector.failed(
                check_id="outcome-authority",
                name="Outcome correspondence",
                message=(
                    "Authority did not remain valid through outcome."
                ),
            )
            outcome_correspondence = IntegrityStatus.INVALID

        if outcome.evidence_remained_valid:
            collector.verified(
                check_id="outcome-evidence",
                name="Outcome correspondence",
                message=(
                    "Evidence remained valid through outcome observation."
                ),
            )
        else:
            collector.failed(
                check_id="outcome-evidence",
                name="Outcome correspondence",
                message=(
                    "Evidence did not remain valid through outcome."
                ),
            )
            outcome_correspondence = IntegrityStatus.INVALID

        if outcome.divergences:
            collector.partial(
                check_id="outcome-divergence",
                name="Outcome divergence",
                message=(
                    f"Outcome contains {len(outcome.divergences)} "
                    "preserved divergence record(s)."
                ),
                observed=[
                    divergence.category
                    for divergence in outcome.divergences
                ],
            )

    return (
        ruleset_integrity,
        action_binding,
        commit_integrity,
        execution_correspondence,
        outcome_correspondence,
    )


def _verify_ledger_object_correspondence(
    *,
    collector: VerificationCollector,
    ledger: LedgerRecord,
    route_manifest: RouteManifest,
    determination: DeterminationReceipt,
    binding: Optional[BindingReceipt],
    commit: Optional[CommitReceipt],
    execution: Optional[ExecutionReceipt],
    outcome: Optional[OutcomeRecord],
) -> None:
    """Verify that ledger object digests correspond to preserved records."""

    expected_objects: dict[str, Any] = {
        str(route_manifest.route_id): route_manifest,
        str(determination.receipt_id): determination,
    }

    if binding is not None:
        expected_objects[
            str(binding.binding_id)
        ] = binding

    if commit is not None:
        expected_objects[
            str(commit.commit_id)
        ] = commit

    if execution is not None:
        expected_objects[
            str(execution.execution_id)
        ] = execution

    if outcome is not None:
        expected_objects[
            str(outcome.outcome_id)
        ] = outcome

    for event in ledger.events:
        preserved = expected_objects.get(
            event.object_id
        )

        if preserved is None:
            collector.partial(
                check_id=f"ledger-object:{event.sequence}",
                name="Ledger object correspondence",
                message=(
                    "Ledger event references an object not loaded by "
                    "the core verifier: "
                    f"{event.object_id}"
                ),
                observed=event.object_type,
                related_object_ids=[
                    event.object_id
                ],
            )
            continue

        observed_digest = digest_object(
            preserved
        )

        if secure_digest_equal(
            observed_digest,
            event.object_digest,
        ):
            collector.verified(
                check_id=f"ledger-object:{event.sequence}",
                name="Ledger object correspondence",
                message=(
                    "Ledger object digest matches preserved record: "
                    f"{event.object_id}"
                ),
                related_object_ids=[
                    event.object_id
                ],
            )
        else:
            collector.failed(
                check_id=f"ledger-object:{event.sequence}",
                name="Ledger object correspondence",
                message=(
                    "Ledger object digest does not match preserved record: "
                    f"{event.object_id}"
                ),
                related_object_ids=[
                    event.object_id
                ],
            )


def verify_replay_package(
    package_path: Path | str,
    *,
    verifier_name: str = "TA-14 Independent Replay Verifier",
    verifier_version: str = "1.0.0",
) -> IndependentVerificationReport:
    """
    Verify a replay package and return a structured independent report.

    Package-format failures raise ReplayVerificationError. Integrity and
    correspondence failures are preserved inside the returned report.
    """

    source = Path(package_path)
    collector = VerificationCollector()

    with tempfile.TemporaryDirectory(
        prefix="ta14-replay-verify-"
    ) as temporary_directory:
        root = (
            Path(temporary_directory)
            / "package"
        )

        _safe_extract(
            source,
            root,
        )

        _verify_required_members(
            collector=collector,
            root=root,
        )

        package_manifest = _parse_model(
            model_type=ReplayPackageManifest,
            data=_read_json(
                root,
                "package-manifest.json",
            ),
            object_name="Package manifest",
        )

        route_manifest = _parse_model(
            model_type=RouteManifest,
            data=_read_json(
                root,
                "route-manifest.json",
            ),
            object_name="Route manifest",
        )

        evidence_index = _parse_model(
            model_type=EvidenceIndex,
            data=_read_json(
                root,
                "evidence-index.json",
            ),
            object_name="Evidence index",
        )

        ruleset = _parse_model(
            model_type=RulesetRecord,
            data=_read_json(
                root,
                "ruleset.json",
            ),
            object_name="Ruleset",
        )

        determination = _parse_model(
            model_type=DeterminationReceipt,
            data=_read_json(
                root,
                "determination.json",
            ),
            object_name="Determination receipt",
        )

        binding = _optional_model(
            root=root,
            relative_path="binding.json",
            model_type=BindingReceipt,
            object_name="Binding receipt",
        )

        commit = _optional_model(
            root=root,
            relative_path="commit.json",
            model_type=CommitReceipt,
            object_name="Commit receipt",
        )

        execution = _optional_model(
            root=root,
            relative_path="execution.json",
            model_type=ExecutionReceipt,
            object_name="Execution receipt",
        )

        outcome = _optional_model(
            root=root,
            relative_path="outcome.json",
            model_type=OutcomeRecord,
            object_name="Outcome record",
        )

        ledger = _parse_model(
            model_type=LedgerRecord,
            data=_read_json(
                root,
                "ledger.json",
            ),
            object_name="Ledger",
        )

        public_key_bundle = _read_json(
            root,
            "public-verification-key.json",
        )

        public_key_pem_value = public_key_bundle.get(
            "public_key_pem"
        )

        if not isinstance(
            public_key_pem_value,
            str,
        ):
            raise ReplayVerificationError(
                "Public verification bundle does not contain public_key_pem."
            )

        try:
            public_key = load_public_key_pem(
                public_key_pem_value.encode(
                    "ascii"
                )
            )
        except (
            UnicodeEncodeError,
            KeyLoadingError,
        ) as exc:
            raise ReplayVerificationError(
                "Unable to load included public verification key."
            ) from exc

        observed_fingerprint = public_key_fingerprint(
            public_key
        )

        declared_fingerprint_data = public_key_bundle.get(
            "public_key_fingerprint"
        )

        declared_fingerprint = None

        if isinstance(
            declared_fingerprint_data,
            dict,
        ):
            try:
                from .replay_models import DigestRecord

                declared_fingerprint = (
                    DigestRecord.model_validate(
                        declared_fingerprint_data
                    )
                )
            except ValidationError:
                declared_fingerprint = None

        if (
            declared_fingerprint is not None
            and secure_digest_equal(
                observed_fingerprint,
                declared_fingerprint,
            )
        ):
            collector.verified(
                check_id="public-key-fingerprint",
                name="Public key fingerprint",
                message=(
                    "Included public-key fingerprint is valid."
                ),
            )
        else:
            collector.failed(
                check_id="public-key-fingerprint",
                name="Public key fingerprint",
                message=(
                    "Included public-key fingerprint is missing or invalid."
                ),
            )

        package_integrity = _verify_manifest_files(
            collector=collector,
            root=root,
            manifest=package_manifest,
        )

        signature_integrity = _verify_signature(
            collector=collector,
            check_id="package-manifest-signature",
            name="Package manifest",
            value=package_manifest,
            signature=package_manifest.signature,
            public_key=public_key,
            required=True,
            related_object_ids=[
                str(package_manifest.package_id)
            ],
        )

        _verify_route_consistency(
            collector=collector,
            route_manifest=route_manifest,
            determination=determination,
            binding=binding,
            commit=commit,
            execution=execution,
            outcome=outcome,
            ledger=ledger,
            package_manifest=package_manifest,
        )

        _verify_stored_digest(
            collector=collector,
            check_id="route-manifest-digest",
            name="Route manifest",
            value=route_manifest,
            stored_digest=route_manifest.manifest_digest,
            related_object_ids=[
                str(route_manifest.route_id)
            ],
        )

        evidence_integrity = _verify_stored_digest(
            collector=collector,
            check_id="evidence-index-digest",
            name="Evidence index",
            value=evidence_index,
            stored_digest=evidence_index.index_digest,
        )

        ruleset_digest_status = _verify_stored_digest(
            collector=collector,
            check_id="ruleset-digest",
            name="Ruleset",
            value=ruleset,
            stored_digest=ruleset.ruleset_digest,
        )

        determination_digest_status = _verify_stored_digest(
            collector=collector,
            check_id="determination-digest",
            name="Determination receipt",
            value=determination,
            stored_digest=determination.determination_digest,
            related_object_ids=[
                str(determination.receipt_id)
            ],
        )

        determination_signature_status = _verify_signature(
            collector=collector,
            check_id="determination-signature",
            name="Determination receipt",
            value=determination,
            signature=determination.signature,
            public_key=public_key,
            required=True,
            related_object_ids=[
                str(determination.receipt_id)
            ],
        )

        if binding is not None:
            _verify_stored_digest(
                collector=collector,
                check_id="binding-digest",
                name="Binding receipt",
                value=binding,
                stored_digest=binding.binding_digest,
                related_object_ids=[
                    str(binding.binding_id)
                ],
            )

            _verify_signature(
                collector=collector,
                check_id="binding-signature",
                name="Binding receipt",
                value=binding,
                signature=binding.signature,
                public_key=public_key,
                required=True,
                related_object_ids=[
                    str(binding.binding_id)
                ],
            )

        if commit is not None:
            _verify_stored_digest(
                collector=collector,
                check_id="commit-digest",
                name="Commit receipt",
                value=commit,
                stored_digest=commit.commit_digest,
                related_object_ids=[
                    str(commit.commit_id)
                ],
            )

            _verify_signature(
                collector=collector,
                check_id="commit-signature",
                name="Commit receipt",
                value=commit,
                signature=commit.signature,
                public_key=public_key,
                required=True,
                related_object_ids=[
                    str(commit.commit_id)
                ],
            )

        if execution is not None:
            _verify_stored_digest(
                collector=collector,
                check_id="execution-digest",
                name="Execution receipt",
                value=execution,
                stored_digest=execution.execution_digest,
                related_object_ids=[
                    str(execution.execution_id)
                ],
            )

            _verify_signature(
                collector=collector,
                check_id="execution-signature",
                name="Execution receipt",
                value=execution,
                signature=execution.signature,
                public_key=public_key,
                required=True,
                related_object_ids=[
                    str(execution.execution_id)
                ],
            )

        if outcome is not None:
            _verify_stored_digest(
                collector=collector,
                check_id="outcome-digest",
                name="Outcome record",
                value=outcome,
                stored_digest=outcome.outcome_digest,
                related_object_ids=[
                    str(outcome.outcome_id)
                ],
            )

            _verify_signature(
                collector=collector,
                check_id="outcome-signature",
                name="Outcome record",
                value=outcome,
                signature=outcome.signature,
                public_key=public_key,
                required=True,
                related_object_ids=[
                    str(outcome.outcome_id)
                ],
            )

        if verify_ledger_chain(
            ledger.events
        ) and verify_ledger_record(ledger):
            collector.verified(
                check_id="ledger-integrity",
                name="Ledger integrity",
                message=(
                    "Ledger sequence, hashes, root, and final digest are valid."
                ),
            )
            ledger_integrity = IntegrityStatus.VALID
        else:
            collector.failed(
                check_id="ledger-integrity",
                name="Ledger integrity",
                message=(
                    "Ledger sequence, hashes, root, or final digest is invalid."
                ),
            )
            ledger_integrity = IntegrityStatus.INVALID

        ledger_seal_status = _verify_signature(
            collector=collector,
            check_id="ledger-seal-signature",
            name="Ledger seal",
            value=ledger,
            signature=ledger.seal_signature,
            public_key=public_key,
            required=True,
            related_object_ids=[
                str(ledger.route_id)
            ],
        )

        if (
            ledger_integrity == IntegrityStatus.VALID
            and ledger_seal_status != IntegrityStatus.VALID
        ):
            ledger_integrity = IntegrityStatus.INVALID

        _verify_ledger_object_correspondence(
            collector=collector,
            ledger=ledger,
            route_manifest=route_manifest,
            determination=determination,
            binding=binding,
            commit=commit,
            execution=execution,
            outcome=outcome,
        )

        (
            ruleset_correspondence,
            action_binding,
            commit_integrity,
            execution_correspondence,
            outcome_correspondence,
        ) = _verify_dependency_correspondence(
            collector=collector,
            route_manifest=route_manifest,
            evidence_index=evidence_index,
            ruleset=ruleset,
            determination=determination,
            binding=binding,
            commit=commit,
            execution=execution,
            outcome=outcome,
        )

        ruleset_integrity = (
            IntegrityStatus.VALID
            if (
                ruleset_digest_status
                == IntegrityStatus.VALID
                and ruleset_correspondence
                == IntegrityStatus.VALID
            )
            else IntegrityStatus.INVALID
        )

        authority_at_commit = (
            IntegrityStatus.VALID
            if (
                outcome is not None
                and outcome.authority_remained_valid
            )
            else IntegrityStatus.UNVERIFIED
        )

        if outcome is None:
            collector.partial(
                check_id="authority-at-commit",
                name="Authority continuity",
                message=(
                    "No outcome record is present to confirm authority "
                    "continuity through consequence."
                ),
            )

        if package_manifest.disclosure_limitations:
            collector.partial(
                check_id="disclosure-limitations",
                name="Disclosure limitations",
                message=(
                    "Package declares disclosure limitations."
                ),
                observed=(
                    package_manifest.disclosure_limitations
                ),
            )

        if package_manifest.contains_sensitive_material:
            collector.partial(
                check_id="sensitive-material",
                name="Sensitive material",
                message=(
                    "Package declares that it contains sensitive material."
                ),
                observed=(
                    package_manifest.encryption_description
                ),
            )

        if (
            determination_digest_status
            != IntegrityStatus.VALID
            or determination_signature_status
            != IntegrityStatus.VALID
        ):
            signature_integrity = IntegrityStatus.INVALID

        overall_status = collector.status()

        independently_replayable = (
            overall_status
            == VerificationStatus.VERIFIED
            and package_integrity
            == IntegrityStatus.VALID
            and signature_integrity
            == IntegrityStatus.VALID
            and ledger_integrity
            == IntegrityStatus.VALID
            and evidence_integrity
            == IntegrityStatus.VALID
            and ruleset_integrity
            == IntegrityStatus.VALID
            and action_binding
            in {
                IntegrityStatus.VALID,
                IntegrityStatus.NOT_APPLICABLE,
            }
            and commit_integrity
            in {
                IntegrityStatus.VALID,
                IntegrityStatus.NOT_APPLICABLE,
            }
            and execution_correspondence
            in {
                IntegrityStatus.VALID,
                IntegrityStatus.NOT_APPLICABLE,
            }
            and outcome_correspondence
            in {
                IntegrityStatus.VALID,
                IntegrityStatus.NOT_APPLICABLE,
            }
        )

        report = IndependentVerificationReport(
            package_id=package_manifest.package_id,
            route_id=route_manifest.route_id,
            verifier_name=verifier_name,
            verifier_version=verifier_version,
            overall_status=overall_status,
            original_decision=determination.decision,
            package_integrity=package_integrity,
            signature_integrity=signature_integrity,
            ledger_integrity=ledger_integrity,
            evidence_integrity=evidence_integrity,
            authority_at_commit=authority_at_commit,
            ruleset_integrity=ruleset_integrity,
            action_binding=action_binding,
            commit_integrity=commit_integrity,
            execution_correspondence=execution_correspondence,
            outcome_correspondence=outcome_correspondence,
            checks=collector.checks,
            failures=collector.failures,
            warnings=collector.warnings,
            independently_replayable=(
                independently_replayable
            ),
            report_digest=None,
            signature=None,
        )

        report_digest = digest_object(
            report
        )

        return report.model_copy(
            update={
                "report_digest": report_digest,
            }
        )


def verification_summary(
    report: IndependentVerificationReport,
) -> str:
    """Create a concise human-readable verification summary."""

    status_lines = [
        (
            "Package integrity",
            report.package_integrity.value,
        ),
        (
            "Signature integrity",
            report.signature_integrity.value,
        ),
        (
            "Ledger integrity",
            report.ledger_integrity.value,
        ),
        (
            "Evidence integrity",
            report.evidence_integrity.value,
        ),
        (
            "Ruleset integrity",
            report.ruleset_integrity.value,
        ),
        (
            "Action binding",
            report.action_binding.value,
        ),
        (
            "Commit integrity",
            report.commit_integrity.value,
        ),
        (
            "Execution correspondence",
            report.execution_correspondence.value,
        ),
        (
            "Outcome correspondence",
            report.outcome_correspondence.value,
        ),
    ]

    rendered_status = "\n".join(
        f"{name}: {value}"
        for name, value in status_lines
    )

    failures = (
        "\n".join(
            f"- {failure}"
            for failure in report.failures
        )
        if report.failures
        else "- None"
    )

    warnings = (
        "\n".join(
            f"- {warning}"
            for warning in report.warnings
        )
        if report.warnings
        else "- None"
    )

    return f"""TA-14 INDEPENDENT ROUTE VERIFICATION
====================================

Overall status: {report.overall_status.value}
Original decision: {report.original_decision.value}
Route ID: {report.route_id}
Package ID: {report.package_id}
Independently replayable: {"YES" if report.independently_replayable else "NO"}

{rendered_status}

Failures
--------
{failures}

Warnings
--------
{warnings}
"""


def verify_and_write_report(
    *,
    package_path: Path | str,
    report_path: Path | str,
    verifier_name: str = "TA-14 Independent Replay Verifier",
    verifier_version: str = "1.0.0",
    overwrite: bool = False,
) -> IndependentVerificationReport:
    """
    Verify a package and write the canonical verification report to JSON.
    """

    destination = Path(report_path)

    if destination.exists() and not overwrite:
        raise ReplayVerificationError(
            f"Refusing to overwrite verification report: {destination}"
        )

    report = verify_replay_package(
        package_path,
        verifier_name=verifier_name,
        verifier_version=verifier_version,
    )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = destination.with_name(
        f".{destination.name}.tmp"
    )

    temporary_path.write_text(
        json.dumps(
            report.model_dump(
                mode="json"
            ),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    temporary_path.replace(destination)

    return report
