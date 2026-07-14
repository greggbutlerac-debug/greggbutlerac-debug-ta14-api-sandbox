"""
TA-14 Independent Route Replay Standard
Deterministic replay-package construction and ZIP export.

Purpose
-------
This module converts a completed governed route into one portable package
that an outside party can inspect without trusting the TA-14 dashboard.

A complete package may contain:

- route-manifest.json;
- evidence-index.json;
- evidence objects;
- authority records;
- jurisdiction records;
- ruleset.json;
- determination.json;
- binding.json;
- commit.json;
- execution.json;
- outcome.json;
- ledger.json;
- ledger.jsonl;
- public-verification-key.json;
- package-manifest.json;
- README.txt.

The package:

- uses canonical JSON;
- records every included file's SHA-256 digest;
- excludes all private key material;
- preserves a signed package manifest;
- uses deterministic ZIP ordering and timestamps;
- can be independently verified by a separate verifier.

This module is additive and does not alter existing public sandbox endpoints.
"""

from __future__ import annotations

import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence
from uuid import UUID

from .replay_crypto import (
    canonical_json_bytes,
    canonical_json_text,
    digest_file,
    digest_named_objects,
    digest_object,
    write_canonical_json,
)
from .replay_ledger import verify_ledger_record
from .replay_models import (
    AuthorityRecord,
    BindingReceipt,
    CommitReceipt,
    CompleteRouteReplayRecord,
    DeterminationReceipt,
    EvidenceIndex,
    EvidenceObject,
    ExecutionReceipt,
    JurisdictionRecord,
    LedgerRecord,
    OutcomeRecord,
    PackageFileRecord,
    ReplayPackageManifest,
    RouteManifest,
    RulesetRecord,
)
from .replay_signing import (
    Ed25519KeyPair,
    public_verification_bundle,
    sign_object,
)


PACKAGE_STANDARD = "TA-14 Independent Route Replay Standard"
PACKAGE_VERSION = "1.0.0"

DETERMINISTIC_ZIP_TIMESTAMP = (
    1980,
    1,
    1,
    0,
    0,
    0,
)


class ReplayPackageError(ValueError):
    """Raised when a replay package cannot be constructed safely."""


@dataclass(frozen=True)
class ReplayPackageBuildResult:
    """Result returned after a replay package is built successfully."""

    package_path: Path
    package_manifest: ReplayPackageManifest
    package_digest: str
    file_count: int
    byte_length: int


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


def _require_aware_datetime(
    value: datetime,
    *,
    field_name: str,
) -> datetime:
    """Reject timestamps that do not include an explicit timezone."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ReplayPackageError(
            f"{field_name} must be timezone-aware."
        )

    return value


def _require_nonempty_text(
    value: str,
    *,
    field_name: str,
) -> str:
    """Validate and normalize required text."""

    normalized = value.strip()

    if not normalized:
        raise ReplayPackageError(
            f"{field_name} must not be empty."
        )

    return normalized


def _require_same_route(
    expected_route_id: UUID,
    observed_route_id: UUID,
    *,
    object_name: str,
) -> None:
    """Require every route-bearing record to belong to one route."""

    if expected_route_id != observed_route_id:
        raise ReplayPackageError(
            f"{object_name} belongs to a different route."
        )


def _safe_filename_component(
    value: str,
) -> str:
    """
    Convert an identifier into a safe portable filename component.
    """

    allowed = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "-_."
    )

    normalized = "".join(
        character
        if character in allowed
        else "-"
        for character in value
    ).strip("-.")

    if not normalized:
        raise ReplayPackageError(
            "Unable to create a safe filename component."
        )

    return normalized


def _write_text_file(
    path: Path,
    content: str,
) -> Path:
    """Write UTF-8 text atomically."""

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = path.with_name(
        f".{path.name}.tmp"
    )

    with temporary_path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file_handle:
        file_handle.write(content)
        file_handle.flush()

    temporary_path.replace(path)

    return path


def _write_jsonl_file(
    path: Path,
    values: Iterable[Any],
) -> Path:
    """
    Write canonical JSON Lines with one object per line.

    Ledger order remains significant.
    """

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = path.with_name(
        f".{path.name}.tmp"
    )

    with temporary_path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file_handle:
        for value in values:
            file_handle.write(
                canonical_json_text(value)
            )
            file_handle.write("\n")

        file_handle.flush()

    temporary_path.replace(path)

    return path


def _package_readme(
    *,
    route_id: UUID,
    decision: str,
    created_at: datetime,
    contains_sensitive_material: bool,
    disclosure_limitations: Sequence[str],
) -> str:
    """Create the package's plain-English verification instructions."""

    limitations = (
        "\n".join(
            f"- {item}"
            for item in disclosure_limitations
        )
        if disclosure_limitations
        else "- None declared."
    )

    sensitive_statement = (
        "YES"
        if contains_sensitive_material
        else "NO"
    )

    return f"""TA-14 INDEPENDENT ROUTE REPLAY PACKAGE
================================================

Standard: {PACKAGE_STANDARD}
Version: {PACKAGE_VERSION}
Route ID: {route_id}
Original determination: {decision}
Package created: {created_at.isoformat()}
Contains sensitive material: {sensitive_statement}

PURPOSE
-------
This package preserves the route records used to evaluate, bind, commit,
execute, and verify one consequence-bearing action.

The package is designed so an outside reviewer can verify:

1. the integrity of every included file;
2. the package-manifest signature;
3. the public signing-key fingerprint;
4. the route and request identifiers;
5. the determination and its reasons;
6. the evidence index and authority state;
7. the exact action binding;
8. the commit authorization;
9. the execution correspondence;
10. the observed outcome;
11. the ordering and integrity of the hash-linked ledger.

IMPORTANT BOUNDARY
------------------
A replay package proves what records were preserved, what determination was
made, what conditions were bound, and whether the preserved execution and
outcome correspond to those records.

It does not independently guarantee that an external evidence source was
truthful unless that source was authenticated and its evidence was included
or independently retrievable.

It is not legal advice, compliance certification, safety certification,
production approval, or a warranty.

DISCLOSURE LIMITATIONS
----------------------
{limitations}

PRIVATE-KEY RULE
----------------
No private signing key is included in this package.

The file public-verification-key.json contains only the public key and its
fingerprint. It may be used by an independent verifier to validate signatures.

EXPECTED VERIFICATION
---------------------
A conforming verifier should:

1. open package-manifest.json;
2. verify every listed file digest;
3. verify the package-manifest signature;
4. verify signed route receipts;
5. verify ledger event hashes and linkage;
6. compare route IDs and dependency digests;
7. report every failure, warning, omission, or divergence.

TA-14 CANON
-----------
No admissible evidence. No admissible execution.
"""


def _validate_complete_record(
    record: CompleteRouteReplayRecord,
) -> None:
    """
    Validate route relationships before any package files are written.
    """

    route_id = record.route_manifest.route_id

    _require_same_route(
        route_id,
        record.determination.route_id,
        object_name="Determination receipt",
    )

    _require_same_route(
        route_id,
        record.ledger.route_id,
        object_name="Ledger",
    )

    if record.binding is not None:
        _require_same_route(
            route_id,
            record.binding.route_id,
            object_name="Binding receipt",
        )

    if record.commit is not None:
        _require_same_route(
            route_id,
            record.commit.route_id,
            object_name="Commit receipt",
        )

    if record.execution is not None:
        _require_same_route(
            route_id,
            record.execution.route_id,
            object_name="Execution receipt",
        )

    if record.outcome is not None:
        _require_same_route(
            route_id,
            record.outcome.route_id,
            object_name="Outcome record",
        )

    for authority in record.authority_records:
        if (
            record.route_manifest.authority_ids
            and authority.authority_id
            not in record.route_manifest.authority_ids
        ):
            raise ReplayPackageError(
                "An authority record is not referenced by the route manifest."
            )

    for evidence in record.evidence_objects:
        if (
            record.route_manifest.evidence_ids
            and evidence.evidence_id
            not in record.route_manifest.evidence_ids
        ):
            raise ReplayPackageError(
                "An evidence object is not referenced by the route manifest."
            )

    if (
        record.route_manifest.ruleset_id
        != record.ruleset.ruleset_id
    ):
        raise ReplayPackageError(
            "Ruleset ID does not match the route manifest."
        )

    if (
        record.route_manifest.ruleset_version
        != record.ruleset.ruleset_version
    ):
        raise ReplayPackageError(
            "Ruleset version does not match the route manifest."
        )

    if record.route_manifest.manifest_digest is None:
        raise ReplayPackageError(
            "Route manifest must contain manifest_digest."
        )

    if record.determination.determination_digest is None:
        raise ReplayPackageError(
            "Determination must contain determination_digest."
        )

    if not verify_ledger_record(record.ledger):
        raise ReplayPackageError(
            "Ledger integrity verification failed."
        )

    if record.ledger.sealed_at is None:
        raise ReplayPackageError(
            "Ledger must be sealed before package construction."
        )


def _required_file_record(
    *,
    root: Path,
    relative_path: str,
    media_type: str,
    required: bool = True,
    encrypted: bool = False,
    redacted: bool = False,
) -> PackageFileRecord:
    """Create one package-file manifest record from a written file."""

    full_path = root / relative_path

    if not full_path.exists():
        raise ReplayPackageError(
            f"Package file does not exist: {relative_path}"
        )

    if not full_path.is_file():
        raise ReplayPackageError(
            f"Package path is not a file: {relative_path}"
        )

    return PackageFileRecord(
        path=relative_path,
        media_type=media_type,
        byte_length=full_path.stat().st_size,
        digest=digest_file(full_path),
        required=required,
        encrypted=encrypted,
        redacted=redacted,
    )


def _write_record_files(
    *,
    root: Path,
    record: CompleteRouteReplayRecord,
    public_key_bundle: dict[str, Any],
) -> list[PackageFileRecord]:
    """
    Write canonical replay files and return their manifest records.
    """

    files: list[PackageFileRecord] = []

    write_canonical_json(
        root / "route-manifest.json",
        record.route_manifest,
    )

    files.append(
        _required_file_record(
            root=root,
            relative_path="route-manifest.json",
            media_type="application/json",
        )
    )

    write_canonical_json(
        root / "evidence-index.json",
        record.evidence_index,
    )

    files.append(
        _required_file_record(
            root=root,
            relative_path="evidence-index.json",
            media_type="application/json",
        )
    )

    for evidence in sorted(
        record.evidence_objects,
        key=lambda item: str(item.evidence_id),
    ):
        relative_path = (
            "evidence/"
            f"{_safe_filename_component(str(evidence.evidence_id))}.json"
        )

        write_canonical_json(
            root / relative_path,
            evidence,
        )

        files.append(
            _required_file_record(
                root=root,
                relative_path=relative_path,
                media_type="application/json",
                required=False,
                encrypted=evidence.encrypted,
                redacted=evidence.redacted,
            )
        )

    for authority in sorted(
        record.authority_records,
        key=lambda item: str(item.authority_id),
    ):
        relative_path = (
            "authority/"
            f"{_safe_filename_component(str(authority.authority_id))}.json"
        )

        write_canonical_json(
            root / relative_path,
            authority,
        )

        files.append(
            _required_file_record(
                root=root,
                relative_path=relative_path,
                media_type="application/json",
            )
        )

    for jurisdiction in sorted(
        record.jurisdiction_records,
        key=lambda item: item.jurisdiction_id,
    ):
        relative_path = (
            "jurisdictions/"
            f"{_safe_filename_component(jurisdiction.jurisdiction_id)}.json"
        )

        write_canonical_json(
            root / relative_path,
            jurisdiction,
        )

        files.append(
            _required_file_record(
                root=root,
                relative_path=relative_path,
                media_type="application/json",
                required=False,
            )
        )

    write_canonical_json(
        root / "ruleset.json",
        record.ruleset,
    )

    files.append(
        _required_file_record(
            root=root,
            relative_path="ruleset.json",
            media_type="application/json",
        )
    )

    write_canonical_json(
        root / "determination.json",
        record.determination,
    )

    files.append(
        _required_file_record(
            root=root,
            relative_path="determination.json",
            media_type="application/json",
        )
    )

    optional_records: list[
        tuple[str, Any, str]
    ] = [
        (
            "binding.json",
            record.binding,
            "application/json",
        ),
        (
            "commit.json",
            record.commit,
            "application/json",
        ),
        (
            "execution.json",
            record.execution,
            "application/json",
        ),
        (
            "outcome.json",
            record.outcome,
            "application/json",
        ),
    ]

    for relative_path, value, media_type in optional_records:
        if value is None:
            continue

        write_canonical_json(
            root / relative_path,
            value,
        )

        files.append(
            _required_file_record(
                root=root,
                relative_path=relative_path,
                media_type=media_type,
                required=False,
            )
        )

    write_canonical_json(
        root / "ledger.json",
        record.ledger,
    )

    files.append(
        _required_file_record(
            root=root,
            relative_path="ledger.json",
            media_type="application/json",
        )
    )

    _write_jsonl_file(
        root / "ledger.jsonl",
        record.ledger.events,
    )

    files.append(
        _required_file_record(
            root=root,
            relative_path="ledger.jsonl",
            media_type="application/x-ndjson",
        )
    )

    write_canonical_json(
        root / "public-verification-key.json",
        public_key_bundle,
    )

    files.append(
        _required_file_record(
            root=root,
            relative_path="public-verification-key.json",
            media_type="application/json",
        )
    )

    return sorted(
        files,
        key=lambda item: item.path,
    )


def _named_file_digest_root(
    files: Sequence[PackageFileRecord],
) -> Any:
    """
    Calculate the compound digest covering all listed package files.
    """

    return digest_named_objects(
        {
            file_record.path: {
                "media_type": file_record.media_type,
                "byte_length": file_record.byte_length,
                "digest": file_record.digest,
                "required": file_record.required,
                "encrypted": file_record.encrypted,
                "redacted": file_record.redacted,
            }
            for file_record in files
        }
    )


def _write_deterministic_zip(
    *,
    source_directory: Path,
    output_path: Path,
) -> None:
    """
    Write a deterministic ZIP archive.

    Files are:

    - sorted by relative path;
    - stored without implementation-dependent compression;
    - assigned one fixed ZIP timestamp;
    - assigned stable permissions;
    - written with forward-slash paths.
    """

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = output_path.with_name(
        f".{output_path.name}.tmp"
    )

    relative_paths = sorted(
        path.relative_to(source_directory)
        for path in source_directory.rglob("*")
        if path.is_file()
    )

    with zipfile.ZipFile(
        temporary_path,
        mode="w",
        compression=zipfile.ZIP_STORED,
        allowZip64=True,
    ) as archive:
        for relative_path in relative_paths:
            source_path = source_directory / relative_path
            archive_name = relative_path.as_posix()

            information = zipfile.ZipInfo(
                filename=archive_name,
                date_time=DETERMINISTIC_ZIP_TIMESTAMP,
            )

            information.compress_type = zipfile.ZIP_STORED
            information.create_system = 3
            information.external_attr = 0o100644 << 16
            information.flag_bits |= 0x800

            archive.writestr(
                information,
                source_path.read_bytes(),
            )

    temporary_path.replace(output_path)


def build_replay_package(
    *,
    replay_record: CompleteRouteReplayRecord,
    output_path: Path | str,
    key_pair: Ed25519KeyPair,
    signer: str,
    created_by: str,
    created_at: Optional[datetime] = None,
    contains_sensitive_material: bool = False,
    encryption_description: Optional[str] = None,
    disclosure_limitations: Sequence[str] = (),
    overwrite: bool = False,
) -> ReplayPackageBuildResult:
    """
    Build and sign a deterministic TA-14 replay package.

    The private key is used only to sign the package manifest. It is never
    written into the package.
    """

    _validate_complete_record(replay_record)

    resolved_created_at = created_at or utc_now()

    _require_aware_datetime(
        resolved_created_at,
        field_name="created_at",
    )

    normalized_signer = _require_nonempty_text(
        signer,
        field_name="signer",
    )

    normalized_created_by = _require_nonempty_text(
        created_by,
        field_name="created_by",
    )

    normalized_limitations = [
        item.strip()
        for item in disclosure_limitations
        if item.strip()
    ]

    if (
        contains_sensitive_material
        and not encryption_description
    ):
        normalized_encryption_description = (
            "Sensitive material may be redacted or externally protected. "
            "Review individual file records."
        )
    else:
        normalized_encryption_description = (
            encryption_description.strip()
            if encryption_description
            else None
        )

    destination = Path(output_path)

    if destination.suffix.lower() != ".zip":
        raise ReplayPackageError(
            "Replay package output_path must end in .zip."
        )

    if destination.exists() and not overwrite:
        raise ReplayPackageError(
            f"Refusing to overwrite existing replay package: {destination}"
        )

    public_key_bundle = public_verification_bundle(
        key_pair.public_key,
        signer=normalized_signer,
        key_id=key_pair.key_id,
    )

    with tempfile.TemporaryDirectory(
        prefix="ta14-replay-package-"
    ) as temporary_directory:
        root = Path(temporary_directory)

        package_files = _write_record_files(
            root=root,
            record=replay_record,
            public_key_bundle=public_key_bundle,
        )

        package_digest = _named_file_digest_root(
            package_files
        )

        package_manifest = ReplayPackageManifest(
            route_id=replay_record.route_manifest.route_id,
            created_at=resolved_created_at,
            created_by=normalized_created_by,
            files=package_files,
            package_digest=package_digest,
            signature=None,
            contains_sensitive_material=(
                contains_sensitive_material
            ),
            encryption_description=(
                normalized_encryption_description
            ),
            disclosure_limitations=(
                normalized_limitations
            ),
        )

        manifest_signature = sign_object(
            package_manifest,
            key_pair=key_pair,
            signer=normalized_signer,
            signed_at=resolved_created_at,
        )

        signed_manifest = package_manifest.model_copy(
            update={
                "signature": manifest_signature,
            }
        )

        write_canonical_json(
            root / "package-manifest.json",
            signed_manifest,
        )

        readme = _package_readme(
            route_id=replay_record.route_manifest.route_id,
            decision=replay_record.determination.decision.value,
            created_at=resolved_created_at,
            contains_sensitive_material=(
                contains_sensitive_material
            ),
            disclosure_limitations=(
                normalized_limitations
            ),
        )

        _write_text_file(
            root / "README.txt",
            readme,
        )

        _write_deterministic_zip(
            source_directory=root,
            output_path=destination,
        )

    final_digest = digest_file(destination)

    return ReplayPackageBuildResult(
        package_path=destination,
        package_manifest=signed_manifest,
        package_digest=final_digest.value,
        file_count=len(signed_manifest.files) + 2,
        byte_length=destination.stat().st_size,
    )


def build_replay_package_from_components(
    *,
    route_manifest: RouteManifest,
    evidence_index: EvidenceIndex,
    ruleset: RulesetRecord,
    determination: DeterminationReceipt,
    ledger: LedgerRecord,
    output_path: Path | str,
    key_pair: Ed25519KeyPair,
    signer: str,
    created_by: str,
    evidence_objects: Sequence[EvidenceObject] = (),
    authority_records: Sequence[AuthorityRecord] = (),
    jurisdiction_records: Sequence[JurisdictionRecord] = (),
    binding: Optional[BindingReceipt] = None,
    commit: Optional[CommitReceipt] = None,
    execution: Optional[ExecutionReceipt] = None,
    outcome: Optional[OutcomeRecord] = None,
    created_at: Optional[datetime] = None,
    contains_sensitive_material: bool = False,
    encryption_description: Optional[str] = None,
    disclosure_limitations: Sequence[str] = (),
    overwrite: bool = False,
) -> ReplayPackageBuildResult:
    """
    Convenience wrapper that constructs CompleteRouteReplayRecord and exports it.
    """

    replay_record = CompleteRouteReplayRecord(
        route_manifest=route_manifest,
        evidence_index=evidence_index,
        evidence_objects=list(evidence_objects),
        authority_records=list(authority_records),
        jurisdiction_records=list(
            jurisdiction_records
        ),
        ruleset=ruleset,
        determination=determination,
        binding=binding,
        commit=commit,
        execution=execution,
        outcome=outcome,
        ledger=ledger,
    )

    return build_replay_package(
        replay_record=replay_record,
        output_path=output_path,
        key_pair=key_pair,
        signer=signer,
        created_by=created_by,
        created_at=created_at,
        contains_sensitive_material=(
            contains_sensitive_material
        ),
        encryption_description=(
            encryption_description
        ),
        disclosure_limitations=(
            disclosure_limitations
        ),
        overwrite=overwrite,
    )


def inspect_package_members(
    package_path: Path | str,
) -> list[str]:
    """
    Return the sorted filenames contained in a replay ZIP package.

    This is a bounded inspection helper and performs no verification.
    """

    path = Path(package_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Replay package does not exist: {path}"
        )

    if not path.is_file():
        raise ReplayPackageError(
            f"Replay package path is not a file: {path}"
        )

    if not zipfile.is_zipfile(path):
        raise ReplayPackageError(
            "Replay package is not a valid ZIP archive."
        )

    with zipfile.ZipFile(
        path,
        mode="r",
    ) as archive:
        return sorted(archive.namelist())


def extract_replay_package(
    *,
    package_path: Path | str,
    destination: Path | str,
    overwrite: bool = False,
) -> Path:
    """
    Safely extract a replay package for controlled inspection.

    Archive members containing absolute paths or parent-directory traversal
    are rejected.
    """

    source = Path(package_path)
    output_directory = Path(destination)

    if not source.exists():
        raise FileNotFoundError(
            f"Replay package does not exist: {source}"
        )

    if not zipfile.is_zipfile(source):
        raise ReplayPackageError(
            "Replay package is not a valid ZIP archive."
        )

    if output_directory.exists():
        if not overwrite:
            raise ReplayPackageError(
                f"Extraction destination already exists: {output_directory}"
            )

        if output_directory.is_dir():
            shutil.rmtree(output_directory)
        else:
            output_directory.unlink()

    output_directory.mkdir(
        parents=True,
        exist_ok=False,
    )

    try:
        with zipfile.ZipFile(
            source,
            mode="r",
        ) as archive:
            for information in archive.infolist():
                member_path = Path(
                    information.filename
                )

                if member_path.is_absolute():
                    raise ReplayPackageError(
                        "Replay package contains an absolute archive path."
                    )

                if ".." in member_path.parts:
                    raise ReplayPackageError(
                        "Replay package contains parent-directory traversal."
                    )

                target = (
                    output_directory
                    / member_path
                ).resolve()

                root = output_directory.resolve()

                if (
                    target != root
                    and root not in target.parents
                ):
                    raise ReplayPackageError(
                        "Replay package member escapes the extraction directory."
                    )

            archive.extractall(
                output_directory
            )

    except Exception:
        shutil.rmtree(
            output_directory,
            ignore_errors=True,
        )
        raise

    return output_directory
