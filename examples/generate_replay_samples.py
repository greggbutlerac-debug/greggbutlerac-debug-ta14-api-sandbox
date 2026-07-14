"""
Generate public TA-14 Independent Route Replay demonstration packages.

Run from the sandbox repository root:

    python -m examples.generate_replay_samples

The generator creates four packages in the repository's samples directory:

    samples/ta14-valid-allow.zip
    samples/ta14-tampered-package.zip
    samples/ta14-broken-ledger.zip
    samples/ta14-wrong-signature.zip

The valid package must independently verify successfully.

The other three packages are intentionally altered after construction so
visitors can observe package-integrity, ledger-integrity, and signature
verification failures.

These are synthetic demonstration records only. They are not evidence of an
actual financial transaction, legal approval, regulatory certification,
safety certification, or production clearance.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from app.replay_crypto import canonical_json_bytes
from app.replay_models import IntegrityStatus, VerificationStatus
from app.replay_signing import (
    generate_key_pair,
    public_verification_bundle,
)
from app.replay_verify import (
    ReplayVerificationError,
    verify_replay_package,
)

from tests.test_replay_verify import build_complete_package


DEFAULT_OUTPUT_DIRECTORY = Path("samples")

VALID_PACKAGE_NAME = "ta14-valid-allow.zip"
TAMPERED_PACKAGE_NAME = "ta14-tampered-package.zip"
BROKEN_LEDGER_PACKAGE_NAME = "ta14-broken-ledger.zip"
WRONG_SIGNATURE_PACKAGE_NAME = "ta14-wrong-signature.zip"


def read_zip_json(
    package_path: Path,
    member_name: str,
) -> dict[str, Any]:
    """Read one JSON document from a replay ZIP package."""

    with zipfile.ZipFile(package_path, mode="r") as archive:
        try:
            raw_document = archive.read(member_name)
        except KeyError as exc:
            raise RuntimeError(
                f"Replay package does not contain {member_name!r}."
            ) from exc

    try:
        parsed = json.loads(raw_document.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"Replay package member {member_name!r} is not valid JSON."
        ) from exc

    if not isinstance(parsed, dict):
        raise RuntimeError(
            f"Replay package member {member_name!r} must contain a JSON object."
        )

    return parsed


def rewrite_zip_member(
    source_path: Path,
    output_path: Path,
    member_name: str,
    replacement: bytes,
) -> None:
    """Copy a replay ZIP while replacing one archive member."""

    with zipfile.ZipFile(source_path, mode="r") as source_archive:
        members = {
            name: source_archive.read(name)
            for name in source_archive.namelist()
            if name != member_name
        }

    members[member_name] = replacement

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(
        output_path,
        mode="w",
        compression=zipfile.ZIP_STORED,
    ) as output_archive:
        for name in sorted(members):
            output_archive.writestr(name, members[name])


def create_valid_package(
    working_directory: Path,
    output_directory: Path,
) -> Path:
    """Create and publish one complete independently verifiable package."""

    generated_path, _replay_record, _key_pair = build_complete_package(
        working_directory,
        filename=VALID_PACKAGE_NAME,
    )

    output_path = output_directory / VALID_PACKAGE_NAME
    shutil.copyfile(generated_path, output_path)
    return output_path


def create_tampered_package(
    valid_package: Path,
    output_directory: Path,
) -> Path:
    """Create a package whose route manifest was altered after signing."""

    route_manifest = read_zip_json(
        valid_package,
        "route-manifest.json",
    )

    metadata = route_manifest.setdefault("metadata", {})
    metadata["public_demo_tamper"] = {
        "altered_after_signing": True,
        "description": (
            "This synthetic route manifest was intentionally changed "
            "after package construction."
        ),
    }

    output_path = output_directory / TAMPERED_PACKAGE_NAME

    rewrite_zip_member(
        valid_package,
        output_path,
        "route-manifest.json",
        canonical_json_bytes(route_manifest),
    )

    return output_path


def create_broken_ledger_package(
    valid_package: Path,
    output_directory: Path,
) -> Path:
    """Create a package with an intentionally altered ledger event."""

    ledger = read_zip_json(
        valid_package,
        "ledger.json",
    )

    events = ledger.get("events")

    if not isinstance(events, list) or not events:
        raise RuntimeError(
            "The valid replay package does not contain ledger events."
        )

    first_event = events[0]

    if not isinstance(first_event, dict):
        raise RuntimeError(
            "The first replay ledger event is not a JSON object."
        )

    first_event["actor"] = (
        "intentional-public-demo-ledger-tamper"
    )

    output_path = output_directory / BROKEN_LEDGER_PACKAGE_NAME

    rewrite_zip_member(
        valid_package,
        output_path,
        "ledger.json",
        canonical_json_bytes(ledger),
    )

    return output_path


def create_wrong_signature_package(
    valid_package: Path,
    output_directory: Path,
) -> Path:
    """
    Create a package whose included public verification key was substituted.

    The preserved route records and signatures remain unchanged, but the
    verifier is given an unrelated public key. This must invalidate public-key
    correspondence and signature integrity.
    """

    wrong_key_pair = generate_key_pair()

    wrong_bundle = public_verification_bundle(
        wrong_key_pair.public_key,
        signer="Intentional Public Demo Substitute Signer",
        key_id=wrong_key_pair.key_id,
    )

    output_path = output_directory / WRONG_SIGNATURE_PACKAGE_NAME

    rewrite_zip_member(
        valid_package,
        output_path,
        "public-verification-key.json",
        canonical_json_bytes(wrong_bundle),
    )

    return output_path


def verify_valid_sample(
    package_path: Path,
) -> None:
    """Require the valid public sample to pass independent verification."""

    report = verify_replay_package(
        package_path,
        verifier_name="TA-14 Public Sample Generator",
        verifier_version="1.0.0",
    )

    if report.overall_status != VerificationStatus.VERIFIED:
        raise RuntimeError(
            "The generated valid sample did not return VERIFIED."
        )

    if not report.independently_replayable:
        raise RuntimeError(
            "The generated valid sample was not independently replayable."
        )

    required_valid_states = {
        "package_integrity": report.package_integrity,
        "signature_integrity": report.signature_integrity,
        "ledger_integrity": report.ledger_integrity,
        "evidence_integrity": report.evidence_integrity,
        "ruleset_integrity": report.ruleset_integrity,
        "action_binding": report.action_binding,
        "commit_integrity": report.commit_integrity,
        "execution_correspondence": report.execution_correspondence,
        "outcome_correspondence": report.outcome_correspondence,
    }

    invalid_states = [
        name
        for name, state in required_valid_states.items()
        if state != IntegrityStatus.VALID
    ]

    if invalid_states:
        raise RuntimeError(
            "The generated valid sample contains invalid verification "
            f"states: {', '.join(invalid_states)}."
        )

    if report.failures:
        raise RuntimeError(
            "The generated valid sample contains verifier failures: "
            + "; ".join(report.failures)
        )


def verify_intentionally_failed_sample(
    package_path: Path,
    *,
    expected_invalid_field: str,
) -> None:
    """Require an intentionally altered package to fail as intended."""

    try:
        report = verify_replay_package(
            package_path,
            verifier_name="TA-14 Public Sample Generator",
            verifier_version="1.0.0",
        )
    except ReplayVerificationError as exc:
        raise RuntimeError(
            f"Sample {package_path.name} could not be processed: {exc}"
        ) from exc

    if report.overall_status != VerificationStatus.FAILED:
        raise RuntimeError(
            f"Sample {package_path.name} did not return FAILED."
        )

    if report.independently_replayable:
        raise RuntimeError(
            f"Sample {package_path.name} was incorrectly marked "
            "independently replayable."
        )

    state = getattr(report, expected_invalid_field, None)

    if state != IntegrityStatus.INVALID:
        raise RuntimeError(
            f"Sample {package_path.name} did not invalidate "
            f"{expected_invalid_field}."
        )


def write_sample_readme(
    output_directory: Path,
) -> Path:
    """Write a plain-language description beside the generated ZIP files."""

    readme_path = output_directory / "README.md"

    readme_path.write_text(
        """# TA-14 Independent Route Replay Samples

These files are synthetic demonstration packages for the public TA-14
Independent Route Replay Verifier.

## Packages

### `ta14-valid-allow.zip`

A complete signed and sealed synthetic route package. It should return:

- Overall status: `VERIFIED`
- Original decision: `ALLOW`
- Independently replayable: `YES`

### `ta14-tampered-package.zip`

The route manifest was changed after package construction. It should fail
package-integrity verification.

### `ta14-broken-ledger.zip`

The first ledger event was changed without rebuilding the hash-linked chain,
signatures, seal, or package manifest. It should fail ledger-integrity
verification.

### `ta14-wrong-signature.zip`

The included public verification key was replaced with an unrelated key while
the original signatures remained unchanged. It should fail signature-integrity
verification.

## Boundary

These files contain synthetic demonstration records only. They are not proof
of an actual financial transaction, legal approval, regulatory certification,
safety certification, production clearance, or the truth of an unauthenticated
external source.
""",
        encoding="utf-8",
    )

    return readme_path


def generate_samples(
    output_directory: Path,
    *,
    overwrite: bool,
) -> list[Path]:
    """Generate, validate, and publish the complete demonstration set."""

    output_directory = output_directory.resolve()

    expected_paths = [
        output_directory / VALID_PACKAGE_NAME,
        output_directory / TAMPERED_PACKAGE_NAME,
        output_directory / BROKEN_LEDGER_PACKAGE_NAME,
        output_directory / WRONG_SIGNATURE_PACKAGE_NAME,
        output_directory / "README.md",
    ]

    existing_paths = [
        path
        for path in expected_paths
        if path.exists()
    ]

    if existing_paths and not overwrite:
        names = ", ".join(path.name for path in existing_paths)

        raise FileExistsError(
            "Refusing to overwrite existing sample files: "
            f"{names}. Run with --overwrite to replace them."
        )

    output_directory.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix="ta14-public-replay-samples-"
    ) as temporary_directory:
        working_directory = Path(temporary_directory)

        valid_package = create_valid_package(
            working_directory,
            output_directory,
        )

        tampered_package = create_tampered_package(
            valid_package,
            output_directory,
        )

        broken_ledger_package = create_broken_ledger_package(
            valid_package,
            output_directory,
        )

        wrong_signature_package = create_wrong_signature_package(
            valid_package,
            output_directory,
        )

    verify_valid_sample(valid_package)

    verify_intentionally_failed_sample(
        tampered_package,
        expected_invalid_field="package_integrity",
    )

    verify_intentionally_failed_sample(
        broken_ledger_package,
        expected_invalid_field="ledger_integrity",
    )

    verify_intentionally_failed_sample(
        wrong_signature_package,
        expected_invalid_field="signature_integrity",
    )

    readme_path = write_sample_readme(output_directory)

    return [
        valid_package,
        tampered_package,
        broken_ledger_package,
        wrong_signature_package,
        readme_path,
    ]


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Generate validated public TA-14 replay demonstration packages."
        )
    )

    parser.add_argument(
        "--output-directory",
        type=Path,
        default=DEFAULT_OUTPUT_DIRECTORY,
        help=(
            "Directory where sample ZIP packages are written. "
            "Default: samples"
        ),
    )

    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace existing generated sample files.",
    )

    return parser.parse_args()


def main() -> int:
    """Generate the samples and print their final paths."""

    arguments = parse_arguments()

    try:
        generated_paths = generate_samples(
            arguments.output_directory,
            overwrite=arguments.overwrite,
        )
    except (
        FileExistsError,
        ReplayVerificationError,
        RuntimeError,
        OSError,
        zipfile.BadZipFile,
    ) as exc:
        print(
            f"Sample generation failed: {exc}",
            file=sys.stderr,
        )
        return 1

    print(
        "TA-14 public replay samples generated and validated:"
    )

    for generated_path in generated_paths:
        print(f"- {generated_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
