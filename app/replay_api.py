"""
TA-14 Independent Route Replay API

Public HTTP interface for independently verifying a TA-14 replay package.

This router is additive. It does not become active until it is included by
the main FastAPI application.

Endpoints
---------
POST /v1/replay/verify
    Upload and independently verify one TA-14 replay ZIP package.

GET /v1/replay/standard
    Return the public replay-standard identity and capability boundary.

GET /v1/replay/health
    Confirm that the replay-verification service is available.

Security boundary
-----------------
This interface verifies preserved route integrity, signatures, ledger state,
and record correspondence.

It does not prove that an unauthenticated external evidence source was
truthful. It is not legal advice, compliance certification, safety
certification, production approval, or a warranty.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from fastapi.responses import JSONResponse

from .replay_models import IndependentVerificationReport
from .replay_verify import (
    ReplayVerificationError,
    verification_summary,
    verify_replay_package,
)


router = APIRouter(
    prefix="/v1/replay",
    tags=["Independent Route Replay"],
)


REPLAY_STANDARD_NAME = "TA-14 Independent Route Replay Standard"
REPLAY_STANDARD_ID = "TA14-IRRS-1.0.0"
REPLAY_STANDARD_VERSION = "1.0.0"
REPLAY_VERIFIER_VERSION = "1.0.0"

MAX_REPLAY_PACKAGE_BYTES = int(
    os.getenv(
        "TA14_MAX_REPLAY_PACKAGE_BYTES",
        str(25 * 1024 * 1024),
    )
)

ALLOWED_CONTENT_TYPES = {
    "application/zip",
    "application/x-zip-compressed",
    "application/octet-stream",
}


def _verification_http_status(
    report: IndependentVerificationReport,
) -> int:
    """
    Map a completed verification result to an HTTP response status.

    A cryptographically valid, independently replayable package returns 200.

    A package that was processed successfully but failed verification returns
    422 because its contents do not satisfy the replay standard.

    Package-format and request failures are handled separately.
    """

    if report.independently_replayable:
        return status.HTTP_200_OK

    return status.HTTP_422_UNPROCESSABLE_ENTITY


def _report_response(
    report: IndependentVerificationReport,
) -> dict[str, Any]:
    """Create the public JSON response for a verification result."""

    return {
        "standard": REPLAY_STANDARD_NAME,
        "standard_id": REPLAY_STANDARD_ID,
        "standard_version": REPLAY_STANDARD_VERSION,
        "verifier_version": REPLAY_VERIFIER_VERSION,
        "verification": report.model_dump(mode="json"),
        "summary": verification_summary(report),
        "boundary": {
            "proves": [
                "Preserved package-file integrity",
                "Included public-key correspondence",
                "Ed25519 signature validity",
                "Route identity consistency",
                "Receipt dependency correspondence",
                "Hash-linked ledger integrity",
                "Execution-to-commit correspondence",
                "Outcome-to-execution correspondence",
            ],
            "does_not_automatically_prove": [
                "Truth of an unauthenticated external evidence source",
                "Legal approval",
                "Regulatory certification",
                "Safety certification",
                "Production clearance",
                "Absence of every possible operational failure",
            ],
        },
    }


async def _save_upload(
    upload: UploadFile,
    destination: Path,
) -> int:
    """
    Save an uploaded replay package with an enforced byte limit.

    The upload is streamed in bounded chunks and never read into memory as one
    unrestricted object.
    """

    chunk_size = 1024 * 1024
    total_bytes = 0

    with destination.open("wb") as output:
        while True:
            chunk = await upload.read(chunk_size)

            if not chunk:
                break

            total_bytes += len(chunk)

            if total_bytes > MAX_REPLAY_PACKAGE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail={
                        "code": "REPLAY_PACKAGE_TOO_LARGE",
                        "message": (
                            "Replay package exceeds the configured upload limit."
                        ),
                        "maximum_bytes": MAX_REPLAY_PACKAGE_BYTES,
                    },
                )

            output.write(chunk)

        output.flush()
        os.fsync(output.fileno())

    return total_bytes


def _validate_upload_metadata(
    upload: UploadFile,
) -> str:
    """Validate the uploaded filename and declared content type."""

    filename = (
        upload.filename
        or "uploaded-replay-package.zip"
    ).strip()

    if not filename:
        filename = "uploaded-replay-package.zip"

    if not filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "INVALID_REPLAY_FILENAME",
                "message": "Replay package filename must end in .zip.",
            },
        )

    content_type = (
        upload.content_type
        or "application/octet-stream"
    ).lower()

    if content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail={
                "code": "UNSUPPORTED_REPLAY_MEDIA_TYPE",
                "message": (
                    "Replay package must be uploaded as a ZIP archive."
                ),
                "received_content_type": content_type,
            },
        )

    return filename


@router.get(
    "/health",
    summary="Replay verifier health",
    description=(
        "Confirm that the independent replay-verification service is available."
    ),
)
def replay_health() -> dict[str, Any]:
    """Return replay-verifier service identity and availability."""

    return {
        "status": "available",
        "service": "TA-14 Independent Route Replay Verifier",
        "standard": REPLAY_STANDARD_NAME,
        "standard_id": REPLAY_STANDARD_ID,
        "standard_version": REPLAY_STANDARD_VERSION,
        "verifier_version": REPLAY_VERIFIER_VERSION,
        "maximum_upload_bytes": MAX_REPLAY_PACKAGE_BYTES,
    }


@router.get(
    "/standard",
    summary="Replay standard identity",
    description=(
        "Return the public identity, capabilities, and boundary of the "
        "TA-14 Independent Route Replay Standard."
    ),
)
def replay_standard() -> dict[str, Any]:
    """Return the public replay-standard capability description."""

    return {
        "name": REPLAY_STANDARD_NAME,
        "identifier": REPLAY_STANDARD_ID,
        "version": REPLAY_STANDARD_VERSION,
        "canonicalization": "TA14-CANONICAL-JSON-1",
        "signature_algorithm": "Ed25519",
        "default_digest_algorithm": "SHA-256",
        "determinations": [
            "ALLOW",
            "HOLD",
            "DENY",
            "ESCALATE",
        ],
        "route": [
            "Reality",
            "Record",
            "Continuity",
            "Admissibility",
            "Binding",
            "Commit",
            "Execution",
            "Outcome",
            "Preserved Proof",
        ],
        "verification_categories": [
            "Package integrity",
            "Signature integrity",
            "Ledger integrity",
            "Evidence integrity",
            "Ruleset integrity",
            "Action binding",
            "Commit integrity",
            "Execution correspondence",
            "Outcome correspondence",
        ],
        "public_claim": (
            "A conforming TA-14 replay package can be verified "
            "without trusting the originating dashboard or operator."
        ),
        "boundary": (
            "Verification establishes integrity and correspondence of preserved "
            "records. It does not automatically prove the truth of an "
            "unauthenticated external source."
        ),
    }


@router.post(
    "/verify",
    summary="Verify a replay package",
    description=(
        "Upload a TA-14 replay ZIP package and independently verify its files, "
        "signatures, route identity, receipt dependencies, ledger, execution, "
        "and outcome."
    ),
    responses={
        200: {
            "description": (
                "Package verified and is independently replayable."
            )
        },
        400: {
            "description": (
                "Invalid filename, empty upload, or malformed request."
            )
        },
        413: {
            "description": (
                "Uploaded replay package exceeds the size limit."
            )
        },
        415: {
            "description": (
                "Uploaded media type is not accepted."
            )
        },
        422: {
            "description": (
                "Package was processed but failed or remained incomplete "
                "under independent verification."
            )
        },
    },
)
async def verify_uploaded_replay_package(
    package: UploadFile = File(
        ...,
        description="TA-14 Independent Route Replay ZIP package.",
    ),
) -> JSONResponse:
    """
    Verify one uploaded replay package.

    The uploaded archive is written to a temporary isolated directory,
    verified using the same independent verifier exposed by the command-line
    interface, and deleted when processing ends.
    """

    filename = _validate_upload_metadata(package)

    try:
        with tempfile.TemporaryDirectory(
            prefix="ta14-replay-api-"
        ) as temporary_directory:
            package_path = (
                Path(temporary_directory)
                / "uploaded-replay-package.zip"
            )

            total_bytes = await _save_upload(
                package,
                package_path,
            )

            if total_bytes == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "code": "EMPTY_REPLAY_PACKAGE",
                        "message": "Uploaded replay package is empty.",
                    },
                )

            try:
                report = verify_replay_package(
                    package_path,
                    verifier_name=(
                        "TA-14 Public Replay Verification API"
                    ),
                    verifier_version=REPLAY_VERIFIER_VERSION,
                )
            except ReplayVerificationError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "code": "INVALID_REPLAY_PACKAGE",
                        "message": str(exc),
                    },
                ) from exc

            response_body = _report_response(report)

            response_body["upload"] = {
                "filename": filename,
                "byte_length": total_bytes,
            }

            return JSONResponse(
                status_code=_verification_http_status(report),
                content=response_body,
            )

    finally:
        await package.close()
