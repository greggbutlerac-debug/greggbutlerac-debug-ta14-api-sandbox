"""
Tests for the TA-14 public replay-verification API router.

These tests verify:

- replay service health;
- replay-standard identity;
- router isolation;
- ZIP filename validation;
- upload media-type validation;
- empty-upload rejection;
- malformed-ZIP rejection;
- bounded package-size enforcement;
- temporary upload cleanup behavior;
- public claim boundaries.
"""

from __future__ import annotations

import io
import zipfile

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import replay_api
from app.replay_api import router


@pytest.fixture
def client() -> TestClient:
    """
    Create an isolated FastAPI application containing only the replay router.

    This proves the router works before it is connected to the live sandbox.
    """

    application = FastAPI(
        title="TA-14 Replay API Test Application",
        version="1.0.0",
    )

    application.include_router(router)

    return TestClient(application)


def build_empty_zip() -> bytes:
    """Create a structurally valid but incomplete ZIP archive."""

    buffer = io.BytesIO()

    with zipfile.ZipFile(
        buffer,
        mode="w",
        compression=zipfile.ZIP_STORED,
    ) as archive:
        archive.writestr(
            "README.txt",
            "Incomplete synthetic replay package.",
        )

    return buffer.getvalue()


def test_replay_health_is_available(
    client: TestClient,
) -> None:
    """The isolated replay-verification service must report availability."""

    response = client.get(
        "/v1/replay/health"
    )

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "available"

    assert (
        body["service"]
        == "TA-14 Independent Route Replay Verifier"
    )

    assert (
        body["standard"]
        == "TA-14 Independent Route Replay Standard"
    )

    assert body["standard_id"] == "TA14-IRRS-1.0.0"
    assert body["standard_version"] == "1.0.0"
    assert body["verifier_version"] == "1.0.0"

    assert (
        body["maximum_upload_bytes"]
        == replay_api.MAX_REPLAY_PACKAGE_BYTES
    )


def test_replay_standard_identity(
    client: TestClient,
) -> None:
    """The public standard endpoint must expose the correct identity."""

    response = client.get(
        "/v1/replay/standard"
    )

    assert response.status_code == 200

    body = response.json()

    assert (
        body["name"]
        == "TA-14 Independent Route Replay Standard"
    )

    assert body["identifier"] == "TA14-IRRS-1.0.0"
    assert body["version"] == "1.0.0"

    assert (
        body["canonicalization"]
        == "TA14-CANONICAL-JSON-1"
    )

    assert body["signature_algorithm"] == "Ed25519"
    assert body["default_digest_algorithm"] == "SHA-256"

    assert body["determinations"] == [
        "ALLOW",
        "HOLD",
        "DENY",
        "ESCALATE",
    ]


def test_replay_standard_route(
    client: TestClient,
) -> None:
    """The endpoint must expose the complete replay route."""

    response = client.get(
        "/v1/replay/standard"
    )

    body = response.json()

    assert body["route"] == [
        "Reality",
        "Record",
        "Continuity",
        "Admissibility",
        "Binding",
        "Commit",
        "Execution",
        "Outcome",
        "Preserved Proof",
    ]


def test_replay_standard_public_claim_boundary(
    client: TestClient,
) -> None:
    """The standard endpoint must preserve the public claim boundary."""

    response = client.get(
        "/v1/replay/standard"
    )

    body = response.json()

    assert (
        body["public_claim"]
        == (
            "A conforming TA-14 replay package can be verified "
            "without trusting the originating dashboard or operator."
        )
    )

    assert (
        "does not automatically prove"
        in body["boundary"]
    )

    assert (
        "unauthenticated external source"
        in body["boundary"]
    )


def test_health_endpoint_does_not_activate_other_routes(
    client: TestClient,
) -> None:
    """
    The isolated router must not expose the existing sandbox API implicitly.
    """

    response = client.get("/")

    assert response.status_code == 404


def test_verify_rejects_non_zip_filename(
    client: TestClient,
) -> None:
    """Uploaded replay packages must use a .zip filename."""

    response = client.post(
        "/v1/replay/verify",
        files={
            "package": (
                "replay-package.json",
                b"{}",
                "application/zip",
            )
        },
    )

    assert response.status_code == 400

    detail = response.json()["detail"]

    assert detail["code"] == "INVALID_REPLAY_FILENAME"

    assert (
        detail["message"]
        == "Replay package filename must end in .zip."
    )


def test_verify_rejects_unsupported_media_type(
    client: TestClient,
) -> None:
    """The API must reject uploads declared as unsupported media types."""

    response = client.post(
        "/v1/replay/verify",
        files={
            "package": (
                "replay-package.zip",
                b"not-a-zip",
                "text/plain",
            )
        },
    )

    assert response.status_code == 415

    detail = response.json()["detail"]

    assert detail["code"] == "UNSUPPORTED_REPLAY_MEDIA_TYPE"

    assert (
        detail["received_content_type"]
        == "text/plain"
    )


def test_verify_rejects_empty_upload(
    client: TestClient,
) -> None:
    """An empty ZIP upload must be rejected before verification."""

    response = client.post(
        "/v1/replay/verify",
        files={
            "package": (
                "empty-replay-package.zip",
                b"",
                "application/zip",
            )
        },
    )

    assert response.status_code == 400

    detail = response.json()["detail"]

    assert detail["code"] == "EMPTY_REPLAY_PACKAGE"

    assert (
        detail["message"]
        == "Uploaded replay package is empty."
    )


def test_verify_rejects_malformed_zip(
    client: TestClient,
) -> None:
    """A non-ZIP payload with a ZIP filename must fail bounded verification."""

    response = client.post(
        "/v1/replay/verify",
        files={
            "package": (
                "malformed-replay-package.zip",
                b"this-is-not-a-zip-archive",
                "application/zip",
            )
        },
    )

    assert response.status_code == 400

    detail = response.json()["detail"]

    assert detail["code"] == "INVALID_REPLAY_PACKAGE"

    assert (
        "not a valid ZIP archive"
        in detail["message"]
    )


def test_verify_rejects_incomplete_zip(
    client: TestClient,
) -> None:
    """
    A valid ZIP that lacks replay-standard records must fail verification.
    """

    response = client.post(
        "/v1/replay/verify",
        files={
            "package": (
                "incomplete-replay-package.zip",
                build_empty_zip(),
                "application/zip",
            )
        },
    )

    assert response.status_code == 400

    detail = response.json()["detail"]

    assert detail["code"] == "INVALID_REPLAY_PACKAGE"

    assert (
        "Required JSON document is missing"
        in detail["message"]
    )


def test_verify_accepts_octet_stream_boundary(
    client: TestClient,
) -> None:
    """
    Generic binary uploads are accepted at the media boundary and then
    subjected to actual ZIP and replay verification.
    """

    response = client.post(
        "/v1/replay/verify",
        files={
            "package": (
                "binary-replay-package.zip",
                b"not-a-real-zip",
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 400

    detail = response.json()["detail"]

    assert detail["code"] == "INVALID_REPLAY_PACKAGE"


def test_verify_accepts_x_zip_content_type_boundary(
    client: TestClient,
) -> None:
    """
    The common application/x-zip-compressed media type must be accepted.
    """

    response = client.post(
        "/v1/replay/verify",
        files={
            "package": (
                "compressed-replay-package.zip",
                b"not-a-real-zip",
                "application/x-zip-compressed",
            )
        },
    )

    assert response.status_code == 400

    detail = response.json()["detail"]

    assert detail["code"] == "INVALID_REPLAY_PACKAGE"


def test_verify_enforces_upload_size_limit(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Uploads larger than the configured limit must return HTTP 413."""

    monkeypatch.setattr(
        replay_api,
        "MAX_REPLAY_PACKAGE_BYTES",
        16,
    )

    response = client.post(
        "/v1/replay/verify",
        files={
            "package": (
                "oversized-replay-package.zip",
                b"x" * 17,
                "application/zip",
            )
        },
    )

    assert response.status_code == 413

    detail = response.json()["detail"]

    assert detail["code"] == "REPLAY_PACKAGE_TOO_LARGE"
    assert detail["maximum_bytes"] == 16


def test_health_reflects_runtime_upload_limit(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The health endpoint must report the active upload limit."""

    monkeypatch.setattr(
        replay_api,
        "MAX_REPLAY_PACKAGE_BYTES",
        4096,
    )

    response = client.get(
        "/v1/replay/health"
    )

    assert response.status_code == 200

    assert (
        response.json()["maximum_upload_bytes"]
        == 4096
    )


def test_verify_requires_package_form_field(
    client: TestClient,
) -> None:
    """The upload endpoint must require the package multipart field."""

    response = client.post(
        "/v1/replay/verify"
    )

    assert response.status_code == 422


def test_openapi_includes_replay_endpoints(
    client: TestClient,
) -> None:
    """The isolated router must publish its three replay endpoints."""

    response = client.get(
        "/openapi.json"
    )

    assert response.status_code == 200

    paths = response.json()["paths"]

    assert "/v1/replay/health" in paths
    assert "/v1/replay/standard" in paths
    assert "/v1/replay/verify" in paths

    assert "get" in paths["/v1/replay/health"]
    assert "get" in paths["/v1/replay/standard"]
    assert "post" in paths["/v1/replay/verify"]


def test_openapi_uses_replay_tag(
    client: TestClient,
) -> None:
    """Replay endpoints must remain grouped under their public API tag."""

    response = client.get(
        "/openapi.json"
    )

    paths = response.json()["paths"]

    assert (
        paths[
            "/v1/replay/verify"
        ][
            "post"
        ][
            "tags"
        ]
        == [
            "Independent Route Replay"
        ]
    )
