"""
Tests for the TA-14 Independent Route Replay signing layer.

These tests verify:

- Ed25519 key generation;
- stable public key fingerprints;
- encrypted private key storage;
- public key export and reload;
- canonical object signing;
- valid signature verification;
- tamper detection;
- wrong-key rejection;
- invalid Base64 rejection;
- public verification bundle generation.
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.replay_models import (
    SignatureAlgorithm,
    VerificationStatus,
)
from app.replay_signing import (
    KeyLoadingError,
    SignatureVerificationError,
    SigningError,
    decode_signature,
    derive_key_id,
    generate_key_pair,
    load_key_pair,
    load_private_key_pem,
    load_public_key_file,
    load_public_key_pem,
    private_key_pem,
    public_key_fingerprint,
    public_key_pem,
    public_verification_bundle,
    require_valid_object_signature,
    save_key_pair,
    sign_object,
    verify_object_signature,
    verified_signature_record,
)


FIXED_TIME = datetime(
    2026,
    7,
    14,
    12,
    0,
    0,
    tzinfo=timezone.utc,
)

TEST_PASSWORD = (
    "TA14-test-password-2026"
)


def sample_record() -> dict:
    """
    Return a deterministic replay record for signing tests.
    """

    return {
        "route_id": "route-001",
        "decision": "ALLOW",
        "issued_at": FIXED_TIME,
        "conditions": [
            "Authority active",
            "Evidence current",
            "Binding intact",
        ],
    }


def test_generate_key_pair_returns_ed25519_identity() -> None:
    """
    A generated key pair must include a stable key ID and fingerprint.
    """

    key_pair = generate_key_pair()

    assert key_pair.private_key is not None
    assert key_pair.public_key is not None

    assert key_pair.key_id.startswith(
        "ta14-ed25519:"
    )

    assert len(
        key_pair.public_key_fingerprint.value
    ) == 64


def test_key_id_is_stable_for_same_public_key() -> None:
    """
    The same public key must always derive the same key identifier.
    """

    key_pair = generate_key_pair()

    first = derive_key_id(
        key_pair.public_key
    )

    second = derive_key_id(
        key_pair.public_key
    )

    assert first == second
    assert first == key_pair.key_id


def test_public_key_fingerprint_is_stable() -> None:
    """
    The same public key must always produce the same fingerprint.
    """

    key_pair = generate_key_pair()

    first = public_key_fingerprint(
        key_pair.public_key
    )

    second = public_key_fingerprint(
        key_pair.public_key
    )

    assert first == second


def test_private_key_requires_strong_enough_password() -> None:
    """
    Weak passwords must be rejected before private-key serialization.
    """

    key_pair = generate_key_pair()

    with pytest.raises(
        SigningError,
        match="at least 16",
    ):
        private_key_pem(
            key_pair.private_key,
            password="short-password",
        )


def test_private_key_serializes_and_reloads() -> None:
    """
    An encrypted private key must reload successfully with the right password.
    """

    key_pair = generate_key_pair()

    pem = private_key_pem(
        key_pair.private_key,
        password=TEST_PASSWORD,
    )

    loaded_private_key = load_private_key_pem(
        pem,
        password=TEST_PASSWORD,
    )

    original_public_pem = public_key_pem(
        key_pair.public_key
    )

    loaded_public_pem = public_key_pem(
        loaded_private_key.public_key()
    )

    assert original_public_pem == loaded_public_pem


def test_private_key_rejects_wrong_password() -> None:
    """
    An encrypted private key must not load with the wrong password.
    """

    key_pair = generate_key_pair()

    pem = private_key_pem(
        key_pair.private_key,
        password=TEST_PASSWORD,
    )

    with pytest.raises(
        KeyLoadingError,
        match="Unable to load",
    ):
        load_private_key_pem(
            pem,
            password="incorrect-password-2026",
        )


def test_public_key_serializes_and_reloads() -> None:
    """
    A public key must survive PEM export and reload without changing.
    """

    key_pair = generate_key_pair()

    pem = public_key_pem(
        key_pair.public_key
    )

    loaded_public_key = load_public_key_pem(
        pem
    )

    original_fingerprint = public_key_fingerprint(
        key_pair.public_key
    )

    loaded_fingerprint = public_key_fingerprint(
        loaded_public_key
    )

    assert original_fingerprint == loaded_fingerprint


def test_save_and_load_key_pair(
    tmp_path: Path,
) -> None:
    """
    Encrypted private and public key files must save and reload correctly.
    """

    key_pair = generate_key_pair()

    private_path, public_path = save_key_pair(
        key_pair,
        directory=tmp_path,
        password=TEST_PASSWORD,
    )

    assert private_path.exists()
    assert public_path.exists()

    loaded_pair = load_key_pair(
        private_key_path=private_path,
        password=TEST_PASSWORD,
    )

    loaded_public = load_public_key_file(
        public_path
    )

    assert loaded_pair.key_id == key_pair.key_id

    assert (
        public_key_fingerprint(
            loaded_public
        )
        == key_pair.public_key_fingerprint
    )


def test_save_key_pair_refuses_overwrite(
    tmp_path: Path,
) -> None:
    """
    Existing key files must not be overwritten by default.
    """

    key_pair = generate_key_pair()

    save_key_pair(
        key_pair,
        directory=tmp_path,
        password=TEST_PASSWORD,
    )

    with pytest.raises(
        SigningError,
        match="Refusing to overwrite",
    ):
        save_key_pair(
            key_pair,
            directory=tmp_path,
            password=TEST_PASSWORD,
        )


def test_sign_object_creates_valid_signature_record() -> None:
    """
    Signing a canonical replay record must create a valid SignatureRecord.
    """

    key_pair = generate_key_pair()

    signature_record = sign_object(
        sample_record(),
        key_pair=key_pair,
        signer="TA-14 Test Signer",
        signed_at=FIXED_TIME,
    )

    assert (
        signature_record.algorithm
        == SignatureAlgorithm.ED25519
    )

    assert signature_record.key_id == key_pair.key_id
    assert signature_record.signer == "TA-14 Test Signer"

    assert (
        signature_record.verification_status
        == VerificationStatus.NOT_VERIFIED
    )

    assert len(
        decode_signature(
            signature_record.signature_base64
        )
    ) == 64


def test_valid_object_signature_verifies() -> None:
    """
    An unchanged object signed by the matching private key must verify.
    """

    key_pair = generate_key_pair()
    record = sample_record()

    signature_record = sign_object(
        record,
        key_pair=key_pair,
        signer="TA-14 Test Signer",
        signed_at=FIXED_TIME,
    )

    result = verify_object_signature(
        record,
        signature_record,
        public_key=key_pair.public_key,
    )

    assert result.valid is True

    assert (
        result.status
        == VerificationStatus.VERIFIED
    )

    assert (
        "signature are valid"
        in result.message
    )


def test_tampered_object_fails_verification() -> None:
    """
    Any material change after signing must invalidate the signature.
    """

    key_pair = generate_key_pair()
    original = sample_record()

    signature_record = sign_object(
        original,
        key_pair=key_pair,
        signer="TA-14 Test Signer",
        signed_at=FIXED_TIME,
    )

    tampered = {
        **original,
        "decision": "DENY",
    }

    result = verify_object_signature(
        tampered,
        signature_record,
        public_key=key_pair.public_key,
    )

    assert result.valid is False

    assert (
        result.status
        == VerificationStatus.FAILED
    )

    assert (
        "digest does not match"
        in result.message
    )


def test_wrong_public_key_fails_verification() -> None:
    """
    A valid signature must fail when checked with a different public key.
    """

    signing_pair = generate_key_pair()
    wrong_pair = generate_key_pair()

    record = sample_record()

    signature_record = sign_object(
        record,
        key_pair=signing_pair,
        signer="TA-14 Test Signer",
        signed_at=FIXED_TIME,
    )

    result = verify_object_signature(
        record,
        signature_record,
        public_key=wrong_pair.public_key,
    )

    assert result.valid is False

    assert (
        result.status
        == VerificationStatus.FAILED
    )

    assert (
        "fingerprint does not match"
        in result.message
    )


def test_invalid_base64_signature_fails_verification() -> None:
    """
    Invalid Base64 signature text must fail safely.
    """

    key_pair = generate_key_pair()
    record = sample_record()

    signature_record = sign_object(
        record,
        key_pair=key_pair,
        signer="TA-14 Test Signer",
        signed_at=FIXED_TIME,
    )

    invalid_record = signature_record.model_copy(
        update={
            "signature_base64": (
                "not-valid-base64!!!"
            ),
        }
    )

    result = verify_object_signature(
        record,
        invalid_record,
        public_key=key_pair.public_key,
    )

    assert result.valid is False

    assert (
        result.status
        == VerificationStatus.FAILED
    )

    assert (
        "valid Base64"
        in result.message
    )


def test_require_valid_signature_raises_on_tampering() -> None:
    """
    Strict verification must raise when a signed object is altered.
    """

    key_pair = generate_key_pair()
    original = sample_record()

    signature_record = sign_object(
        original,
        key_pair=key_pair,
        signer="TA-14 Test Signer",
        signed_at=FIXED_TIME,
    )

    tampered = {
        **original,
        "conditions": [
            "Authority active",
        ],
    }

    with pytest.raises(
        SignatureVerificationError,
        match="Signature verification failed",
    ):
        require_valid_object_signature(
            tampered,
            signature_record,
            public_key=key_pair.public_key,
            object_name="determination receipt",
        )


def test_verified_signature_record_updates_status() -> None:
    """
    Successful verification must produce an updated verification record.
    """

    key_pair = generate_key_pair()
    record = sample_record()

    signature_record = sign_object(
        record,
        key_pair=key_pair,
        signer="TA-14 Test Signer",
        signed_at=FIXED_TIME,
    )

    verified_record = verified_signature_record(
        record,
        signature_record,
        public_key=key_pair.public_key,
    )

    assert (
        verified_record.verification_status
        == VerificationStatus.VERIFIED
    )

    assert verified_record.verification_message is not None

    assert (
        "signature are valid"
        in verified_record.verification_message
    )


def test_public_verification_bundle_contains_no_private_key() -> None:
    """
    A public verification bundle must expose only public key material.
    """

    key_pair = generate_key_pair()

    bundle = public_verification_bundle(
        key_pair.public_key,
        signer="TA-14 Test Signer",
        key_id=key_pair.key_id,
    )

    assert bundle["algorithm"] == "Ed25519"
    assert bundle["key_id"] == key_pair.key_id
    assert bundle["signer"] == "TA-14 Test Signer"

    assert (
        "BEGIN PUBLIC KEY"
        in bundle["public_key_pem"]
    )

    serialized_bundle = str(bundle)

    assert "PRIVATE KEY" not in serialized_bundle
    assert "private_key" not in serialized_bundle.lower()


def test_empty_signer_is_rejected() -> None:
    """
    Every signed replay object must identify its signer.
    """

    key_pair = generate_key_pair()

    with pytest.raises(
        SigningError,
        match="signer must not be empty",
    ):
        sign_object(
            sample_record(),
            key_pair=key_pair,
            signer="   ",
            signed_at=FIXED_TIME,
        )
