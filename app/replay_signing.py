"""
TA-14 Independent Route Replay Standard
Ed25519 signing, key management, and independent signature verification.

Purpose
-------
Hashing proves that content changed. Digital signatures additionally prove
which signing key attested to the content.

This module provides:

- Ed25519 key generation;
- encrypted private-key storage;
- public-key export;
- stable key identifiers and fingerprints;
- canonical object signing;
- raw byte signing;
- SignatureRecord creation;
- signature verification without trusting the TA-14 operator;
- key loading with strict Ed25519 type validation;
- public verification bundles;
- safe filesystem permissions where supported.

Security boundary
-----------------
The public sandbox must never generate or persist a production signing key.

Production signing keys should be supplied through a managed secret service,
hardware security module, cloud key-management service, or encrypted private
key file protected by a strong password.

This implementation supports encrypted PEM files for controlled development
and bounded deployments. It does not claim to replace enterprise key
management or hardware-backed signing.
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .replay_crypto import (
    canonical_json_bytes,
    digest_bytes,
    secure_digest_equal,
)
from .replay_models import (
    DigestRecord,
    SignatureAlgorithm,
    SignatureRecord,
    VerificationStatus,
)


SIGNING_STANDARD = "TA14-ED25519-SIGNATURE-1"
DEFAULT_PRIVATE_KEY_FILENAME = "ta14-ed25519-private.pem"
DEFAULT_PUBLIC_KEY_FILENAME = "ta14-ed25519-public.pem"


class SigningError(ValueError):
    """Raised when a replay record cannot be signed safely."""


class KeyLoadingError(ValueError):
    """Raised when a signing or verification key cannot be loaded safely."""


class SignatureVerificationError(ValueError):
    """Raised when signature verification is explicitly required and fails."""


@dataclass(frozen=True)
class VerificationResult:
    """
    Structured result returned by non-raising verification functions.
    """

    valid: bool
    status: VerificationStatus
    message: str
    key_id: Optional[str] = None
    signer: Optional[str] = None


@dataclass(frozen=True)
class Ed25519KeyPair:
    """
    In-memory Ed25519 signing key pair.

    The private key must never be returned through an API response, written
    into a replay package, committed to source control, or included in logs.
    """

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    key_id: str
    public_key_fingerprint: DigestRecord


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


def _require_nonempty_text(
    value: str,
    *,
    field_name: str,
) -> str:
    """Validate and normalize required human-readable identifiers."""

    normalized = value.strip()

    if not normalized:
        raise SigningError(
            f"{field_name} must not be empty."
        )

    return normalized


def _require_password(
    password: str | bytes,
) -> bytes:
    """
    Validate a private-key encryption password.

    A minimum of 16 UTF-8 bytes is enforced for file-based development keys.
    Production deployments should use a secret manager and substantially
    stronger randomly generated credentials.
    """

    if isinstance(password, str):
        encoded = password.encode("utf-8")
    elif isinstance(password, bytes):
        encoded = password
    else:
        raise SigningError(
            "Private-key password must be text or bytes."
        )

    if len(encoded) < 16:
        raise SigningError(
            "Private-key password must contain at least 16 UTF-8 bytes."
        )

    return encoded


def public_key_raw_bytes(
    public_key: Ed25519PublicKey,
) -> bytes:
    """Serialize an Ed25519 public key into its 32-byte raw representation."""

    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_key_raw_bytes(
    private_key: Ed25519PrivateKey,
) -> bytes:
    """
    Serialize an Ed25519 private key into its 32-byte raw representation.

    This function is intended for controlled testing and integration with a
    managed secret store. Do not expose its output through the public API.
    """

    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_fingerprint(
    public_key: Ed25519PublicKey,
) -> DigestRecord:
    """
    Calculate the SHA-256 fingerprint of the raw public key.
    """

    return digest_bytes(
        public_key_raw_bytes(public_key)
    )


def derive_key_id(
    public_key: Ed25519PublicKey,
    *,
    prefix: str = "ta14-ed25519",
) -> str:
    """
    Derive a stable public key identifier from its fingerprint.

    The identifier contains the first 24 hexadecimal fingerprint characters.
    The complete fingerprint remains available in SignatureRecord.
    """

    normalized_prefix = _require_nonempty_text(
        prefix,
        field_name="key ID prefix",
    )

    fingerprint = public_key_fingerprint(public_key)

    return (
        f"{normalized_prefix}:"
        f"{fingerprint.value[:24]}"
    )


def generate_key_pair(
    *,
    key_id_prefix: str = "ta14-ed25519",
) -> Ed25519KeyPair:
    """
    Generate a new Ed25519 signing key pair in memory.
    """

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    return Ed25519KeyPair(
        private_key=private_key,
        public_key=public_key,
        key_id=derive_key_id(
            public_key,
            prefix=key_id_prefix,
        ),
        public_key_fingerprint=public_key_fingerprint(
            public_key
        ),
    )


def private_key_pem(
    private_key: Ed25519PrivateKey,
    *,
    password: str | bytes,
) -> bytes:
    """
    Serialize an Ed25519 private key as encrypted PKCS8 PEM.
    """

    password_bytes = _require_password(password)

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password_bytes
        ),
    )


def public_key_pem(
    public_key: Ed25519PublicKey,
) -> bytes:
    """
    Serialize an Ed25519 public key as SubjectPublicKeyInfo PEM.
    """

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_pem(
    content: bytes,
    *,
    password: str | bytes,
) -> Ed25519PrivateKey:
    """
    Load and strictly validate an encrypted Ed25519 private key.
    """

    password_bytes = _require_password(password)

    try:
        loaded = serialization.load_pem_private_key(
            content,
            password=password_bytes,
        )
    except (TypeError, ValueError) as exc:
        raise KeyLoadingError(
            "Unable to load the encrypted private signing key."
        ) from exc

    if not isinstance(loaded, Ed25519PrivateKey):
        raise KeyLoadingError(
            "The supplied private key is not an Ed25519 key."
        )

    return loaded


def load_public_key_pem(
    content: bytes,
) -> Ed25519PublicKey:
    """
    Load and strictly validate an Ed25519 public key.
    """

    try:
        loaded = serialization.load_pem_public_key(
            content
        )
    except (TypeError, ValueError) as exc:
        raise KeyLoadingError(
            "Unable to load the public verification key."
        ) from exc

    if not isinstance(loaded, Ed25519PublicKey):
        raise KeyLoadingError(
            "The supplied public key is not an Ed25519 key."
        )

    return loaded


def load_private_key_raw(
    content: bytes,
) -> Ed25519PrivateKey:
    """
    Load a 32-byte raw Ed25519 private key.
    """

    if len(content) != 32:
        raise KeyLoadingError(
            "A raw Ed25519 private key must contain exactly 32 bytes."
        )

    try:
        return Ed25519PrivateKey.from_private_bytes(
            content
        )
    except ValueError as exc:
        raise KeyLoadingError(
            "Unable to load the raw Ed25519 private key."
        ) from exc


def load_public_key_raw(
    content: bytes,
) -> Ed25519PublicKey:
    """
    Load a 32-byte raw Ed25519 public key.
    """

    if len(content) != 32:
        raise KeyLoadingError(
            "A raw Ed25519 public key must contain exactly 32 bytes."
        )

    try:
        return Ed25519PublicKey.from_public_bytes(
            content
        )
    except ValueError as exc:
        raise KeyLoadingError(
            "Unable to load the raw Ed25519 public key."
        ) from exc


def _write_private_file(
    path: Path,
    content: bytes,
) -> None:
    """
    Write a private key without leaving a partial file behind.

    POSIX file permissions are restricted to the current user where supported.
    """

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = path.with_name(
        f".{path.name}.tmp"
    )

    file_descriptor = os.open(
        temporary_path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )

    try:
        with os.fdopen(
            file_descriptor,
            "wb",
        ) as file_handle:
            file_handle.write(content)
            file_handle.flush()
            os.fsync(file_handle.fileno())

        temporary_path.replace(path)

        try:
            os.chmod(path, 0o600)
        except OSError:
            # Some platforms and mounted filesystems do not support POSIX
            # permission changes. The write remains valid, but production
            # deployments must enforce equivalent secret-store controls.
            pass

    except Exception:
        try:
            temporary_path.unlink(
                missing_ok=True
            )
        except OSError:
            pass

        raise


def _write_public_file(
    path: Path,
    content: bytes,
) -> None:
    """Write a public key atomically."""

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = path.with_name(
        f".{path.name}.tmp"
    )

    with temporary_path.open("wb") as file_handle:
        file_handle.write(content)
        file_handle.flush()
        os.fsync(file_handle.fileno())

    temporary_path.replace(path)


def save_key_pair(
    key_pair: Ed25519KeyPair,
    *,
    directory: Path | str,
    password: str | bytes,
    private_filename: str = DEFAULT_PRIVATE_KEY_FILENAME,
    public_filename: str = DEFAULT_PUBLIC_KEY_FILENAME,
    overwrite: bool = False,
) -> tuple[Path, Path]:
    """
    Save an encrypted private key and public verification key.

    Existing files are never overwritten unless overwrite=True.
    """

    output_directory = Path(directory)
    private_path = output_directory / private_filename
    public_path = output_directory / public_filename

    if not overwrite:
        existing = [
            path
            for path in (
                private_path,
                public_path,
            )
            if path.exists()
        ]

        if existing:
            names = ", ".join(
                str(path)
                for path in existing
            )

            raise SigningError(
                f"Refusing to overwrite existing key files: {names}"
            )

    _write_private_file(
        private_path,
        private_key_pem(
            key_pair.private_key,
            password=password,
        ),
    )

    try:
        _write_public_file(
            public_path,
            public_key_pem(
                key_pair.public_key
            ),
        )
    except Exception:
        try:
            private_path.unlink(
                missing_ok=True
            )
        except OSError:
            pass

        raise

    return private_path, public_path


def load_key_pair(
    *,
    private_key_path: Path | str,
    password: str | bytes,
    key_id_prefix: str = "ta14-ed25519",
) -> Ed25519KeyPair:
    """
    Load an encrypted private key and derive its matching public key.
    """

    path = Path(private_key_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Private signing key does not exist: {path}"
        )

    if not path.is_file():
        raise KeyLoadingError(
            f"Private signing key path is not a file: {path}"
        )

    private_key = load_private_key_pem(
        path.read_bytes(),
        password=password,
    )

    public_key = private_key.public_key()

    return Ed25519KeyPair(
        private_key=private_key,
        public_key=public_key,
        key_id=derive_key_id(
            public_key,
            prefix=key_id_prefix,
        ),
        public_key_fingerprint=public_key_fingerprint(
            public_key
        ),
    )


def load_public_key_file(
    path: Path | str,
) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file."""

    key_path = Path(path)

    if not key_path.exists():
        raise FileNotFoundError(
            f"Public verification key does not exist: {key_path}"
        )

    if not key_path.is_file():
        raise KeyLoadingError(
            f"Public verification key path is not a file: {key_path}"
        )

    return load_public_key_pem(
        key_path.read_bytes()
    )


def encode_signature(
    signature: bytes,
) -> str:
    """Encode signature bytes as canonical Base64 text."""

    return base64.b64encode(
        signature
    ).decode("ascii")


def decode_signature(
    signature_base64: str,
) -> bytes:
    """
    Decode strict Base64 signature text.

    Ed25519 signatures must contain exactly 64 decoded bytes.
    """

    try:
        decoded = base64.b64decode(
            signature_base64,
            validate=True,
        )
    except (
        binascii.Error,
        ValueError,
    ) as exc:
        raise SignatureVerificationError(
            "Signature is not valid Base64."
        ) from exc

    if len(decoded) != 64:
        raise SignatureVerificationError(
            "An Ed25519 signature must contain exactly 64 bytes."
        )

    return decoded


def sign_bytes(
    content: bytes,
    *,
    private_key: Ed25519PrivateKey,
) -> bytes:
    """Sign raw bytes with an Ed25519 private key."""

    if not isinstance(content, bytes):
        raise SigningError(
            "Signed content must be bytes."
        )

    return private_key.sign(content)


def verify_bytes_signature(
    content: bytes,
    signature: bytes,
    *,
    public_key: Ed25519PublicKey,
) -> bool:
    """
    Verify an Ed25519 signature over raw bytes.
    """

    try:
        public_key.verify(
            signature,
            content,
        )
    except InvalidSignature:
        return False

    return True


def sign_object(
    value: Any,
    *,
    key_pair: Ed25519KeyPair,
    signer: str,
    signed_at: Optional[datetime] = None,
) -> SignatureRecord:
    """
    Canonicalize, digest, and sign a replay-standard object.

    Signature and verification fields are excluded by the canonicalization
    layer, allowing a SignatureRecord to be attached after signing without
    invalidating the signed object.
    """

    normalized_signer = _require_nonempty_text(
        signer,
        field_name="signer",
    )

    canonical_content = canonical_json_bytes(
        value,
        exclude_digest_fields=False,
    )

    signed_digest = digest_bytes(
        canonical_content
    )

    signature_bytes = sign_bytes(
        canonical_content,
        private_key=key_pair.private_key,
    )

    return SignatureRecord(
        algorithm=SignatureAlgorithm.ED25519,
        key_id=key_pair.key_id,
        public_key_fingerprint=(
            key_pair.public_key_fingerprint
        ),
        signed_digest=signed_digest,
        signature_base64=encode_signature(
            signature_bytes
        ),
        signed_at=signed_at or utc_now(),
        signer=normalized_signer,
        certificate_chain=[],
        verification_status=(
            VerificationStatus.NOT_VERIFIED
        ),
        verification_message=None,
    )


def verify_object_signature(
    value: Any,
    signature_record: SignatureRecord,
    *,
    public_key: Ed25519PublicKey,
) -> VerificationResult:
    """
    Independently verify an object's digest, key fingerprint, and signature.
    """

    if (
        signature_record.algorithm
        != SignatureAlgorithm.ED25519
    ):
        return VerificationResult(
            valid=False,
            status=VerificationStatus.FAILED,
            message=(
                "Signature algorithm is not Ed25519."
            ),
            key_id=signature_record.key_id,
            signer=signature_record.signer,
        )

    observed_fingerprint = public_key_fingerprint(
        public_key
    )

    if not secure_digest_equal(
        observed_fingerprint,
        signature_record.public_key_fingerprint,
    ):
        return VerificationResult(
            valid=False,
            status=VerificationStatus.FAILED,
            message=(
                "Public key fingerprint does not match "
                "the signing receipt."
            ),
            key_id=signature_record.key_id,
            signer=signature_record.signer,
        )

    canonical_content = canonical_json_bytes(
        value,
        exclude_digest_fields=False,
    )

    observed_digest = digest_bytes(
        canonical_content
    )

    if not secure_digest_equal(
        observed_digest,
        signature_record.signed_digest,
    ):
        return VerificationResult(
            valid=False,
            status=VerificationStatus.FAILED,
            message=(
                "Signed object digest does not match "
                "the preserved receipt."
            ),
            key_id=signature_record.key_id,
            signer=signature_record.signer,
        )

    try:
        signature_bytes = decode_signature(
            signature_record.signature_base64
        )
    except SignatureVerificationError as exc:
        return VerificationResult(
            valid=False,
            status=VerificationStatus.FAILED,
            message=str(exc),
            key_id=signature_record.key_id,
            signer=signature_record.signer,
        )

    signature_valid = verify_bytes_signature(
        canonical_content,
        signature_bytes,
        public_key=public_key,
    )

    if not signature_valid:
        return VerificationResult(
            valid=False,
            status=VerificationStatus.FAILED,
            message=(
                "Cryptographic signature verification failed."
            ),
            key_id=signature_record.key_id,
            signer=signature_record.signer,
        )

    return VerificationResult(
        valid=True,
        status=VerificationStatus.VERIFIED,
        message=(
            "Object digest, public key fingerprint, "
            "and Ed25519 signature are valid."
        ),
        key_id=signature_record.key_id,
        signer=signature_record.signer,
    )


def require_valid_object_signature(
    value: Any,
    signature_record: SignatureRecord,
    *,
    public_key: Ed25519PublicKey,
    object_name: str = "replay object",
) -> None:
    """
    Verify a signature and raise when independent verification fails.
    """

    result = verify_object_signature(
        value,
        signature_record,
        public_key=public_key,
    )

    if not result.valid:
        raise SignatureVerificationError(
            f"Signature verification failed for "
            f"{object_name}: {result.message}"
        )


def verified_signature_record(
    value: Any,
    signature_record: SignatureRecord,
    *,
    public_key: Ed25519PublicKey,
) -> SignatureRecord:
    """
    Return a copy of a SignatureRecord containing its verification result.

    Verification metadata is excluded from the object's canonical signature
    calculation and can therefore be safely attached after verification.
    """

    result = verify_object_signature(
        value,
        signature_record,
        public_key=public_key,
    )

    return signature_record.model_copy(
        update={
            "verification_status": result.status,
            "verification_message": result.message,
        }
    )


def public_verification_bundle(
    public_key: Ed25519PublicKey,
    *,
    signer: str,
    key_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Create a public, machine-readable verification-key record.

    This bundle contains no private key material and may be distributed with
    replay packages or exposed through a bounded public verification endpoint.
    """

    normalized_signer = _require_nonempty_text(
        signer,
        field_name="signer",
    )

    resolved_key_id = (
        key_id
        or derive_key_id(public_key)
    )

    fingerprint = public_key_fingerprint(
        public_key
    )

    return {
        "standard": SIGNING_STANDARD,
        "algorithm": SignatureAlgorithm.ED25519.value,
        "key_id": resolved_key_id,
        "signer": normalized_signer,
        "public_key_pem": public_key_pem(
            public_key
        ).decode("ascii"),
        "public_key_fingerprint": (
            fingerprint.model_dump(
                mode="json"
            )
        ),
    }
