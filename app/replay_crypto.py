"""
TA-14 Independent Route Replay Standard
Canonical serialization and cryptographic digest utilities.

Purpose
-------
Independent replay requires two parties to calculate the same digest from
the same record.

Ordinary JSON serialization is not sufficient because differences in field
order, whitespace, datetime formatting, UUID representation, or omitted
values can produce different bytes from logically identical records.

This module establishes the TA-14 canonical representation used for:

- evidence digests;
- route-manifest digests;
- determination receipts;
- binding receipts;
- commit receipts;
- execution receipts;
- outcome records;
- ledger events;
- replay-package files;
- independent verification.

This module provides deterministic serialization and hashing.
Asymmetric signing and signature verification are added separately.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import asdict, is_dataclass
from datetime import date, datetime, timezone
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Set
from uuid import UUID

from pydantic import BaseModel

from .replay_models import DigestRecord, HashAlgorithm, LedgerEvent


# ---------------------------------------------------------------------------
# Standard identity
# ---------------------------------------------------------------------------

CANONICALIZATION_STANDARD = "TA14-CANONICAL-JSON-1"
DEFAULT_HASH_ALGORITHM = HashAlgorithm.SHA256


# Fields that normally contain a signature or verification result and must
# not participate in the digest of the record they attest to.
DEFAULT_EXCLUDED_FIELDS: Set[str] = {
    "signature",
    "seal_signature",
    "verification_status",
    "verification_message",
}


# Fields that contain calculated digests. These are excluded when calculating
# the digest of the object that owns them.
DIGEST_FIELDS: Set[str] = {
    "action_digest",
    "binding_digest",
    "commit_digest",
    "determination_digest",
    "event_digest",
    "execution_digest",
    "final_event_digest",
    "index_digest",
    "manifest_digest",
    "outcome_digest",
    "package_digest",
    "report_digest",
    "root_digest",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented canonically."""


class DigestVerificationError(ValueError):
    """Raised when a digest cannot be verified safely."""


# ---------------------------------------------------------------------------
# Primitive normalization
# ---------------------------------------------------------------------------

def normalize_datetime(value: datetime) -> str:
    """
    Convert a datetime to canonical UTC ISO-8601 form.

    Naive datetimes are rejected because independently replayable records
    must never depend on an unstated local timezone.
    """

    if value.tzinfo is None or value.utcoffset() is None:
        raise CanonicalizationError(
            "Naive datetime values are not allowed in replay records."
        )

    utc_value = value.astimezone(timezone.utc)

    return utc_value.isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def normalize_date(value: date) -> str:
    """Convert a date to canonical ISO-8601 form."""

    return value.isoformat()


def normalize_decimal(value: Decimal) -> str:
    """
    Convert a Decimal to a stable, non-exponent string.

    Trailing fractional zeroes are removed while zero remains represented
    as the string "0".
    """

    if not value.is_finite():
        raise CanonicalizationError(
            "NaN and infinite Decimal values are not allowed."
        )

    normalized = format(value, "f")

    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")

    if normalized in {"", "-0"}:
        return "0"

    return normalized


def normalize_float(value: float) -> int | float:
    """
    Normalize a finite floating-point value.

    Integer-valued floats become integers. Other values retain Python's
    shortest round-trip representation. NaN and infinity are rejected.
    """

    if not math.isfinite(value):
        raise CanonicalizationError(
            "NaN and infinite floating-point values are not allowed."
        )

    if value == 0:
        return 0

    if value.is_integer():
        return int(value)

    return float(repr(value))


# ---------------------------------------------------------------------------
# Recursive canonicalization
# ---------------------------------------------------------------------------

def _should_exclude_field(
    field_name: str,
    *,
    excluded_fields: Set[str],
    exclude_digest_fields: bool,
) -> bool:
    """Return whether a field must be excluded from canonical output."""

    if field_name in excluded_fields:
        return True

    if exclude_digest_fields and field_name in DIGEST_FIELDS:
        return True

    return False


def to_canonical_value(
    value: Any,
    *,
    excluded_fields: Optional[Iterable[str]] = None,
    exclude_none: bool = False,
    exclude_digest_fields: bool = False,
    use_default_exclusions: bool = False,
) -> Any:
    """
    Convert a supported Python value into canonical JSON-compatible data.

    Supported values include:

    - Pydantic models;
    - dataclasses;
    - mappings with string keys;
    - lists and tuples;
    - sets and frozensets;
    - UUID values;
    - timezone-aware datetimes;
    - dates;
    - enums;
    - Decimal values;
    - pathlib Path values;
    - bytes;
    - standard JSON primitives.
    """

    exclusions = (
        set(DEFAULT_EXCLUDED_FIELDS)
        if use_default_exclusions
        else set()
    )

    if excluded_fields is not None:
        exclusions.update(excluded_fields)

    if isinstance(value, BaseModel):
        raw_value = value.model_dump(
            mode="python",
            by_alias=True,
            exclude_none=False,
        )

        return to_canonical_value(
            raw_value,
            excluded_fields=exclusions,
            exclude_none=exclude_none,
            exclude_digest_fields=exclude_digest_fields,
            use_default_exclusions=use_default_exclusions,
        )

    if is_dataclass(value) and not isinstance(value, type):
        return to_canonical_value(
            asdict(value),
            excluded_fields=exclusions,
            exclude_none=exclude_none,
            exclude_digest_fields=exclude_digest_fields,
            use_default_exclusions=use_default_exclusions,
        )

    if isinstance(value, Enum):
        return to_canonical_value(
            value.value,
            excluded_fields=exclusions,
            exclude_none=exclude_none,
            exclude_digest_fields=exclude_digest_fields,
            use_default_exclusions=use_default_exclusions,
        )

    if isinstance(value, UUID):
        return str(value).lower()

    if isinstance(value, datetime):
        return normalize_datetime(value)

    if isinstance(value, date):
        return normalize_date(value)

    if isinstance(value, Decimal):
        return normalize_decimal(value)

    if isinstance(value, Path):
        return value.as_posix()

    if isinstance(value, bytes):
        return value.hex()

    if isinstance(value, Mapping):
        canonical_mapping: Dict[str, Any] = {}

        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(
                    "Canonical JSON mappings require string keys."
                )

            if _should_exclude_field(
                key,
                excluded_fields=exclusions,
                exclude_digest_fields=exclude_digest_fields,
            ):
                continue

            if exclude_none and item is None:
                continue

            canonical_mapping[key] = to_canonical_value(
                item,
                excluded_fields=exclusions,
                exclude_none=exclude_none,
                exclude_digest_fields=exclude_digest_fields,
            )

        return {
            key: canonical_mapping[key]
            for key in sorted(canonical_mapping)
        }

    if isinstance(value, (set, frozenset)):
        canonical_items = [
            to_canonical_value(
                item,
                excluded_fields=exclusions,
                exclude_none=exclude_none,
                exclude_digest_fields=exclude_digest_fields,
            )
            for item in value
        ]

        return sorted(
            canonical_items,
            key=lambda item: json.dumps(
                item,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
        )

    if isinstance(value, (list, tuple)):
        return [
            to_canonical_value(
                item,
                excluded_fields=exclusions,
                exclude_none=exclude_none,
                exclude_digest_fields=exclude_digest_fields,
            )
            for item in value
        ]

    if isinstance(value, float):
        return normalize_float(value)

    if value is None or isinstance(value, (str, int, bool)):
        return value

    raise CanonicalizationError(
        f"Unsupported canonicalization type: {type(value).__name__}"
    )


def canonical_json_bytes(
    value: Any,
    *,
    excluded_fields: Optional[Iterable[str]] = None,
    exclude_none: bool = False,
    exclude_digest_fields: bool = False,
    use_default_exclusions: bool = False,
) -> bytes:
    """
    Serialize a value into deterministic UTF-8 JSON bytes.

    Canonical encoding rules:

    - UTF-8 encoding;
    - sorted object keys;
    - no insignificant whitespace;
    - Unicode preserved;
    - NaN and infinity prohibited;
    - timezone-aware datetimes normalized to UTC;
    - UUID values lowercase;
    - signature fields preserved for ordinary document serialization;
    - cryptographic callers may enable the standard signature exclusions;
    - digest fields optionally excluded.
    """

    canonical_value = to_canonical_value(
        value,
        excluded_fields=excluded_fields,
        exclude_none=exclude_none,
        exclude_digest_fields=exclude_digest_fields,
        use_default_exclusions=use_default_exclusions,
    )

    try:
        encoded = json.dumps(
            canonical_value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(
            f"Unable to serialize value canonically: {exc}"
        ) from exc

    return encoded.encode("utf-8")


def canonical_json_text(
    value: Any,
    *,
    excluded_fields: Optional[Iterable[str]] = None,
    exclude_none: bool = False,
    exclude_digest_fields: bool = False,
    use_default_exclusions: bool = False,
) -> str:
    """Return canonical JSON as text."""

    return canonical_json_bytes(
        value,
        excluded_fields=excluded_fields,
        exclude_none=exclude_none,
        exclude_digest_fields=exclude_digest_fields,
        use_default_exclusions=use_default_exclusions,
    ).decode("utf-8")


# ---------------------------------------------------------------------------
# Digest creation
# ---------------------------------------------------------------------------

def _hashlib_name(algorithm: HashAlgorithm) -> str:
    """Map a replay hash algorithm to its hashlib identifier."""

    names = {
        HashAlgorithm.SHA256: "sha256",
        HashAlgorithm.SHA384: "sha384",
        HashAlgorithm.SHA512: "sha512",
    }

    try:
        return names[algorithm]
    except KeyError as exc:
        raise CanonicalizationError(
            f"Unsupported hash algorithm: {algorithm}"
        ) from exc


def digest_bytes(
    content: bytes,
    *,
    algorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM,
) -> DigestRecord:
    """Calculate a digest over raw bytes."""

    hasher = hashlib.new(_hashlib_name(algorithm))
    hasher.update(content)

    return DigestRecord(
        algorithm=algorithm,
        value=hasher.hexdigest(),
    )


def digest_text(
    content: str,
    *,
    algorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM,
) -> DigestRecord:
    """Calculate a digest over UTF-8 text."""

    return digest_bytes(
        content.encode("utf-8"),
        algorithm=algorithm,
    )


def digest_object(
    value: Any,
    *,
    algorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM,
    excluded_fields: Optional[Iterable[str]] = None,
    exclude_none: bool = False,
    exclude_digest_fields: bool = True,
) -> DigestRecord:
    """
    Calculate the digest of a canonical replay object.

    Digest fields are excluded by default so a record's stored digest does
    not participate in its own calculation.
    """

    content = canonical_json_bytes(
        value,
        excluded_fields=excluded_fields,
        exclude_none=exclude_none,
        exclude_digest_fields=exclude_digest_fields,
        use_default_exclusions=True,
    )

    return digest_bytes(
        content,
        algorithm=algorithm,
    )


def digest_file(
    path: Path | str,
    *,
    algorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM,
    chunk_size: int = 1024 * 1024,
) -> DigestRecord:
    """
    Calculate a streaming digest for a file.

    Files are processed in chunks so large evidence files do not need to fit
    entirely in memory.
    """

    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero.")

    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Replay file does not exist: {file_path}"
        )

    if not file_path.is_file():
        raise ValueError(
            f"Replay path is not a file: {file_path}"
        )

    hasher = hashlib.new(_hashlib_name(algorithm))

    with file_path.open("rb") as file_handle:
        while True:
            chunk = file_handle.read(chunk_size)

            if not chunk:
                break

            hasher.update(chunk)

    return DigestRecord(
        algorithm=algorithm,
        value=hasher.hexdigest(),
    )


# ---------------------------------------------------------------------------
# Digest verification
# ---------------------------------------------------------------------------

def secure_digest_equal(
    first: DigestRecord,
    second: DigestRecord,
) -> bool:
    """Compare two digest records using constant-time comparison."""

    if first.algorithm != second.algorithm:
        return False

    return hmac.compare_digest(
        first.value,
        second.value,
    )


def verify_bytes_digest(
    content: bytes,
    expected: DigestRecord,
) -> bool:
    """Verify raw bytes against an expected digest."""

    observed = digest_bytes(
        content,
        algorithm=expected.algorithm,
    )

    return secure_digest_equal(
        observed,
        expected,
    )


def verify_text_digest(
    content: str,
    expected: DigestRecord,
) -> bool:
    """Verify UTF-8 text against an expected digest."""

    observed = digest_text(
        content,
        algorithm=expected.algorithm,
    )

    return secure_digest_equal(
        observed,
        expected,
    )


def verify_object_digest(
    value: Any,
    expected: DigestRecord,
    *,
    excluded_fields: Optional[Iterable[str]] = None,
    exclude_none: bool = False,
    exclude_digest_fields: bool = True,
) -> bool:
    """Verify a canonical replay object against an expected digest."""

    observed = digest_object(
        value,
        algorithm=expected.algorithm,
        excluded_fields=excluded_fields,
        exclude_none=exclude_none,
        exclude_digest_fields=exclude_digest_fields,
    )

    return secure_digest_equal(
        observed,
        expected,
    )


def verify_file_digest(
    path: Path | str,
    expected: DigestRecord,
) -> bool:
    """Verify a file against an expected digest."""

    observed = digest_file(
        path,
        algorithm=expected.algorithm,
    )

    return secure_digest_equal(
        observed,
        expected,
    )


def require_valid_object_digest(
    value: Any,
    expected: DigestRecord,
    *,
    object_name: str = "object",
    excluded_fields: Optional[Iterable[str]] = None,
    exclude_none: bool = False,
    exclude_digest_fields: bool = True,
) -> None:
    """Verify a digest or raise a clear exception."""

    is_valid = verify_object_digest(
        value,
        expected,
        excluded_fields=excluded_fields,
        exclude_none=exclude_none,
        exclude_digest_fields=exclude_digest_fields,
    )

    if not is_valid:
        raise DigestVerificationError(
            f"Digest verification failed for {object_name}."
        )


# ---------------------------------------------------------------------------
# Compound and chain digests
# ---------------------------------------------------------------------------

def digest_sequence(
    values: Sequence[Any],
    *,
    algorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM,
) -> DigestRecord:
    """
    Digest an ordered sequence of objects.

    Sequence order is significant.
    """

    member_digests = [
        digest_object(
            value,
            algorithm=algorithm,
        ).value
        for value in values
    ]

    return digest_object(
        {
            "canonicalization_standard": CANONICALIZATION_STANDARD,
            "ordered_member_digests": member_digests,
        },
        algorithm=algorithm,
    )


def digest_named_objects(
    values: Mapping[str, Any],
    *,
    algorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM,
) -> DigestRecord:
    """
    Digest a named collection of records.

    Record names are sorted canonically. This is useful for package roots and
    other compound integrity values.
    """

    member_digests = {
        name: digest_object(
            value,
            algorithm=algorithm,
        ).value
        for name, value in values.items()
    }

    return digest_object(
        {
            "canonicalization_standard": CANONICALIZATION_STANDARD,
            "named_member_digests": member_digests,
        },
        algorithm=algorithm,
    )


def calculate_ledger_event_digest(
    event: LedgerEvent,
) -> DigestRecord:
    """
    Calculate a ledger event digest.

    The event's own event_digest and signature fields are excluded. The prior
    event digest remains included because it creates the chain relationship.
    """

    return digest_object(
        event,
        excluded_fields={
            "event_digest",
            "signature",
        },
        exclude_digest_fields=False,
    )


def apply_ledger_event_digest(
    event: LedgerEvent,
) -> LedgerEvent:
    """Return a copy of a ledger event with its digest populated."""

    event_digest = calculate_ledger_event_digest(event)

    return event.model_copy(
        update={
            "event_digest": event_digest,
        }
    )


def verify_ledger_event_digest(
    event: LedgerEvent,
) -> bool:
    """Verify the digest stored on a ledger event."""

    if event.event_digest is None:
        return False

    observed = calculate_ledger_event_digest(event)

    return secure_digest_equal(
        observed,
        event.event_digest,
    )


def verify_ledger_chain(
    events: Sequence[LedgerEvent],
) -> bool:
    """
    Verify ledger sequence, event digests, and hash linkage.

    A valid ledger:

    - begins at sequence 1;
    - contains no missing sequence numbers;
    - contains a valid digest for every event;
    - contains no previous digest on the first event;
    - links each later event to the prior event's digest.
    """

    if not events:
        return True

    ordered_events = sorted(
        events,
        key=lambda item: item.sequence,
    )

    expected_sequences = list(
        range(1, len(ordered_events) + 1)
    )

    actual_sequences = [
        event.sequence
        for event in ordered_events
    ]

    if actual_sequences != expected_sequences:
        return False

    for index, event in enumerate(ordered_events):
        if not verify_ledger_event_digest(event):
            return False

        if index == 0:
            if event.previous_event_digest is not None:
                return False

            continue

        prior_event = ordered_events[index - 1]

        if prior_event.event_digest is None:
            return False

        if event.previous_event_digest is None:
            return False

        if not secure_digest_equal(
            event.previous_event_digest,
            prior_event.event_digest,
        ):
            return False

    return True


# ---------------------------------------------------------------------------
# Canonical document input and output
# ---------------------------------------------------------------------------

def write_canonical_json(
    path: Path | str,
    value: Any,
    *,
    excluded_fields: Optional[Iterable[str]] = None,
    exclude_none: bool = False,
    exclude_digest_fields: bool = False,
    create_parents: bool = True,
) -> Path:
    """
    Write a complete canonical JSON document atomically.

    Completed documents preserve attached signature and seal-signature records.
    Cryptographic digest operations use digest_object(), which applies the
    standard signature exclusions separately.

    A temporary sibling file is written first and then moved into place. This
    reduces the chance of preserving a partially written replay record.
    """

    output_path = Path(path)

    if create_parents:
        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    content = canonical_json_bytes(
        value,
        excluded_fields=excluded_fields,
        exclude_none=exclude_none,
        exclude_digest_fields=exclude_digest_fields,
    )

    temporary_path = output_path.with_name(
        f".{output_path.name}.tmp"
    )

    with temporary_path.open("wb") as file_handle:
        file_handle.write(content)
        file_handle.flush()

    temporary_path.replace(output_path)

    return output_path


def read_json_document(
    path: Path | str,
) -> Any:
    """Read and parse a UTF-8 JSON document."""

    input_path = Path(path)

    if not input_path.exists():
        raise FileNotFoundError(
            f"Replay JSON document does not exist: {input_path}"
        )

    if not input_path.is_file():
        raise ValueError(
            f"Replay JSON path is not a file: {input_path}"
        )

    with input_path.open(
        "r",
        encoding="utf-8",
    ) as file_handle:
        return json.load(file_handle)
