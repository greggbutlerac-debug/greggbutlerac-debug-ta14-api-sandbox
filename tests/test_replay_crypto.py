"""
Tests for the TA-14 Independent Route Replay cryptographic foundation.

These tests verify deterministic canonicalization, digest generation,
tamper detection, file integrity, and hash-linked ledger behavior before
the replay standard is connected to live API endpoints.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from app.replay_crypto import (
    CANONICALIZATION_STANDARD,
    CanonicalizationError,
    apply_ledger_event_digest,
    canonical_json_bytes,
    canonical_json_text,
    digest_bytes,
    digest_file,
    digest_named_objects,
    digest_object,
    digest_sequence,
    digest_text,
    read_json_document,
    secure_digest_equal,
    verify_bytes_digest,
    verify_file_digest,
    verify_ledger_chain,
    verify_ledger_event_digest,
    verify_object_digest,
    verify_text_digest,
    write_canonical_json,
)
from app.replay_models import (
    DigestRecord,
    HashAlgorithm,
    LedgerEvent,
    RouteEventType,
)


FIXED_TIME = datetime(
    2026,
    7,
    13,
    12,
    30,
    45,
    123456,
    tzinfo=timezone.utc,
)


def sample_digest(value: str = "a") -> DigestRecord:
    """
    Return a valid deterministic SHA-256 digest record for test fixtures.
    """

    return DigestRecord(
        algorithm=HashAlgorithm.SHA256,
        value=value * 64,
    )


def build_first_ledger_event() -> LedgerEvent:
    """
    Create and digest the first event in a test route ledger.
    """

    event = LedgerEvent(
        sequence=1,
        route_id=uuid4(),
        event_type=RouteEventType.ROUTE_CREATED,
        occurred_at=FIXED_TIME,
        actor="ta14-test-suite",
        object_type="route_manifest",
        object_id="route-manifest-001",
        object_digest=sample_digest("a"),
        previous_event_digest=None,
        metadata={
            "standard": CANONICALIZATION_STANDARD,
        },
    )

    return apply_ledger_event_digest(event)


def test_canonical_json_is_independent_of_mapping_order() -> None:
    """
    Logically identical mappings must produce identical canonical bytes.
    """

    first = {
        "route_id": "route-001",
        "decision": "ALLOW",
        "links": {
            "reality": True,
            "record": True,
            "continuity": True,
        },
    }

    second = {
        "links": {
            "continuity": True,
            "record": True,
            "reality": True,
        },
        "decision": "ALLOW",
        "route_id": "route-001",
    }

    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert digest_object(first) == digest_object(second)


def test_canonical_json_contains_no_insignificant_whitespace() -> None:
    """
    Canonical JSON must not contain formatting spaces or line breaks.
    """

    value = {
        "decision": "HOLD",
        "reason": "Evidence continuity is incomplete.",
    }

    canonical = canonical_json_text(value)

    assert "\n" not in canonical
    assert ": " not in canonical
    assert ", " not in canonical
    assert canonical == (
        '{"decision":"HOLD",'
        '"reason":"Evidence continuity is incomplete."}'
    )


def test_timezone_aware_datetime_is_normalized_to_utc() -> None:
    """
    Equivalent timestamps in different offsets must canonicalize identically.
    """

    utc_timestamp = datetime(
        2026,
        7,
        13,
        16,
        0,
        0,
        tzinfo=timezone.utc,
    )

    eastern_offset = timezone(
        timedelta(hours=-4)
    )

    eastern_timestamp = datetime(
        2026,
        7,
        13,
        12,
        0,
        0,
        tzinfo=eastern_offset,
    )

    first = canonical_json_text(
        {
            "observed_at": utc_timestamp,
        }
    )

    second = canonical_json_text(
        {
            "observed_at": eastern_timestamp,
        }
    )

    assert first == second
    assert first == '{"observed_at":"2026-07-13T16:00:00.000000Z"}'


def test_naive_datetime_is_rejected() -> None:
    """
    Replay records must never depend on an unstated local timezone.
    """

    naive_timestamp = datetime(
        2026,
        7,
        13,
        12,
        0,
        0,
    )

    with pytest.raises(
        CanonicalizationError,
        match="Naive datetime values are not allowed",
    ):
        canonical_json_bytes(
            {
                "observed_at": naive_timestamp,
            }
        )


def test_uuid_values_are_lowercase_and_stable() -> None:
    """
    UUID values must use one stable lowercase string representation.
    """

    route_id = uuid4()

    canonical = canonical_json_text(
        {
            "route_id": route_id,
        }
    )

    assert str(route_id).lower() in canonical
    assert canonical == (
        f'{{"route_id":"{str(route_id).lower()}"}}'
    )


def test_set_order_does_not_change_canonical_output() -> None:
    """
    Sets have no semantic order and must be sorted canonically.
    """

    first = {
        "jurisdictions": {
            "DE",
            "FR",
            "NL",
        }
    }

    second = {
        "jurisdictions": {
            "NL",
            "DE",
            "FR",
        }
    }

    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert digest_object(first) == digest_object(second)


def test_digest_bytes_and_text_are_repeatable() -> None:
    """
    Identical byte and text inputs must always produce identical digests.
    """

    byte_content = b"TA-14 independent route replay"
    text_content = "TA-14 independent route replay"

    first_byte_digest = digest_bytes(byte_content)
    second_byte_digest = digest_bytes(byte_content)

    first_text_digest = digest_text(text_content)
    second_text_digest = digest_text(text_content)

    assert secure_digest_equal(
        first_byte_digest,
        second_byte_digest,
    )

    assert secure_digest_equal(
        first_text_digest,
        second_text_digest,
    )

    assert verify_bytes_digest(
        byte_content,
        first_byte_digest,
    )

    assert verify_text_digest(
        text_content,
        first_text_digest,
    )


def test_changed_content_produces_a_different_digest() -> None:
    """
    A material change to a route record must change its digest.
    """

    original = {
        "decision": "ALLOW",
        "amount": 2500000,
        "currency": "EUR",
    }

    changed = {
        "decision": "ALLOW",
        "amount": 612000000,
        "currency": "EUR",
    }

    original_digest = digest_object(original)
    changed_digest = digest_object(changed)

    assert not secure_digest_equal(
        original_digest,
        changed_digest,
    )

    assert not verify_object_digest(
        changed,
        original_digest,
    )


def test_signature_fields_do_not_change_record_digest() -> None:
    """
    A record's signature must not participate in the digest it signs.
    """

    unsigned = {
        "route_id": "route-001",
        "decision": "ALLOW",
        "signature": None,
    }

    signed = {
        "route_id": "route-001",
        "decision": "ALLOW",
        "signature": {
            "algorithm": "Ed25519",
            "signature_base64": "example-signature-value",
        },
    }

    unsigned_digest = digest_object(unsigned)
    signed_digest = digest_object(signed)

    assert secure_digest_equal(
        unsigned_digest,
        signed_digest,
    )


def test_digest_fields_are_excluded_from_own_object_digest() -> None:
    """
    Stored digest fields must not participate in their own calculation.
    """

    without_digest = {
        "route_id": "route-001",
        "decision": "ALLOW",
        "determination_digest": None,
    }

    with_digest = {
        "route_id": "route-001",
        "decision": "ALLOW",
        "determination_digest": {
            "algorithm": "SHA-256",
            "value": "b" * 64,
        },
    }

    first = digest_object(
        without_digest,
        exclude_digest_fields=True,
    )

    second = digest_object(
        with_digest,
        exclude_digest_fields=True,
    )

    assert secure_digest_equal(
        first,
        second,
    )


def test_ordered_sequence_digest_changes_when_order_changes() -> None:
    """
    Route-event ordering is significant and must affect sequence digests.
    """

    first_order = [
        {
            "event": "binding",
        },
        {
            "event": "commit",
        },
        {
            "event": "execution",
        },
    ]

    second_order = [
        {
            "event": "commit",
        },
        {
            "event": "binding",
        },
        {
            "event": "execution",
        },
    ]

    first_digest = digest_sequence(first_order)
    second_digest = digest_sequence(second_order)

    assert not secure_digest_equal(
        first_digest,
        second_digest,
    )


def test_named_object_digest_is_independent_of_mapping_order() -> None:
    """
    Named package members must produce one stable compound root digest.
    """

    first = {
        "manifest.json": {
            "route_id": "route-001",
        },
        "determination.json": {
            "decision": "ALLOW",
        },
    }

    second = {
        "determination.json": {
            "decision": "ALLOW",
        },
        "manifest.json": {
            "route_id": "route-001",
        },
    }

    first_digest = digest_named_objects(first)
    second_digest = digest_named_objects(second)

    assert secure_digest_equal(
        first_digest,
        second_digest,
    )


def test_file_digest_verifies_and_detects_tampering(
    tmp_path: Path,
) -> None:
    """
    File hashing must verify the original file and reject altered content.
    """

    evidence_file = tmp_path / "evidence.txt"

    evidence_file.write_text(
        "Original independently reviewable evidence.",
        encoding="utf-8",
    )

    expected_digest = digest_file(evidence_file)

    assert verify_file_digest(
        evidence_file,
        expected_digest,
    )

    evidence_file.write_text(
        "Altered evidence.",
        encoding="utf-8",
    )

    assert not verify_file_digest(
        evidence_file,
        expected_digest,
    )


def test_canonical_json_write_and_read(
    tmp_path: Path,
) -> None:
    """
    Canonical JSON output must be written atomically and read successfully.
    """

    output_path = tmp_path / "route" / "manifest.json"

    value = {
        "route_id": "route-001",
        "decision": "ESCALATE",
        "created_at": FIXED_TIME,
        "conditions": [
            "Human review required.",
            "Authority scope requires confirmation.",
        ],
    }

    written_path = write_canonical_json(
        output_path,
        value,
    )

    assert written_path == output_path
    assert output_path.exists()

    raw_text = output_path.read_text(
        encoding="utf-8",
    )

    assert "\n" not in raw_text
    assert ": " not in raw_text

    loaded = read_json_document(output_path)

    assert loaded["route_id"] == "route-001"
    assert loaded["decision"] == "ESCALATE"
    assert loaded["created_at"] == (
        "2026-07-13T12:30:45.123456Z"
    )


def test_first_ledger_event_digest_is_valid() -> None:
    """
    The first ledger event must contain a valid digest and no predecessor.
    """

    event = build_first_ledger_event()

    assert event.event_digest is not None
    assert event.previous_event_digest is None
    assert verify_ledger_event_digest(event)


def test_two_event_ledger_chain_is_valid() -> None:
    """
    A later event must bind to the exact digest of the preceding event.
    """

    first_event = build_first_ledger_event()

    second_event = LedgerEvent(
        sequence=2,
        route_id=first_event.route_id,
        event_type=RouteEventType.EVIDENCE_REGISTERED,
        occurred_at=FIXED_TIME + timedelta(seconds=1),
        actor="ta14-test-suite",
        object_type="evidence_object",
        object_id="evidence-001",
        object_digest=sample_digest("b"),
        previous_event_digest=first_event.event_digest,
        metadata={
            "evidence_type": "synthetic-test-record",
        },
    )

    second_event = apply_ledger_event_digest(
        second_event
    )

    assert second_event.event_digest is not None

    assert verify_ledger_chain(
        [
            first_event,
            second_event,
        ]
    )


def test_ledger_chain_rejects_missing_sequence_number() -> None:
    """
    Ledger event sequences must begin at one and remain contiguous.
    """

    first_event = build_first_ledger_event()

    third_event = LedgerEvent(
        sequence=3,
        route_id=first_event.route_id,
        event_type=RouteEventType.DETERMINATION_ISSUED,
        occurred_at=FIXED_TIME + timedelta(seconds=2),
        actor="ta14-test-suite",
        object_type="determination_receipt",
        object_id="determination-001",
        object_digest=sample_digest("c"),
        previous_event_digest=first_event.event_digest,
        metadata={
            "decision": "ALLOW",
        },
    )

    third_event = apply_ledger_event_digest(
        third_event
    )

    assert not verify_ledger_chain(
        [
            first_event,
            third_event,
        ]
    )


def test_ledger_chain_rejects_wrong_previous_digest() -> None:
    """
    A ledger event linked to the wrong predecessor must fail verification.
    """

    first_event = build_first_ledger_event()

    second_event = LedgerEvent(
        sequence=2,
        route_id=first_event.route_id,
        event_type=RouteEventType.AUTHORITY_REGISTERED,
        occurred_at=FIXED_TIME + timedelta(seconds=1),
        actor="ta14-test-suite",
        object_type="authority_record",
        object_id="authority-001",
        object_digest=sample_digest("d"),
        previous_event_digest=sample_digest("e"),
        metadata={},
    )

    second_event = apply_ledger_event_digest(
        second_event
    )

    assert not verify_ledger_chain(
        [
            first_event,
            second_event,
        ]
    )


def test_ledger_chain_detects_event_tampering() -> None:
    """
    Changing an event after its digest was calculated must break the chain.
    """

    first_event = build_first_ledger_event()

    tampered_event = first_event.model_copy(
        update={
            "actor": "unauthorized-actor",
        }
    )

    assert tampered_event.event_digest is not None
    assert not verify_ledger_event_digest(tampered_event)

    assert not verify_ledger_chain(
        [
            tampered_event,
        ]
    )


def test_digest_record_rejects_non_hexadecimal_values() -> None:
    """
    Digest records must reject values that are not hexadecimal.
    """

    with pytest.raises(
        ValueError,
        match="hexadecimal characters only",
    ):
        DigestRecord(
            algorithm=HashAlgorithm.SHA256,
            value="z" * 64,
        )


def test_digest_record_rejects_unsupported_length() -> None:
    """
    Digest records must reject unsupported digest lengths.
    """

    with pytest.raises(
        ValueError,
        match="64, 96, or 128",
    ):
        DigestRecord(
            algorithm=HashAlgorithm.SHA256,
            value="a" * 40,
        )
