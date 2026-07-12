#!/usr/bin/env python3
"""
TA-14 controlled synthetic sandbox activity runner.

Purpose:
- Select varied scenarios from automation/scenarios.json.
- Send clearly labeled synthetic demonstration requests to the TA-14 sandbox.
- Record accepted, rejected, and failed requests in automation/logs/.
- Avoid representing synthetic traffic as customer activity or production use.

The runner discovers the sandbox endpoint and request contract from OpenAPI.
It also attempts to use repository example JSON files when they are valid.
Unreadable, binary, or malformed example files are skipped safely.
"""

from __future__ import annotations

import copy
import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests


ROOT_DIR = Path(__file__).resolve().parents[1]
AUTOMATION_DIR = ROOT_DIR / "automation"
SCENARIO_FILE = AUTOMATION_DIR / "scenarios.json"
LOG_DIR = AUTOMATION_DIR / "logs"

DEFAULT_BASE_URL = (
    "https://greggbutlerac-debug-ta14-api-sandbox.onrender.com"
)
DEFAULT_RUN_COUNT = 1
MAX_BATCH_SIZE = 10
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_DELAY_MIN_SECONDS = 8
DEFAULT_DELAY_MAX_SECONDS = 20

EXAMPLE_FILES = (
    ROOT_DIR / "evaluate-execution.json",
    ROOT_DIR / "examples" / "evaluate-execution.json",
    ROOT_DIR / "evaluate-evidence.json",
    ROOT_DIR / "examples" / "evaluate-evidence.json",
)

PREFERRED_ENDPOINTS = (
    "/v1/evaluate",
    "/evaluate",
    "/v1/evaluate-execution",
    "/evaluate-execution",
    "/v1/evidence/evaluate",
    "/evidence/evaluate",
    "/api/evaluate",
)

FINAL_ROUTES = ("ALLOW", "HOLD", "DENY", "ESCALATE")

TRUE_WORDS = {
    "verified",
    "complete",
    "current",
    "valid",
    "present",
    "approved",
    "authorized",
    "sufficient",
}

FALSE_WORDS = {
    "absent",
    "missing",
    "incomplete",
    "stale",
    "invalid",
    "unverified",
    "unknown",
    "prohibited",
}


class RunnerConfigurationError(RuntimeError):
    """Raised when the runner cannot be configured safely."""


def utc_now() -> str:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def read_integer_environment(name: str, default: int) -> int:
    """Read an integer environment variable."""
    raw_value = os.getenv(name)

    if raw_value is None or not raw_value.strip():
        return default

    try:
        return int(raw_value)
    except ValueError as exc:
        raise RunnerConfigurationError(
            f"{name} must be an integer. Received {raw_value!r}."
        ) from exc


def normalize_base_url(value: str) -> str:
    """Validate and normalize the sandbox URL."""
    cleaned = value.strip()

    if not cleaned:
        raise RunnerConfigurationError(
            "TA14_SANDBOX_BASE_URL cannot be empty."
        )

    if not cleaned.startswith(("https://", "http://")):
        raise RunnerConfigurationError(
            "TA14_SANDBOX_BASE_URL must begin with "
            "https:// or http://."
        )

    return cleaned.rstrip("/")


def load_json_file(path: Path) -> Any:
    """
    Load a JSON file.

    utf-8-sig supports normal UTF-8 files and files containing a UTF-8
    byte-order marker. Binary, malformed, or unsupported encodings produce
    a controlled error instead of crashing the workflow.
    """
    try:
        with path.open("r", encoding="utf-8-sig") as file_handle:
            return json.load(file_handle)

    except FileNotFoundError as exc:
        raise RunnerConfigurationError(
            f"Required file was not found: {path}"
        ) from exc

    except UnicodeDecodeError as exc:
        raise RunnerConfigurationError(
            f"File is not readable UTF-8 JSON: {path}"
        ) from exc

    except json.JSONDecodeError as exc:
        raise RunnerConfigurationError(
            f"Invalid JSON in {path}. "
            f"Line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc


def load_scenarios() -> list[dict[str, Any]]:
    """Load and validate automation/scenarios.json."""
    document = load_json_file(SCENARIO_FILE)

    if not isinstance(document, dict):
        raise RunnerConfigurationError(
            "scenarios.json must contain a JSON object."
        )

    scenarios = document.get("scenarios")

    if not isinstance(scenarios, list) or not scenarios:
        raise RunnerConfigurationError(
            "scenarios.json must contain a non-empty 'scenarios' array."
        )

    validated: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for index, scenario in enumerate(scenarios, start=1):
        if not isinstance(scenario, dict):
            raise RunnerConfigurationError(
                f"Scenario {index} must be a JSON object."
            )

        scenario_id = str(scenario.get("scenario_id", "")).strip()
        name = str(scenario.get("name", "")).strip()

        if not scenario_id or not name:
            raise RunnerConfigurationError(
                f"Scenario {index} requires scenario_id and name."
            )

        if scenario_id in seen_ids:
            raise RunnerConfigurationError(
                f"Duplicate scenario_id: {scenario_id}"
            )

        seen_ids.add(scenario_id)
        validated.append(scenario)

    return validated


def fetch_openapi(
    session: requests.Session,
    base_url: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    """Fetch the deployed FastAPI OpenAPI document."""
    openapi_url = f"{base_url}/openapi.json"

    try:
        response = session.get(
            openapi_url,
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        document = response.json()

    except requests.RequestException as exc:
        raise RunnerConfigurationError(
            f"Could not retrieve OpenAPI from {openapi_url}: {exc}"
        ) from exc

    except ValueError as exc:
        raise RunnerConfigurationError(
            f"OpenAPI response from {openapi_url} was not valid JSON."
        ) from exc

    if not isinstance(document, dict):
        raise RunnerConfigurationError(
            "OpenAPI document must be a JSON object."
        )

    return document


def operation_looks_like_evaluation(
    path: str,
    operation: dict[str, Any],
) -> bool:
    """Determine whether an OpenAPI POST operation is an evaluation route."""
    combined = " ".join(
        (
            path,
            str(operation.get("operationId", "")),
            str(operation.get("summary", "")),
            str(operation.get("description", "")),
        )
    ).lower()

    terms = (
        "evaluate",
        "evaluation",
        "execution",
        "evidence",
        "admissib",
        "route",
    )

    return any(term in combined for term in terms)


def discover_endpoint(
    openapi_document: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Find the most likely POST evaluation endpoint and operation."""
    paths = openapi_document.get("paths", {})

    if not isinstance(paths, dict):
        raise RunnerConfigurationError(
            "OpenAPI document does not contain a valid paths object."
        )

    candidates: list[tuple[str, dict[str, Any]]] = []

    for path, methods in paths.items():
        if not isinstance(path, str) or not isinstance(methods, dict):
            continue

        post_operation = methods.get("post")

        if not isinstance(post_operation, dict):
            continue

        if operation_looks_like_evaluation(path, post_operation):
            candidates.append((path, post_operation))

    for preferred in PREFERRED_ENDPOINTS:
        for candidate_path, operation in candidates:
            if candidate_path == preferred:
                return candidate_path, operation

    if candidates:
        candidates.sort(
            key=lambda item: (
                0 if "evaluate" in item[0].lower() else 1,
                len(item[0]),
                item[0],
            )
        )
        return candidates[0]

    available_post_paths = []

    for path, methods in paths.items():
        if isinstance(methods, dict) and isinstance(
            methods.get("post"),
            dict,
        ):
            available_post_paths.append(str(path))

    raise RunnerConfigurationError(
        "No evaluation POST endpoint was found. "
        f"Available POST endpoints: {available_post_paths}"
    )


def resolve_reference(
    openapi_document: dict[str, Any],
    reference: str,
) -> dict[str, Any]:
    """Resolve a local OpenAPI JSON reference."""
    if not reference.startswith("#/"):
        return {}

    current: Any = openapi_document

    for part in reference[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")

        if not isinstance(current, dict) or part not in current:
            return {}

        current = current[part]

    return current if isinstance(current, dict) else {}


def example_from_schema(
    schema: dict[str, Any],
    openapi_document: dict[str, Any],
    depth: int = 0,
) -> Any:
    """
    Build a conservative request example from an OpenAPI schema.

    Existing examples and defaults are preferred. Required object properties
    are generated recursively.
    """
    if depth > 12:
        return None

    if "$ref" in schema:
        resolved = resolve_reference(
            openapi_document,
            str(schema["$ref"]),
        )
        return example_from_schema(
            resolved,
            openapi_document,
            depth + 1,
        )

    if "example" in schema:
        return copy.deepcopy(schema["example"])

    if "default" in schema:
        return copy.deepcopy(schema["default"])

    enum_values = schema.get("enum")

    if isinstance(enum_values, list) and enum_values:
        return copy.deepcopy(enum_values[0])

    for combined_key in ("allOf", "oneOf", "anyOf"):
        combined = schema.get(combined_key)

        if isinstance(combined, list) and combined:
            if combined_key == "allOf":
                merged: dict[str, Any] = {}

                for child_schema in combined:
                    if not isinstance(child_schema, dict):
                        continue

                    child_value = example_from_schema(
                        child_schema,
                        openapi_document,
                        depth + 1,
                    )

                    if isinstance(child_value, dict):
                        merged.update(child_value)

                if merged:
                    return merged

            for child_schema in combined:
                if not isinstance(child_schema, dict):
                    continue

                value = example_from_schema(
                    child_schema,
                    openapi_document,
                    depth + 1,
                )

                if value is not None:
                    return value

    schema_type = schema.get("type")

    if not schema_type and "properties" in schema:
        schema_type = "object"

    if schema_type == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        if not isinstance(properties, dict):
            return {}

        result: dict[str, Any] = {}

        for name, property_schema in properties.items():
            if not isinstance(property_schema, dict):
                continue

            include_property = (
                name in required
                or "example" in property_schema
                or "default" in property_schema
            )

            if not include_property:
                continue

            value = example_from_schema(
                property_schema,
                openapi_document,
                depth + 1,
            )

            if value is not None:
                result[name] = value

        return result

    if schema_type == "array":
        item_schema = schema.get("items", {})

        if isinstance(item_schema, dict):
            item = example_from_schema(
                item_schema,
                openapi_document,
                depth + 1,
            )
            return [] if item is None else [item]

        return []

    if schema_type == "boolean":
        return False

    if schema_type == "integer":
        minimum = schema.get("minimum")
        return int(minimum) if isinstance(minimum, int) else 1

    if schema_type == "number":
        minimum = schema.get("minimum")
        return float(minimum) if isinstance(
            minimum,
            (int, float),
        ) else 1.0

    if schema_type == "string":
        string_format = schema.get("format")

        if string_format == "date-time":
            return utc_now()

        if string_format == "date":
            return datetime.now(timezone.utc).date().isoformat()

        if string_format == "uuid":
            return str(uuid.uuid4())

        if string_format == "email":
            return "synthetic-demo@ta14.invalid"

        return "synthetic_demo"

    return None


def request_example_from_operation(
    operation: dict[str, Any],
    openapi_document: dict[str, Any],
) -> dict[str, Any] | None:
    """Extract or generate a JSON request body from an OpenAPI operation."""
    request_body = operation.get("requestBody")

    if not isinstance(request_body, dict):
        return None

    if "$ref" in request_body:
        request_body = resolve_reference(
            openapi_document,
            str(request_body["$ref"]),
        )

    content = request_body.get("content", {})

    if not isinstance(content, dict):
        return None

    media = (
        content.get("application/json")
        or content.get("application/*+json")
    )

    if not isinstance(media, dict):
        return None

    if "example" in media and isinstance(media["example"], dict):
        return copy.deepcopy(media["example"])

    examples = media.get("examples")

    if isinstance(examples, dict):
        for example_record in examples.values():
            if not isinstance(example_record, dict):
                continue

            example_value = example_record.get("value")

            if isinstance(example_value, dict):
                return copy.deepcopy(example_value)

    schema = media.get("schema")

    if not isinstance(schema, dict):
        return None

    generated = example_from_schema(
        schema,
        openapi_document,
    )

    return generated if isinstance(generated, dict) else None


def load_repository_example() -> tuple[dict[str, Any] | None, str]:
    """
    Load the first usable repository example.

    Unreadable, binary, or invalid example files are skipped.
    """
    skipped: list[str] = []

    for path in EXAMPLE_FILES:
        if not path.exists():
            continue

        try:
            payload = load_json_file(path)

        except RunnerConfigurationError as exc:
            skipped.append(f"{path.name}: {exc}")
            continue

        if isinstance(payload, dict):
            return payload, str(path.relative_to(ROOT_DIR))

        skipped.append(
            f"{path.name}: JSON root was not an object"
        )

    if skipped:
        print("Repository request examples skipped:")
        for item in skipped:
            print(f"  - {item}")

    return None, "none"


def status_for_field(
    field_name: str,
    scenario: dict[str, Any],
) -> Any:
    """Map an API field name to a scenario status."""
    normalized = field_name.lower().replace("-", "_")

    mappings = (
        ("authority", "authority_status"),
        ("evidence", "evidence_status"),
        ("record", "evidence_status"),
        ("continuity", "continuity_status"),
        ("security", "security_status"),
        ("human_approval", "human_approval"),
        ("human_review", "human_approval"),
        ("approval", "human_approval"),
    )

    for token, scenario_key in mappings:
        if token in normalized:
            return scenario.get(scenario_key)

    return None


def status_to_boolean(value: Any, fallback: bool) -> bool:
    """Convert a scenario status to a boolean when needed."""
    if isinstance(value, bool):
        return value

    normalized = str(value).strip().lower()

    if normalized in TRUE_WORDS:
        return True

    if normalized in FALSE_WORDS:
        return False

    return fallback


def mutate_scalar(
    field_name: str,
    current_value: Any,
    scenario: dict[str, Any],
) -> Any:
    """Apply scenario values to recognized request fields."""
    normalized = field_name.lower().replace("-", "_")
    status_value = status_for_field(normalized, scenario)

    if normalized in {
        "scenario_id",
        "case_id",
        "request_id",
        "evaluation_id",
        "route_id",
        "idempotency_key",
    }:
        return (
            f"{scenario['scenario_id']}-"
            f"{uuid.uuid4().hex[:8].upper()}"
        )

    if normalized in {
        "name",
        "title",
        "scenario_name",
        "case_name",
    }:
        return str(scenario.get("name", current_value))

    if normalized in {"industry", "sector", "domain"}:
        return str(scenario.get("industry", current_value))

    if normalized in {
        "consequence_level",
        "risk_level",
        "impact_level",
        "severity",
    }:
        return str(
            scenario.get("consequence_level", current_value)
        )

    if normalized in {
        "system_identity",
        "system_name",
        "subject",
        "system",
    } and isinstance(current_value, str):
        return str(
            scenario.get("system_identity", current_value)
        )

    if normalized in {
        "description",
        "summary",
        "context",
        "request_description",
        "statement",
    } and isinstance(current_value, str):
        facts = scenario.get("facts", [])
        fact_text = " ".join(str(item) for item in facts)

        return (
            f"Synthetic demonstration scenario "
            f"{scenario['scenario_id']}: "
            f"{scenario['name']}. {fact_text}"
        ).strip()

    if status_value is not None:
        if isinstance(current_value, bool):
            return status_to_boolean(
                status_value,
                current_value,
            )

        if isinstance(current_value, str):
            return str(status_value)

    return current_value


def apply_scenario(
    value: Any,
    scenario: dict[str, Any],
    parent_key: str = "",
) -> Any:
    """Recursively apply scenario values to a request body."""
    if isinstance(value, dict):
        updated: dict[str, Any] = {}

        for key, child_value in value.items():
            if isinstance(child_value, (dict, list)):
                updated[key] = apply_scenario(
                    child_value,
                    scenario,
                    key,
                )
            else:
                updated[key] = mutate_scalar(
                    key,
                    child_value,
                    scenario,
                )

        return updated

    if isinstance(value, list):
        normalized_parent = (
            parent_key.lower().replace("-", "_")
        )

        if normalized_parent in {
            "facts",
            "observations",
            "submitted_facts",
            "evidence_items",
        }:
            return copy.deepcopy(
                scenario.get("facts", value)
            )

        return [
            apply_scenario(item, scenario, parent_key)
            for item in value
        ]

    return value


def extract_route(response_body: Any) -> str | None:
    """Find the final route in a nested response."""
    possible_keys = {
        "route",
        "decision",
        "classification",
        "outcome",
        "result",
        "route_outcome",
        "final_route",
        "determination",
    }

    if isinstance(response_body, dict):
        for key, value in response_body.items():
            normalized_key = key.lower().replace("-", "_")

            if (
                normalized_key in possible_keys
                and isinstance(value, str)
            ):
                candidate = value.strip().upper()

                for route in FINAL_ROUTES:
                    if route in candidate:
                        return route

        for nested_value in response_body.values():
            route = extract_route(nested_value)

            if route:
                return route

    if isinstance(response_body, list):
        for item in response_body:
            route = extract_route(item)

            if route:
                return route

    return None


def create_response_preview(
    response: requests.Response,
) -> Any:
    """Create a bounded response value for logs."""
    try:
        body = response.json()
    except ValueError:
        return response.text[:3000]

    serialized = json.dumps(body, ensure_ascii=False)

    if len(serialized) <= 7000:
        return body

    return {
        "truncated": True,
        "preview": serialized[:7000],
    }


def append_log(
    log_path: Path,
    record: dict[str, Any],
) -> None:
    """Append one JSON Lines record."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    with log_path.open("a", encoding="utf-8") as file_handle:
        file_handle.write(
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n"
        )


def build_headers(
    api_key: str | None,
    run_class: str,
    run_source: str,
    scenario: dict[str, Any],
    run_id: str,
) -> dict[str, str]:
    """Create explicit synthetic classification headers."""
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "TA14-Synthetic-Demo-Runner/2.0",
        "X-TA14-Run-Class": run_class,
        "X-TA14-Run-Source": run_source,
        "X-TA14-Scenario-ID": str(
            scenario["scenario_id"]
        ),
        "X-TA14-Synthetic": "true",
        "X-Correlation-ID": run_id,
        "Idempotency-Key": run_id,
    }

    if api_key:
        headers["X-API-Key"] = api_key
        headers["Authorization"] = f"Bearer {api_key}"

    return headers


def execute_scenario(
    session: requests.Session,
    base_url: str,
    endpoint_path: str,
    base_payload: dict[str, Any],
    scenario: dict[str, Any],
    timeout_seconds: int,
    api_key: str | None,
    run_class: str,
    run_source: str,
    batch_id: str,
    log_path: Path,
) -> bool:
    """Execute and log one synthetic request."""
    run_id = str(uuid.uuid4())

    request_url = urljoin(
        f"{base_url}/",
        endpoint_path.lstrip("/"),
    )

    payload = apply_scenario(
        copy.deepcopy(base_payload),
        scenario,
    )

    headers = build_headers(
        api_key=api_key,
        run_class=run_class,
        run_source=run_source,
        scenario=scenario,
        run_id=run_id,
    )

    started_at = utc_now()
    monotonic_start = time.monotonic()

    try:
        response = session.post(
            request_url,
            json=payload,
            headers=headers,
            timeout=timeout_seconds,
        )

        elapsed_ms = round(
            (time.monotonic() - monotonic_start) * 1000,
            2,
        )

        response_body = create_response_preview(response)
        returned_route = extract_route(response_body)

        expected_route = (
            str(scenario.get("expected_route", ""))
            .strip()
            .upper()
            or None
        )

        append_log(
            log_path,
            {
                "timestamp": started_at,
                "batch_id": batch_id,
                "run_id": run_id,
                "run_class": run_class,
                "run_source": run_source,
                "synthetic": True,
                "scenario_id": scenario["scenario_id"],
                "scenario_name": scenario["name"],
                "industry": scenario.get("industry"),
                "consequence_level": scenario.get(
                    "consequence_level"
                ),
                "endpoint": endpoint_path,
                "http_status": response.status_code,
                "elapsed_ms": elapsed_ms,
                "request_accepted": response.ok,
                "expected_route": expected_route,
                "returned_route": returned_route,
                "route_matches_expected": (
                    returned_route == expected_route
                    if returned_route and expected_route
                    else None
                ),
                "response": response_body,
            },
        )

        status_text = (
            "ACCEPTED" if response.ok else "REJECTED"
        )

        print(
            f"[{status_text}] "
            f"{scenario['scenario_id']} "
            f"HTTP {response.status_code} "
            f"route={returned_route or 'UNKNOWN'} "
            f"elapsed={elapsed_ms}ms"
        )

        if not response.ok:
            print(
                "Response preview: "
                f"{json.dumps(response_body, ensure_ascii=False)[:1200]}"
            )

        return response.ok

    except requests.RequestException as exc:
        elapsed_ms = round(
            (time.monotonic() - monotonic_start) * 1000,
            2,
        )

        append_log(
            log_path,
            {
                "timestamp": started_at,
                "batch_id": batch_id,
                "run_id": run_id,
                "run_class": run_class,
                "run_source": run_source,
                "synthetic": True,
                "scenario_id": scenario["scenario_id"],
                "scenario_name": scenario["name"],
                "endpoint": endpoint_path,
                "elapsed_ms": elapsed_ms,
                "request_accepted": False,
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )

        print(
            f"[ERROR] {scenario['scenario_id']} "
            f"{type(exc).__name__}: {exc}"
        )

        return False


def main() -> int:
    """Run one controlled batch."""
    try:
        base_url = normalize_base_url(
            os.getenv(
                "TA14_SANDBOX_BASE_URL",
                DEFAULT_BASE_URL,
            )
        )

        run_count = read_integer_environment(
            "TA14_SYNTHETIC_RUN_COUNT",
            DEFAULT_RUN_COUNT,
        )

        timeout_seconds = read_integer_environment(
            "TA14_HTTP_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECONDS,
        )

        delay_min_seconds = read_integer_environment(
            "TA14_REQUEST_DELAY_MIN_SECONDS",
            DEFAULT_DELAY_MIN_SECONDS,
        )

        delay_max_seconds = read_integer_environment(
            "TA14_REQUEST_DELAY_MAX_SECONDS",
            DEFAULT_DELAY_MAX_SECONDS,
        )

        if not 1 <= run_count <= MAX_BATCH_SIZE:
            raise RunnerConfigurationError(
                "TA14_SYNTHETIC_RUN_COUNT must be between "
                f"1 and {MAX_BATCH_SIZE}."
            )

        if not 5 <= timeout_seconds <= 180:
            raise RunnerConfigurationError(
                "TA14_HTTP_TIMEOUT_SECONDS must be between "
                "5 and 180."
            )

        if (
            delay_min_seconds < 0
            or delay_max_seconds < delay_min_seconds
        ):
            raise RunnerConfigurationError(
                "Synthetic request delay values are invalid."
            )

        scenarios = load_scenarios()

    except RunnerConfigurationError as exc:
        print(
            f"Configuration error: {exc}",
            file=sys.stderr,
        )
        return 2

    session = requests.Session()

    try:
        openapi_document = fetch_openapi(
            session=session,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
        )

        endpoint_path, operation = discover_endpoint(
            openapi_document
        )

        repository_example, example_source = (
            load_repository_example()
        )

        if repository_example is not None:
            base_payload = repository_example
        else:
            generated_example = request_example_from_operation(
                operation,
                openapi_document,
            )

            if generated_example is None:
                raise RunnerConfigurationError(
                    "No valid repository request example was found, "
                    "and a JSON request body could not be generated "
                    "from the OpenAPI operation."
                )

            base_payload = generated_example
            example_source = "generated from OpenAPI"

    except RunnerConfigurationError as exc:
        print(
            f"Configuration error: {exc}",
            file=sys.stderr,
        )
        return 2

    batch_id = (
        "SYN-BATCH-"
        f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-"
        f"{uuid.uuid4().hex[:8].upper()}"
    )

    log_path = LOG_DIR / f"{batch_id}.jsonl"

    run_class = (
        os.getenv(
            "TA14_RUN_CLASS",
            "synthetic_demo",
        ).strip()
        or "synthetic_demo"
    )

    run_source = (
        os.getenv(
            "TA14_RUN_SOURCE",
            "github_actions_scheduled_runner",
        ).strip()
        or "github_actions_scheduled_runner"
    )

    api_key = os.getenv("TA14_SYNTHETIC_API_KEY")

    if api_key:
        api_key = api_key.strip() or None

    selected_scenarios = random.sample(
        scenarios,
        k=min(run_count, len(scenarios)),
    )

    print("TA-14 controlled synthetic sandbox activity")
    print(f"Batch ID: {batch_id}")
    print(f"Run class: {run_class}")
    print(f"Run source: {run_source}")
    print(f"Base URL: {base_url}")
    print(f"Endpoint: {endpoint_path}")
    print(f"Request contract source: {example_source}")
    print(f"Scenario count: {len(selected_scenarios)}")
    print(
        "Classification: synthetic demonstration activity; "
        "not customer, adoption, or production activity."
    )

    accepted_count = 0

    for index, scenario in enumerate(
        selected_scenarios,
        start=1,
    ):
        print()
        print(
            f"Run {index}/{len(selected_scenarios)}: "
            f"{scenario['scenario_id']} - "
            f"{scenario['name']}"
        )

        accepted = execute_scenario(
            session=session,
            base_url=base_url,
            endpoint_path=endpoint_path,
            base_payload=base_payload,
            scenario=scenario,
            timeout_seconds=timeout_seconds,
            api_key=api_key,
            run_class=run_class,
            run_source=run_source,
            batch_id=batch_id,
            log_path=log_path,
        )

        if accepted:
            accepted_count += 1

        if index < len(selected_scenarios):
            delay_seconds = random.randint(
                delay_min_seconds,
                delay_max_seconds,
            )

            print(
                f"Waiting {delay_seconds} seconds "
                "before the next synthetic request."
            )

            time.sleep(delay_seconds)

    append_log(
        log_path,
        {
            "timestamp": utc_now(),
            "record_type": "batch_summary",
            "batch_id": batch_id,
            "run_class": run_class,
            "run_source": run_source,
            "synthetic": True,
            "requested_runs": len(selected_scenarios),
            "accepted_requests": accepted_count,
            "rejected_or_failed_requests": (
                len(selected_scenarios) - accepted_count
            ),
            "endpoint": endpoint_path,
            "request_contract_source": example_source,
        },
    )

    print()
    print("Batch complete.")
    print(
        f"Accepted requests: "
        f"{accepted_count}/{len(selected_scenarios)}"
    )
    print(
        "All requests were labeled synthetic demonstration activity."
    )

    # A rejected scenario remains a useful recorded sandbox result.
    # The workflow fails only for runner configuration failures.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
