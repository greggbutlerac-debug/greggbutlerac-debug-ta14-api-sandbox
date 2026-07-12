#!/usr/bin/env python3
"""
TA-14 synthetic sandbox activity runner.

This runner:
- selects varied synthetic demonstration scenarios;
- sends them to the TA-14 sandbox API;
- labels every request as synthetic demonstration activity;
- records results in automation/logs/;
- does not represent synthetic runs as customers, production, or adoption.
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
DEFAULT_TIMEOUT_SECONDS = 45
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
)

FINAL_ROUTES = (
    "ALLOW",
    "HOLD",
    "DENY",
    "ESCALATE",
)

TRUE_VALUES = {
    "verified",
    "complete",
    "current",
    "valid",
    "present",
    "approved",
    "authorized",
}

FALSE_VALUES = {
    "absent",
    "missing",
    "incomplete",
    "stale",
    "invalid",
    "unverified",
    "unknown",
}


class RunnerConfigurationError(RuntimeError):
    """Raised when the runner configuration is incomplete or invalid."""


def utc_now() -> str:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def read_integer_environment(name: str, default: int) -> int:
    """Read an integer environment variable safely."""
    raw_value = os.getenv(name)

    if raw_value is None or not raw_value.strip():
        return default

    try:
        return int(raw_value)
    except ValueError as exc:
        raise RunnerConfigurationError(
            f"{name} must be an integer. Received: {raw_value!r}"
        ) from exc


def normalize_base_url(value: str) -> str:
    """Validate and normalize the sandbox base URL."""
    cleaned = value.strip()

    if not cleaned:
        raise RunnerConfigurationError(
            "TA14_SANDBOX_BASE_URL cannot be empty."
        )

    if not cleaned.startswith(("https://", "http://")):
        raise RunnerConfigurationError(
            "TA14_SANDBOX_BASE_URL must start with "
            "https:// or http://."
        )

    return cleaned.rstrip("/")


def load_json_file(path: Path) -> Any:
    """Load JSON and provide useful errors."""
    try:
        with path.open("r", encoding="utf-8") as file_handle:
            return json.load(file_handle)
    except FileNotFoundError as exc:
        raise RunnerConfigurationError(
            f"Required file was not found: {path}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise RunnerConfigurationError(
            f"Invalid JSON in {path}. "
            f"Line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc


def load_scenarios() -> list[dict[str, Any]]:
    """Load and validate scenarios.json."""
    document = load_json_file(SCENARIO_FILE)

    if not isinstance(document, dict):
        raise RunnerConfigurationError(
            "scenarios.json must contain a JSON object."
        )

    scenarios = document.get("scenarios")

    if not isinstance(scenarios, list) or not scenarios:
        raise RunnerConfigurationError(
            "scenarios.json must contain a non-empty "
            "'scenarios' array."
        )

    validated_scenarios: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for index, scenario in enumerate(scenarios, start=1):
        if not isinstance(scenario, dict):
            raise RunnerConfigurationError(
                f"Scenario {index} must be a JSON object."
            )

        scenario_id = str(
            scenario.get("scenario_id", "")
        ).strip()

        scenario_name = str(
            scenario.get("name", "")
        ).strip()

        if not scenario_id or not scenario_name:
            raise RunnerConfigurationError(
                f"Scenario {index} must contain "
                "scenario_id and name."
            )

        if scenario_id in seen_ids:
            raise RunnerConfigurationError(
                f"Duplicate scenario_id: {scenario_id}"
            )

        seen_ids.add(scenario_id)
        validated_scenarios.append(scenario)

    return validated_scenarios


def load_example_payload() -> tuple[dict[str, Any], Path]:
    """
    Load an existing repository example request.

    This avoids inventing a request schema that may not match
    the current FastAPI application.
    """
    for path in EXAMPLE_FILES:
        if not path.exists():
            continue

        payload = load_json_file(path)

        if isinstance(payload, dict):
            return payload, path

    checked_paths = "\n".join(
        f"  - {path}" for path in EXAMPLE_FILES
    )

    raise RunnerConfigurationError(
        "No usable API example request was found.\n"
        f"Checked:\n{checked_paths}"
    )


def fetch_openapi(
    session: requests.Session,
    base_url: str,
    timeout_seconds: int,
) -> dict[str, Any] | None:
    """Fetch OpenAPI if the deployed application exposes it."""
    openapi_url = f"{base_url}/openapi.json"

    try:
        response = session.get(
            openapi_url,
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        document = response.json()
    except (requests.RequestException, ValueError):
        return None

    if isinstance(document, dict):
        return document

    return None


def looks_like_evaluation_operation(
    path: str,
    operation: dict[str, Any],
) -> bool:
    """Identify likely evaluation routes from OpenAPI metadata."""
    combined_text = " ".join(
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
    )

    return any(term in combined_text for term in terms)


def discover_endpoint(
    openapi_document: dict[str, Any] | None,
) -> str:
    """Select the most likely POST evaluation endpoint."""
    discovered_post_paths: list[str] = []

    if openapi_document:
        paths = openapi_document.get("paths", {})

        if isinstance(paths, dict):
            for path, methods in paths.items():
                if not isinstance(path, str):
                    continue

                if not isinstance(methods, dict):
                    continue

                post_operation = methods.get("post")

                if not isinstance(post_operation, dict):
                    continue

                if looks_like_evaluation_operation(
                    path,
                    post_operation,
                ):
                    discovered_post_paths.append(path)

    for preferred_path in PREFERRED_ENDPOINTS:
        if preferred_path in discovered_post_paths:
            return preferred_path

    if discovered_post_paths:
        discovered_post_paths.sort(
            key=lambda item: (
                0 if "evaluate" in item.lower() else 1,
                len(item),
                item,
            )
        )
        return discovered_post_paths[0]

    return "/evaluate"


def map_scenario_status(
    field_name: str,
    scenario: dict[str, Any],
) -> Any:
    """Map an API field name to the nearest scenario field."""
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

    for field_token, scenario_key in mappings:
        if field_token in normalized:
            return scenario.get(scenario_key)

    return None


def convert_status_to_boolean(
    value: Any,
    fallback: bool,
) -> bool:
    """Convert scenario status text to a boolean."""
    if isinstance(value, bool):
        return value

    normalized = str(value).strip().lower()

    if normalized in TRUE_VALUES:
        return True

    if normalized in FALSE_VALUES:
        return False

    return fallback


def mutate_scalar_value(
    key: str,
    current_value: Any,
    scenario: dict[str, Any],
) -> Any:
    """
    Replace recognized example fields with scenario values.

    Unrecognized fields retain the original example value.
    """
    normalized = key.lower().replace("-", "_")
    mapped_status = map_scenario_status(normalized, scenario)

    if normalized in {
        "scenario_id",
        "case_id",
        "request_id",
        "evaluation_id",
        "route_id",
    }:
        scenario_id = str(
            scenario.get("scenario_id", "SYN")
        )
        return (
            f"{scenario_id}-"
            f"{uuid.uuid4().hex[:8].upper()}"
        )

    if normalized in {
        "name",
        "title",
        "scenario_name",
        "case_name",
    }:
        return str(
            scenario.get("name", current_value)
        )

    if normalized in {
        "industry",
        "sector",
        "domain",
    }:
        return str(
            scenario.get("industry", current_value)
        )

    if normalized in {
        "consequence_level",
        "risk_level",
        "impact_level",
        "severity",
    }:
        return str(
            scenario.get(
                "consequence_level",
                current_value,
            )
        )

    if normalized in {
        "system_identity",
        "system_name",
        "subject",
        "system",
    } and isinstance(current_value, str):
        return str(
            scenario.get(
                "system_identity",
                current_value,
            )
        )

    if normalized in {
        "description",
        "summary",
        "context",
        "request_description",
    } and isinstance(current_value, str):
        facts = scenario.get("facts", [])

        fact_text = " ".join(
            str(item) for item in facts
        )

        return (
            f"Synthetic demonstration scenario "
            f"{scenario.get('scenario_id')}: "
            f"{scenario.get('name')}. "
            f"{fact_text}"
        ).strip()

    if mapped_status is not None:
        if isinstance(current_value, bool):
            return convert_status_to_boolean(
                mapped_status,
                current_value,
            )

        if isinstance(current_value, str):
            return str(mapped_status)

    return current_value


def apply_scenario_to_payload(
    value: Any,
    scenario: dict[str, Any],
    parent_key: str = "",
) -> Any:
    """Recursively apply a scenario to the example payload."""
    if isinstance(value, dict):
        updated: dict[str, Any] = {}

        for key, child_value in value.items():
            if isinstance(child_value, (dict, list)):
                updated[key] = apply_scenario_to_payload(
                    child_value,
                    scenario,
                    key,
                )
            else:
                updated[key] = mutate_scalar_value(
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
        }:
            return copy.deepcopy(
                scenario.get("facts", value)
            )

        return [
            apply_scenario_to_payload(
                item,
                scenario,
                parent_key,
            )
            for item in value
        ]

    return value


def extract_route(response_body: Any) -> str | None:
    """Find ALLOW, HOLD, DENY, or ESCALATE in a response."""
    possible_keys = {
        "route",
        "decision",
        "classification",
        "outcome",
        "result",
        "route_outcome",
        "final_route",
    }

    if isinstance(response_body, dict):
        for key, value in response_body.items():
            normalized_key = (
                key.lower().replace("-", "_")
            )

            if (
                normalized_key in possible_keys
                and isinstance(value, str)
            ):
                candidate = value.strip().upper()

                for route in FINAL_ROUTES:
                    if route in candidate:
                        return route

        for nested_value in response_body.values():
            found_route = extract_route(nested_value)

            if found_route:
                return found_route

    if isinstance(response_body, list):
        for item in response_body:
            found_route = extract_route(item)

            if found_route:
                return found_route

    return None


def create_response_preview(
    response: requests.Response,
) -> Any:
    """Create a bounded response preview for the log."""
    try:
        response_body = response.json()
    except ValueError:
        return response.text[:2000]

    serialized = json.dumps(
        response_body,
        ensure_ascii=False,
    )

    if len(serialized) <= 5000:
        return response_body

    return {
        "truncated": True,
        "preview": serialized[:5000],
    }


def append_log(
    log_path: Path,
    record: dict[str, Any],
) -> None:
    """Append one JSON Lines record."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    with log_path.open(
        "a",
        encoding="utf-8",
    ) as log_file:
        log_file.write(
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
    """Create request headers with explicit synthetic labels."""
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": (
            "TA14-Synthetic-Demo-Runner/1.0"
        ),
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
        headers["Authorization"] = (
            f"Bearer {api_key}"
        )

    return headers


def execute_scenario(
    session: requests.Session,
    base_url: str,
    endpoint_path: str,
    example_payload: dict[str, Any],
    scenario: dict[str, Any],
    timeout_seconds: int,
    api_key: str | None,
    run_class: str,
    run_source: str,
    batch_id: str,
    log_path: Path,
) -> bool:
    """Execute one synthetic scenario."""
    run_id = str(uuid.uuid4())

    request_url = urljoin(
        f"{base_url}/",
        endpoint_path.lstrip("/"),
    )

    payload = apply_scenario_to_payload(
        copy.deepcopy(example_payload),
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
    start_time = time.monotonic()

    try:
        response = session.post(
            request_url,
            json=payload,
            headers=headers,
            timeout=timeout_seconds,
        )

        elapsed_ms = round(
            (time.monotonic() - start_time) * 1000,
            2,
        )

        response_body = create_response_preview(
            response
        )

        returned_route = extract_route(
            response_body
        )

        expected_route = str(
            scenario.get("expected_route", "")
        ).strip().upper() or None

        log_record = {
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
        }

        append_log(
            log_path,
            log_record,
        )

        status_text = (
            "ACCEPTED"
            if response.ok
            else "REJECTED"
        )

        print(
            f"[{status_text}] "
            f"{scenario['scenario_id']} "
            f"HTTP {response.status_code} "
            f"route={returned_route or 'UNKNOWN'} "
            f"elapsed={elapsed_ms}ms"
        )

        return response.ok

    except requests.RequestException as exc:
        elapsed_ms = round(
            (time.monotonic() - start_time) * 1000,
            2,
        )

        error_record = {
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
            "elapsed_ms": elapsed_ms,
            "request_accepted": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }

        append_log(
            log_path,
            error_record,
        )

        print(
            f"[ERROR] "
            f"{scenario['scenario_id']} "
            f"{type(exc).__name__}: {exc}"
        )

        return False


def main() -> int:
    """Run one controlled synthetic batch."""
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
                "TA14_SYNTHETIC_RUN_COUNT must be "
                f"between 1 and {MAX_BATCH_SIZE}."
            )

        if not 5 <= timeout_seconds <= 180:
            raise RunnerConfigurationError(
                "TA14_HTTP_TIMEOUT_SECONDS must be "
                "between 5 and 180."
            )

        if (
            delay_min_seconds < 0
            or delay_max_seconds < delay_min_seconds
        ):
            raise RunnerConfigurationError(
                "Synthetic request delay values are invalid."
            )

        scenarios = load_scenarios()

        (
            example_payload,
            example_path,
        ) = load_example_payload()

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

    api_key = os.getenv(
        "TA14_SYNTHETIC_API_KEY"
    )

    if api_key:
        api_key = api_key.strip() or None

    session = requests.Session()

    openapi_document = fetch_openapi(
        session=session,
        base_url=base_url,
        timeout_seconds=timeout_seconds,
    )

    endpoint_path = discover_endpoint(
        openapi_document
    )

    selected_scenarios = random.sample(
        scenarios,
        k=min(
            run_count,
            len(scenarios),
        ),
    )

    print("TA-14 synthetic sandbox activity runner")
    print(f"Batch ID: {batch_id}")
    print(f"Run class: {run_class}")
    print(f"Run source: {run_source}")
    print(f"Base URL: {base_url}")
    print(f"Endpoint: {endpoint_path}")
    print(
        "Example request: "
        f"{example_path.relative_to(ROOT_DIR)}"
    )
    print(
        f"Scenario count: {len(selected_scenarios)}"
    )
    print(
        "Classification: synthetic demonstration activity; "
        "not customer or production activity."
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
            example_payload=example_payload,
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
                "before the next run."
            )

            time.sleep(delay_seconds)

    summary_record = {
        "timestamp": utc_now(),
        "record_type": "batch_summary",
        "batch_id": batch_id,
        "run_class": run_class,
        "run_source": run_source,
        "synthetic": True,
        "requested_runs": len(
            selected_scenarios
        ),
        "accepted_requests": accepted_count,
        "rejected_or_failed_requests": (
            len(selected_scenarios)
            - accepted_count
        ),
        "endpoint": endpoint_path,
        "example_request": str(
            example_path.relative_to(ROOT_DIR)
        ),
    }

    append_log(
        log_path,
        summary_record,
    )

    print()
    print("Batch complete.")
    print(
        f"Accepted requests: "
        f"{accepted_count}/"
        f"{len(selected_scenarios)}"
    )
    print(
        "These counts are labeled synthetic "
        "demonstration activity only."
    )

    # The workflow completes even when an individual request is
    # rejected, because rejection details are preserved in the log.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
