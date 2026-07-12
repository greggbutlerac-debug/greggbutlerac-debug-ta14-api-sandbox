#!/usr/bin/env python3
"""
TA-14 controlled synthetic sandbox activity runner.

Capabilities:
- Runs random scenarios from automation/scenarios.json.
- Accepts an exact scenario through TA14_SYNTHETIC_SCENARIO_ID.
- Includes a deterministic fully supported route named SYN-ALLOW-001.
- Discovers the live request schema from OpenAPI.
- Labels all activity as synthetic demonstration traffic.
- Writes JSONL execution logs to automation/logs/.
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

import requests


ROOT_DIR = Path(__file__).resolve().parents[1]
AUTOMATION_DIR = ROOT_DIR / "automation"
SCENARIO_FILE = AUTOMATION_DIR / "scenarios.json"
LOG_DIR = AUTOMATION_DIR / "logs"

DEFAULT_BASE_URL = (
    "https://greggbutlerac-debug-ta14-api-sandbox.onrender.com"
)
DEFAULT_ENDPOINT = "/v1/evaluate-execution"

DEFAULT_RUN_COUNT = 1
MAX_BATCH_SIZE = 10
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_DELAY_MIN_SECONDS = 7
DEFAULT_DELAY_MAX_SECONDS = 16

FINAL_ROUTES = ("ALLOW", "HOLD", "DENY", "ESCALATE")


BUILT_IN_ALLOW_SCENARIO: dict[str, Any] = {
    "scenario_id": "SYN-ALLOW-001",
    "name": "Fully supported bounded execution route",
    "industry": "governed_operations",
    "consequence_level": "low",
    "expected_route": "ALLOW",
    "force_profile": "allow",
    "system_identity": "Bounded synthetic execution assistant",
    "authority_status": "verified",
    "evidence_status": "complete",
    "continuity_status": "current",
    "human_approval": True,
    "security_status": "verified",
    "facts": [
        "The system identity is established.",
        "The proposed action is narrowly bounded.",
        "The evidence record is complete and current.",
        "Record continuity and chain of custody are preserved.",
        "The actor has verified authority for the declared scope.",
        "Legitimacy is clear.",
        "Human approval is present.",
        "No unresolved safety condition exists.",
        "The execution can be stopped before consequence.",
        "Outcome recording and review are available."
    ],
}


class RunnerConfigurationError(RuntimeError):
    """Raised when the synthetic runner cannot be configured safely."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_integer_environment(name: str, default: int) -> int:
    raw_value = os.getenv(name)

    if raw_value is None or not raw_value.strip():
        return default

    try:
        return int(raw_value)
    except ValueError as exc:
        raise RunnerConfigurationError(
            f"{name} must contain a whole number."
        ) from exc


def normalize_base_url(value: str) -> str:
    cleaned = value.strip()

    if not cleaned.startswith(("https://", "http://")):
        raise RunnerConfigurationError(
            "TA14_SANDBOX_BASE_URL must begin with https:// or http://."
        )

    return cleaned.rstrip("/")


def load_json_file(path: Path) -> Any:
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
            f"Invalid JSON in {path}: "
            f"line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc


def load_scenarios() -> list[dict[str, Any]]:
    document = load_json_file(SCENARIO_FILE)

    if not isinstance(document, dict):
        raise RunnerConfigurationError(
            "scenarios.json must contain a JSON object."
        )

    raw_scenarios = document.get("scenarios")

    if not isinstance(raw_scenarios, list):
        raise RunnerConfigurationError(
            "scenarios.json must contain a scenarios array."
        )

    scenarios: list[dict[str, Any]] = [
        copy.deepcopy(BUILT_IN_ALLOW_SCENARIO)
    ]

    seen_ids = {BUILT_IN_ALLOW_SCENARIO["scenario_id"]}

    for index, scenario in enumerate(raw_scenarios, start=1):
        if not isinstance(scenario, dict):
            raise RunnerConfigurationError(
                f"Scenario {index} is not a JSON object."
            )

        scenario_id = str(
            scenario.get("scenario_id", "")
        ).strip()

        scenario_name = str(
            scenario.get("name", "")
        ).strip()

        if not scenario_id or not scenario_name:
            raise RunnerConfigurationError(
                f"Scenario {index} requires scenario_id and name."
            )

        if scenario_id in seen_ids:
            continue

        seen_ids.add(scenario_id)
        scenarios.append(scenario)

    return scenarios


def resolve_reference(
    openapi_document: dict[str, Any],
    reference: str,
) -> dict[str, Any]:
    if not reference.startswith("#/"):
        return {}

    current: Any = openapi_document

    for part in reference[2:].split("/"):
        decoded = part.replace("~1", "/").replace("~0", "~")

        if not isinstance(current, dict):
            return {}

        if decoded not in current:
            return {}

        current = current[decoded]

    return current if isinstance(current, dict) else {}


def fetch_openapi(
    session: requests.Session,
    base_url: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    url = f"{base_url}/openapi.json"

    try:
        response = session.get(url, timeout=timeout_seconds)
        response.raise_for_status()
        document = response.json()
    except requests.RequestException as exc:
        raise RunnerConfigurationError(
            f"Unable to retrieve OpenAPI from {url}: {exc}"
        ) from exc
    except ValueError as exc:
        raise RunnerConfigurationError(
            "The OpenAPI response was not valid JSON."
        ) from exc

    if not isinstance(document, dict):
        raise RunnerConfigurationError(
            "The OpenAPI document was not a JSON object."
        )

    return document


def find_evaluation_operation(
    openapi_document: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    paths = openapi_document.get("paths", {})

    if not isinstance(paths, dict):
        raise RunnerConfigurationError(
            "OpenAPI does not contain a paths object."
        )

    preferred_paths = (
        "/v1/evaluate-execution",
        "/v1/evaluate-evidence",
        "/v1/check-authority",
        "/v1/validate-continuity",
    )

    for path in preferred_paths:
        methods = paths.get(path)

        if not isinstance(methods, dict):
            continue

        operation = methods.get("post")

        if isinstance(operation, dict):
            return path, operation

    raise RunnerConfigurationError(
        "No supported TA-14 evaluation endpoint was found."
    )


def example_from_schema(
    schema: dict[str, Any],
    openapi_document: dict[str, Any],
    depth: int = 0,
) -> Any:
    if depth > 20:
        return None

    reference = schema.get("$ref")

    if isinstance(reference, str):
        resolved = resolve_reference(
            openapi_document,
            reference,
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

    for combination_name in ("allOf", "oneOf", "anyOf"):
        alternatives = schema.get(combination_name)

        if not isinstance(alternatives, list):
            continue

        if combination_name == "allOf":
            combined_object: dict[str, Any] = {}

            for alternative in alternatives:
                if not isinstance(alternative, dict):
                    continue

                generated = example_from_schema(
                    alternative,
                    openapi_document,
                    depth + 1,
                )

                if isinstance(generated, dict):
                    combined_object.update(generated)

            if combined_object:
                return combined_object

        for alternative in alternatives:
            if not isinstance(alternative, dict):
                continue

            generated = example_from_schema(
                alternative,
                openapi_document,
                depth + 1,
            )

            if generated is not None:
                return generated

    schema_type = schema.get("type")

    if not schema_type and "properties" in schema:
        schema_type = "object"

    if schema_type == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        if not isinstance(properties, dict):
            return {}

        result: dict[str, Any] = {}

        for property_name, property_schema in properties.items():
            if not isinstance(property_schema, dict):
                continue

            include_property = (
                property_name in required
                or "default" in property_schema
                or "example" in property_schema
            )

            if not include_property:
                continue

            generated = example_from_schema(
                property_schema,
                openapi_document,
                depth + 1,
            )

            if generated is not None:
                result[property_name] = generated

        return result

    if schema_type == "array":
        item_schema = schema.get("items", {})

        if not isinstance(item_schema, dict):
            return []

        generated_item = example_from_schema(
            item_schema,
            openapi_document,
            depth + 1,
        )

        if generated_item is None:
            return []

        return [generated_item]

    if schema_type == "boolean":
        return False

    if schema_type == "integer":
        minimum = schema.get("minimum")

        if isinstance(minimum, int):
            return minimum

        return 1

    if schema_type == "number":
        minimum = schema.get("minimum")

        if isinstance(minimum, (int, float)):
            return float(minimum)

        return 1.0

    if schema_type == "string":
        string_format = schema.get("format")

        if string_format == "uuid":
            return str(uuid.uuid4())

        if string_format == "date-time":
            return utc_now()

        if string_format == "date":
            return datetime.now(timezone.utc).date().isoformat()

        if string_format == "email":
            return "synthetic-demo@ta14.invalid"

        minimum_length = schema.get("minLength", 0)

        if isinstance(minimum_length, int) and minimum_length > 10:
            return (
                "Synthetic demonstration value supplied for "
                "controlled TA-14 evaluation."
            )

        return "synthetic_demo"

    return None


def request_body_from_operation(
    operation: dict[str, Any],
    openapi_document: dict[str, Any],
) -> dict[str, Any]:
    request_body = operation.get("requestBody")

    if not isinstance(request_body, dict):
        raise RunnerConfigurationError(
            "The evaluation endpoint has no JSON request body."
        )

    reference = request_body.get("$ref")

    if isinstance(reference, str):
        request_body = resolve_reference(
            openapi_document,
            reference,
        )

    content = request_body.get("content", {})

    if not isinstance(content, dict):
        raise RunnerConfigurationError(
            "The evaluation request body has no content definition."
        )

    media = content.get("application/json")

    if not isinstance(media, dict):
        raise RunnerConfigurationError(
            "The evaluation endpoint does not define application/json."
        )

    if isinstance(media.get("example"), dict):
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
        raise RunnerConfigurationError(
            "The evaluation endpoint has no usable JSON schema."
        )

    generated = example_from_schema(
        schema,
        openapi_document,
    )

    if not isinstance(generated, dict):
        raise RunnerConfigurationError(
            "Unable to generate an evaluation request from OpenAPI."
        )

    return generated


def is_negative_field(field_name: str) -> bool:
    normalized = field_name.lower().replace("-", "_")

    negative_terms = (
        "missing",
        "absent",
        "invalid",
        "unsafe",
        "conflict",
        "revoked",
        "expired",
        "blocked",
        "prohibited",
        "stale",
        "unresolved",
        "unauthorized",
        "gaps_identified",
        "gap_identified",
        "exception_active",
        "risk_unresolved",
        "harm_present",
    )

    return any(term in normalized for term in negative_terms)


def allowed_string_value(
    field_name: str,
    current_value: str,
    scenario: dict[str, Any],
) -> str:
    normalized = field_name.lower().replace("-", "_")

    if normalized in {
        "risk_class",
        "risk_level",
        "consequence_level",
        "impact_level",
        "severity",
    }:
        return "low"

    if "authority_source" in normalized:
        return "Verified accountable synthetic authority"

    if "authority_scope" in normalized:
        return "Bounded synthetic demonstration scope"

    if "identity" in normalized or normalized in {
        "system_name",
        "actor_name",
        "subject",
    }:
        return str(
            scenario.get(
                "system_identity",
                "Bounded synthetic execution assistant",
            )
        )

    if normalized in {
        "name",
        "title",
        "scenario_name",
        "case_name",
    }:
        return str(scenario["name"])

    if normalized in {"industry", "sector", "domain"}:
        return str(
            scenario.get(
                "industry",
                "governed_operations",
            )
        )

    if normalized in {
        "description",
        "summary",
        "context",
        "claim",
        "claim_or_function",
        "consequence_question",
        "proposed_action",
        "action",
        "purpose",
        "reason",
    }:
        facts = " ".join(
            str(item)
            for item in scenario.get("facts", [])
        )

        return (
            f"Synthetic demonstration scenario "
            f"{scenario['scenario_id']}: "
            f"{scenario['name']}. {facts}"
        )

    positive_status_terms = (
        "status",
        "continuity",
        "evidence",
        "record",
        "security",
        "governance",
        "legitimacy",
        "binding",
        "approval",
        "verification",
        "validation",
        "custody",
        "preservation",
        "current",
    )

    if any(term in normalized for term in positive_status_terms):
        return "verified"

    if current_value in {
        "",
        "synthetic_demo",
    }:
        return "Verified synthetic demonstration value"

    return current_value


def apply_allow_profile(
    value: Any,
    scenario: dict[str, Any],
    parent_key: str = "",
) -> Any:
    """
    Convert the generated request into a fully supported bounded route.

    Positive prerequisites are set true. Negative or failure-state flags
    are set false. Text fields receive verified, current, and bounded values.
    """
    if isinstance(value, dict):
        result: dict[str, Any] = {}

        for key, child_value in value.items():
            normalized_key = key.lower().replace("-", "_")

            if isinstance(child_value, (dict, list)):
                result[key] = apply_allow_profile(
                    child_value,
                    scenario,
                    key,
                )
                continue

            if isinstance(child_value, bool):
                result[key] = not is_negative_field(
                    normalized_key
                )
                continue

            if isinstance(child_value, str):
                result[key] = allowed_string_value(
                    normalized_key,
                    child_value,
                    scenario,
                )
                continue

            if isinstance(child_value, int):
                result[key] = max(child_value, 1)
                continue

            if isinstance(child_value, float):
                result[key] = max(child_value, 1.0)
                continue

            result[key] = child_value

        return result

    if isinstance(value, list):
        normalized_parent = (
            parent_key.lower().replace("-", "_")
        )

        if normalized_parent in {
            "facts",
            "observations",
            "materials_available",
            "evidence_items",
        }:
            return copy.deepcopy(
                scenario.get("facts", value)
            )

        return [
            apply_allow_profile(
                item,
                scenario,
                parent_key,
            )
            for item in value
        ]

    return value


def apply_general_scenario(
    value: Any,
    scenario: dict[str, Any],
    parent_key: str = "",
) -> Any:
    if scenario.get("force_profile") == "allow":
        return apply_allow_profile(
            value,
            scenario,
            parent_key,
        )

    if isinstance(value, dict):
        result: dict[str, Any] = {}

        for key, child_value in value.items():
            normalized = key.lower().replace("-", "_")

            if isinstance(child_value, (dict, list)):
                result[key] = apply_general_scenario(
                    child_value,
                    scenario,
                    key,
                )
                continue

            if isinstance(child_value, bool):
                if "authority" in normalized:
                    result[key] = (
                        scenario.get("authority_status")
                        == "verified"
                    )
                elif "evidence" in normalized:
                    result[key] = (
                        scenario.get("evidence_status")
                        == "complete"
                    )
                elif "continuity" in normalized:
                    result[key] = (
                        scenario.get("continuity_status")
                        == "current"
                    )
                elif "security" in normalized:
                    result[key] = (
                        scenario.get("security_status")
                        == "verified"
                    )
                elif (
                    "approval" in normalized
                    or "human_review" in normalized
                ):
                    result[key] = bool(
                        scenario.get("human_approval")
                    )
                else:
                    result[key] = child_value

                continue

            if isinstance(child_value, str):
                if normalized in {
                    "name",
                    "title",
                    "scenario_name",
                }:
                    result[key] = str(scenario["name"])
                elif normalized in {
                    "industry",
                    "sector",
                    "domain",
                }:
                    result[key] = str(
                        scenario.get(
                            "industry",
                            child_value,
                        )
                    )
                elif normalized in {
                    "risk_class",
                    "risk_level",
                    "consequence_level",
                }:
                    result[key] = str(
                        scenario.get(
                            "consequence_level",
                            child_value,
                        )
                    )
                elif normalized in {
                    "description",
                    "summary",
                    "context",
                    "claim_or_function",
                    "consequence_question",
                    "proposed_action",
                }:
                    result[key] = (
                        f"Synthetic scenario "
                        f"{scenario['scenario_id']}: "
                        f"{scenario['name']}. "
                        + " ".join(
                            str(item)
                            for item in scenario.get(
                                "facts",
                                [],
                            )
                        )
                    )
                else:
                    result[key] = child_value

                continue

            result[key] = child_value

        return result

    if isinstance(value, list):
        normalized_parent = (
            parent_key.lower().replace("-", "_")
        )

        if normalized_parent in {
            "facts",
            "observations",
            "evidence_items",
        }:
            return copy.deepcopy(
                scenario.get("facts", value)
            )

        return [
            apply_general_scenario(
                item,
                scenario,
                parent_key,
            )
            for item in value
        ]

    return value


def extract_route(response_body: Any) -> str | None:
    possible_keys = {
        "decision",
        "route",
        "classification",
        "outcome",
        "result",
        "route_outcome",
        "final_route",
        "determination",
    }

    if isinstance(response_body, dict):
        for key, value in response_body.items():
            normalized = key.lower().replace("-", "_")

            if (
                normalized in possible_keys
                and isinstance(value, str)
            ):
                candidate = value.upper()

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


def append_log(
    log_path: Path,
    record: dict[str, Any],
) -> None:
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
    scenario: dict[str, Any],
    run_id: str,
    api_key: str | None,
    run_class: str,
    run_source: str,
) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "TA14-Synthetic-Demo-Runner/3.0",
        "X-TA14-Run-Class": run_class,
        "X-TA14-Run-Source": run_source,
        "X-TA14-Synthetic": "true",
        "X-TA14-Scenario-ID": str(
            scenario["scenario_id"]
        ),
        "X-Request-ID": run_id,
        "X-Correlation-ID": run_id,
        "Idempotency-Key": run_id,
    }

    if api_key:
        headers["X-API-Key"] = api_key

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
    run_id = str(uuid.uuid4())
    request_url = f"{base_url}{endpoint_path}"

    payload = apply_general_scenario(
        copy.deepcopy(base_payload),
        scenario,
    )

    headers = build_headers(
        scenario=scenario,
        run_id=run_id,
        api_key=api_key,
        run_class=run_class,
        run_source=run_source,
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

        try:
            response_body: Any = response.json()
        except ValueError:
            response_body = response.text[:5000]

        returned_route = extract_route(response_body)

        expected_route = (
            str(scenario.get("expected_route", ""))
            .strip()
            .upper()
            or None
        )

        record = {
            "timestamp": started_at,
            "batch_id": batch_id,
            "run_id": run_id,
            "synthetic": True,
            "run_class": run_class,
            "run_source": run_source,
            "scenario_id": scenario["scenario_id"],
            "scenario_name": scenario["name"],
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

        append_log(log_path, record)

        status_label = (
            "ACCEPTED"
            if response.ok
            else "REJECTED"
        )

        print(
            f"[{status_label}] "
            f"{scenario['scenario_id']} "
            f"HTTP {response.status_code} "
            f"decision={returned_route or 'UNKNOWN'} "
            f"elapsed={elapsed_ms}ms"
        )

        if not response.ok:
            print(
                json.dumps(
                    response_body,
                    ensure_ascii=False,
                )[:2000]
            )

        return response.ok

    except requests.RequestException as exc:
        elapsed_ms = round(
            (time.monotonic() - start_time) * 1000,
            2,
        )

        append_log(
            log_path,
            {
                "timestamp": started_at,
                "batch_id": batch_id,
                "run_id": run_id,
                "synthetic": True,
                "run_class": run_class,
                "run_source": run_source,
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


def select_scenarios(
    scenarios: list[dict[str, Any]],
    run_count: int,
    selected_scenario_id: str,
) -> list[dict[str, Any]]:
    if selected_scenario_id:
        selected = next(
            (
                scenario
                for scenario in scenarios
                if scenario["scenario_id"]
                == selected_scenario_id
            ),
            None,
        )

        if selected is None:
            available = ", ".join(
                scenario["scenario_id"]
                for scenario in scenarios
            )

            raise RunnerConfigurationError(
                f"Scenario ID {selected_scenario_id!r} "
                f"was not found. Available IDs: {available}"
            )

        return [
            copy.deepcopy(selected)
            for _ in range(run_count)
        ]

    return random.sample(
        scenarios,
        k=min(run_count, len(scenarios)),
    )


def main() -> int:
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

        selected_scenario_id = os.getenv(
            "TA14_SYNTHETIC_SCENARIO_ID",
            "",
        ).strip()

        if not 1 <= run_count <= MAX_BATCH_SIZE:
            raise RunnerConfigurationError(
                f"Run count must be between 1 and "
                f"{MAX_BATCH_SIZE}."
            )

        if delay_min_seconds < 0:
            raise RunnerConfigurationError(
                "Minimum delay cannot be negative."
            )

        if delay_max_seconds < delay_min_seconds:
            raise RunnerConfigurationError(
                "Maximum delay cannot be below minimum delay."
            )

        scenarios = load_scenarios()

        selected_scenarios = select_scenarios(
            scenarios=scenarios,
            run_count=run_count,
            selected_scenario_id=selected_scenario_id,
        )

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

        endpoint_path, operation = find_evaluation_operation(
            openapi_document
        )

        base_payload = request_body_from_operation(
            operation=operation,
            openapi_document=openapi_document,
        )

    except RunnerConfigurationError as exc:
        print(
            f"Configuration error: {exc}",
            file=sys.stderr,
        )
        return 2

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
        "TA14_SYNTHETIC_API_KEY",
        "",
    ).strip() or None

    batch_id = (
        "SYN-BATCH-"
        f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-"
        f"{uuid.uuid4().hex[:8].upper()}"
    )

    log_path = LOG_DIR / f"{batch_id}.jsonl"

    print("TA-14 controlled synthetic sandbox activity")
    print(f"Batch ID: {batch_id}")
    print(f"Base URL: {base_url}")
    print(f"Endpoint: {endpoint_path}")
    print(f"Run count: {len(selected_scenarios)}")
    print(
        "Scenario selection: "
        f"{selected_scenario_id or 'random'}"
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
            f"{scenario['scenario_id']} — "
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
                "before the next request."
            )

            time.sleep(delay_seconds)

    append_log(
        log_path,
        {
            "timestamp": utc_now(),
            "record_type": "batch_summary",
            "batch_id": batch_id,
            "synthetic": True,
            "run_class": run_class,
            "run_source": run_source,
            "selected_scenario_id": (
                selected_scenario_id or None
            ),
            "requested_runs": len(selected_scenarios),
            "accepted_requests": accepted_count,
            "rejected_or_failed_requests": (
                len(selected_scenarios)
                - accepted_count
            ),
            "endpoint": endpoint_path,
        },
    )

    print()
    print("Batch complete.")
    print(
        f"Accepted requests: "
        f"{accepted_count}/{len(selected_scenarios)}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
