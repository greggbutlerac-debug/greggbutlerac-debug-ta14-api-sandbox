#!/usr/bin/env python3
"""
TA-14 controlled synthetic sandbox activity runner.

- Runs random scenarios from automation/scenarios.json.
- Accepts an exact scenario through TA14_SYNTHETIC_SCENARIO_ID.
- Includes a deterministic SYN-ALLOW-001 route.
- Discovers the live request schema from OpenAPI.
- Labels all traffic as synthetic demonstration activity.
- Writes JSONL logs to automation/logs/.
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

DEFAULT_BASE_URL = "https://greggbutlerac-debug-ta14-api-sandbox.onrender.com"
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
        "System identity is established.",
        "The action is narrowly bounded.",
        "Evidence is complete and current.",
        "Continuity and chain of custody are preserved.",
        "Authority and legitimacy are verified.",
        "Human approval is present.",
        "No unresolved safety condition exists.",
        "Rollback and outcome recording are available."
    ],
}


class RunnerConfigurationError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RunnerConfigurationError(f"{name} must be an integer.") from exc


def normalize_base_url(value: str) -> str:
    cleaned = value.strip()
    if not cleaned.startswith(("https://", "http://")):
        raise RunnerConfigurationError(
            "TA14_SANDBOX_BASE_URL must begin with https:// or http://."
        )
    return cleaned.rstrip("/")


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise RunnerConfigurationError(f"Missing file: {path}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerConfigurationError(f"Invalid JSON file: {path}") from exc


def load_scenarios() -> list[dict[str, Any]]:
    document = load_json(SCENARIO_FILE)
    raw = document.get("scenarios") if isinstance(document, dict) else None
    if not isinstance(raw, list):
        raise RunnerConfigurationError(
            "automation/scenarios.json must contain a scenarios array."
        )

    scenarios = [copy.deepcopy(BUILT_IN_ALLOW_SCENARIO)]
    seen = {BUILT_IN_ALLOW_SCENARIO["scenario_id"]}

    for index, scenario in enumerate(raw, start=1):
        if not isinstance(scenario, dict):
            raise RunnerConfigurationError(f"Scenario {index} is not an object.")
        scenario_id = str(scenario.get("scenario_id", "")).strip()
        name = str(scenario.get("name", "")).strip()
        if not scenario_id or not name:
            raise RunnerConfigurationError(
                f"Scenario {index} requires scenario_id and name."
            )
        if scenario_id not in seen:
            seen.add(scenario_id)
            scenarios.append(scenario)

    return scenarios


def resolve_ref(document: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        return {}
    current: Any = document
    for part in reference[2:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or key not in current:
            return {}
        current = current[key]
    return current if isinstance(current, dict) else {}


def fetch_openapi(
    session: requests.Session,
    base_url: str,
    timeout: int,
) -> dict[str, Any]:
    url = f"{base_url}/openapi.json"
    try:
        response = session.get(url, timeout=timeout)
        response.raise_for_status()
        document = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise RunnerConfigurationError(
            f"Unable to read OpenAPI from {url}: {exc}"
        ) from exc

    if not isinstance(document, dict):
        raise RunnerConfigurationError("OpenAPI document is not an object.")
    return document


def find_operation(
    openapi: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    paths = openapi.get("paths", {})
    if not isinstance(paths, dict):
        raise RunnerConfigurationError("OpenAPI paths are missing.")

    for path in (
        "/v1/evaluate-execution",
        "/v1/evaluate-evidence",
        "/v1/check-authority",
        "/v1/validate-continuity",
    ):
        methods = paths.get(path)
        if isinstance(methods, dict) and isinstance(methods.get("post"), dict):
            return path, methods["post"]

    raise RunnerConfigurationError("No supported evaluation endpoint found.")


def example_from_schema(
    schema: dict[str, Any],
    openapi: dict[str, Any],
    depth: int = 0,
) -> Any:
    if depth > 20:
        return None

    reference = schema.get("$ref")
    if isinstance(reference, str):
        return example_from_schema(
            resolve_ref(openapi, reference),
            openapi,
            depth + 1,
        )

    if "example" in schema:
        return copy.deepcopy(schema["example"])
    if "default" in schema:
        return copy.deepcopy(schema["default"])

    enum_values = schema.get("enum")
    if isinstance(enum_values, list) and enum_values:
        return copy.deepcopy(enum_values[0])

    for name in ("allOf", "oneOf", "anyOf"):
        alternatives = schema.get(name)
        if not isinstance(alternatives, list):
            continue

        if name == "allOf":
            merged: dict[str, Any] = {}
            for alternative in alternatives:
                if isinstance(alternative, dict):
                    value = example_from_schema(
                        alternative,
                        openapi,
                        depth + 1,
                    )
                    if isinstance(value, dict):
                        merged.update(value)
            if merged:
                return merged

        for alternative in alternatives:
            if isinstance(alternative, dict):
                value = example_from_schema(
                    alternative,
                    openapi,
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
        result: dict[str, Any] = {}
        if not isinstance(properties, dict):
            return result

        for key, child_schema in properties.items():
            if not isinstance(child_schema, dict):
                continue
            if (
                key in required
                or "example" in child_schema
                or "default" in child_schema
            ):
                value = example_from_schema(
                    child_schema,
                    openapi,
                    depth + 1,
                )
                if value is not None:
                    result[key] = value
        return result

    if schema_type == "array":
        item_schema = schema.get("items", {})
        if not isinstance(item_schema, dict):
            return []
        item = example_from_schema(item_schema, openapi, depth + 1)
        return [] if item is None else [item]

    if schema_type == "boolean":
        return False
    if schema_type == "integer":
        return max(int(schema.get("minimum", 1)), 1)
    if schema_type == "number":
        return max(float(schema.get("minimum", 1.0)), 1.0)
    if schema_type == "string":
        fmt = schema.get("format")
        if fmt == "uuid":
            return str(uuid.uuid4())
        if fmt == "date-time":
            return utc_now()
        if fmt == "date":
            return datetime.now(timezone.utc).date().isoformat()
        if fmt == "email":
            return "synthetic-demo@ta14.invalid"
        return "synthetic_demo"

    return None


def request_body(
    operation: dict[str, Any],
    openapi: dict[str, Any],
) -> dict[str, Any]:
    body = operation.get("requestBody")
    if not isinstance(body, dict):
        raise RunnerConfigurationError("Evaluation endpoint has no request body.")

    if isinstance(body.get("$ref"), str):
        body = resolve_ref(openapi, body["$ref"])

    content = body.get("content", {})
    media = content.get("application/json") if isinstance(content, dict) else None
    if not isinstance(media, dict):
        raise RunnerConfigurationError(
            "Evaluation endpoint does not define application/json."
        )

    if isinstance(media.get("example"), dict):
        return copy.deepcopy(media["example"])

    examples = media.get("examples")
    if isinstance(examples, dict):
        for record in examples.values():
            if isinstance(record, dict) and isinstance(record.get("value"), dict):
                return copy.deepcopy(record["value"])

    schema = media.get("schema")
    if not isinstance(schema, dict):
        raise RunnerConfigurationError("No usable request schema found.")

    generated = example_from_schema(schema, openapi)
    if not isinstance(generated, dict):
        raise RunnerConfigurationError(
            "Unable to generate request body from OpenAPI."
        )
    return generated


def is_negative_field(name: str) -> bool:
    normalized = name.lower().replace("-", "_")
    terms = (
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
    return any(term in normalized for term in terms)


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
        )[:200]

    if normalized in {
        "name",
        "title",
        "scenario_name",
        "case_name",
    }:
        return str(scenario["name"])[:200]

    if normalized in {"industry", "sector", "domain"}:
        return str(
            scenario.get("industry", "governed_operations")
        )[:100]

    if normalized in {"proposed_action", "action"}:
        return (
            "Permit a bounded synthetic assistant to complete a low-risk "
            "demonstration task after identity, evidence, continuity, "
            "authority, legitimacy, human approval, rollback, and outcome "
            "recording have been verified."
        )

    if normalized in {"claim_or_function", "purpose"}:
        return (
            "Evaluate a fully documented low-risk synthetic execution route "
            "with verified authority and accountable human approval."
        )

    if normalized == "consequence_question":
        return (
            "May this bounded synthetic demonstration proceed when all "
            "required evidence, authority, continuity, and controls are present?"
        )

    if normalized in {
        "description",
        "summary",
        "context",
        "claim",
        "reason",
        "statement",
    }:
        return (
            "Controlled synthetic demonstration with verified identity, "
            "complete current evidence, preserved continuity, bounded "
            "authority, clear legitimacy, human approval, rollback readiness, "
            "and outcome recording."
        )

    if any(
        term in normalized
        for term in (
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
    ):
        return "verified"

    if current_value in {"", "synthetic_demo"}:
        return "Verified synthetic demonstration value"

    return current_value[:400]


def apply_allow_profile(
    value: Any,
    scenario: dict[str, Any],
    parent_key: str = "",
) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            if isinstance(child, (dict, list)):
                result[key] = apply_allow_profile(child, scenario, key)
            elif isinstance(child, bool):
                result[key] = not is_negative_field(normalized)
            elif isinstance(child, str):
                result[key] = allowed_string_value(normalized, child, scenario)
            elif isinstance(child, int):
                result[key] = max(child, 1)
            elif isinstance(child, float):
                result[key] = max(child, 1.0)
            else:
                result[key] = child
        return result

    if isinstance(value, list):
        normalized = parent_key.lower().replace("-", "_")
        if normalized in {
            "facts",
            "observations",
            "materials_available",
            "evidence_items",
        }:
            return copy.deepcopy(scenario.get("facts", value))
        return [
            apply_allow_profile(item, scenario, parent_key)
            for item in value
        ]

    return value


def apply_general_scenario(
    value: Any,
    scenario: dict[str, Any],
    parent_key: str = "",
) -> Any:
    if scenario.get("force_profile") == "allow":
        return apply_allow_profile(value, scenario, parent_key)

    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")

            if isinstance(child, (dict, list)):
                result[key] = apply_general_scenario(child, scenario, key)
            elif isinstance(child, bool):
                if "authority" in normalized:
                    result[key] = scenario.get("authority_status") == "verified"
                elif "evidence" in normalized:
                    result[key] = scenario.get("evidence_status") == "complete"
                elif "continuity" in normalized:
                    result[key] = scenario.get("continuity_status") == "current"
                elif "security" in normalized:
                    result[key] = scenario.get("security_status") == "verified"
                elif "approval" in normalized or "human_review" in normalized:
                    result[key] = bool(scenario.get("human_approval"))
                else:
                    result[key] = child
            elif isinstance(child, str):
                if normalized in {"name", "title", "scenario_name"}:
                    result[key] = str(scenario["name"])
                elif normalized in {"industry", "sector", "domain"}:
                    result[key] = str(scenario.get("industry", child))
                elif normalized in {
                    "risk_class",
                    "risk_level",
                    "consequence_level",
                }:
                    result[key] = str(
                        scenario.get("consequence_level", child)
                    )
                elif normalized in {
                    "description",
                    "summary",
                    "context",
                    "claim_or_function",
                    "consequence_question",
                    "proposed_action",
                }:
                    text = (
                        f"Synthetic scenario {scenario['scenario_id']}: "
                        f"{scenario['name']}. "
                        + " ".join(
                            str(item)
                            for item in scenario.get("facts", [])
                        )
                    )
                    result[key] = text[:450]
                else:
                    result[key] = child
            else:
                result[key] = child
        return result

    if isinstance(value, list):
        normalized = parent_key.lower().replace("-", "_")
        if normalized in {"facts", "observations", "evidence_items"}:
            return copy.deepcopy(scenario.get("facts", value))
        return [
            apply_general_scenario(item, scenario, parent_key)
            for item in value
        ]

    return value


def extract_route(body: Any) -> str | None:
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

    if isinstance(body, dict):
        for key, value in body.items():
            if (
                key.lower().replace("-", "_") in possible_keys
                and isinstance(value, str)
            ):
                candidate = value.upper()
                for route in FINAL_ROUTES:
                    if route in candidate:
                        return route
        for value in body.values():
            route = extract_route(value)
            if route:
                return route

    if isinstance(body, list):
        for item in body:
            route = extract_route(item)
            if route:
                return route

    return None


def append_log(path: Path, record: dict[str, Any]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
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
        "User-Agent": "TA14-Synthetic-Demo-Runner/3.1",
        "X-TA14-Run-Class": run_class,
        "X-TA14-Run-Source": run_source,
        "X-TA14-Synthetic": "true",
        "X-TA14-Scenario-ID": str(scenario["scenario_id"]),
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
    payload = apply_general_scenario(
        copy.deepcopy(base_payload),
        scenario,
    )
    headers = build_headers(
        scenario,
        run_id,
        api_key,
        run_class,
        run_source,
    )

    started_at = utc_now()
    started = time.monotonic()

    try:
        response = session.post(
            f"{base_url}{endpoint_path}",
            json=payload,
            headers=headers,
            timeout=timeout_seconds,
        )
        elapsed_ms = round((time.monotonic() - started) * 1000, 2)

        try:
            response_body: Any = response.json()
        except ValueError:
            response_body = response.text[:5000]

        returned_route = extract_route(response_body)
        expected_route = (
            str(scenario.get("expected_route", "")).strip().upper() or None
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
                "request_payload": payload,
                "response": response_body,
            },
        )

        status = "ACCEPTED" if response.ok else "REJECTED"
        print(
            f"[{status}] {scenario['scenario_id']} "
            f"HTTP {response.status_code} "
            f"decision={returned_route or 'UNKNOWN'} "
            f"elapsed={elapsed_ms}ms"
        )

        if not response.ok:
            print(json.dumps(response_body, ensure_ascii=False)[:2000])

        return response.ok

    except requests.RequestException as exc:
        elapsed_ms = round((time.monotonic() - started) * 1000, 2)
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
                if scenario["scenario_id"] == selected_scenario_id
            ),
            None,
        )
        if selected is None:
            available = ", ".join(
                scenario["scenario_id"] for scenario in scenarios
            )
            raise RunnerConfigurationError(
                f"Scenario ID {selected_scenario_id!r} was not found. "
                f"Available IDs: {available}"
            )
        return [copy.deepcopy(selected) for _ in range(run_count)]

    return random.sample(
        scenarios,
        k=min(run_count, len(scenarios)),
    )


def main() -> int:
    try:
        base_url = normalize_base_url(
            os.getenv("TA14_SANDBOX_BASE_URL", DEFAULT_BASE_URL)
        )
        run_count = read_int(
            "TA14_SYNTHETIC_RUN_COUNT",
            DEFAULT_RUN_COUNT,
        )
        timeout_seconds = read_int(
            "TA14_HTTP_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECONDS,
        )
        delay_min = read_int(
            "TA14_REQUEST_DELAY_MIN_SECONDS",
            DEFAULT_DELAY_MIN_SECONDS,
        )
        delay_max = read_int(
            "TA14_REQUEST_DELAY_MAX_SECONDS",
            DEFAULT_DELAY_MAX_SECONDS,
        )
        selected_id = os.getenv(
            "TA14_SYNTHETIC_SCENARIO_ID",
            "",
        ).strip()

        if not 1 <= run_count <= MAX_BATCH_SIZE:
            raise RunnerConfigurationError(
                f"Run count must be between 1 and {MAX_BATCH_SIZE}."
            )
        if delay_min < 0 or delay_max < delay_min:
            raise RunnerConfigurationError("Invalid request delay values.")

        scenarios = load_scenarios()
        selected = select_scenarios(
            scenarios,
            run_count,
            selected_id,
        )

    except RunnerConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    session = requests.Session()

    try:
        openapi = fetch_openapi(
            session,
            base_url,
            timeout_seconds,
        )
        endpoint_path, operation = find_operation(openapi)
        base_payload = request_body(operation, openapi)
    except RunnerConfigurationError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    run_class = (
        os.getenv("TA14_RUN_CLASS", "synthetic_demo").strip()
        or "synthetic_demo"
    )
    run_source = (
        os.getenv(
            "TA14_RUN_SOURCE",
            "github_actions_scheduled_runner",
        ).strip()
        or "github_actions_scheduled_runner"
    )
    api_key = os.getenv("TA14_SYNTHETIC_API_KEY", "").strip() or None

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
    print(f"Run count: {len(selected)}")
    print(f"Scenario selection: {selected_id or 'random'}")
    print(
        "Classification: synthetic demonstration activity; "
        "not customer or production activity."
    )

    accepted = 0

    for index, scenario in enumerate(selected, start=1):
        print()
        print(
            f"Run {index}/{len(selected)}: "
            f"{scenario['scenario_id']} — {scenario['name']}"
        )

        if execute_scenario(
            session,
            base_url,
            endpoint_path,
            base_payload,
            scenario,
            timeout_seconds,
            api_key,
            run_class,
            run_source,
            batch_id,
            log_path,
        ):
            accepted += 1

        if index < len(selected):
            delay = random.randint(delay_min, delay_max)
            print(f"Waiting {delay} seconds before the next request.")
            time.sleep(delay)

    append_log(
        log_path,
        {
            "timestamp": utc_now(),
            "record_type": "batch_summary",
            "batch_id": batch_id,
            "synthetic": True,
            "run_class": run_class,
            "run_source": run_source,
            "selected_scenario_id": selected_id or None,
            "requested_runs": len(selected),
            "accepted_requests": accepted,
            "rejected_or_failed_requests": len(selected) - accepted,
            "endpoint": endpoint_path,
        },
    )

    print()
    print("Batch complete.")
    print(f"Accepted requests: {accepted}/{len(selected)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
