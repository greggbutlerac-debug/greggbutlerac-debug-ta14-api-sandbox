from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["meta"]["api_version"] == "0.3.0"


def test_chain_spec():
    response = client.get("/v1/chain-spec")
    assert response.status_code == 200
    body = response.json()
    assert "reality" in body["chain"]
    assert "ALLOW" in body["decisions"]


def test_decision_matrix():
    response = client.get("/v1/decision-matrix")
    assert response.status_code == 200
    body = response.json()
    assert "ALLOW" in body["matrix"]
    assert "HOLD" in body["matrix"]
    assert "DENY" in body["matrix"]
    assert "ESCALATE" in body["matrix"]


def test_public_boundary():
    response = client.get("/v1/public-boundary")
    assert response.status_code == 200
    body = response.json()
    assert "public API sandbox" in body["public_claim"]
    assert len(body["non_claims"]) >= 4


def test_evaluate_execution_holds_on_continuity_gap():
    payload = {
        "route_name": "AI procurement agent vendor approval route",
        "proposed_action": "Approve a vendor for pilot deployment",
        "risk_class": "high",
        "reality_valid": True,
        "record_preserved": True,
        "continuity_intact": False,
        "evidence_sufficient": True,
        "reliance_justified": False,
        "authority_source": "Department manager approval policy",
        "authority_in_scope": True,
        "legitimacy_clear": True,
        "consequence_defined": "The vendor may enter an enterprise pilot.",
        "binding_clear": True,
        "commit_point_known": True,
        "execution_reversible": False,
        "outcome_reviewable": True,
        "human_review_available": True,
        "metadata": {"test": True},
    }

    response = client.post("/v1/evaluate-execution", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] in ["HOLD", "ESCALATE"]
    assert "continuity" in body["failed_links"]


def test_evaluate_execution_allows_complete_low_risk_route():
    payload = {
        "route_name": "Low risk notification route",
        "proposed_action": "Send an internal non-binding notification",
        "risk_class": "low",
        "reality_valid": True,
        "record_preserved": True,
        "continuity_intact": True,
        "evidence_sufficient": True,
        "reliance_justified": True,
        "authority_source": "Internal notification policy",
        "authority_in_scope": True,
        "legitimacy_clear": True,
        "consequence_defined": "The notification informs a team without binding action.",
        "binding_clear": True,
        "commit_point_known": True,
        "execution_reversible": True,
        "outcome_reviewable": True,
        "human_review_available": True,
        "metadata": {"test": True},
    }

    response = client.post("/v1/evaluate-execution", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ALLOW"


def test_evaluate_evidence_holds_on_continuity_gap():
    payload = {
        "evidence_name": "Vendor model audit packet",
        "evidence_claim": "The vendor claims the route is fully auditable.",
        "source_known": True,
        "record_preserved": True,
        "continuity_intact": False,
        "tamper_resistant": True,
        "independently_reviewable": False,
        "linked_to_consequence": True,
        "metadata": {"test": True},
    }

    response = client.post("/v1/evaluate-evidence", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "HOLD"
    assert "continuity_intact" in body["failed_links"]


def test_unknown_fields_are_rejected():
    payload = {
        "route_name": "Bad request route",
        "proposed_action": "Do something",
        "unknown_field": "should fail",
    }

    response = client.post("/v1/evaluate-execution", json=payload)
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "Validation failed."


def test_api_key_protection_when_enabled(monkeypatch):
    import app.main as main_module

    monkeypatch.setattr(main_module, "API_KEY", "secret-test-key")

    payload = {
        "route_name": "Low risk notification route",
        "proposed_action": "Send an internal non-binding notification",
        "risk_class": "low",
        "reality_valid": True,
        "record_preserved": True,
        "continuity_intact": True,
        "evidence_sufficient": True,
        "reliance_justified": True,
        "authority_source": "Internal notification policy",
        "authority_in_scope": True,
        "legitimacy_clear": True,
        "consequence_defined": "The notification informs a team without binding action.",
        "binding_clear": True,
        "commit_point_known": True,
        "execution_reversible": True,
        "outcome_reviewable": True,
        "human_review_available": True,
        "metadata": {"test": True},
    }

    response = client.post("/v1/evaluate-execution", json=payload)
    assert response.status_code == 401

    response = client.post(
        "/v1/evaluate-execution",
        json=payload,
        headers={"X-API-Key": "secret-test-key"},
    )
    assert response.status_code == 200

    monkeypatch.setattr(main_module, "API_KEY", None)
