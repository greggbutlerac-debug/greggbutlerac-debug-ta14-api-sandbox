# TA-14 Admissible Execution API Sandbox

<p align="center">
  <strong>Govern consequence before execution. Preserve the complete route. Verify it independently afterward.</strong>
</p>

<p align="center">
  <a href="https://ta14-architecture.netlify.app/"><strong>TA-14 Authority Portal</strong></a>
  &nbsp;•&nbsp;
  <a href="https://greggbutlerac-debug-ta14-api-sandbox.onrender.com/docs"><strong>Live API Documentation</strong></a>
  &nbsp;•&nbsp;
  <a href="https://ta14-architecture.netlify.app/replay-verification"><strong>Public Replay Verifier</strong></a>
  &nbsp;•&nbsp;
  <a href="https://doi.org/10.5281/zenodo.21365307"><strong>Zenodo Reference Release</strong></a>
</p>

---

## No Admissible Evidence. No Admissible Execution.

Most AI governance systems begin too late.

They monitor outputs, display approvals, preserve logs, and explain decisions after a system has already acted.

**TA-14 begins while consequence is still preventable.**

The **TA-14 Admissible Execution API Sandbox** is a public reference implementation for evaluating whether a consequence-bearing AI system, autonomous agent, automated workflow, digital service, or operational process should be permitted to proceed.

It does not merely ask whether a policy rule passed.

It examines whether the route remains supported by sufficient evidence, present authority, intact continuity, applicable rules, bounded scope, valid binding, controlled commitment, corresponding execution, and accountable outcome.

The sandbox returns one of four governed determinations:

| Determination | Meaning |
|---|---|
| **ALLOW** | The submitted route satisfies the sandbox requirements for the evaluated scope. |
| **HOLD** | The route cannot proceed until missing, stale, uncertain, or unresolved conditions are corrected. |
| **DENY** | The route contains a disqualifying conflict, invalid authority state, prohibited condition, or material integrity failure. |
| **ESCALATE** | The route requires review by a higher authority, specialist, external reviewer, or separately governed process. |

> **TA-14 governs before consequence and preserves proof afterward.**

---

## Live Public Surfaces

### TA-14 Authority Portal

Public architecture, services, use cases, review pathways, pricing, resources, positioning, and institutional record:

**https://ta14-architecture.netlify.app/**

### Live OpenAPI Documentation

Explore the public API endpoints, schemas, request models, response structures, and interactive test surface:

**https://greggbutlerac-debug-ta14-api-sandbox.onrender.com/docs**

### Independent Route Replay Verifier

Download a valid replay package, upload it into the public verifier, and compare it against intentionally altered packages:

**https://ta14-architecture.netlify.app/replay-verification**

### DOI-Backed Reference Implementation

Version-specific archival release:

**https://doi.org/10.5281/zenodo.21365307**

Concept DOI for the full release family:

**https://doi.org/10.5281/zenodo.21365306**

### Public Replay Standard

TA-14 Independent Route Replay Standard:

**https://github.com/greggbutlerac-debug/greggbutlerac-debug-ta14-api-sandbox/blob/main/TA14_INDEPENDENT_ROUTE_REPLAY_STANDARD.md**

### Public API Boundary

Published claim boundary for the sandbox:

**https://github.com/greggbutlerac-debug/greggbutlerac-debug-ta14-api-sandbox/blob/main/PUBLIC_API_BOUNDARY.md**

### Rate-Limit and Usage-Control Documentation

Persistent sandbox quotas, plans, and abuse protection:

**https://github.com/greggbutlerac-debug/greggbutlerac-debug-ta14-api-sandbox/blob/main/RATE_LIMIT_SETUP.md**

### TA-14 Public Website Repository

Source repository for the main TA-14 Authority Portal:

**https://github.com/greggbutlerac-debug/ta14-architecture-site**

### TA-14 Admissible Execution Gate Repository

Broader gate architecture and implementation record:

**https://github.com/greggbutlerac-debug/ta14-admissible-execution-gate**

### Request a TA-14 Evaluation

**https://ta14-architecture.netlify.app/request-evaluation.html**

### Public Contact

**ta14admissibleexecution@gmail.com**

---

## The Governance Problem

A consequence-bearing system can appear governed while still failing at the point that matters.

A dashboard may show approval even though the supporting evidence has expired.

A signature may remain valid even though the authority behind it has been revoked.

A route may have been admissible when it began and become inadmissible while execution is still in flight.

A system may preserve a log while failing to prove:

- what evidence was relied upon;
- whether that evidence remained current;
- who or what possessed authority;
- whether the authority applied to the exact scope;
- what action was approved;
- what conditions were attached;
- whether commitment remained valid;
- whether execution matched the approved action;
- whether the observed outcome corresponded;
- whether the preserved record was later altered.

TA-14 addresses that problem as a complete route-governance architecture rather than a dashboard, policy overlay, monitoring layer, or post-event explanation system.

---

## TA-14 Consequence-Bearing Chain

### Core Architecture

```text
Reality
→ Record
→ Continuity
→ Admissibility
→ Binding
→ Commit
→ Execution
→ Outcome
```

### Expanded Sandbox Evaluation Chain

```text
Reality
→ Record
→ Continuity
→ Evidence
→ Reliance
→ Authority
→ Legitimacy
→ Binding
→ Commit
→ Execution
→ Outcome
→ Memory
```

### Preserved Verification Route

```text
Reality
→ Record
→ Continuity
→ Admissibility
→ Binding
→ Commit
→ Execution
→ Outcome
→ Preserved Proof
```

Each part of the route has a distinct governance purpose.

| Route Element | Governance Question |
|---|---|
| **Reality** | What condition, event, request, or circumstance is claimed to exist? |
| **Record** | How was that condition captured and represented? |
| **Continuity** | Has the record remained current, intact, attributable, and connected? |
| **Evidence** | What evidence supports the requested consequence? |
| **Reliance** | Is the evidence sufficient and appropriate for this specific use? |
| **Authority** | Who or what is permitted to act? |
| **Legitimacy** | Is that authority current, scoped, recognized, and applicable? |
| **Admissibility** | Should this route be permitted to continue under present conditions? |
| **Binding** | Is the proposed action bound to the evidence, authority, rules, target, and conditions? |
| **Commit** | Has a valid, bounded authorization to execute been issued and consumed correctly? |
| **Execution** | Did the executed action correspond to the committed action? |
| **Outcome** | Did the observed result correspond to execution and remain inside the governed boundary? |
| **Memory** | Can the resulting route be preserved, examined, replayed, and independently verified? |

---

## What This Repository Contains

This repository is not a conceptual placeholder.

It contains a working public implementation with:

- deterministic admissibility evaluation;
- `ALLOW`, `HOLD`, `DENY`, and `ESCALATE` route classification;
- evidence-evaluation endpoints;
- execution-evaluation endpoints;
- synthetic consequence-bearing scenarios;
- public OpenAPI documentation;
- persistent sandbox quotas;
- rate limiting and abuse protection;
- API-key plan support;
- scheduled synthetic activity;
- automated tests;
- reproducible request examples;
- route-receipt construction;
- deterministic canonicalization;
- SHA-256 integrity checking;
- Ed25519 signing and verification;
- hash-linked ledger construction;
- deterministic replay-package generation;
- replay-package upload and verification;
- valid public sample packages;
- intentionally altered failure packages;
- complete structured verification reports;
- command-line replay-verification tests;
- GitHub Actions workflows;
- Render deployment configuration;
- Docker deployment support;
- public claim-boundary documentation;
- a published replay-verification standard;
- a DOI-backed archival reference implementation.

---

## End-to-End Architecture Flow

```text
Client, Agent, or Operational System
                |
                v
Submitted Consequence-Bearing Route
                |
                v
Reality, Evidence, and Continuity Evaluation
                |
                v
Authority, Legitimacy, and Scope Evaluation
                |
                v
ALLOW / HOLD / DENY / ESCALATE
                |
                v
Binding and Commit Controls
                |
                v
Execution and Outcome Receipts
                |
                v
Hash-Linked Route Ledger
                |
                v
Deterministic Replay Package
                |
                v
Independent Replay Verifier
                |
                v
Structured Verification Report
```

The first half governs whether execution should proceed.

The second half preserves what occurred and enables an independent party to verify the route afterward.

---

## Route Determinations

### ALLOW

`ALLOW` means the submitted route satisfies the sandbox requirements for the declared scope.

It does **not** mean:

- universal safety;
- legal approval;
- regulatory certification;
- unrestricted authority;
- production clearance;
- proof that every external source was truthful.

It means the submitted route satisfied the deterministic sandbox rules applied to that specific evaluation.

### HOLD

`HOLD` means the route cannot proceed yet.

Typical causes may include:

- missing evidence;
- expired evidence;
- incomplete continuity;
- unresolved contradiction;
- missing authority;
- uncertain scope;
- incomplete binding;
- unconfirmed target state;
- absent execution prerequisites.

A held route may become admissible after the missing conditions are corrected and the route is reevaluated.

### DENY

`DENY` means the route contains a disqualifying condition.

Typical causes may include:

- invalid authority;
- prohibited action;
- scope violation;
- broken continuity;
- material evidence conflict;
- invalid commitment;
- unacceptable consequence exposure;
- execution divergence;
- failed integrity controls.

A denied route should not proceed under the evaluated conditions.

### ESCALATE

`ESCALATE` means the sandbox refuses to authorize automatic execution and routes the matter to a higher or different authority.

Escalation may be required when:

- the route exceeds automated authority;
- specialist review is required;
- legal or regulatory interpretation is necessary;
- evidence remains materially uncertain;
- consequences exceed the permitted sandbox threshold;
- the matter requires domain-specific professional judgment.

Escalation is not approval.

It is a governed refusal to allow unsupported automatic execution.

---

## Continuous Admissibility

TA-14 does not treat admissibility as a one-time approval.

A route is not admissible merely because it was admissible at an earlier moment.

Evidence may expire.

Identity may be compromised.

Authority may be revoked.

A consequence budget may be consumed.

The target may change.

The operating environment may change.

Execution may begin diverging from the committed route.

TA-14 therefore distinguishes between:

```text
Initial admissibility
```

and:

```text
Continuing admissibility
```

The governing principle is:

> **No initial admissibility, no execution.**  
> **No continuing admissibility, no continuing authority.**

The broader TA-14 standards family defines runtime preservation through continuous and event-driven reevaluation, authority leases, continuity controls, fracture events, narrowing, restraint, revocation, containment, closure, and replayable proof.

---

## Independent Route Replay Verification

This repository includes the **TA-14 Independent Route Replay Verification Reference Implementation**.

Most governance systems present their own history through their own dashboard.

They show:

- an approval;
- a log;
- an execution record;
- an outcome;
- a compliance indicator;
- a final status.

But the system presenting that history is often the same system that created it.

TA-14 uses a different principle:

> **Verify the route, not the dashboard.**

A replay package preserves the records necessary to examine whether a consequence-bearing route remained connected from determination through outcome.

An independent reviewer can evaluate the package without relying on the originating dashboard or operator.

---

## What the Replay Verifier Checks

| Verification Category | What It Establishes |
|---|---|
| **Package integrity** | Every declared file is present and matches its recorded digest and byte length. |
| **Signature integrity** | Preserved signatures correspond to the included public key and signed-object digests. |
| **Route identity** | Receipts, manifests, ledger events, executions, and outcomes belong to the same route. |
| **Evidence integrity** | Preserved evidence records remain present, intact, and digest-consistent. |
| **Ruleset integrity** | The ruleset identity, version, and digest correspond to the governed route. |
| **Receipt dependencies** | Determination, binding, commit, execution, and outcome receipts preserve required relationships. |
| **Action binding** | The approved action remains connected to the evidence, authority, rules, target, and conditions that governed it. |
| **Commit integrity** | Execution authorization remains bounded, valid, unrevoked, and correctly consumed. |
| **Ledger integrity** | Event ordering, digests, hash links, root state, final state, and ledger seal remain coherent. |
| **Execution correspondence** | The executed action corresponds to the committed and bound action. |
| **Outcome correspondence** | The observed outcome corresponds to execution and the preserved route conditions. |
| **Independent replayability** | The package contains sufficient coherent material to support independent verification. |

A valid synthetic package can return:

```text
TA-14 INDEPENDENT ROUTE VERIFICATION
====================================

Overall status: VERIFIED
Original decision: ALLOW
Independently replayable: YES

Package integrity: VALID
Signature integrity: VALID
Ledger integrity: VALID
Evidence integrity: VALID
Ruleset integrity: VALID
Action binding: VALID
Commit integrity: VALID
Execution correspondence: VALID
Outcome correspondence: VALID

Failures
--------
- None

Warnings
--------
- None
```

---

## Public Replay Demonstration

The public verifier provides a complete self-contained demonstration.

Visitors do not need their own replay package.

They can:

1. Open the public verifier.
2. Download the valid TA-14 replay package.
3. Upload it into the live verifier.
4. Receive a `VERIFIED` result.
5. Download intentionally altered packages.
6. Upload each altered package.
7. Observe the verifier detect distinct integrity failures.

Open the live demonstration:

**https://ta14-architecture.netlify.app/replay-verification**

---

## Public Sample Packages

### Valid Replay Package

```text
ta14-valid-allow.zip
```

Expected result:

```text
Overall status: VERIFIED
Original decision: ALLOW
Independently replayable: YES
```

### Tampered Replay Package

```text
ta14-tampered-package.zip
```

Expected result:

```text
NOT VERIFIED
```

Demonstrates detection of post-construction package or manifest alteration.

### Broken Ledger Package

```text
ta14-broken-ledger.zip
```

Expected result:

```text
NOT VERIFIED
```

Demonstrates detection of ledger-link, event-digest, root, seal, or manifest-correspondence failure.

### Wrong Signature Package

```text
ta14-wrong-signature.zip
```

Expected result:

```text
NOT VERIFIED
```

Demonstrates detection of public-key and signature-correspondence failure.

These altered packages are intentionally invalid.

They exist so reviewers can observe bounded failure detection instead of merely trusting a successful demonstration.

---

## Replay Package Anatomy

A conforming replay package may preserve objects such as:

```text
Replay Package
├── package manifest
├── route manifest
├── evidence index
├── preserved evidence records
├── ruleset identity
├── determination receipt
├── binding receipt
├── commit receipt
├── execution receipt
├── outcome receipt
├── route ledger
├── ledger seal
├── public verification key
├── cryptographic signatures
├── file digests
└── verification metadata
```

The package is designed to answer:

- What route was evaluated?
- What evidence was relied upon?
- What rules applied?
- What authority existed?
- What determination was issued?
- What action was bound?
- What commitment authorized execution?
- What actually executed?
- What outcome followed?
- Did the route remain internally coherent?
- Was the package altered afterward?

---

## Cryptographic Method

### SHA-256

Used for:

- file integrity;
- object digests;
- manifest correspondence;
- evidence integrity;
- ledger-event integrity;
- route verification;
- package verification.

### Ed25519

Used for:

- signing preserved route objects;
- verifying signature correspondence;
- validating included public-key relationships;
- detecting substituted keys;
- detecting invalid signatures.

### Deterministic Canonicalization

Deterministic construction is necessary so independent implementations can calculate the same protected representation of the same object.

Relevant controls include:

- canonical serialization;
- stable field ordering;
- deterministic object encoding;
- stable ZIP-member ordering;
- stable file naming;
- route-identity preservation;
- declared digest computation;
- repeatable signature verification.

### Hash-Linked Ledger

The route ledger preserves:

- event ordering;
- event identity;
- event digests;
- previous-event linkage;
- route-root state;
- final state;
- seal correspondence.

A material break in that chain causes verification failure.

---

## Threats the Verifier Is Designed to Detect

The replay verifier is designed to identify conditions such as:

- missing package files;
- modified package files;
- byte-length mismatch;
- SHA-256 digest mismatch;
- substituted public keys;
- invalid Ed25519 signatures;
- signed-object digest mismatch;
- route-ID mismatch;
- package-ID mismatch;
- missing receipt dependencies;
- broken ledger links;
- ledger-event reordering;
- ledger-root mismatch;
- final-digest mismatch;
- invalid ledger seal;
- evidence mismatch;
- ruleset mismatch;
- action-binding divergence;
- invalid commit state;
- execution divergence;
- outcome divergence;
- incomplete replay material.

---

## What Verification Does Not Automatically Prove

A successful verification does not automatically establish:

- that every external source was truthful;
- that a physical sensor was accurate;
- that a human entered correct information;
- that a regulator approved the action;
- that the route was legally authorized in every jurisdiction;
- that the action was universally safe;
- that every operational risk was eliminated;
- that the package is suitable for production deployment;
- that the public sandbox provides production-grade key management;
- that an organization implemented the architecture correctly outside the verified package.

The verifier establishes something narrower and more defensible:

> **The preserved records remain internally intact, cryptographically corresponding, route-consistent, and independently replayable under the published verification method.**

---

## Repository Structure

```text
.
├── .github/
│   └── workflows/
├── app/
├── automation/
├── examples/
├── samples/
├── tests/
├── Dockerfile
├── docker-compose.yml
├── Procfile
├── render.yaml
├── requirements.txt
├── pytest.ini
├── env.example
├── main.py
├── engine.py
├── models.py
├── rate_limit.py
├── replay_api.py
├── test_api.py
├── test_replay_api.py
├── evaluate-evidence.json
├── evaluate-execution.json
├── PUBLIC_API_BOUNDARY.md
├── RATE_LIMIT_SETUP.md
├── TA14_INDEPENDENT_ROUTE_REPLAY_STANDARD.md
└── README.md
```

---

## Main Components

### `main.py`

Primary application entry point and public API exposure.

### `engine.py`

Deterministic route-evaluation and admissibility-decision logic.

### `models.py`

Request models, route-state objects, evaluation structures, and response schemas.

### `rate_limit.py`

Persistent usage limits, quotas, API-key plans, and abuse-protection behavior.

### `replay_api.py`

Replay-package upload, isolated processing, verification, reporting, and cleanup behavior.

### `examples/`

Public evaluation requests and synthetic route examples.

### `samples/`

Valid and intentionally altered replay packages.

### `automation/`

Controlled synthetic activity and demonstration support.

### `tests/`

Evaluation, API, replay, integrity, and CLI-verification tests.

### `.github/workflows/`

Automated testing, verification, sample generation, and synthetic-activity workflows.

### `PUBLIC_API_BOUNDARY.md`

Defines the permitted public claims and production boundary for the sandbox.

### `RATE_LIMIT_SETUP.md`

Documents usage counters, quota behavior, API-key plans, and rate-limit configuration.

### `TA14_INDEPENDENT_ROUTE_REPLAY_STANDARD.md`

Published replay-package and independent-verification standard.

---

## Example API Evaluation

A submitted route may return a bounded decision such as:

```json
{
  "decision": "ALLOW",
  "route_status": "admissible",
  "reasons": [],
  "required_actions": [],
  "claim_boundary": "Public sandbox evaluation only"
}
```

A route with missing or unresolved conditions may return:

```json
{
  "decision": "HOLD",
  "route_status": "not_ready",
  "reasons": [
    "Required evidence is incomplete",
    "Authority continuity has not been established"
  ],
  "required_actions": [
    "Provide missing evidence",
    "Revalidate authority state"
  ]
}
```

A route containing a disqualifying conflict may return:

```json
{
  "decision": "DENY",
  "route_status": "inadmissible",
  "reasons": [
    "Requested action exceeds declared authority",
    "Binding conditions do not permit execution"
  ]
}
```

A route requiring external review may return:

```json
{
  "decision": "ESCALATE",
  "route_status": "external_review_required",
  "reasons": [
    "The submitted route exceeds automated sandbox authority"
  ]
}
```

Exact schemas and current endpoint behavior are available through the live documentation:

**https://greggbutlerac-debug-ta14-api-sandbox.onrender.com/docs**

---

## Local Development

### Clone the Repository

```bash
git clone https://github.com/greggbutlerac-debug/greggbutlerac-debug-ta14-api-sandbox.git
cd greggbutlerac-debug-ta14-api-sandbox
```

### Create a Virtual Environment

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

macOS or Linux:

```bash
source .venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure the Environment

Windows PowerShell:

```powershell
Copy-Item env.example .env
```

macOS or Linux:

```bash
cp env.example .env
```

Review the environment settings before starting the service.

### Run the API

```bash
uvicorn main:app --reload
```

Local API:

**http://127.0.0.1:8000**

Local OpenAPI documentation:

**http://127.0.0.1:8000/docs**

---

## Docker

Build the image:

```bash
docker build -t ta14-api-sandbox .
```

Run the container:

```bash
docker run -p 8000:8000 ta14-api-sandbox
```

Or use Docker Compose:

```bash
docker compose up --build
```

---

## Testing

Run the complete test suite:

```bash
pytest
```

Run with verbose output:

```bash
pytest -v
```

Run API tests:

```bash
pytest test_api.py
```

Run replay-verification tests:

```bash
pytest test_replay_api.py
```

Material changes to any of the following should include corresponding tests:

- decision logic;
- evidence evaluation;
- authority evaluation;
- canonicalization;
- receipt construction;
- signing behavior;
- ledger construction;
- replay packaging;
- verification behavior;
- public response schemas;
- rate-limit behavior.

---

## Deployment

The public API service is deployed through Render.

Deployment configuration is maintained in:

```text
render.yaml
```

Additional deployment files include:

```text
Dockerfile
Procfile
docker-compose.yml
```

Live service documentation:

**https://greggbutlerac-debug-ta14-api-sandbox.onrender.com/docs**

The public website and replay-verification interface are deployed through Netlify:

**https://ta14-architecture.netlify.app/**

---

## Public API Boundary

This repository is a public sandbox and reference implementation.

It must not be described as:

- enterprise production enforcement;
- legal approval;
- regulatory certification;
- compliance certification;
- safety certification;
- operational authorization;
- production clearance;
- universal truth verification;
- a warranty that execution is lawful, safe, or complete.

Approved public framing:

> **TA-14 provides a public API sandbox for admissible execution evaluation. It classifies submitted consequence-bearing routes as ALLOW, HOLD, DENY, or ESCALATE based on submitted evidence, continuity, authority, binding, commitment, execution, and outcome state.**

The replay implementation may be described as:

> **TA-14 provides a public reference implementation for preserving cryptographically bound route receipts, sealed replay ledgers, deterministic replay packages, and independent verification reports that do not require trust in the originating dashboard or operator.**

Full public API boundary:

**https://github.com/greggbutlerac-debug/greggbutlerac-debug-ta14-api-sandbox/blob/main/PUBLIC_API_BOUNDARY.md**

---

## Security Boundary

The public sandbox is intentionally open for testing, demonstration, technical review, and reproducibility.

A production implementation would require additional controls, including:

- authenticated clients;
- managed API keys;
- customer and tenant isolation;
- encrypted transport and storage;
- formal retention controls;
- managed secret storage;
- HSM- or KMS-backed signing keys;
- key rotation;
- revocation handling;
- role-based access control;
- customer-specific rulesets;
- signed release management;
- dependency review;
- privacy review;
- incident-response procedures;
- penetration testing;
- service-level objectives;
- audit logging;
- production monitoring;
- deployment-specific legal and regulatory review.

Do not submit confidential, regulated, private, or production-sensitive information to the public sandbox.

Do not commit production credentials or private signing keys to this repository.

---

## Intended Evaluation Domains

The architecture may be explored across consequence-bearing routes such as:

- autonomous AI agents;
- automated payments;
- financial approvals;
- procurement actions;
- software deployment;
- CI/CD remediation;
- security automation;
- identity and access actions;
- healthcare workflow routing;
- clinical prioritization;
- claims processing;
- insurer review;
- vendor actions;
- industrial automation;
- environmental control;
- infrastructure changes;
- evidence-sensitive approvals;
- cross-organizational handoffs;
- high-consequence operational workflows.

These examples do not imply that the public sandbox is approved for live production use in those domains.

---

## Organizational Value

The public sandbox and replay verifier can help organizations explore stronger evidence for:

- internal audit;
- AI-agent accountability;
- incident review;
- customer disputes;
- insurer review;
- vendor oversight;
- procurement assurance;
- operational investigations;
- regulatory preparation;
- execution governance;
- evidence preservation;
- chain-of-authority review;
- software-deployment accountability;
- workflow-integrity review;
- independent technical verification.

The value is not simply that a log exists.

It is that an organization may be able to produce a portable route showing:

- what evidence was relied upon;
- what authority existed;
- what conditions applied;
- what action was approved;
- what was committed;
- what executed;
- what outcome followed;
- whether the preserved route remained intact.

---

## Enterprise and Review Pathway

The public sandbox demonstrates the architecture.

Organizations seeking implementation, review, private deployment, or production-readiness support may require a written scope.

Potential TA-14 services include:

- Reviewability Check;
- API Readiness Review;
- Replay Readiness Review;
- Admissible Execution Boundary Review;
- Evidence Integrity Review;
- Runtime Readiness Review;
- route and receipt mapping;
- customer-specific ruleset design;
- replay-package integration;
- private verifier deployment;
- independent technical verification reports;
- production-security architecture;
- implementation support;
- version migration;
- certification-readiness preparation.

Request a review:

**https://ta14-architecture.netlify.app/request-evaluation.html**

Email:

**ta14admissibleexecution@gmail.com**

---

## Versioning

The project should use semantic versioning.

### Patch Release

```text
1.0.0 → 1.0.1
```

Use for:

- documentation corrections;
- metadata clarification;
- non-breaking fixes;
- compatible sample regeneration.

### Minor Release

```text
1.0.0 → 1.1.0
```

Use for:

- new optional receipt types;
- additional verification checks;
- backward-compatible endpoint additions;
- new compatible sample packages.

### Major Release

```text
1.x → 2.0.0
```

Required for:

- breaking package-schema changes;
- canonicalization changes;
- signature-model changes;
- incompatible endpoint behavior;
- breaking route semantics;
- changes to the governing standard identifier.

Historically meaningful versions should not be silently replaced.

Create a new release and preserve the previous version.

---

## Citation

Preferred citation:

```text
Butler, G. D. (2026).
TA-14 Independent Route Replay Verification:
Reference Implementation v1.0.0.
Zenodo.
https://doi.org/10.5281/zenodo.21365307
```

Version-specific DOI:

**https://doi.org/10.5281/zenodo.21365307**

Concept DOI:

**https://doi.org/10.5281/zenodo.21365306**

---

## Creator and Institution

**Greggory Don Butler**  
Founder, TA-14 Authority Governance Institution  
Architect of Admissible Execution Architecture, Environmental Integrity Governance, and Atmospheric Integrity Records

Public website:

**https://ta14-architecture.netlify.app/**

Public contact:

**ta14admissibleexecution@gmail.com**

---

## Final Position

TA-14 is not another policy dashboard, orchestration layer, monitoring screen, approval interface, or post-event explanation system.

It is an admissibility-before-execution architecture designed to govern the complete consequence-bearing route and preserve that route for independent verification afterward.

```text
Reality
→ Record
→ Continuity
→ Admissibility
→ Binding
→ Commit
→ Execution
→ Outcome
→ Preserved Proof
```

The sandbox demonstrates the decision boundary.

The runtime architecture preserves continuing admissibility.

The replay verifier demonstrates that the resulting route can be independently examined.

Together, they establish a public technical model for:

```text
Governing before consequence
Preserving through consequence
Verifying after consequence
```

> ## Verify the route, not the dashboard.

> ## No admissible evidence. No admissible execution.
