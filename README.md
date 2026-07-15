# TA-14 Admissible Execution API Sandbox

<p align="center">
  <strong>Govern consequence before execution. Preserve the route. Verify it independently afterward.</strong>
</p>

<p align="center">
  <a href="https://ta14-architecture.netlify.app/">
    TA-14 Public Site
  </a>
  ·
  <a href="https://greggbutlerac-debug-ta14-api-sandbox.onrender.com/docs">
    Live API Documentation
  </a>
  ·
  <a href="https://ta14-architecture.netlify.app/replay-verification">
    Public Replay Verifier
  </a>
  ·
  <a href="https://doi.org/10.5281/zenodo.21365307">
    Zenodo Reference Release
  </a>
</p>

---

## No Admissible Evidence. No Admissible Execution.

Most AI governance systems begin too late.

They monitor outputs, display approvals, preserve logs, and explain decisions after a system has already acted.

TA-14 begins while consequence is still preventable.

The **TA-14 Admissible Execution API Sandbox** is a public reference implementation for evaluating whether a consequence-bearing AI system, autonomous agent, automated workflow, digital service, or operational process should be permitted to proceed.

It does not merely ask whether a rule passed.

It examines whether the route remains supported by sufficient evidence, current authority, intact continuity, applicable rules, bounded scope, valid binding, controlled commitment, corresponding execution, and accountable outcome.

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

The public architecture, services, review pathways, use cases, positioning, resources, and institutional record are available at:

**https://ta14-architecture.netlify.app/**

### Live OpenAPI Documentation

Explore the public API, schemas, endpoints, request models, and response structures:

**https://greggbutlerac-debug-ta14-api-sandbox.onrender.com/docs**

### Independent Route Replay Verifier

Download a valid replay package, upload it into the public verifier, and compare it against intentionally altered packages:

**https://ta14-architecture.netlify.app/replay-verification**

### DOI-Backed Reference Implementation

Canonical archival publication for Version 1.0.0:

**https://doi.org/10.5281/zenodo.21365307**

Concept DOI for the complete release family:

**https://doi.org/10.5281/zenodo.21365306**

### Public Replay Standard

The TA-14 Independent Route Replay Standard is maintained in this repository:

**https://github.com/greggbutlerac-debug/greggbutlerac-debug-ta14-api-sandbox/blob/main/TA14_INDEPENDENT_ROUTE_REPLAY_STANDARD.md**

### Related TA-14 Architecture Repository

Main public website source repository:

**https://github.com/greggbutlerac-debug/ta14-architecture-site**

### Related Admissible Execution Gate Repository

Broader TA-14 Admissible Execution Gate implementation record:

**https://github.com/greggbutlerac-debug/ta14-admissible-execution-gate**

---

## The Governance Problem

A consequence-bearing system may appear governed while still failing at the point that matters.

A dashboard may show approval even though the supporting evidence has expired.

A signature may remain valid even though the authority behind it has been revoked.

A route may have been admissible when it began and become inadmissible while execution is still in flight.

A system may preserve a log while failing to prove:

- what evidence was relied upon;
- whether that evidence remained current;
- who or what had authority;
- whether the authority applied to the exact scope;
- what action was approved;
- what conditions were attached;
- whether execution matched the approved action;
- whether the observed outcome corresponded;
- whether the preserved record was later altered.

TA-14 addresses that problem as a route-governance architecture rather than a dashboard, policy overlay, or post-event explanation layer.

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
