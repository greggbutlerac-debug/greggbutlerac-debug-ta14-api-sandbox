# TA-14 Admissible Execution API Sandbox

**Public reference API for evaluating consequence-bearing AI, automation, evidence, authority, and runtime execution routes before action becomes consequence.**

TA-14 is built around one governing principle:

> **No admissible evidence. No admissible execution.**

This repository contains the public developer-facing implementation of the **TA-14 Admissible Execution API Sandbox**, including:

- deterministic route evaluation;
- `ALLOW`, `HOLD`, `DENY`, and `ESCALATE` classifications;
- evidence and execution evaluation endpoints;
- synthetic scenario generation;
- persistent usage controls and rate limiting;
- public OpenAPI documentation;
- cryptographically bound replay packages;
- independent route replay verification;
- valid and intentionally altered public sample packages;
- automated tests and reproducible verification workflows.

This is not merely a dashboard or post-event logging surface.

It is a public reference implementation for examining whether a consequence-bearing route has enough evidence, continuity, authority, scope, binding, commitment, and execution correspondence to proceed—and whether the preserved route can later be independently verified without trusting the originating operator or dashboard.

---

## Live Public Access

### API Documentation

**https://greggbutlerac-debug-ta14-api-sandbox.onrender.com/docs**

### Public Replay Verifier

**https://ta14-architecture.netlify.app/replay-verification**

### TA-14 Public Architecture Site

**https://ta14-architecture.netlify.app/**

### DOI-Backed Reference Implementation

**https://doi.org/10.5281/zenodo.21365307**

---

## What TA-14 Evaluates

TA-14 evaluates submitted routes across a complete consequence-bearing governance chain.

### Core TA-14 Chain

```text
Reality
→ Record
→ Continuity
→ Admissibility
→ Binding
→ Commit
→ Execution
→ Outcome
