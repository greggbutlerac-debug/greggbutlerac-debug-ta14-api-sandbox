# TA-14 Admissible Execution API Sandbox

Most AI governance systems record what happened after execution.

TA-14 governs whether execution should be allowed before consequence, preserves the complete route that justified the action, and enables an independent party to verify afterward that the preserved evidence, authority, binding, commitment, execution, and outcome still correspond.

This repository contains the public reference implementation of that architecture.

It includes:

- deterministic admissibility evaluation;
- ALLOW, HOLD, DENY, and ESCALATE routing;
- evidence, authority, and execution checks;
- cryptographically bound route receipts;
- hash-linked ledger construction;
- deterministic replay-package generation;
- Ed25519 signature verification;
- SHA-256 integrity checking;
- valid and intentionally altered public samples;
- independent replay verification;
- structured verification reports;
- public OpenAPI access;
- automated tests and reproducible workflows.

The public sandbox demonstrates one governing principle:

> No admissible evidence. No admissible execution.

And one verification principle:

> Verify the route, not the dashboard.
