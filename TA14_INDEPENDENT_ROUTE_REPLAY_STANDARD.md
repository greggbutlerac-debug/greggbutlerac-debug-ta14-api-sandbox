<div align="center">

# TA-14 INDEPENDENT ROUTE REPLAY STANDARD

## Portable Verification of Consequence-Bearing Execution Routes

### Version 1.0.0

<br>

![Status](https://img.shields.io/badge/Status-Public%20Technical%20Specification-2563eb)
![Standard](https://img.shields.io/badge/Standard-TA14--IRRS--1.0.0-0f172a)
![Digest](https://img.shields.io/badge/Digest-SHA--256-0891b2)
![Signature](https://img.shields.io/badge/Signature-Ed25519-7c3aed)
![Verification](https://img.shields.io/badge/Verification-Independent-16a34a)

<br>

**Architecture:** TA-14 Admissible Execution Architecture  
**Standard Identifier:** `TA14-IRRS-1.0.0`  
**Release Status:** Public Technical Specification  
**Canonical Principle:** **No admissible evidence. No admissible execution.**

</div>

---

> [!IMPORTANT]
> ## Controlling Standard Question
>
> **Did this specific consequence remain connected to the admissible route that authorized it, and can that relationship be independently verified from preserved proof?**

---

## 1. Purpose

The **TA-14 Independent Route Replay Standard** establishes the requirements for creating, preserving, transporting, and independently verifying a complete **consequence-bearing execution route**.

A conforming replay package shall preserve sufficient evidence for an outside reviewer to determine—without relying on the originating dashboard, operator, or live runtime:

- **what action was proposed;**
- **what reality and records supported the route;**
- **what evidence was admitted, excluded, or declared unavailable;**
- **what identity, authority, delegation, and scope existed;**
- **what ruleset and ruleset version governed the route;**
- **what admissibility determination was issued;**
- **what conditions, limitations, dependencies, and exceptions were bound to the action;**
- **what commitment authorized entry into execution;**
- **what action was actually executed;**
- **what outcome was observed;**
- **whether execution corresponded to the bound and committed action;**
- **whether the outcome corresponded to the preserved execution;**
- **whether route identity and dependency continuity survived across all stages;**
- **whether any protected record was altered, substituted, omitted, invalidated, or superseded after issuance;**
- **and whether the preserved route remains independently replayable.**

> [!NOTE]
> This standard does not treat a dashboard, log entry, approval record, execution status, or reported outcome as sufficient proof by itself.

A route becomes independently verifiable only when its preserved:

- records;
- evidence;
- cryptographic signatures;
- digests;
- authority relationships;
- ruleset relationships;
- dependency links;
- ledger continuity;
- execution correspondence;
- and outcome correspondence

can be evaluated **outside the originating system**.

### 1.1 The purpose is not merely event reconstruction

Independent route replay does not exist only to show that events occurred in a particular order.

Its purpose is to determine whether a specific consequence remained connected to the complete route that made execution admissible.

| Required dependency | Verification question |
|---|---|
| **Reality** | What condition or claimed state initiated the route? |
| **Record** | How was that reality converted into a reviewable record? |
| **Continuity** | Did the record survive time, custody, transfer, and transformation? |
| **Admissibility** | Was the evidence sufficient for governed reliance? |
| **Determination** | What explicit route decision was issued? |
| **Binding** | What action, conditions, authority, and evidence were bound together? |
| **Commit** | What authorized entry into the consequence-bearing path? |
| **Execution** | What action was actually performed? |
| **Outcome** | What result was observed? |
| **Preserved Proof** | Can the complete relationship be independently verified? |

### 1.2 Governing purpose

The standard exists to allow an independent verifier to determine whether:

1. the route was formed from preserved records;
2. the records maintained continuity;
3. the evidence was sufficient for the declared determination;
4. the determination was issued before consequence;
5. the exact action was bound to its evidence, authority, rules, conditions, and limitations;
6. a valid commitment authorized entry into execution;
7. the performed action matched the committed action;
8. the observed outcome corresponded to the execution;
9. the event ledger remained continuous and sealed;
10. and the complete route can be verified without trusting the originating dashboard.

---

## 2. Governing Requirement

> [!CAUTION]
> A successful outcome does not repair an inadmissible route.

No consequence-bearing route shall be considered **independently replayable** unless the verifier can evaluate the complete preserved relationship between:

<div align="center">

### REALITY  
↓  
### RECORD  
↓  
### CONTINUITY  
↓  
### ADMISSIBILITY  
↓  
### DETERMINATION  
↓  
### BINDING  
↓  
### COMMIT  
↓  
### EXECUTION  
↓  
### OUTCOME  
↓  
### PRESERVED PROOF

</div>

Each stage shall remain attributable to the **same governed route**.

Each downstream stage shall preserve its required dependency on the prior stage.

The following rules apply:

1. **Route identity shall remain continuous.**
2. **Evidence shall remain attributable to the route that relied upon it.**
3. **Authority shall remain bounded to the identity, purpose, scope, and action declared.**
4. **The ruleset identity, version, and artifact digest shall remain preserved.**
5. **The determination shall remain bound to the preserved route manifest and ruleset.**
6. **The bound action shall remain unchanged through commitment and execution.**
7. **Execution shall correspond to the action that was actually committed.**
8. **The observed outcome shall correspond to the preserved execution.**
9. **The ledger shall preserve event order, digest continuity, root identity, final-event identity, and sealing.**
10. **Protected records shall remain cryptographically verifiable.**
11. **Declared failures, exceptions, omissions, redactions, substitutions, and divergences shall not be concealed.**
12. **Independent replay shall not depend upon trust in the originating dashboard or operator.**

> [!WARNING]
> A failed, interrupted, denied, held, or escalated route does not eliminate the preservation requirement.  
> The route must remain reviewable whether consequence occurred, was prevented, was interrupted, or diverged.

---

## 3. Scope

This standard governs a **single consequence-bearing execution route** and the records required to verify that route independently.

### 3.1 Applicable systems

This standard may be applied to routes originating from:

- artificial intelligence systems;
- autonomous and agentic systems;
- software services;
- human-operated workflows;
- institutional decision systems;
- financial and administrative processes;
- physical and cyber-physical systems;
- environmental and building-control systems;
- healthcare-supporting systems;
- industrial and infrastructure systems;
- public-sector systems;
- organizational approval systems;
- and mixed human-machine execution environments.

### 3.2 Applicable consequence classes

This standard may be applied when an action can create:

- financial consequence;
- legal consequence;
- administrative consequence;
- physical consequence;
- environmental consequence;
- infrastructure consequence;
- institutional consequence;
- access or eligibility consequence;
- safety consequence;
- human welfare consequence;
- data or privacy consequence;
- or another material and reviewable change in reality.

### 3.3 Verification domains

A conforming verifier shall evaluate the applicable domains below:

| No. | Verification domain | Required purpose |
|---:|---|---|
| 1 | **Package integrity** | Confirm required files and declared file digests. |
| 2 | **Record integrity** | Confirm preserved objects have not been altered. |
| 3 | **Evidence integrity** | Confirm evidence indexes and evidence relationships remain coherent. |
| 4 | **Route identity** | Confirm every route-bearing object belongs to the same route. |
| 5 | **Authority correspondence** | Confirm identity, delegation, scope, and authority relationships. |
| 6 | **Ruleset correspondence** | Confirm the governing ruleset identity, version, and digest. |
| 7 | **Determination integrity** | Confirm the preserved determination corresponds to the route. |
| 8 | **Binding correspondence** | Confirm action, evidence, authority, rules, and conditions remain bound. |
| 9 | **Commit integrity** | Confirm execution authorization corresponds to the preserved binding. |
| 10 | **Execution correspondence** | Confirm the performed action corresponds to the committed action. |
| 11 | **Outcome correspondence** | Confirm the observed outcome corresponds to execution. |
| 12 | **Ledger continuity** | Confirm sequence, hash linkage, root, final digest, and seal. |
| 13 | **Signature integrity** | Confirm cryptographic signatures and public-key correspondence. |
| 14 | **Exception disclosure** | Confirm declared omissions, redactions, divergence, and limitations. |
| 15 | **Independent replayability** | Determine whether the route can be verified without dashboard trust. |

### 3.4 Out-of-scope claims

This standard does not automatically determine:

- whether every external evidence source was truthful;
- whether every relevant fact was included;
- whether a route was legally sufficient;
- whether a route complied with every applicable regulation;
- whether execution was universally safe;
- whether production deployment controls were adequate;
- whether the signer possessed authority beyond the scope preserved in the route;
- or whether undisclosed events occurred outside the preserved package.

---

## 4. Standard Objective

The standard governs more than event reconstruction.

It governs the **preservation of admissibility across consequence**.

A conforming implementation shall enable an outside verifier to determine whether:

```text
PROPOSED ACTION
      |
      v
PRESERVED REALITY AND RECORDS
      |
      v
CONTINUITY-VALID EVIDENCE
      |
      v
VALID IDENTITY AND AUTHORITY
      |
      v
APPLICABLE RULESET
      |
      v
ADMISSIBILITY DETERMINATION
      |
      v
BOUND ACTION AND CONDITIONS
      |
      v
COMMIT AUTHORIZATION
      |
      v
ACTUAL EXECUTION
      |
      v
OBSERVED OUTCOME
      |
      v
SEALED PRESERVED PROOF
      |
      v
INDEPENDENT VERIFICATION REPORT
```

The controlling distinction is:

| Ordinary system claim | TA-14 replay requirement |
|---|---|
| “The dashboard says it was approved.” | Preserve the determination receipt and verify its signature. |
| “The action was authorized.” | Verify authority, scope, binding, and commit correspondence. |
| “The execution completed.” | Verify the executed action matches the committed action. |
| “The outcome was successful.” | Verify outcome correspondence and preserved route continuity. |
| “The logs are available.” | Verify the ledger, signatures, digests, and dependencies independently. |
| “The operator confirmed it.” | Verify the route without depending upon operator trust. |
| “Nothing appears to have changed.” | Recalculate digests and cryptographic correspondence. |

> [!TIP]
> **Verify the route, not the dashboard.**

---

## 5. Claim Boundary

A successful verification under this standard establishes that the preserved records are:

- **internally consistent;**
- **cryptographically intact;**
- **route-corresponding;**
- **dependency-consistent;**
- **ledger-continuous;**
- **and independently replayable.**

### 5.1 What successful verification can establish

A successful verification can establish:

- preservation of package integrity;
- correspondence between files and declared digests;
- validity of supported cryptographic signatures;
- public-key fingerprint correspondence;
- route identity continuity;
- evidence-index integrity;
- ruleset identity and version correspondence;
- determination-to-route correspondence;
- binding-to-determination correspondence;
- commit-to-binding correspondence;
- execution-to-commit correspondence;
- outcome-to-execution correspondence;
- hash-linked ledger continuity;
- ledger root and final-event correspondence;
- ledger seal validity;
- and the absence of detected protected-record alteration.

### 5.2 What successful verification does not automatically establish

> [!WARNING]
> Independent verification does not convert incomplete, unauthenticated, or false source evidence into truth.

A successful verification does not automatically establish:

- truthfulness of an unauthenticated external source;
- completeness of facts outside the preserved package;
- legal approval;
- regulatory certification;
- safety certification;
- production clearance;
- universal operational correctness;
- absence of undisclosed circumstances;
- suitability for a specific production deployment;
- or authority beyond the scope preserved in the route.

The verifier establishes what the preserved package can prove.

It does not claim what the preserved package cannot prove.

### 5.3 Internal integrity versus external truth

The standard distinguishes between:

| Verification object | What may be established |
|---|---|
| **Preserved record** | Whether its protected bytes and declared digest correspond. |
| **Signature** | Whether the preserved object corresponds to the supplied verification key. |
| **Ledger** | Whether sequence, linkage, root, final digest, and seal remain intact. |
| **Route dependency** | Whether downstream receipts correspond to upstream records. |
| **External source claim** | Only what its authentication, provenance, and evidence support. |
| **Legal authority** | Only the authority and scope preserved within the route. |
| **Operational safety** | Only the safety conditions explicitly preserved and evaluated. |

---

## 6. Core Terms

| Term | Meaning under this standard |
|---|---|
| **Consequence-bearing route** | A governed sequence capable of producing a material digital, organizational, financial, environmental, physical, legal, or human consequence. |
| **Replay package** | A portable collection of route records, manifests, receipts, signatures, digests, ledger data, and verification material. |
| **Independent verifier** | A verifier capable of evaluating the package without trusting the originating dashboard, operator, or live runtime. |
| **Reality** | The condition, event, state, or claimed circumstance from which the route originates. |
| **Record** | The preserved representation of reality relied upon by the route. |
| **Continuity** | The governed survival of a record across time, custody, transfer, transformation, and reliance. |
| **Admissibility** | The governed condition under which records and evidence may support consequence-bearing reliance. |
| **Determination** | An explicit, evidence-bound, rule-constrained route decision. |
| **Binding** | The governed attachment of action, evidence, authority, rules, conditions, and determination. |
| **Commit** | The authorization that permits a bound route to enter the consequence-bearing execution path. |
| **Execution** | The action actually performed under the committed route. |
| **Execution correspondence** | Proof that the performed action corresponds to the action that was bound and committed. |
| **Outcome** | The observed consequence following execution. |
| **Outcome correspondence** | Proof that the observed result corresponds to the preserved execution. |
| **Preserved proof** | The portable record set required to examine and verify the governed route independently. |
| **Independent replay** | The reconstruction and verification of a route from its preserved package. |
| **Independently replayable** | A status indicating that the complete preserved route satisfies the required integrity and correspondence checks. |
| **Protected record** | A record whose integrity is preserved through a declared digest, signature, ledger relationship, or package-manifest relationship. |
| **Route manifest** | The record defining the governed route identity, proposed action, evidence relationships, authority state, and governing ruleset. |
| **Receipt** | A structured record issued at a governed stage of the route. |
| **Ledger event** | A hash-linked event representing a protected transition or preserved route object. |
| **Ledger seal** | A cryptographic signature applied to the completed ledger state. |
| **Verification report** | The structured result produced by an independent verifier. |

---

## 7. Conformance Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this standard indicate requirement strength.

| Term | Meaning |
|---|---|
| **MUST / SHALL / REQUIRED** | Mandatory for conformance. |
| **MUST NOT / SHALL NOT** | Prohibited for conformance. |
| **SHOULD / RECOMMENDED** | Expected unless a documented reason justifies deviation. |
| **SHOULD NOT** | Discouraged unless a documented reason justifies use. |
| **MAY / OPTIONAL** | Permitted but not required. |

A conforming implementation shall not represent an optional control as mandatory unless the applicable profile declares it mandatory.

---

## 8. Route Model

A conforming route shall preserve the ordered relationship:

```text
Reality
  -> Record
  -> Continuity
  -> Admissibility
  -> Determination
  -> Binding
  -> Commit
  -> Execution
  -> Outcome
  -> Preserved Proof
```

### 8.1 Reality

Reality represents the condition, event, state, or claimed circumstance that initiates the route.

The route shall identify the reality claims upon which later records and evidence depend.

### 8.2 Record

The Record stage preserves the representation of the claimed reality.

The record should identify:

- source;
- capture time;
- capture method;
- creator or originating system;
- scope;
- custody state;
- transformation history;
- and declared limitations.

### 8.3 Continuity

Continuity determines whether the record remained the same governed witness through:

- time;
- custody;
- transfer;
- transformation;
- system movement;
- review;
- reliance;
- and preservation.

### 8.4 Admissibility

Admissibility determines whether the preserved evidence may support governed reliance.

Admissibility shall not be inferred merely because a record exists.

### 8.5 Determination

The determination shall state the explicit route decision.

Supported determination classes may include:

- `ALLOW`
- `HOLD`
- `DENY`
- `ESCALATE`

The determination shall be bound to the route manifest, evidence state, authority state, and ruleset.

### 8.6 Binding

Binding shall preserve the exact relationship between:

- proposed action;
- evidence;
- authority;
- ruleset;
- determination;
- conditions;
- limitations;
- audience;
- dependencies;
- and expiration or revocation state.

### 8.7 Commit

Commit shall represent the authorization that permits the bound route to enter execution.

A commit shall not authorize an action materially different from the action that was bound.

### 8.8 Execution

Execution shall preserve what action was actually performed.

The execution record shall support comparison between:

- proposed action;
- bound action;
- committed action;
- submitted action;
- and performed action.

### 8.9 Outcome

Outcome shall preserve the observed result of execution.

The outcome record should identify:

- intended consequence;
- observed consequence;
- correspondence status;
- divergence;
- authority continuity;
- evidence continuity;
- and whether binding conditions remained satisfied.

### 8.10 Preserved Proof

Preserved Proof is the complete portable record required to verify the route independently.

Preserved proof shall not depend upon continued access to the originating dashboard.

---

## 9. Independent Verification Requirement

A conforming verifier shall evaluate the replay package without relying upon:

- the originating dashboard;
- the originating operator account;
- the private signing key;
- the original live runtime;
- or undocumented institutional interpretation.

The verifier shall use the preserved package and supported public verification material to determine whether the route satisfies the applicable verification requirements.

The verifier shall return a structured result that includes:

- overall status;
- route identifier;
- package identifier;
- original determination;
- independently replayable status;
- integrity-category results;
- failed checks;
- warnings;
- verifier identity;
- verifier version;
- and verification time.

---

## 10. Governing Law of Replay

> [!IMPORTANT]
> Replay is not merely the reproduction of events.
>
> Replay is the independent examination of whether consequence remained connected to the route that authorized it.

The following principles govern this standard:

1. **A route is not verified because the dashboard says it succeeded.**
2. **A record is not intact merely because it remains stored.**
3. **A signature is not valid merely because a signature field exists.**
4. **A ledger is not continuous merely because events are ordered.**
5. **An action is not authorized merely because an approval occurred.**
6. **Execution is not corresponding merely because it completed.**
7. **An outcome is not admissible merely because it was favorable.**
8. **A preserved package is not independently replayable unless required integrity and correspondence checks succeed.**
9. **No later success cures an earlier route fracture.**
10. **No failed route is exempt from preservation.**

---

<div align="center">

## TA-14 OPERATING LAW

### NO ADMISSIBLE EVIDENCE.  
### NO ADMISSIBLE EXECUTION.

**Verify the route, not the dashboard.**

</div>
