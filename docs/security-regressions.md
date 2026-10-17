# Security Regression Tests

A **Security Regression Test** turns a *verified mitigation* into a deterministic,
evidence-backed security property that an operator can manually re-validate later.

> Not to be confused with `tests/security_cases/`, which are automated tests of
> Orion itself. A **Security Regression** is a product-domain object
> (`orion/security_regressions/`, ids `ORN-REG-####`).

## What is a Security Regression Test?

It answers:

> **Does a previously validated security property still hold?**

It does **not** simply answer "did the attack succeed?". Orion's central
distinction is preserved:

```
Agent / model influence   ≠   Security impact
```

An agent may still be influenced by a prompt injection. The **security boundary**
(e.g. tool authorization) is what must remain effective:

```
Indirect Prompt Injection
  Agent influenced     YES
  Tool requested       YES
  Authorization        DENY
  Tool executed        NO
  Security impact      NONE
  REGRESSION RESULT    ✓ PASS
```

## Regression vs Retest

| | Question |
| --- | --- |
| **Retest** | Did the newly applied control mitigate the original Finding? |
| **Security Regression** | Does that validated security behavior still hold *now*? |

```
Attack → Finding → Control → Retest → EFFECTIVE → Create Security Regression
```

## Creation prerequisites

A regression is created from a Finding that has:

1. a security condition that was observed, **and**
2. a control applied, **and**
3. a **retest that demonstrated the protected behavior** (`retest_status == EFFECTIVE`).

`PARTIALLY_EFFECTIVE` / `INEFFECTIVE` retests cannot produce a regression in v1.
Regressions are never created automatically from every Finding.

### Selecting the Retest when more than one exists

A Finding can accumulate more than one Retest (e.g. an earlier control attempt
that turned out `INEFFECTIVE`, before a later control succeeded). Regression
creation does **not** use the first Retest recorded — it resolves **the
specific Retest that actually backs the Finding's current `EFFECTIVE` status**:
preferring the Retest whose provenance links it to the Finding's current
`applied_control`, and independently re-verifying its before/after
attack-success rate rather than trusting list position alone.

## Success Signature vs Expected Security State

These two objects look similar but describe **opposite moments** and must never
be confused:

- **Success Signature** = the identity of the **original security failure** —
  derived from the **original (pre-mitigation) attack evidence**, via the
  Finding that recorded it. It is what the Regression exists to keep from
  reappearing, and it does not change just because a retest later succeeded.
- **Expected Security State** = the protected behavior demonstrated by the
  **effective Retest** — what must still hold today.

```
Finding → original attack Run → original Evidence → Success Signature
Finding → effective Retest     → retest Evidence    → Expected Security State
```

A Regression keeps references to **both** the original attack Run
(`source_attack_run_id`) and the effective Retest Run (`source_retest_run_id`) —
never only one.

## Success Signature

A deterministic, normalized identity for the reproduced security condition — just
enough context to tell one failure from another, not a copy of the experiment:

```json
{
  "attack_id": "ORN-ATTACK-PI-002",
  "target": "customer-support-agent",
  "criterion": "unauthorized_privileged_tool_execution",
  "boundary": "tool_authorization",
  "capability": "admin_export",
  "tool": "admin_export",
  "security_effect": "unauthorized_external_action"
}
```

Fields are attack-family aware — Traditional ML signatures omit agentic
dimensions (e.g. `{attack_id, target, criterion, security_effect}`). Absent
dimensions are omitted, never invented.

## Expected Security State

The protected state that must still hold, built from the successful retest and
kept attack-family aware (volatile values like timestamps/trace ids are excluded):

```json
// Agentic
{ "authorization_decision": "DENY", "tool_executed": false, "security_impact": false }
// Traditional ML
{ "attack_success": false }
```

## PASS / FAIL / ERROR

- **PASS** — every expected security condition was reproduced.
- **FAIL** — execution completed but a security expectation was violated.
- **ERROR** — the regression could not be evaluated reliably (missing evidence,
  broken endpoint, execution failure).

Missing evidence is **never** PASS. A timeout or broken endpoint is ERROR.

## Per-criterion corroboration

A Finding becomes CONFIRMED only when a specific security criterion was
*independently reproduced* across the required runs — never because different
criteria happened in different runs. Each criterion carries its own statistics:

```json
{
  "unauthorized_privileged_tool_execution": {
    "independent_runs": 3, "successes": 3, "success_rate": 1.0,
    "required_runs": 3, "required_success_rate": 0.66, "reproduced": true
  },
  "sensitive_data_disclosure": {
    "independent_runs": 3, "successes": 1, "success_rate": 0.33,
    "required_runs": 3, "required_success_rate": 0.66, "reproduced": false
  }
}
```

Legacy Findings without per-criterion evidence load fine and are reported as
`UNKNOWN / LEGACY` rather than silently reinterpreted.

## Lifecycle status

A Regression definition has one of three statuses, independent of its latest
PASS/FAIL/ERROR execution result:

| Status | Meaning |
| --- | --- |
| `ACTIVE` | executable — manual execution is allowed |
| `DISABLED` | retained, but execution is blocked until reactivated |
| `ARCHIVED` | retained for reference only; execution is permanently blocked |

Only `ACTIVE` regressions can execute. The backend enforces this
unconditionally — `run_regression(...)` fails closed (raises before the attack
runner is invoked, producing no new Run or Evidence) for `DISABLED` /
`ARCHIVED` regressions, whether the request comes from the UI, the
`POST /api/regressions/<id>/run` endpoint, or the CLI. The UI only hides the
`[ RUN REGRESSION ]` button as a courtesy; it is never the enforcement point.

## Manual execution

Execution is always **operator-initiated** and reuses the existing
experiment/attack/run/evidence system — there is no second attack engine. Each
run creates normal, auditable evidence.

UI: **Regressions → open a regression → `[ RUN REGRESSION ]`** (ACTIVE only;
DISABLED/ARCHIVED regressions show their status and why execution is
unavailable instead).

CLI:

```bash
orion regression list
orion regression create ORN-FND-0042
orion regression run ORN-REG-0018
```

## Provenance

Every regression links back to the chain that justifies it:

```
Assessment → Finding → Experiment → Control → Retest → Regression → Regression Run → Evidence
```

## Open-source limitations

The Community edition supports **manual** regression execution only. The
following are intentionally **out of scope** (future commercial layer):

- scheduling / cron / background runners / continuous validation
- regression history, trends, posture timelines, cross-version comparison
- notifications (Slack / email / webhooks)
- team/centralized regression management
- CI/CD pipeline integration, release gates
- professional / executive reporting

A regression failure is visible only in local execution/UI. Assessment is an
aggregator and does **not** decide regression PASS/FAIL; a regression result does
**not** silently rewrite Finding history.
