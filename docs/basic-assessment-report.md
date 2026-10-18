# Basic Assessment Report

Export the factual, evidence-backed state of an Orion Assessment as **Markdown**
and **JSON**. This is the final planned Orion Community feature:

```
Assessment + Manual Security Regression Tests + Basic Assessment Report
```

is the OSS product boundary. Everything beyond it belongs to the future
commercial layer (see [Community boundary](#community-boundary) below).

## Purpose

> Export the factual, evidence-backed state of an Assessment, in both
> human-readable and machine-readable form.

The report is a **representation layer**, not a second security engine. It
never computes a new Finding, severity, corroboration result, control
effectiveness or Regression outcome — it reshapes and renders state that
Orion's existing domain logic already produced.

## Report model

```
Existing Orion State
        |
Normalized AssessmentReport (orion.reports.assessment.AssessmentReport)
        |
   +----+----+
Markdown     JSON
Renderer     Renderer
```

`build_assessment_report(assessment_id, base_dir)` builds one
`AssessmentReport` dataclass. `render_markdown(report)` and
`render_json(report)` both render **that same object** — there is no
format-specific domain logic. `write_report(report, format, base_dir)` writes
the rendered content to disk; nothing else is written.

The model reuses `AssessmentService.summary()` — the same deterministic,
partial-tolerant aggregation the Assessment Detail page already uses — for
profiles, experiments, findings and controls, and adds the two things that
summary doesn't carry: Manual Security Regressions and a normalized evidence
index / provenance view.

### Top-level fields

```
report_version, generated_at,
assessment, scope,
profiles, analysis_context, threat_models, plans,
experiments, findings, controls, retests, security_regressions,
posture_summary,
evidence_index, provenance,
unknowns, unavailable_references
```

## Markdown format

`assessment-report.md` — one document per Assessment, organized as:

```
# Orion AI Security Assessment Report
## Assessment
## Scope
## System / Target / Environment
## Analysis Context
## Threat Models
## Plans and Experiments
## Findings
## Controls and Retests
## Manual Security Regressions
## Current Factual Posture
## Evidence Index
## Provenance
## Unknowns and Unavailable References
## Limitations
```

Written for research / security review / technical handoff / as a Git
repository artifact — headings and tables, no decoration, no executive tone.

## JSON format

`assessment-report.json` is `json.dumps(report.to_dict(), indent=2)` of the
exact same `AssessmentReport` — nothing format-specific is added or omitted.
Field order is deterministic (dataclass declaration order + sorted list
construction), so the same underlying Assessment state produces the same JSON
except for `generated_at`.

## What is included

| Section | Source | Note |
| --- | --- | --- |
| Findings | `Finding.to_dict()` via `FindingStore` | includes the full `corroboration` structure (`per_criterion`, `criteria_reproduced`, `confirmation_eligible`, `legacy`, …), never reduced to "confirmed: yes/no" |
| Controls | `AssessmentService.summary()['control_records']` | `applied_status` is always `APPLIED`; **never** `EFFECTIVE`/`MITIGATED` — that belongs to Retests |
| Retests | one row per `Finding.retest_refs` entry | `result` is `Finding.retest_status` as-is (`EFFECTIVE` / `PARTIALLY_EFFECTIVE` / `INEFFECTIVE` / `UNKNOWN`) — never recomputed |
| Security Regressions | `RegressionRepository.list()` filtered by `assessment_id` | `latest_result` only (`PASS` / `FAIL` / `ERROR` / `NOT_RUN`) — **no** execution history, no pass-rate, no trend |
| Evidence Index | run IDs referenced by experiments/findings/regressions | references only, never raw trace payloads |

## Security semantics preserved

The report must never imply a verdict the underlying state doesn't support.
Explicitly preserved:

```
Assessment lifecycle status  ≠  security verdict (COMPLETED is not SECURE)
No Findings                  ≠  no vulnerabilities
Control Applied               ≠  Effective (effectiveness is a Retest's result)
Regression PASS               ≠  "the model cannot be influenced"
```

There is **no** Security Score, Risk Score, posture rating (A/B/C), or
SECURE/INSECURE verdict anywhere in the report. `posture_summary` is counts of
existing recorded state only; users interpret the evidence.

## UNKNOWN semantics

`UNKNOWN ≠ 0`. A `posture_summary` count is `null`/`None` (and listed under
`unknowns`) whenever one of its supporting references is unresolved — it is
never silently reported as zero.

## Unavailable / corrupt references

Any reference the Assessment carries that cannot currently be resolved (a
missing workspace, a corrupt experiment record, a deleted plan, …) is listed
under `unavailable_references` as `{"type", "id", "reason"}` — it is never
dropped silently and never replaced with fabricated content. Report
generation degrades to a **partial report** for a non-critical missing
reference; it only fails outright if the Assessment itself cannot be loaded.

## Explicit, read-only generation

Report generation is operator-initiated only — `[ MARKDOWN ]` / `[ JSON ]` on
the Assessment Detail page, `POST /api/assessments/<id>/report`, or
`orion assessment report <id> --format ...`. It is never scheduled and never
triggered automatically by another domain mutation. The only write it
performs is the report artifact itself
(`artifacts/<assessment_id>/reports/assessment-report.{md,json}`); Assessment,
Experiment, Finding, Control, Retest, Evidence and SecurityRegression are
never mutated by report generation.

## API

```
GET  /api/assessments/<assessment_id>/report            # read-only JSON preview, writes nothing
POST /api/assessments/<assessment_id>/report             # {"format": "markdown"|"json"} — writes + returns the artifact
```

## CLI

```bash
orion assessment report ORN-ASMT-0042 --format markdown
orion assessment report ORN-ASMT-0042 --format json
```

## Community boundary

After this milestone, Orion Community is feature-complete at:

```
Core AI Security methodology, System/Target/Environment, Analysis Context,
Threat Modelling, Experiment Planning, Human Approval, Experiments, Attacks,
Metrics, Runs, Evidence, Findings, Corroboration, Controls, Retests,
Assessments, Assessment Integrity, Manual Security Regression Tests,
Basic Markdown Assessment Report, Basic JSON Assessment Report.
```

Explicitly **not** in Community (future Orion Pro / Team / Enterprise):
continuous/scheduled regressions, regression history and trends,
cross-assessment comparison, reproducibility bundles, professional/PDF/HTML
reporting, executive reporting, branding/templates, collaboration, approvals,
governance, SSO/RBAC, integrations, notifications, CI/CD automation.
