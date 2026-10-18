# Orion

> Orion is an **evidence-driven AI security experimentation framework** for
> Traditional ML, Generative AI and Agentic AI systems. It turns system context
> and threat models into controlled security experiments, measures attack impact,
> validates defensive controls through retesting, and preserves the evidence chain.

Orion does not exist to prove that AI can fail. It exists to **understand how it
fails, measure the failure, and improve the system before an adversary does.**

A central design principle: **model/agent compromise is not the same as system
security impact.** An agent can be influenced by a prompt injection, but the
finding is the *observable boundary crossing* it causes — and a control is only
proven by retesting the same experiment.

![Orion Demo](demo.gif)

---

## 1. What is Orion?

Orion is a hands-on framework for running security experiments against AI systems
across three families — **Traditional ML, Generative AI, Agentic AI** — under one
methodology, so results are coherent, reproducible, measurable and evidence-driven,
usable by red teams, blue teams and researchers.

### Security experiment families

```
Traditional ML
├── FGSM
├── PGD
├── C&W
└── Black-box Evasion

Generative AI
├── Direct Prompt Injection
└── Indirect Prompt Injection

Agentic AI
└── Tool / Privilege Abuse
```

Only executable attacks are listed; roadmap techniques are not claimed as present.

Orion is used in the talk *"Building Orion: Un framework para romper y defender
modelos de IA."*

## 2. Why Orion exists

Most AI-security demos stop at a screenshot of a misclassified image. Orion
insists on the harder, more useful questions: *Against which adversary? By how
much did the model degrade? Does a defense actually help when the same attack is
replayed?*

> **An attack algorithm without a threat model is only an experiment.**

## 3. Methodology

Orion is an **evidence-driven AI security experimentation framework**. One
methodology spans every family it supports — Traditional ML, Generative AI and
Agentic AI — organised into four phases:

```
UNDERSTAND          Know Yourself · Know Your Target · Know the Environment
                                        ↓
                    Analysis Context → Threat Model → Experiment Plan
                                        ↓
                              ⟨ Human Approval ⟩
                                        ↓
OPERATIONS          Attack → Measure → Defend → Retest
                                        ↓
ANALYSIS            Finding   (the security interpretation of the evidence)
                                        ↓
OBSERVABILITY       Evidence  (provenance chain: what happened, and why)
```

| Phase | What happens | Package |
| --- | --- | --- |
| **Understand** | Build **Self, Target and Environment** context → Analysis Context | `orion.know_yourself`, `orion.target_analysis`, `orion.context` |
| Threat Model | Define assets, adversary, surfaces (from all 3 profiles) | `orion.threat_model` |
| Experiment Plan | Select applicable attack hypotheses; **human approves** | `orion.plans` |
| **Attack** | Run a controlled, justified attack (any family) | `orion.experiments`, `orion.adversarial`, `orion.agentic` |
| Measure | Quantify impact with **family-aware** metrics | `orion.metrics`, `orion.catalog.metrics` |
| Defend | Apply a candidate **control** (not yet validated) | `orion.defenses`, `orion.catalog.controls` |
| Retest | Replay the same attack under the new posture; compare | `orion.experiments` |
| **Finding** | Interpret the evidence as a security finding | `orion.findings` |
| **Evidence** | Preserve the full provenance chain | `orion.evidence` |

Every attack, metric and control is defined once in the **unified catalog**
(`orion.catalog`) and reused by applicability, planning, execution, metrics and
remediation. See [Unified Catalog](#unified-catalog), [GenAI / Agentic
experiments](#genai--agentic-experiments) and [Findings](#findings).

Full write-up: [docs/methodology.md](docs/methodology.md).

## The Three Context Pillars

Understanding is built from three **distinct** pillars, each producing a reusable
profile. They are independent and compose progressively (any one may be absent).

### Know Yourself
Understand the AI system itself → **Self Profile** (`orion.know_yourself`).
Traditional ML (model-centric) or Generative AI (system-centric).

### Know Your Target
Define *what* is being assessed and *why* → **Target Profile**
(`orion.context.target`). It **consumes** Self and Environment profiles; it does
not own or duplicate reconnaissance.

### Know the Environment
Map the terrain *around* the target → **Environment Profile**
(`orion.context.environment`): assets, technologies, external & **AI
dependencies**, MCP/tool ecosystem, identity context, trust relationships and a
lightweight topology. **Recon is a data source that populates this profile** — it
is not the environment model.

These profiles converge into an **Analysis Context** (`orion.context`) at
`/context` — pick any combination of Self / Target / Environment (any may be
absent), **[ RUN AGENT ANALYSIS ]** correlates them into a **source-aware** threat
model and applicability (each conclusion tagged `SELF` / `TARGET` /
`ENVIRONMENT`), then **[ APPROVE PLAN ]** hands off to Attack with the full
context (`analysis_context_id`, `self_profile_id`, `target_profile_id`,
`environment_profile_id`) preserved end-to-end. It drives threat modeling and
experiment planning:

```
KNOW YOURSELF ─┐
KNOW YOUR TARGET ─┼─▶ ANALYSIS CONTEXT ─▶ THREAT MODEL ─▶ EXPERIMENT PLAN
KNOW THE ENVIRONMENT ─┘        ↓ HUMAN APPROVAL ↓
                        ATTACK ─▶ MEASURE ─▶ DEFEND ─▶ RETEST ─▶ EVIDENCE
```

> Know Yourself describes the system. Know Your Target defines the objective.
> Know the Environment maps the terrain. Orion correlates the evidence. Humans decide.

## 4. Architecture

```
app.py                     # lightweight Flask web/application layer (routes only)
orion/                     # the methodology framework (logic lives here)
  methodology.py           #   the six phases as code
  threat_model/            #   assets, adversary, boundaries, scenario (no LLM)
  scenarios/               #   YAML scenario loader + validation
  metrics/                 #   reusable metric interfaces
  experiments/             #   scenario -> attack -> measure -> evidence (+ synthetic backend)
  evidence/                #   trace ids, experiment.json, report.md, statuses
  defenses/                #   pluggable hardening mechanisms
  mappings/                #   curated MITRE ATLAS index
  policies/                #   human-oversight / approval (fail closed)
  adversarial/             #   structured adversarial-image experiment (wraps libs.adversarial)
  agents/                  #   agent copilots + boundary guards (wraps libs.agent)
  recon/                   #   'Know the Environment' (wraps libs.recon)
  integrations/            #   Flask blueprint exposing the methodology
libs/, tools/              # existing implementations (preserved)
scenarios/                 # scenario files (e.g. pgd_evasion.yaml)
docs/                      # methodology, agent-role, attack-replay, limitations
tests/security_cases/      # security regression tests
artifacts/                 # generated evidence (git-ignored)
```

Business logic stays out of Flask routes; routes call into `orion.*`.

## 5. Threat model

Threat models are structured, LLM-independent objects
(`orion.threat_model.ThreatModel`) describing the target, the adversary
(knowledge / access / goal / budget / constraints), the assets at stake, and the
attack surfaces. See [docs/methodology.md](docs/methodology.md#2-threat-model--define-the-adversary).

## 6. Adversarial ML

The classic Carlini & Wagner / PGD image flow is preserved and now returns
**both** a visual artifact and measurable evidence
(`orion.adversarial.generate_adversarial_evidence`):

```json
{
  "attack": "PGD",
  "baseline_prediction": "stop_sign",   "baseline_confidence": 0.997,
  "adversarial_prediction": "speed_limit_30", "adversarial_confidence": 0.913,
  "perturbation_linf": 0.028, "attack_success": true
}
```

A deterministic, dependency-free synthetic backend runs the same methodology
without a GPU (used by the CLI and tests).

## 6b. Know Yourself — AI security profiling

> What exactly do I have, how does it behave, what assumptions does it make,
> how fragile is it, and which experiments are actually applicable?

**Know Yourself** (`/know-yourself`) characterizes an AI system *before* any
attack (profiling only — execution belongs to the Attack phase). It auto-detects
the branch and never mixes their security assumptions:

- **Traditional ML** (model-centric): model fingerprint (framework, task,
  input/output, access, gradients, artifact hash/size), input/feature surface,
  model assumptions (`OBSERVED` / `INFERRED` / `UNKNOWN`), control inventory, and
  a robustness-oriented security posture.
- **Generative AI** (system-centric): system fingerprint (provider, RAG, memory,
  tools, MCP, external actions, human approval), prompt/context surface
  (`TRUSTED` / `UNTRUSTED` / `MIXED` / `UNKNOWN`), **trust-boundary inventory**,
  tool/MCP and identity profiles, and a control inventory.

The **security posture** lists each attack as `APPLICABLE` / `CONDITIONAL` /
`NOT_APPLICABLE` with rationale, evidence and prerequisites, using deterministic
rules (white-box gradients → PGD/FGSM/C&W/DeepFool applicable; black-box →
conditional; prompt injection requires an LLM surface; RAG poisoning requires
retrieval; tool/MCP poisoning requires a tool/MCP surface). It then proposes
**recommended next experiments** — proposals only, sent to the Attack phase on
human review, never auto-executed. `UNKNOWN` is a valid answer and never becomes
`NOT_FOUND`. Results export to `artifacts/<trace_id>/know_yourself.json`.
`orion/know_yourself/` keeps the two branches in separate modules.

## 6c. The Experiment lifecycle

> **Analysis proposes. Humans approve. Humans execute.
> Approve Plan ≠ Run Attack. Defense applied ≠ defense effective.
> Retest determines whether posture improved.**

Context pillars end with **[ APPROVE PLAN ]**, which builds a shared
`ExperimentPlan` (`orion/plans/`), records human approval and produces a handoff —
*without executing anything*. **[ OPEN EXPERIMENT ]** then opens the single
**Experiment workspace** (`/experiment/<id>`), a stateful console that runs the
whole lifecycle as **one continuous workflow** (not five separate apps):

```
PLAN → ATTACK → MEASURE → DEFEND → RETEST
```

`ExperimentLifecycle` (`orion/experiments/lifecycle.py`, persisted to
`artifacts/<ORN-EXP-id>/workspace.json`) tracks the stage states, the active
experiment (queue), and `attack_run_id / measurement_id / defense_id /
retest_run_id`. Transitions are **deterministic and fail-closed** (no attack
before an approved plan; no measure before attack; no retest before an applied
defense), and a deterministic next-action engine drives the UI — never the LLM.
The ATTACK stage starts from the **attacker's access level**, which is the
operational form of the threat model's `adversary.knowledge` and is **derived**
from the plan's origin — Know Yourself (you own the model) → **white-box** weights;
an external live service → **black-box** query-only — then shown for the analyst to
**confirm or override** (never a silent decision). The chosen level drives an
**attack catalog** (`orion/adversarial/catalog.py`), each entry shipping **base
tuning** so a run is one click away while every parameter stays editable:

* **White-box** → real gradient attacks (torch + ART) on the weights:
  **C&W (L2)**, **PGD (L∞)**, **FGSM** — `orion.adversarial.run_adversarial_experiment`.
  The class count is **inferred from the checkpoint** (`infer_num_outputs`), not
  demanded from the user.
* **Black-box** → **decision-based query evasion**
  (`orion.adversarial.run_blackbox_evasion`): L∞-bounded perturbed inputs to the
  live endpoint, measuring the decision change under a bounded query budget.

A **demo runner** (synthetic robustness via `scenarios/pgd_evasion.yaml`,
reproducible without a GPU) remains for the no-weights/no-GPU path. Attack
execution stays **explicit** (`[ RUN ATTACK ]`, with a confirm step before any
real queries to a live endpoint). Image attacks then render the
[Image Attack Comparison](#image-attack-comparison) immediately. Retest replays the **same attack**
under the new posture and the BEFORE/AFTER comparison is a *result* of retest.
Provenance links the whole chain
(`self → target → environment → context → threat_model → plan → experiment →
run → defense → retest`). Legacy `/attack`, `/measure`, `/defend` reuse this one
workspace (no parallel UX); **Evidence** stays globally accessible.

## Image Attack Comparison

When an attack operates on images, Orion shows the attack the way an analyst
reasons about it — **side by side**:

```
ORIGINAL            ADVERSARIAL          PERTURBATION / DIFFERENCE MAP
prediction: cat     prediction: dog      L∞ = 0.0312  ·  L2 = 1.456
confidence: 0.98    confidence: 0.71     absolute difference  [ amplify ]
```

The third panel is the **perturbation / difference map** (`|adversarial −
original|`), never a "mask" unless a real segmentation mask exists. The
comparison is a **reusable, type-aware artifact**, not a one-off view:

* **One source of truth.** A single Jinja component
  (`templates/components/image_attack_comparison.html`) renders it server-side on
  **Evidence** (`/runs/<id>`), and the matching client renderer
  (`Orion.imageComparison`) renders the *identical* markup inside the Experiment
  console at the **Attack**, **Measure** and **Retest** stages — so it appears
  **immediately after an image attack runs**, not only in Evidence.
* **Type-aware.** Tabular, text, agentic and network experiments carry no image
  artifacts, so the component renders **nothing** for them — no empty panels.
* **Honest semantics.** The prediction change is explicit (**CLASSIFICATION
  CHANGED** vs **ATTACK FAILED / UNCHANGED**), and attack success comes from the
  experiment's own metric (`attack_success`), **not** from how different the
  images look.
* **Display vs measurement.** Images are denormalized/clipped **for display
  only**; the reported `perturbation_linf` / `perturbation_l2` are the **raw**
  metric values, shown verbatim. The **[ amplify ]** control scales the
  difference image ×8 **for visibility only** (labelled display-only) and never
  touches the numbers. Click any panel to inspect the raw artifact.
* **Retest before/after.** Retest shows the original adversarial example
  *before* defense and the hardened replay *after*; if the hardened replay
  produced no new image, it says **NO NEW IMAGE ARTIFACT** rather than
  fabricating one.
* **Conference mode.** Append `?demo=1` to make the comparison prominent.

## Unified Catalog

Attacks, metrics and controls are each defined **once** in `orion.catalog` and
referenced everywhere (applicability, threat modelling, planning, execution,
metrics, remediation) — no duplicated metadata across the app.

* **Attacks** (`orion.catalog.attacks`) — one `AttackDefinition` per technique,
  across three families, with a common schema (`family`, `applicable_targets`,
  `required_capabilities`, `required_access`, `parameters`, `success_criteria`,
  `supported_metrics`, `recommended_controls`, `framework_mappings`):

  ```
  Traditional ML   FGSM · PGD · C&W · Black-box Evasion
  Generative AI    Direct Prompt Injection · Indirect Prompt Injection
  Agentic AI       Tool Poisoning · Privilege / Tool Abuse
  ```

* **Metrics** (`orion.catalog.metrics`) — each declares its family and whether
  higher or lower is *better*, so Measure renders per experiment type and
  before/after retests are scored consistently (image L∞/robust-accuracy;
  GenAI refusal/policy-violation/instruction-following; agentic
  unauthorized-tool-call/privilege-boundary/approval-bypass rates).
* **Controls** (`orion.catalog.controls`) — replayable defenses incl. the
  agentic ones (`tool_authorization`, `least_privilege`, `destination_allowlist`,
  `instruction_provenance`, `context_isolation`, `human_approval`).

The adversarial **access-level** chooser (white-box vs black-box) is a thin
projection of this catalog, not a second copy.

## GenAI / Agentic experiments

Orion runs **real, controlled** GenAI/agentic experiments through a tool-enabled
agent (`orion.agentic.agent`) whose **tool selection comes from a model** reading
its context — not a fabricated constant. The default model is a deterministic
instruction-following interpreter (testable); a live LLM can be plugged in. Tool
calls and authorization decisions are observable, and verdicts come from the
catalog's **executable success criteria**, never asserted.

* **Direct Prompt Injection** (`ORN-ATTACK-PI-001`) — the malicious instruction
  arrives through the **user channel**; trust boundary `User Input → Instruction
  Boundary → LLM / Agent`. Its evidence contains **no retrieved resource**.
  (`orion.agentic.run_direct_prompt_injection`; also runnable live against a real
  endpoint via `orion.agentic.run_live_prompt_injection` with the OWASP payload catalog.)
* **Indirect Prompt Injection** (`ORN-ATTACK-PI-002`) — a benign user request plus
  **untrusted retrieved content** carrying a hidden instruction; trust boundary
  `External Content → Retrieval → Trusted Agent Context → Agent Reasoning → Tool
  Authorization → Privileged Capability`. The flagship scenario: the agent is
  influenced to call `admin_export`, and in a vulnerable configuration the
  authorization boundary is crossed and the tool executes.
  (`orion.agentic.run_indirect_prompt_injection`.)
* **Tool / Privilege Abuse** (`ORN-ATTACK-AG-002`) — influenced reasoning attempts
  a tool above the agent's privilege. Trace captures `requested_tool`,
  `agent_identity`, `required_privilege`, `effective_privilege`,
  `authorization_decision`, `tool_executed`.

**Influence is not impact.** Orion separates *the agent was influenced* from *a
security boundary was crossed*: under `tool_authorization` the agent is still
influenced (it requests `admin_export`) but the call is **denied**, the tool does
**not** execute, and the attack-success criteria are not met — demonstrating
defense-in-depth. Controls are also split into **definition vs implementation**
(`orion.catalog.controls`): a gateway injection filter is a `PARTIAL`
implementation of instruction provenance, never claimed as full coverage. Applying
a control never auto-mitigates a finding; only a **retest** of the same experiment
sets control effectiveness. Every trace component carries provenance
(`source` / `type` / `run_id`), shown under **Evidence**.

### Live endpoint extension

Discovered AI endpoints are **targets for a later step**. When analysis reads a
service's OpenAPI schema (or elicits an inference response), each AI/LLM endpoint
(e.g. `/api/chat`) is recorded as an `ai_endpoint` and carried through to the
Experiment Workspace. The ATTACK stage then offers a **LIVE TARGET** option that
runs a real prompt injection against that endpoint
(`orion.agentic.run_live_prompt_injection`) — the GenAI analogue of the
decision-based black-box image runner. Success is detected with a unique
**canary** token (the injected instruction asks the model to echo it), so
"the instruction was followed" is observable **without knowing any server-side
secret**, and the result is honest (if the model refuses, the run is
`ATTACK_BLOCKED`). Retest can apply a client-side **prompt-injection input
filter** (what `instruction_provenance` / `context_isolation` mean for a live
endpoint) and replay the same attack for a real before/after.

Payloads come from an **OWASP LLM Top 10 catalog** (`orion.agentic.payloads`):
direct/indirect injection and jailbreak (LLM01), system-prompt leakage (LLM07),
sensitive-information disclosure (LLM06), insecure output handling (LLM02) and
excessive agency (LLM08). A run can be filtered to one category, and the result
records a **per-OWASP breakdown**. Success is counted when the model echoes the
canary **or** a non-refusing response shows technique-specific compliance (e.g.
it actually reveals its system prompt) — conservative, and visible in the trace.
Against a real OWASP LLM lab this yields an honest per-category score (e.g. system
prompt leakage and insecure output confirmed, naive direct injection refused).

## Findings

A **Finding** (`orion.findings`) is Orion's *security interpretation* of the
evidence — a first-class object, not the evidence itself:

```
Evidence = what happened.      Finding = the security meaning of what happened.
```

A successful attack produces an **OBSERVED** finding. Promotion to **CONFIRMED**
requires a **corroboration policy** (`orion.findings.CorroborationPolicy`,
default: `minimum_trials=3`, `minimum_success_rate=0.66`, independent runs) to be
met across *independent* experiment runs that reproduced the same success
criterion against the same target — two evidence refs alone never confirm. A
finding records `severity`, `confidence`, `boundary_crossed` (inherited from the
attack's trust boundary), `observed_action`, the `evidence_refs` behind it,
`corroboration` metadata, `recommended_controls` and `framework_mappings`. After a
retest, its `retest_status` is set from the measured before/after
(`INEFFECTIVE` / `PARTIALLY_EFFECTIVE` / `EFFECTIVE`), moving the finding to
`MITIGATED` / `PARTIALLY_MITIGATED` or leaving it unmitigated. The structured
classification is deterministic (from evidence + criteria), not LLM-generated.
Findings live under their own **Findings** view with full provenance; the Evidence
screen is not overloaded with this responsibility.

Confirmation is **per-criterion**: a Finding becomes `CONFIRMED` only when a
specific security criterion was *independently reproduced* across the required
runs — never because different criteria happened in different runs. Legacy
Findings without per-criterion evidence load fine and read as `UNKNOWN / LEGACY`.

## Security Regressions

A verified mitigation can become a **Security Regression Test** — a deterministic,
evidence-backed security property an operator can manually re-validate later:

```
Finding → Control → Retest → Verified Mitigation → Manual Security Regression
```

A Security Regression asks *"does the previously validated security behavior still
hold?"*, not *"did the attack succeed?"*. It preserves Orion's core distinction:
the agent may remain influenceable, but the **security boundary** (e.g. tool
authorization) must stay effective — so a regression can `PASS` even while the
agent is still influenced. Created only from an **EFFECTIVE** retest, it re-runs
the same attack under the control (reusing the existing experiment/run/evidence
system), compares observed vs expected security state, and returns
**PASS / FAIL / ERROR** (missing evidence is never PASS). Execution is **manual**
(`[ RUN REGRESSION ]` or `orion regression run ORN-REG-…`); scheduling, history,
trends and notifications are intentionally out of scope. See
[docs/security-regressions.md](docs/security-regressions.md).

## 7. AI agents

Agents are **copilots, not oracles**: they plan and explain; metrics and
experiments decide the result. Boundaries are enforced in code. See
[docs/agent-role.md](docs/agent-role.md).

## 8. Know the Environment (`/environment`)

The third context pillar. Reconnaissance (Playwright, Nuclei, MCP tools, SSE,
mock mode, approvals, screenshots, reports) is **one capability** here — a data
source that populates the **Environment Profile** (assets, technologies, external
& AI dependencies, MCP/tools, identity, trust relationships, topology). Build a
profile from a completed recon run or a direct URL probe, then
**[ SEND TO TARGET ANALYSIS ]** passes the `environment_profile_id` onward — no
data is copied by hand.

## 8b. Know Your Target — evidence-grounded Target Analysis

> **Recon collects. Orion interprets. Humans decide.**

The **Know Your Target** workflow (`/target-analysis`) defines the Target Profile
and interprets evidence (from a recon run, a direct probe, or a loaded
**Environment Profile**), following the core principle:

> **Evidence → applicability → hypothesis → test → finding** (never
> *generic knowledge → finding*).

It **consumes** the Environment Profile (`?environment_profile_id=…`); it does not
own reconnaissance. Preferred flow: **Environment Profile → Analyze → Threat
Model → Experiment Plan → Human review**.

Every conclusion is classified `OBSERVED` / `INFERRED` / `HYPOTHESIS` /
`NOT_APPLICABLE`, carries evidence references + confidence + rationale, and is
checked by a deterministic validation layer (`orion.target_analysis`). A
hypothesis is never promoted to a finding; a suggested experiment is not evidence
of a vulnerability.

### AI Surface Detection

AI-specific threats are only surfaced when recon actually observed an AI/ML
surface. Detection is deterministic and strength-scored:

- **STRONG signals** (confirm on their own): classic ML model-serving routes
  (`/v1/models`, `/v2/models`, `/invocations`) and stacks (TensorFlow Serving,
  TorchServe, Triton, KServe, BentoML, MLflow, scikit-learn/XGBoost); LLM routes
  (`/v1/chat/completions`, `/v1/embeddings`); SDKs (OpenAI/Anthropic/LangChain);
  MCP server metadata; model artifacts (`.pt`, `.pth`, `.onnx`, `.safetensors`,
  `.joblib`); and prediction-shaped JSON responses (`predictions` /
  `probabilities` / `logits` / `softmax` / `signature_name`).
- **MEDIUM signals** (need corroboration): `/predict`, `/inference`, `rag`,
  `embedding`, `vector database`, `machine learning`, chatbot/assistant UIs.
- **WEAK signals** (never confirm alone): generic `/chat`, `/model`, `/tool`,
  `/assistant`, bare "ai"/"chat" text.

Classification: `CONFIRMED` = ≥1 strong **or** ≥2 medium; `POSSIBLE` = 1 medium
or ≥2 weak; `NOT_OBSERVED` otherwise. A lone weak route (`/chat`, `/model`, …)
can **never** confirm AI. For a traditional web app, Orion reports
`AI SURFACE: NOT_OBSERVED`, maps **no** ATLAS techniques, and **abstains** —
"insufficient evidence to determine whether this target exposes an AI/ML attack
surface" — which is a useful result, not a failure. Generic web findings
(WordPress, login forms, APIs) are **never** converted into prompt injection,
model extraction, adversarial ML or RAG poisoning without AI-specific evidence.

> **Recon is real by default** for live, reproducible results. **Know The
> Environment → Live Recon** connects to the target now (GET + an optional
> harmless active test request) and normalizes the response into the Environment
> Profile (`POST /api/environment/from-url {"url":…, "active":true}`) — no mock,
> no LLM dependency. `--mock` is an opt-in safe simulation (deterministic
> fixtures that never reach the target, so it yields `NOT_OBSERVED` on a real
> app). The active probe only applies to systems you are authorized to test.

### Honest threat model

Orion does not invent adversary properties. Only what recon can establish is
marked `[OBSERVED]` (e.g. network reachability → `REMOTE_PUBLIC`); goal,
knowledge and budget default to `UNDEFINED` / `UNKNOWN` and require analyst
input.

## 9. MITRE ATLAS

Orion uses **MITRE ATLAS** for AI-specific threats (and only references MITRE
ATT&CK where a real ATT&CK mapping exists). Scenarios declare ATLAS mappings;
unknown technique IDs are flagged as unverified rather than invented
(`orion.mappings`).

## 10. Evidence

Every run writes `artifacts/<trace_id>/` with `experiment.json`, `report.md`
and images. Statuses: `NO_ATTACK`, `ATTACK_SUCCESS`, `ATTACK_BLOCKED`,
`PARTIALLY_MITIGATED`.

## 11. Attack replay

Replay the same attack before and after hardening and compare. See
[docs/attack-replay.md](docs/attack-replay.md).

## 12. Quick start

```bash
git clone https://github.com/urcuqui/orion.git
cd orion
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # full stack (torch, langgraph, ...)
# For just the methodology + CLI + tests you only need pyyaml + pytest:
# pip install pyyaml pytest

# Run the methodology end-to-end (no GPU required):
python -m orion run scenarios/pgd_evasion.yaml --mode baseline
python -m orion run scenarios/pgd_evasion.yaml --mode attack
python -m orion replay <attack_trace_id> --mode hardened
python -m orion compare <attack_trace_id> <hardened_trace_id>

# Or launch the web UI:
python app.py   # http://localhost:5000
```

## 13. Scenarios

Scenarios are declarative YAML that bind the whole methodology together
(target, adversary, attack, metrics, defenses, ATLAS mappings). Example:
[scenarios/pgd_evasion.yaml](scenarios/pgd_evasion.yaml). Validate one with
`python -m orion validate scenarios/pgd_evasion.yaml`.

## 14. Web UI

The Flask/Jinja UI is an **AI Security Validation Workspace** with a persistent
sidebar, terminal path header, Analyst/Classic appearance modes and a decorative
Orion Sentinel. Analyst keeps operational screens clear; Classic adds restrained
terminal personality. Appearance never changes execution or security state.

Navigation retains the Art of War structure:

- **OVERVIEW** — assessment summary, Next Action, posture, profiles and activity.
- **ASSESS** — **Assessments**, System (Know Yourself), Target (Know Your Target),
  Environment (Know the Terrain), Analysis (Understand the Battlefield).
- **VALIDATE** — Experiments (PLAN → ATTACK → MEASURE → DEFEND → RETEST) and Findings.
- **OBSERVE** — Runs (what executed) and Evidence (records/artifacts proving it).

An Experiment validates one hypothesis. An **Assessment** coordinates several
experiments over a defined system, target and scope. Create one at `/assessments`,
link analysis/plans/workspaces or create linked workspaces from existing plans,
and review factual Findings, controls, Retests and provenance. Assessment
completion is an analyst declaration, **not a secure-system verdict**. Existing
standalone experiments still work. See [Assessments](docs/assessments.md) for the
model, APIs, relationship semantics and foundation limits.

Conference mode (`?demo=1`) retains the existing Classic/demo presentation.

The Flask app is preserved: adversarial image generation, AI chat, streaming
(SSE), and the reconnaissance workflow with human approval. The methodology is
also exposed under `/orion/*` and a JSON API under `/api/*` (`/api/runs`,
`/api/agent/analyze-recon`, `/api/recon/runs`, …). Legacy URLs such as
`/red-pill.html` redirect to the current Red Team landing page.

## 15. CLI

```bash
python -m orion list
python -m orion run <scenario.yaml> [--mode baseline|attack|hardened]
python -m orion replay <trace_id> [--mode ...]
python -m orion report <trace_id>
python -m orion compare <baseline_trace> <hardened_trace>
python -m orion validate <scenario.yaml>
```

## 16. Limitations

Orion measures failure under specific conditions; it does not certify security.
Read [docs/limitations.md](docs/limitations.md) before drawing conclusions.

## 17. Responsible use

This project is for research and education. Use it only against systems you are
authorized to test. Sensitive actions require human approval and fail closed.
Report results honestly, always stating the threat model and limitations.

---

Christian Camilo Urcuqui López
