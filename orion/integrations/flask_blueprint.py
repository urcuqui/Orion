"""Flask blueprints exposing the Orion methodology and evidence to the UI.

- ``orion_bp`` (/orion/*): methodology metadata + scenario/run/compare helpers.
- ``api_bp`` (/api/*): JSON API the frontend consumes (runs, run detail,
  adversarial execution, replay) plus safe evidence-file serving.

Route handlers stay thin: all logic lives in the ``orion`` package. No attack,
metric or evidence logic is recreated here.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from flask import Blueprint, jsonify, request, send_from_directory

from orion.evidence import EvidenceStore
from orion.experiments import compare as compare_traces
from orion.experiments import replay as replay_trace
from orion.experiments import run_scenario
from orion.methodology import PHASES, describe_phase
from orion.scenarios.loader import list_scenarios, load_scenario

orion_bp = Blueprint("orion", __name__, url_prefix="/orion")
api_bp = Blueprint("orion_api", __name__, url_prefix="/api")

ARTIFACT_DIR = "artifacts"


# --------------------------------------------------------------------------- #
# /orion/* — methodology metadata
# --------------------------------------------------------------------------- #
@orion_bp.get("/methodology")
def methodology():
    return jsonify({
        "phases": [{"phase": p.value, "order": p.order, "description": describe_phase(p)} for p in PHASES],
        "principle": "An attack algorithm without a threat model is only an experiment.",
    })


@orion_bp.get("/scenarios")
def scenarios():
    return jsonify({"scenarios": list_scenarios("scenarios")})


@orion_bp.post("/run")
def run():
    payload = request.get_json(silent=True) or {}
    scenario_path = payload.get("scenario")
    mode = payload.get("mode", "attack")
    if not scenario_path:
        return jsonify({"error": "scenario is required"}), 400
    try:
        scenario = load_scenario(scenario_path)
        record = run_scenario(scenario, mode=mode)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 400
    return jsonify(record.to_dict())


@orion_bp.get("/compare")
def compare():
    before = request.args.get("before")
    after = request.args.get("after")
    if not before or not after:
        return jsonify({"error": "before and after trace ids are required"}), 400
    try:
        result = compare_traces(before, after)
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify(result)


# --------------------------------------------------------------------------- #
# /api/* — JSON API consumed by the frontend
# --------------------------------------------------------------------------- #
@api_bp.get("/scenarios")
def api_scenarios():
    return jsonify({"scenarios": list_scenarios("scenarios")})


@api_bp.get("/runs")
def api_runs():
    return jsonify({"runs": EvidenceStore(ARTIFACT_DIR).list_summaries()})


@api_bp.get("/runs/<trace_id>")
def api_run_detail(trace_id):
    store = EvidenceStore(ARTIFACT_DIR)
    try:
        record = store.load(trace_id)
    except FileNotFoundError:
        return jsonify({"error": "unknown trace_id"}), 404
    data = record.to_dict()
    # Attach a rendered Markdown report if present.
    report = store.trace_dir(trace_id) / "report.md"
    data["report_markdown"] = report.read_text(encoding="utf-8") if report.exists() else None
    return jsonify(data)


@api_bp.post("/replay/<trace_id>")
def api_replay(trace_id):
    payload = request.get_json(silent=True) or {}
    mode = payload.get("mode")
    try:
        record = replay_trace(trace_id, mode=mode, base_dir=ARTIFACT_DIR)
    except FileNotFoundError:
        return jsonify({"error": "unknown trace_id"}), 404
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 400
    return jsonify(record.to_dict())


@api_bp.post("/scenario-run")
def api_scenario_run():
    """Run a synthetic scenario (baseline/attack/hardened) — no GPU required."""
    payload = request.get_json(silent=True) or {}
    scenario_path = payload.get("scenario", "scenarios/pgd_evasion.yaml")
    mode = payload.get("mode", "attack")
    try:
        record = run_scenario(load_scenario(scenario_path), mode=mode, base_dir=ARTIFACT_DIR)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 400
    return jsonify(record.to_dict())


@api_bp.post("/adversarial/run")
def api_adversarial_run():
    """Run the real (torch + ART) adversarial-image attack and save evidence.

    Accepts either a multipart upload (weights + image + numberoutputs) or a
    JSON body ``{"preset": true}`` that uses bundled local demo assets. Never
    fabricates a result: if torch/ART are unavailable it returns a clean error.
    """
    from orion.adversarial import TORCH_AVAILABLE, run_adversarial_experiment

    if not TORCH_AVAILABLE:
        return jsonify({"error": "torch/ART unavailable on this host; adversarial demo disabled.",
                        "status": "ERROR"}), 503

    tmpdir = None
    try:
        json_body = request.get_json(silent=True) or {}
        if json_body.get("preset") or json_body.get("weights_path"):
            # Preset / Know-Yourself hand-off: run a local model artifact without
            # re-upload. Paths are validated to stay inside weights/ and static/.
            weights_path = json_body.get("weights_path") or "weights/vit_teacher.pth"
            num_outputs = int(json_body.get("num_outputs") or 2)
            image_path = json_body.get("image") or "static/fake/0001_00_00_01_0.jpg"
            weights_dir = (Path.cwd() / "weights").resolve()
            static_dir = (Path.cwd() / "static").resolve()
            wp = (Path.cwd() / weights_path).resolve()
            ip = (Path.cwd() / image_path).resolve()
            if weights_dir not in wp.parents or not wp.exists():
                return jsonify({"error": f"weights must be an existing file under weights/ ({weights_path})",
                                "status": "ERROR"}), 400
            if static_dir not in ip.parents or not ip.exists():
                return jsonify({"error": f"image must be an existing file under static/ ({image_path})",
                                "status": "ERROR"}), 400
            weights_path, image_path = str(wp), str(ip)
        else:
            weights = request.files.get("weights")
            image = request.files.get("file")
            if not weights or not image:
                return jsonify({"error": "weights and image files are required",
                                "status": "ERROR"}), 400
            num_outputs = int(request.values.get("numberoutputs") or 2)
            # Weights load from weights/<name> (matches existing behaviour).
            Path("weights").mkdir(exist_ok=True)
            weights_path = str(Path("weights") / Path(weights.filename).name)
            weights.save(weights_path)
            tmpdir = tempfile.mkdtemp(prefix="orion_adv_")
            image_path = str(Path(tmpdir) / Path(image.filename).name)
            image.save(image_path)

        record = run_adversarial_experiment(
            weights_path=weights_path,
            num_outputs=num_outputs,
            image_path=image_path,
            base_dir=ARTIFACT_DIR,
        )
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc), "status": "ERROR"}), 500
    finally:
        if tmpdir:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    return jsonify(record.to_dict())


# --------------------------------------------------------------------------- #
# Know the Environment: Environment Profile (normalized from recon), Target
# Profile, and the shared Analysis Context.
# --------------------------------------------------------------------------- #
@api_bp.post("/environment/from-recon/<run_id>")
def api_env_from_recon(run_id):
    """Normalize a completed recon run into a persistent Environment Profile."""
    from orion.target_analysis import summarize_recon
    from orion.context import build_environment_profile, save_profile
    summary = summarize_recon(run_id)
    if summary is None:
        return jsonify({"error": "unknown recon run"}), 404
    profile = build_environment_profile(summary, target_reference=summary.get("target", ""),
                                        recon_run_id=run_id)
    save_profile(profile.environment_profile_id, profile.to_dict(), ARTIFACT_DIR)
    return jsonify(profile.to_dict())


@api_bp.post("/environment/from-url")
def api_env_from_url():
    """Build an Environment Profile from a direct URL probe (GET-only / active)."""
    from orion.target_analysis import probe_url
    from orion.context import build_environment_profile, save_profile
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    try:
        summary = probe_url(url, active=bool(payload.get("active")))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    profile = build_environment_profile(summary, target_reference=url)
    save_profile(profile.environment_profile_id, profile.to_dict(), ARTIFACT_DIR)
    return jsonify(profile.to_dict())


@api_bp.get("/environment/<env_id>")
def api_env_get(env_id):
    from orion.context import load_profile
    data = load_profile(env_id, ARTIFACT_DIR)
    if data is None:
        return jsonify({"error": "unknown environment profile"}), 404
    return jsonify(data)


@api_bp.post("/environment/<env_id>/analyze")
def api_env_analyze(env_id):
    """Interpret an Environment Profile (lets the environment change applicability)."""
    from orion.context import load_profile, EnvironmentProfile, environment_to_summary
    from orion.target_analysis import build_assessment_from_summary
    data = load_profile(env_id, ARTIFACT_DIR)
    if data is None:
        return jsonify({"error": "unknown environment profile"}), 404
    summary = environment_to_summary(EnvironmentProfile.from_dict(data))
    assessment = build_assessment_from_summary(summary)
    assessment["environment_profile_id"] = env_id
    return jsonify(assessment)


@api_bp.get("/profiles")
def api_profiles_list():
    """List persisted profiles (self / target / environment) for context building."""
    base = Path.cwd() / ARTIFACT_DIR
    out = {"self": [], "target": [], "environment": []}
    if not base.exists():
        return jsonify(out)
    import json as _json
    for d in sorted(base.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        for fname, key, labelfn in (
            ("self.json", "self", lambda j: j.get("system_type", "")),
            ("target.json", "target", lambda j: j.get("name") or j.get("target_type", "")),
            ("environment.json", "environment", lambda j: j.get("target_reference", "")),
        ):
            f = d / fname
            if f.exists():
                try:
                    j = _json.loads(f.read_text(encoding="utf-8"))
                except Exception:  # noqa: BLE001
                    continue
                out[key].append({"id": d.name, "label": labelfn(j),
                                 "updated_at": j.get("updated_at") or j.get("created_at", "")})
    return jsonify(out)


@api_bp.post("/target-profile")
def api_target_profile():
    from orion.context import build_target_profile, save_profile
    payload = request.get_json(silent=True) or {}
    profile = build_target_profile(payload)
    save_profile(profile.target_profile_id, profile.to_dict(), ARTIFACT_DIR)
    return jsonify(profile.to_dict())


@api_bp.post("/context")
def api_context_create():
    from orion.context import build_analysis_context, save_profile
    payload = request.get_json(silent=True) or {}
    ctx = build_analysis_context(
        self_id=payload.get("self_profile_id"),
        target_id=payload.get("target_profile_id"),
        environment_id=payload.get("environment_profile_id"),
        scope=payload.get("scope"))
    save_profile(ctx.analysis_context_id, ctx.to_dict(), ARTIFACT_DIR)
    return jsonify(ctx.to_dict())


@api_bp.post("/context/analyze")
def api_context_analyze():
    """Correlate available profiles into a source-aware Analysis Context assessment."""
    from orion.context import (load_profile, build_analysis_context, save_profile,
                               build_context_assessment)
    payload = request.get_json(silent=True) or {}
    sid = payload.get("self_profile_id")
    tid = payload.get("target_profile_id")
    eid = payload.get("environment_profile_id")
    self_p = load_profile(sid, ARTIFACT_DIR) if sid else None
    target_p = load_profile(tid, ARTIFACT_DIR) if tid else None
    env_p = load_profile(eid, ARTIFACT_DIR) if eid else None
    if not (self_p or target_p or env_p):
        return jsonify({"error": "provide at least one existing profile id"}), 400
    ctx = build_analysis_context(self_id=(sid if self_p else None),
                                 target_id=(tid if target_p else None),
                                 environment_id=(eid if env_p else None))
    save_profile(ctx.analysis_context_id, ctx.to_dict(), ARTIFACT_DIR)
    assessment = build_context_assessment(self_p, target_p, env_p)
    assessment["analysis_context_id"] = ctx.analysis_context_id
    assessment["self_profile_id"] = sid if self_p else None
    assessment["target_profile_id"] = tid if target_p else None
    assessment["environment_profile_id"] = eid if env_p else None
    assessment["coverage"] = ctx.coverage()
    assessment["status"] = ctx.status()
    return jsonify(assessment)


@api_bp.get("/context/<ctx_id>")
def api_context_get(ctx_id):
    from orion.context import load_profile
    data = load_profile(ctx_id, ARTIFACT_DIR)
    if data is None:
        return jsonify({"error": "unknown analysis context"}), 404
    return jsonify(data)


# --------------------------------------------------------------------------- #
# Know Your Target: recon listing + agent interpretation (deterministic)
# --------------------------------------------------------------------------- #
@api_bp.get("/recon/runs")
def api_recon_runs():
    """List in-memory recon runs (newest first)."""
    try:
        from libs.recon import web as recon_web
        from orion.target_analysis import display_run_id
    except Exception as exc:  # noqa: BLE001
        return jsonify({"runs": [], "error": str(exc)}), 200
    runs = []
    for rid, session in list(getattr(recon_web, "RUNS", {}).items()):
        objective = target = ""
        with session.lock:
            for ev in session.events[:3]:
                if ev.get("type") == "start":
                    objective, target = ev.get("objective", ""), ev.get("target", "")
                    break
            status = session.status
        runs.append({"run_id": rid, "display_id": display_run_id(rid),
                     "objective": objective, "target": target or "unknown", "status": status})
    runs.reverse()
    return jsonify({"runs": runs})


@api_bp.get("/recon/runs/<run_id>")
def api_recon_run_detail(run_id):
    from orion.target_analysis import summarize_recon
    summary = summarize_recon(run_id)
    if summary is None:
        return jsonify({"error": "unknown recon run"}), 404
    return jsonify(summary)


@api_bp.post("/agent/analyze-recon")
def api_agent_analyze_recon():
    """Interpret a recon run into a PROPOSED threat model + experiment plan."""
    from orion.target_analysis import build_assessment
    payload = request.get_json(silent=True) or {}
    run_id = payload.get("recon_run_id") or payload.get("run_id")
    if not run_id:
        return jsonify({"error": "recon_run_id is required"}), 400
    assessment = build_assessment(run_id)
    if assessment is None:
        return jsonify({"error": "unknown recon run"}), 404
    return jsonify(assessment)


@api_bp.post("/target-analysis/probe")
def api_probe_url():
    """Directly probe a running URL (GET-only) and analyze the real evidence.

    Authorized use only. Returns an evidence-grounded assessment built from the
    target's actual responses — unlike mock recon, this reaches the service.
    """
    from orion.target_analysis import probe_url, build_assessment_from_summary
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()
    # Active mode sends a harmless test image via POST (a sensitive action):
    # only when the caller explicitly opts in (the UI checkbox = human approval).
    active = bool(payload.get("active"))
    if not url:
        return jsonify({"error": "url is required (e.g. http://127.0.0.1:5001)"}), 400
    try:
        summary = probe_url(url, active=active)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"probe failed: {exc}"}), 502
    return jsonify(build_assessment_from_summary(summary))


@api_bp.post("/agent/analyze-context")
def api_agent_analyze_context():
    """Interpret user-provided context (no recon) into a PROPOSED assessment."""
    from orion.target_analysis import build_assessment_from_context
    payload = request.get_json(silent=True) or {}
    context = (payload.get("context") or "").strip()
    if not context:
        return jsonify({"error": "context is required"}), 400
    target = (payload.get("target") or "manual-context").strip()
    return jsonify(build_assessment_from_context(context, target))


@api_bp.get("/target-analysis/<run_id>")
def api_target_analysis(run_id):
    from orion.target_analysis import ANALYSES, build_assessment
    assessment = ANALYSES.get(run_id) or build_assessment(run_id)
    if assessment is None:
        return jsonify({"error": "unknown run"}), 404
    return jsonify(assessment)


@api_bp.post("/threat-model/<run_id>/approve")
def api_threat_model_approve(run_id):
    from orion.target_analysis import approve_threat_model
    payload = request.get_json(silent=True) or {}
    approved = payload.get("approved", True)
    result = approve_threat_model(run_id, bool(approved))
    if result is None:
        return jsonify({"error": "unknown run"}), 404
    return jsonify(result)


# --------------------------------------------------------------------------- #
# Experiment plans: approve (prepare) -> handoff -> explicit run
# --------------------------------------------------------------------------- #
@api_bp.post("/plans/approve")
def api_plans_approve():
    """Build + human-approve a plan from an analysis. Prepares execution; never runs."""
    from orion import plans as PL
    payload = request.get_json(silent=True) or {}
    source = payload.get("source_type")
    data = payload.get("analysis")
    if source == "know_yourself" and isinstance(data, dict):
        plan = PL.build_plan_from_know_yourself(data)
    elif source == "know_your_target" and isinstance(data, dict):
        plan = PL.build_plan_from_target_analysis(data)
    elif source == "analysis_context" and isinstance(data, dict):
        plan = PL.build_plan_from_context(data)
    else:
        return jsonify({"error": "source_type (know_yourself|know_your_target|analysis_context) and analysis required"}), 400
    # Analyst edits (EDIT PLAN): remove experiments / tune parameters / add notes.
    PL.apply_plan_edits(plan, exclude=payload.get("exclude"),
                        overrides=payload.get("overrides"), notes=payload.get("notes"))
    PL.approve_plan(plan, scope=payload.get("scope", "all_approved"))
    PL.save_plan(plan, ARTIFACT_DIR)
    return jsonify({"plan": plan.to_dict(), "handoff": plan.handoff()})


@api_bp.post("/plans/draft")
def api_plans_draft():
    """Build a DRAFT plan from an analysis (not approved) for review/editing."""
    from orion import plans as PL
    payload = request.get_json(silent=True) or {}
    source = payload.get("source_type")
    data = payload.get("analysis")
    if source == "know_yourself" and isinstance(data, dict):
        plan = PL.build_plan_from_know_yourself(data)
    elif source == "know_your_target" and isinstance(data, dict):
        plan = PL.build_plan_from_target_analysis(data)
    elif source == "analysis_context" and isinstance(data, dict):
        plan = PL.build_plan_from_context(data)
    else:
        return jsonify({"error": "source_type and analysis required"}), 400
    plan.status = PL.UNDER_REVIEW
    PL.save_plan(plan, ARTIFACT_DIR)
    return jsonify({"plan": plan.to_dict()})


@api_bp.post("/plans/<plan_id>/approve")
def api_plan_approve_by_id(plan_id):
    """Approve a draft plan with analyst edits (exclude / overrides / notes)."""
    from orion import plans as PL
    plan = PL.load_plan(plan_id, ARTIFACT_DIR)
    if plan is None:
        return jsonify({"error": "unknown plan"}), 404
    payload = request.get_json(silent=True) or {}
    PL.apply_plan_edits(plan, exclude=payload.get("exclude"),
                        overrides=payload.get("overrides"), notes=payload.get("notes"))
    PL.approve_plan(plan, scope=payload.get("scope", "all_approved"))
    PL.save_plan(plan, ARTIFACT_DIR)
    return jsonify({"plan": plan.to_dict(), "handoff": plan.handoff()})


@api_bp.get("/plans/<plan_id>")
def api_plan_get(plan_id):
    from orion import plans as PL
    plan = PL.load_plan(plan_id, ARTIFACT_DIR)
    if plan is None:
        return jsonify({"error": "unknown plan"}), 404
    return jsonify({"plan": plan.to_dict(), "handoff": plan.handoff()})


# --------------------------------------------------------------------------- #
# Experiment workspace: one lifecycle over PLAN → ATTACK → MEASURE → DEFEND → RETEST
# --------------------------------------------------------------------------- #
@api_bp.get("/experiment")
def api_experiment_list():
    from orion.experiments import list_workspaces
    return jsonify({"workspaces": list_workspaces(ARTIFACT_DIR)})


@api_bp.post("/experiment/from-plan/<plan_id>")
def api_experiment_from_plan(plan_id):
    from orion import plans as PL
    from orion.experiments import create_from_plan, list_workspaces, load_workspace
    plan = PL.load_plan(plan_id, ARTIFACT_DIR)
    if plan is None:
        return jsonify({"error": "unknown plan"}), 404
    # Reuse an existing workspace for this plan if one already exists.
    for w in list_workspaces(ARTIFACT_DIR):
        if w.get("plan_id") == plan_id:
            ws = load_workspace(w["experiment_workspace_id"], ARTIFACT_DIR)
            return jsonify(ws.to_dict())
    ws = create_from_plan(plan, ARTIFACT_DIR)
    return jsonify(ws.to_dict())


@api_bp.get("/experiment/<ws_id>")
def api_experiment_get(ws_id):
    from orion.experiments import load_workspace
    ws = load_workspace(ws_id, ARTIFACT_DIR)
    if ws is None:
        return jsonify({"error": "unknown workspace"}), 404
    data = ws.to_dict()
    from orion import plans as PL
    plan = PL.load_plan(ws.plan_id, ARTIFACT_DIR) if ws.plan_id else None
    data["plan"] = plan.to_dict() if plan else None
    return jsonify(data)


@api_bp.post("/experiment/<ws_id>/select/<experiment_id>")
def api_experiment_select(ws_id, experiment_id):
    from orion.experiments import load_workspace, select_experiment
    ws = load_workspace(ws_id, ARTIFACT_DIR)
    if ws is None:
        return jsonify({"error": "unknown workspace"}), 404
    return jsonify(select_experiment(ws, experiment_id, ARTIFACT_DIR).to_dict())


def _experiment_stage(ws_id, fn):
    from orion.experiments import load_workspace, StageError
    ws = load_workspace(ws_id, ARTIFACT_DIR)
    if ws is None:
        return jsonify({"error": "unknown workspace"}), 404
    try:
        result = fn(ws)
    except StageError as exc:
        return jsonify({"error": str(exc), "status": "BLOCKED"}), 409
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc), "status": "ERROR"}), 500
    result["workspace"] = ws.to_dict()
    return jsonify(result)


@api_bp.post("/experiment/<ws_id>/attack")
def api_experiment_attack(ws_id):
    from orion.experiments import run_attack
    return _experiment_stage(ws_id, lambda ws: run_attack(ws, ARTIFACT_DIR))


@api_bp.post("/experiment/<ws_id>/attack-blackbox")
def api_experiment_attack_blackbox(ws_id):
    """Run a real decision-based black-box evasion against the live endpoint."""
    from orion.experiments import run_blackbox_attack
    payload = request.get_json(silent=True) or {}
    return _experiment_stage(ws_id, lambda ws: run_blackbox_attack(ws, payload, ARTIFACT_DIR))


@api_bp.get("/experiment/<ws_id>/attack-options")
def api_experiment_attack_options(ws_id):
    """Derived access level (white/black-box) + the attack catalog with base tuning."""
    from orion.experiments import load_workspace, attack_options
    ws = load_workspace(ws_id, ARTIFACT_DIR)
    if ws is None:
        return jsonify({"error": "unknown workspace"}), 404
    return jsonify(attack_options(ws, ARTIFACT_DIR))


@api_bp.post("/experiment/<ws_id>/attack-whitebox")
def api_experiment_attack_whitebox(ws_id):
    """Run a real white-box (torch + ART) adversarial-image attack on the weights."""
    from orion.experiments import run_whitebox_attack
    payload = request.get_json(silent=True) or {}
    return _experiment_stage(ws_id, lambda ws: run_whitebox_attack(ws, payload, ARTIFACT_DIR))


@api_bp.post("/experiment/<ws_id>/measure")
def api_experiment_measure(ws_id):
    from orion.experiments import measure
    return _experiment_stage(ws_id, lambda ws: measure(ws, ARTIFACT_DIR))


@api_bp.post("/experiment/<ws_id>/attack-agentic")
def api_experiment_attack_agentic(ws_id):
    """Run a controlled GenAI / Agentic experiment (prompt injection, tool abuse)."""
    from orion.experiments import run_agentic_attack
    payload = request.get_json(silent=True) or {}
    return _experiment_stage(ws_id, lambda ws: run_agentic_attack(ws, payload, ARTIFACT_DIR))


@api_bp.post("/experiment/<ws_id>/attack-agentic-live")
def api_experiment_attack_agentic_live(ws_id):
    """Run a real prompt injection against a live discovered AI endpoint."""
    from orion.experiments import run_live_agentic_attack
    payload = request.get_json(silent=True) or {}
    return _experiment_stage(ws_id, lambda ws: run_live_agentic_attack(ws, payload, ARTIFACT_DIR))


@api_bp.post("/experiment/<ws_id>/defend")
def api_experiment_defend(ws_id):
    from orion.experiments import apply_defense
    payload = request.get_json(silent=True) or {}
    return _experiment_stage(ws_id, lambda ws: apply_defense(ws, payload, ARTIFACT_DIR))


@api_bp.post("/experiment/<ws_id>/retest")
def api_experiment_retest(ws_id):
    from orion.experiments import retest
    return _experiment_stage(ws_id, lambda ws: retest(ws, ARTIFACT_DIR))


@api_bp.get("/experiment/<ws_id>/controls")
def api_experiment_controls(ws_id):
    """Candidate controls for the current attack (from the unified control catalog)."""
    from orion.experiments import load_workspace
    from orion.catalog import controls as CC, attacks as CAT
    ws = load_workspace(ws_id, ARTIFACT_DIR)
    if ws is None:
        return jsonify({"error": "unknown workspace"}), 404
    aid = ws.attack_catalog_id
    if not aid and ws.attack_run_id:
        try:
            rec = EvidenceStore(ARTIFACT_DIR).load(ws.attack_run_id)
            a = CAT.get(rec.parameters.get("attack_id")) or CAT.get(rec.attack_technique)
            aid = a.id if a else None
        except Exception:  # noqa: BLE001
            aid = None
    items = CC.for_attack(aid) if aid else CC._CONTROLS
    out = []
    for c in items:
        d = c.to_dict()
        impl = CC.default_implementation(c.id)
        d["implementation"] = impl.to_dict() if impl else None
        out.append(d)
    return jsonify({"controls": out})


@api_bp.get("/catalog")
def api_catalog():
    """The unified attack catalog grouped by AI security family."""
    from orion.catalog import attacks as CAT
    return jsonify({"families": CAT.grouped_by_family(),
                    "family_labels": CAT.FAMILY_LABELS})


@api_bp.get("/payloads")
def api_payloads():
    """The OWASP LLM prompt-injection payload catalog (metadata only)."""
    from orion.agentic import payloads as PLD
    return jsonify({"categories": PLD.owasp_categories(),
                    "payloads": [p.to_dict() for p in PLD.all_payloads()]})


@api_bp.get("/findings")
def api_findings():
    from orion.findings import list_findings
    return jsonify({"findings": [f.to_dict() for f in list_findings(ARTIFACT_DIR)]})


@api_bp.get("/findings/<finding_id>")
def api_finding_detail(finding_id):
    from orion.findings import load_finding
    f = load_finding(finding_id, ARTIFACT_DIR)
    if f is None:
        return jsonify({"error": "unknown finding"}), 404
    return jsonify(f.to_dict())


@api_bp.get("/regressions")
def api_regressions_list():
    from orion import security_regressions as SR
    return jsonify({"regressions": [r.to_dict() for r in SR.list_regressions(ARTIFACT_DIR)]})


@api_bp.get("/regressions/<regression_id>")
def api_regression_get(regression_id):
    from orion import security_regressions as SR
    reg = SR.get(regression_id, ARTIFACT_DIR)
    if reg is None:
        return jsonify({"error": "unknown regression"}), 404
    out = reg.to_dict()
    out["latest_result"] = SR.RegressionRepository(ARTIFACT_DIR).load_result(regression_id)
    return jsonify(out)


@api_bp.post("/regressions")
def api_regression_create():
    """Create a Security Regression from an effectively-mitigated Finding."""
    from orion import security_regressions as SR
    payload = request.get_json(silent=True) or {}
    finding_id = (payload.get("finding_id") or "").strip()
    if not finding_id:
        return jsonify({"error": "finding_id is required"}), 400
    try:
        reg = SR.create_from_finding(finding_id, ARTIFACT_DIR, name=payload.get("name"))
    except SR.PreconditionError as exc:
        return jsonify({"error": str(exc), "status": "NOT_ELIGIBLE"}), 409
    except SR.RegressionError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(reg.to_dict())


@api_bp.post("/regressions/<regression_id>/run")
def api_regression_run(regression_id):
    """Manually execute a regression (operator-initiated only). Only ACTIVE
    regressions may run; DISABLED/ARCHIVED are a normal lifecycle rejection,
    never a server error."""
    from orion import security_regressions as SR
    try:
        result = SR.run_regression(regression_id, ARTIFACT_DIR)
    except SR.RegressionStatusError as exc:
        return jsonify({"error": str(exc)}), 409
    except SR.RegressionError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify(result.to_dict())


@api_bp.post("/regressions/<regression_id>/status")
def api_regression_status(regression_id):
    from orion import security_regressions as SR
    payload = request.get_json(silent=True) or {}
    try:
        reg = SR.set_status(regression_id, (payload.get("status") or "").upper(), ARTIFACT_DIR)
    except SR.RegressionError as exc:
        return jsonify({"error": str(exc)}), 400
    if reg is None:
        return jsonify({"error": "unknown regression"}), 404
    return jsonify(reg.to_dict())


@api_bp.get("/plans/<plan_id>/handoff")
def api_plan_handoff(plan_id):
    from orion import plans as PL
    h = PL.load_handoff(plan_id, ARTIFACT_DIR)
    if h is None:
        return jsonify({"error": "unknown plan"}), 404
    return jsonify(h)


@api_bp.post("/plans/<plan_id>/experiments/<experiment_id>/run")
def api_plan_run_experiment(plan_id, experiment_id):
    """Explicitly run one approved experiment (the human pressed RUN)."""
    from orion import plans as PL
    plan = PL.load_plan(plan_id, ARTIFACT_DIR)
    if plan is None:
        return jsonify({"error": "unknown plan"}), 404
    try:
        result = PL.run_experiment(plan, experiment_id, base_dir=ARTIFACT_DIR)
    except PL.ExperimentNotRunnable as exc:
        return jsonify({"error": str(exc), "status": "NOT_RUNNABLE"}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc), "status": "ERROR"}), 500
    return jsonify(result)


@api_bp.post("/know-yourself/analyze")
def api_know_yourself():
    """Profile an AI system (Traditional ML / Generative AI / Hybrid)."""
    from orion.know_yourself import analyze
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip() or None
    context = (payload.get("context") or "").strip() or None
    descriptor = payload.get("descriptor") if isinstance(payload.get("descriptor"), dict) else None
    force_type = payload.get("force_type") or None
    active = bool(payload.get("active"))
    if not (url or context or descriptor):
        return jsonify({"error": "provide url, context, or descriptor"}), 400
    try:
        result = analyze(url=url, context=context, descriptor=descriptor,
                         active=active, force_type=force_type)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"profile failed: {exc}"}), 500
    return jsonify(result)


@api_bp.post("/compare")
def api_compare_multi():
    """Compare metrics across labelled runs (e.g. baseline/attack/hardened/retest)."""
    payload = request.get_json(silent=True) or {}
    traces = payload.get("traces") or {}
    if not isinstance(traces, dict) or not traces:
        return jsonify({"error": "traces mapping {label: trace_id} required"}), 400
    store = EvidenceStore(ARTIFACT_DIR)
    _ORDER = ["BASELINE", "ATTACK", "HARDENED", "RETEST"]
    columns = sorted(traces.keys(), key=lambda c: (_ORDER.index(c) if c in _ORDER else 99, c))
    values: Dict[str, Dict[str, Any]] = {}
    statuses: Dict[str, str] = {}
    for label, tid in traces.items():
        try:
            rec = store.load(tid)
        except Exception:  # noqa: BLE001
            continue
        statuses[label] = rec.status
        for mkey, m in (rec.metrics or {}).items():
            if isinstance(m, dict) and "value" in m and isinstance(m["value"], (int, float)):
                values.setdefault(mkey, {})[label] = m["value"]
    matrix = [{"metric": k, **{c: v.get(c) for c in columns}} for k, v in values.items()]
    return jsonify({"columns": columns, "statuses": statuses, "matrix": matrix})


@api_bp.get("/mcp_tools")
def api_mcp_tools():
    """Return MCP tools with descriptions/schemas; never crash the UI."""
    try:
        from tools.mcp_client import list_tools_detailed
        tools = list_tools_detailed()
        return jsonify({"tools": tools, "state": "AVAILABLE"})
    except Exception as exc:  # noqa: BLE001
        return jsonify({"tools": [], "state": "ERROR", "error": str(exc)}), 200


@api_bp.get("/artifacts/<trace_id>/<path:filename>")
def api_artifact_file(trace_id, filename):
    """Serve an evidence file (png/json/md) with strict path validation."""
    if "/" in filename or ".." in filename or "\\" in filename:
        return jsonify({"error": "invalid filename"}), 400
    if not filename.lower().endswith((".png", ".json", ".md")):
        return jsonify({"error": "unsupported file type"}), 400
    if "/" in trace_id or ".." in trace_id:
        return jsonify({"error": "invalid trace_id"}), 400
    tdir = (Path.cwd() / ARTIFACT_DIR / trace_id).resolve()
    base = (Path.cwd() / ARTIFACT_DIR).resolve()
    if base not in tdir.parents and tdir != base:
        return jsonify({"error": "invalid path"}), 400
    if not (tdir / filename).exists():
        return jsonify({"error": "not found"}), 404
    return send_from_directory(str(tdir), filename)
