import json
from pathlib import Path

from flask import Flask, Response, render_template, request, jsonify, send_from_directory
#import ollama
#from libs.utils import clean_response_deepseek
from libs.agent import build_api_state, format_report, run_supervisor_state, run_supervisor_stream
from tools.mcp_client import list_tools
#from libs.agent_wrap import get_conversational_model
#from ollama import Ollama
import os
from libs.adversarial import generate_advimage
from prompts import system
from libs.recon import web as recon_web

app = Flask(__name__)

# Register the Orion methodology blueprint (Understand -> Threat Model -> Attack
# -> Measure -> Harden -> Retest). Guarded so the existing app keeps working
# even if the optional methodology dependencies are unavailable.
try:
    from orion.integrations.flask_blueprint import orion_bp, api_bp
    app.register_blueprint(orion_bp)
    app.register_blueprint(api_bp)
    from orion.assessments.routes import assessment_bp
    app.register_blueprint(assessment_bp)
except Exception as _orion_exc:  # noqa: BLE001
    print(f"[orion] methodology blueprint not registered: {_orion_exc}")

def get_ollama_response(prompt):
    #llm = agent.get_model()

    #cleaned_response = clean_response_deepseek(ollama.chat(
    #model = "deepseek-r1:7b",    
    
    #)["message"]["content"])    
    llm = get_conversational_model()
    #cleaned_response = clean_response_deepseek(llm.invoke({"question":prompt})["answer"])
    
    response_two = clean_response_deepseek(ollama.chat(
    model = "deepseek-r1:7b",
    messages=[
        {"role": "system", "content": system.SYSTEM_ATLAS},
        #{"role": "user", "content": "I need a set of tools and frameworks for {}".format(prompt)}
        {"role": "user", "content": prompt}
    ]
    )["message"]["content"])
    print("First response sent")
    
    return response_two

    #return cleaned_response


def get_deepseek_response(prompt):
    # Placeholder function - Replace with actual DeepSeek API call
    return f"DeepSeek: {prompt}"

@app.route('/know-your-enemy.html')
def enemey():
    return render_template('know-your-enemy.html')

@app.route('/')
def index():
    from orion.workspace_view import overview
    return render_template('index.html', overview=overview())

# --- Orion command-center pages (new UI) ---
@app.route('/know-yourself')
def know_yourself_page():
    return render_template('know-yourself.html')

@app.route('/adversarial')
def adversarial_page():
    return render_template('adversarial.html')

@app.route('/environment')
@app.route('/environment/<env_id>')
def environment_page(env_id=None):
    return render_template('environment.html', env_id=env_id)

@app.route('/context')
def analysis_context_page():
    return render_template('context.html')

# --- Experiment workspace: one lifecycle (PLAN/ATTACK/MEASURE/DEFEND/RETEST) ---
@app.route('/experiment')
@app.route('/experiment/<ws_id>')
def experiment_page(ws_id=None):
    return render_template('experiment.html', ws_id=ws_id)

# Backward-compatible routes: reuse the single Experiment workspace (no parallel UX).
@app.route('/attack')
def attack_workspace_page():
    return render_template('experiment.html', ws_id=None, compat_stage='attack')

@app.route('/measure')
@app.route('/measure/<trace_id>')
def measure_page(trace_id=None):
    return render_template('experiment.html', ws_id=None, compat_stage='measure', trace_id=trace_id)

@app.route('/defend')
@app.route('/defend/<trace_id>')
def defend_page(trace_id=None):
    return render_template('experiment.html', ws_id=None, compat_stage='defend', trace_id=trace_id)

@app.route('/agent')
def agent_page():
    return render_template('agent.html')

@app.route('/target-analysis')
@app.route('/know-your-target')
def target_analysis_page():
    return render_template('target-analysis.html')

@app.route('/runs')
def runs_page():
    return render_template('runs.html')

@app.route('/runs/<trace_id>')
def run_detail_page(trace_id):
    record = None
    report_md = None
    try:
        from orion.evidence import EvidenceStore
        store = EvidenceStore('artifacts')
        rec = store.load(trace_id)
        record = rec.to_dict()
        report_path = store.trace_dir(trace_id) / 'report.md'
        if report_path.exists():
            report_md = report_path.read_text(encoding='utf-8')
    except Exception:
        record = None
    finding = None
    try:
        from orion.findings import FindingStore
        findings_store = FindingStore('artifacts')
        f = findings_store.find_by_evidence(trace_id)
        if f is None:
            f = next((item for item in findings_store.list() if trace_id in item.retest_refs), None)
        finding = f.to_dict() if f else None
    except Exception:
        finding = None
    workspace = None
    if record and (record.get('provenance') or {}).get('experiment_workspace_id'):
        try:
            from orion.experiments import load_workspace
            ws = load_workspace(record['provenance']['experiment_workspace_id'], 'artifacts')
            if ws and trace_id in (ws.attack_run_id, ws.retest_run_id):
                workspace = ws.to_dict()
        except (OSError, ValueError, TypeError):
            pass
    return render_template('run-detail.html', trace_id=trace_id, record=record,
                           report_md=report_md, finding=finding, workspace=workspace)

@app.route('/findings')
def findings_page():
    from orion.findings import list_findings
    findings = [f.to_dict() for f in list_findings('artifacts')]
    return render_template('findings.html', findings=findings)

@app.route('/findings/<finding_id>')
def finding_detail_page(finding_id):
    from orion.findings import load_finding
    f = load_finding(finding_id, 'artifacts')
    from orion.workspace_view import finding_workspace
    # Security Regression eligibility + any regression already created from this finding.
    regression = regression_eligible = regression_reason = None
    try:
        from orion import security_regressions as SR
        regression_eligible, regression_reason = SR.can_create_regression(f) if f else (False, "Unknown finding.")
        regression = next((r.to_dict() for r in SR.list_regressions('artifacts')
                           if r.source_finding_id == finding_id), None)
    except Exception:
        pass
    return render_template('finding-detail.html',
                           finding=f.to_dict() if f else None, finding_id=finding_id,
                           workspace=finding_workspace(f),
                           regression=regression, regression_eligible=regression_eligible,
                           regression_reason=regression_reason)


@app.route('/regressions')
def regressions_page():
    from orion import security_regressions as SR
    regressions = [r.to_dict() for r in SR.list_regressions('artifacts')]
    return render_template('regressions.html', regressions=regressions)


@app.route('/regressions/<regression_id>')
def regression_detail_page(regression_id):
    from orion import security_regressions as SR
    reg = SR.get(regression_id, 'artifacts')
    latest = SR.RegressionRepository('artifacts').load_result(regression_id) if reg else None
    return render_template('regression-detail.html',
                           regression=reg.to_dict() if reg else None,
                           regression_id=regression_id, latest=latest)

@app.route('/red-team')
def red_team_page():
    return render_template('red-team.html')

@app.route('/red-pill.html')
def red_pill():
    # Retired as a monolith: now the Red Team landing page.
    return render_template('red-team.html')

@app.route('/know-environment.html')
def know_environment():
    return render_template('know-environment.html')


@app.route('/know-environment/run', methods=['POST'])
def know_environment_run():
    form = request.form
    objective = (form.get('objective') or '').strip()
    target = (form.get('target') or '').strip()
    if not objective or not target:
        return jsonify({"error": "objective and target are required"}), 400

    try:
        max_iterations = int(form.get('max_iterations') or 12)
    except ValueError:
        max_iterations = 12

    run_id = recon_web.start_run(
        objective,
        target,
        max_iterations=max_iterations,
        require_human_approval=bool(form.get('human_approval')),
        require_sensitive_approval=bool(form.get('require_sensitive_approval')),
        mock_mode=bool(form.get('mock')),  # real recon by default; --mock is opt-in
        enable_playwright=bool(form.get('enable_playwright')),
        enable_nuclei=bool(form.get('enable_nuclei')),
        browser_username=(form.get('browser_username') or '').strip(),
        browser_password=form.get('browser_password') or '',
    )
    return jsonify({"run_id": run_id}), 202


@app.route('/know-environment/screenshots/<filename>')
def know_environment_screenshot(filename):
    """Serve a browser evidence screenshot (PNG only, no path traversal)."""
    if not filename.endswith('.png') or '/' in filename or '..' in filename:
        return jsonify({"error": "invalid filename"}), 400
    screenshot_dir = (Path.cwd() / "reports" / "screenshots").resolve()
    return send_from_directory(str(screenshot_dir), filename)


@app.route('/know-environment/run/<run_id>')
def know_environment_run_page(run_id):
    if recon_web.get_run(run_id) is None:
        return jsonify({"error": "unknown run_id"}), 404
    return render_template('know-environment-run.html', run_id=run_id)


@app.route('/know-environment/events/<run_id>')
def know_environment_events(run_id):
    if recon_web.get_run(run_id) is None:
        return jsonify({"error": "unknown run_id"}), 404
    response = Response(recon_web.stream_events(run_id), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    return response


@app.route('/know-environment/approve/<run_id>', methods=['POST'])
def know_environment_approve(run_id):
    payload = request.get_json(silent=True) or {}
    result = recon_web.submit_approval(run_id, bool(payload.get('approved')))
    status_code = result.pop('status_code')
    return jsonify(result), status_code

@app.route('/chat_phishing', methods=['POST'])
def chat_phishing():    
    bot_response = get_ollama_response("Create one phishing email in English.")
    return jsonify({"response": bot_response})

@app.route("/adverimage", methods=["GET", "POST"])
def adversarial():
    """Legacy adversarial endpoint — now a thin wrapper over the shared
    experiment service (orion.adversarial.run_adversarial_experiment) so there is
    no duplicate attack logic. Response shape is preserved for backward compat.
    """
    import tempfile
    tmpdir = None
    try:
        weights = request.files.get("weights")
        file = request.files.get("file")
        if not weights:
            return "No wights uploaded", 400
        if not file:
            return "No file uploaded", 400
        num_outputs = int(request.values.get("numberoutputs") or 2)
        Path("weights").mkdir(exist_ok=True)
        weights_path = str(Path("weights") / Path(weights.filename).name)
        weights.save(weights_path)
        tmpdir = tempfile.mkdtemp(prefix="orion_adv_legacy_")
        image_path = str(Path(tmpdir) / Path(file.filename).name)
        file.save(image_path)

        from orion.adversarial import run_adversarial_experiment
        record = run_adversarial_experiment(
            weights_path=weights_path, num_outputs=num_outputs, image_path=image_path)
        return jsonify(message="Adversarial image created successfully",
                       image_url="/static/adversarial/output_art.png",
                       trace_id=record.trace_id, status=record.status), 200
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        if tmpdir:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


@app.route('/chat', methods=['POST'])
def chat():
    user_input = request.json.get("message", "")
    #model = request.json.get("model", "ollama")
    
    
    #bot_response = get_ollama_response(user_input)
    final_state = run_supervisor_state(user_input)
    bot_response = format_report(final_state)
    
    return jsonify({"response": bot_response, "state": build_api_state(final_state)})

@app.route('/mcp_tools', methods=['GET'])
def mcp_tools():
    try:
        tools = list_tools()
    except Exception as exc:
        return jsonify({"tools": [], "error": str(exc)}), 200
    return jsonify({"tools": tools})


@app.route('/chat_stream', methods=['POST'])
def chat_stream():
    user_input = request.json.get("message", "")

    def generate():
        last_state = None
        for state in run_supervisor_stream(user_input):
            last_state = state
            payload = {"state": build_api_state(state)}
            yield f"data: {json.dumps(payload)}\n\n"
        if last_state:
            response = format_report(last_state)
            payload = {"state": build_api_state(last_state), "response": response}
            yield f"data: {json.dumps(payload)}\n\n"

    return Response(generate(), mimetype="text/event-stream")

if __name__ == '__main__':
    # threaded=True is required: without it the dev server serialises requests,
    # so a live know-environment SSE stream would starve the /approve endpoint.
    app.run(debug=False, threaded=True)
