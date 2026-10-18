"""Small Flask adapter over the Assessment service and existing workflows."""
from flask import Blueprint, jsonify, request, render_template
from .service import AssessmentService

assessment_bp = Blueprint('assessments', __name__)


def service():
    from orion.integrations.flask_blueprint import ARTIFACT_DIR
    return AssessmentService(ARTIFACT_DIR)


def api_result(operation, status=200):
    try:
        return jsonify(operation()), status
    except LookupError as exc:
        return jsonify(error=str(exc)), 404
    except (ValueError, TypeError) as exc:
        return jsonify(error=str(exc)), 400
    except OSError:
        return jsonify(error='assessment storage unavailable'), 503


@assessment_bp.get('/api/assessments')
def api_list():
    def result():
        records, errors = service().repository.list()
        return {'assessments': [a.to_dict() for a in records], 'errors': errors}
    return api_result(result)


@assessment_bp.post('/api/assessments')
def api_create():
    return api_result(lambda: service().create(request.get_json(silent=True)).to_dict(), 201)


@assessment_bp.get('/api/assessments/<assessment_id>')
def api_get(assessment_id):
    return api_result(lambda: service().get(assessment_id).to_dict())


@assessment_bp.patch('/api/assessments/<assessment_id>')
def api_update(assessment_id):
    return api_result(lambda: service().update(assessment_id, request.get_json(silent=True)).to_dict())


@assessment_bp.get('/api/assessments/<assessment_id>/summary')
def api_summary(assessment_id):
    return api_result(lambda: service().summary(assessment_id))


@assessment_bp.get('/api/assessments/<assessment_id>/integrity')
def api_integrity(assessment_id):
    return api_result(lambda: service().validate_integrity(assessment_id))


@assessment_bp.get('/api/assessments/<assessment_id>/report')
def api_report_preview(assessment_id):
    """Read-only normalized report preview — never writes a report artifact."""
    def result():
        from orion.reports import build_assessment_report
        from orion.integrations.flask_blueprint import ARTIFACT_DIR
        return build_assessment_report(assessment_id, ARTIFACT_DIR).to_dict()
    return api_result(result)


@assessment_bp.post('/api/assessments/<assessment_id>/report')
def api_report_generate(assessment_id):
    """Explicit, operator-initiated report generation. Writes the report
    artifact under the Assessment's own directory; never scheduled, never
    triggered by other domain mutations."""
    def result():
        from orion.reports import build_assessment_report, render_markdown, render_json, write_report
        from orion.integrations.flask_blueprint import ARTIFACT_DIR
        payload = request.get_json(silent=True) or {}
        fmt = (payload.get('format') or 'markdown').lower()
        if fmt not in ('markdown', 'json'):
            raise ValueError("format must be 'markdown' or 'json'")
        report = build_assessment_report(assessment_id, ARTIFACT_DIR)
        path = write_report(report, fmt, ARTIFACT_DIR)
        content = render_markdown(report) if fmt == 'markdown' else render_json(report)
        return {'assessment_id': assessment_id, 'format': fmt, 'path': str(path), 'content': content}
    return api_result(result)


@assessment_bp.post('/api/assessments/<assessment_id>/experiments')
def api_create_experiment(assessment_id):
    def create():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) - {'plan_id', 'proposal_id'}:
            raise ValueError('provide plan_id and optional proposal_id')
        return service().create_experiment(assessment_id, payload.get('plan_id'), payload.get('proposal_id')).to_dict()
    return api_result(create, 201)


@assessment_bp.get('/assessments')
def list_page():
    records, errors = service().repository.list()
    summaries = [service().summary(a.assessment_id) for a in records]
    return render_template('assessments.html', summaries=summaries, errors=errors)


@assessment_bp.get('/assessments/<assessment_id>')
def detail_page(assessment_id):
    try:
        summary = service().summary(assessment_id)
    except LookupError:
        return render_template('assessment-detail.html', summary=None), 404
    except (ValueError, TypeError, OSError):
        return render_template('assessment-detail.html', summary=None), 503
    return render_template('assessment-detail.html', summary=summary)
