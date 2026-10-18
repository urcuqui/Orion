/* Assessment metadata and explicit links only; execution stays in the workspace. */
(function () {
  "use strict";
  const split = text => text.split(',').map(value => value.trim()).filter(Boolean);
  async function write(form, method, path, payload, destination) {
    const status = form.querySelector('[data-form-status]');
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const response = await fetch(path, {method, headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Assessment request failed');
      location.assign(destination(result));
    } catch (error) { Orion.setState(status, 'error', error.message); button.disabled = false; }
  }
  const profileSelectors = document.querySelectorAll('[data-profile-kind]');
  if (profileSelectors.length) Orion.getJSON('/api/profiles').then(profiles => {
    profileSelectors.forEach(select => {
      (profiles[select.dataset.profileKind] || []).forEach(profile => {
        if (!Array.from(select.options).some(option => option.value === profile.id)) {
          const option = document.createElement('option'); option.value = profile.id; option.textContent = profile.label ? `${profile.id} · ${profile.label}` : profile.id; select.appendChild(option);
        }
      });
      select.value = select.dataset.current || '';
    });
  }).catch(() => { /* Explicit recorded IDs remain editable if listing is unavailable. */ });
  document.querySelectorAll('[data-assessment-form]').forEach(form => form.addEventListener('submit', event => {
    event.preventDefault();
    const data = new FormData(form);
    const scopeElement = document.getElementById('assessment-scope');
    const scope = scopeElement ? JSON.parse(scopeElement.textContent) : {};
    for (const key of ['surfaces', 'in_scope_capabilities', 'out_of_scope_capabilities']) {
      const values = split(data.get(key) || ''); if (values.length) scope[key] = values; else delete scope[key];
    }
    for (const key of ['access_model', 'notes']) {
      const value = (data.get(key) || '').trim(); if (value) scope[key] = value; else delete scope[key];
    }
    const payload = {name: data.get('name'), description: data.get('description'), scope};
    for (const key of ['system_profile_id', 'target_id', 'environment_id']) payload[key] = data.get(key) || null;
    if (form.dataset.id) {
      payload.status = data.get('status');
      for (const key of ['analysis_context_ids', 'plan_ids', 'threat_model_ids']) {
        const existing = split(form.querySelector(`[name="${key}"]`).defaultValue || '');
        const additions = split(data.get(key) || '').filter(value => !existing.includes(value));
        if (additions.length) payload[key] = additions;
      }
    }
    write(form, form.dataset.id ? 'PATCH' : 'POST', '/api/assessments' + (form.dataset.id ? '/' + encodeURIComponent(form.dataset.id) : ''), payload, result => '/assessments/' + encodeURIComponent(result.assessment_id));
  }));
  document.querySelectorAll('[data-link-form]').forEach(form => form.addEventListener('submit', event => {
    event.preventDefault(); const payload = {[form.dataset.kind]: [new FormData(form).get('id').trim()]};
    write(form, 'PATCH', '/api/assessments/' + encodeURIComponent(form.dataset.id), payload, () => location.pathname);
  }));
  document.querySelectorAll('[data-plan-form]').forEach(form => form.addEventListener('submit', event => {
    event.preventDefault(); const data = new FormData(form); const payload = {plan_id: data.get('plan_id').trim()};
    if (data.get('proposal_id').trim()) payload.proposal_id = data.get('proposal_id').trim();
    write(form, 'POST', '/api/assessments/' + encodeURIComponent(form.dataset.id) + '/experiments', payload, result => '/experiment/' + encodeURIComponent(result.experiment_workspace_id));
  }));
  document.querySelectorAll('[data-report-btn]').forEach(btn => btn.addEventListener('click', async () => {
    const host = document.querySelector('[data-report-result]');
    const format = btn.dataset.format;
    Orion.setState(host, 'running', 'generating ' + format + ' report…');
    try {
      const res = await Orion.postJSON('/api/assessments/' + encodeURIComponent(btn.dataset.id) + '/report', {format});
      host.innerHTML = `<p class="sub">Written to <span class="mono">${Orion.esc(res.path)}</span></p><pre class="term-pre">${Orion.esc(res.content)}</pre>`;
    } catch (error) { Orion.setState(host, 'error', '[x] ' + error.message); }
  }));
})();
