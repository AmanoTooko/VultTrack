const state = {
  mode: 'vulnerability',
  selectedId: null
};

const el = {
  statusLine: document.querySelector('#statusLine'),
  refreshButton: document.querySelector('#refreshButton'),
  metricVulns: document.querySelector('#metricVulns'),
  metricRecords: document.querySelector('#metricRecords'),
  metricAffected: document.querySelector('#metricAffected'),
  metricComponents: document.querySelector('#metricComponents'),
  tabs: [...document.querySelectorAll('.tab')],
  searchForm: document.querySelector('#searchForm'),
  queryInput: document.querySelector('#queryInput'),
  vendorInput: document.querySelector('#vendorInput'),
  versionInput: document.querySelector('#versionInput'),
  ecosystemInput: document.querySelector('#ecosystemInput'),
  queryLabel: document.querySelector('#queryLabel'),
  componentFields: document.querySelector('#componentFields'),
  resultList: document.querySelector('#resultList'),
  detailPane: document.querySelector('#detailPane')
};

el.refreshButton.addEventListener('click', () => {
  loadStatus();
  runSearch();
});

  el.tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      state.mode = tab.dataset.mode;
      el.tabs.forEach((item) => item.classList.toggle('is-active', item === tab));
      el.componentFields.hidden = state.mode !== 'component';
      el.searchForm.hidden = state.mode === 'sbom';
      el.queryLabel.textContent = state.mode === 'component' ? 'Component name, vendor, or purl' : 'Identifier or keyword';
      el.queryInput.placeholder = state.mode === 'component' ? 'pkg:maven/org.apache.logging.log4j/log4j-core' : 'CVE-2021-44228';
      if (state.mode === 'sbom') loadSbomList();
      else runSearch();
    });
  });

el.searchForm.addEventListener('submit', (event) => {
  event.preventDefault();
  runSearch();
});

el.detailPane.addEventListener('click', (event) => {
  const toggle = event.target.closest('.cvss-toggle');
  if (!toggle) return;
  const target = document.getElementById(toggle.dataset.target);
  if (!target) return;
  const expanded = toggle.getAttribute('aria-expanded') === 'true';
  toggle.setAttribute('aria-expanded', !expanded);
  target.hidden = expanded;
});

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'content-type': 'application/json' },
    ...options
  });
  const body = await res.json();
  if (!res.ok || body.ok === false) {
    throw new Error(body.error?.message ?? `Request failed: ${res.status}`);
  }
  return body.data;
}

async function loadStatus() {
  try {
    const data = await api('/api/v1/system.status');
    el.metricVulns.textContent = fmt(data.vulnerabilities);
    el.metricRecords.textContent = fmt(data.vulnerabilityRecords);
    el.metricAffected.textContent = fmt(data.affectedComponents);
    el.metricComponents.textContent = fmt(data.components);
    const pending = data.normalizeStatus.find((item) => item.status === 'pending')?.count ?? 0;
    el.statusLine.textContent = `${fmt(pending)} raw records pending normalization`;
  } catch (error) {
    el.statusLine.textContent = error.message;
  }
}

async function runSearch() {
  const query = el.queryInput.value.trim();
  el.resultList.innerHTML = '<div class="muted result-item">Loading</div>';
  try {
    if (state.mode === 'component') {
      await runComponentSearch(query);
    } else {
      await runVulnerabilitySearch(query);
    }
  } catch (error) {
    el.resultList.innerHTML = `<div class="muted result-item">${escapeHtml(error.message)}</div>`;
  }
}

async function runVulnerabilitySearch(query) {
  const data = await api('/api/v1/vulnerability.search', {
    method: 'POST',
    body: JSON.stringify({ query, pageSize: query ? 50 : 10 })
  });

  if (!data.items.length) {
    el.resultList.innerHTML = '<div class="muted result-item">No vulnerabilities found</div>';
    return;
  }

  if (!query) {
    el.resultList.innerHTML = '<div class="muted result-item" style="font-weight:600">Recently updated</div>';
  }
  el.resultList.innerHTML += data.items.map((item) => vulnerabilityResult(item)).join('');
  el.resultList.querySelectorAll('[data-vulnerability-id]').forEach((button) => {
    button.addEventListener('click', () => loadVulnerabilityDetail(button.dataset.vulnerabilityId));
  });
}

async function runComponentSearch(query) {
  const vendor = el.vendorInput.value.trim();
  const version = el.versionInput.value.trim();
  const ecosystem = el.ecosystemInput.value.trim();

  const versionRegex = /^v?\d+\.\d+(?:\.\d+)?(?:[-.+]\w+)*$/;
  const detectedVersion = version || (versionRegex.test(query) ? query : null);
  const inferred = inferComponentInput(query, vendor);
  const compName = versionRegex.test(query) ? null : inferred.name;
  const inferredVendor = inferred.vendor || vendor || null;
  const purl = query.startsWith('pkg:') ? query : null;

  const catalog = await api('/api/v1/component.search', {
    method: 'POST',
    body: JSON.stringify({
      query: compName ?? query,
      name: compName,
      vendor: inferredVendor,
      purl,
      ecosystem: ecosystem || null,
      version: detectedVersion || null,
      pageSize: 25
    })
  });
  const vulns = await api('/api/v1/component.vulnerabilitySearch', {
    method: 'POST',
    body: JSON.stringify({
      componentName: compName,
      name: compName,
      vendor: inferredVendor,
      purl,
      ecosystem: ecosystem || null,
      version: detectedVersion || null,
      pageSize: 25
    })
  });

  const blocks = [];
  if (vulns.items.length) {
    blocks.push('<div class="muted result-item">Matching vulnerabilities</div>');
    blocks.push(...vulns.items.map((item) => componentVulnerabilityResult(item)));
  }
  if (catalog.components.length || catalog.registryPackages.length) {
    blocks.push('<div class="muted result-item">Component catalog</div>');
    blocks.push(...catalog.components.map((item) => componentResult(item)));
    blocks.push(...catalog.registryPackages.map((item) => registryResult(item)));
  }
  el.resultList.innerHTML = blocks.join('') || '<div class="muted result-item">No components found</div>';
  el.resultList.querySelectorAll('[data-vulnerability-id]').forEach((button) => {
    button.addEventListener('click', () => loadVulnerabilityDetail(button.dataset.vulnerabilityId));
  });
}

async function loadVulnerabilityDetail(id) {
  state.selectedId = id;
  el.resultList.querySelectorAll('.result-item').forEach((item) => {
    item.classList.toggle('is-active', item.dataset.vulnerabilityId === id);
  });
  el.detailPane.innerHTML = '<div class="empty-state"><h2>Loading</h2></div>';
  try {
    const data = await api(`/api/v1/vulnerability.detail?id=${encodeURIComponent(id)}`);
    renderDetail(data);
  } catch (error) {
    el.detailPane.innerHTML = `<div class="empty-state"><h2>Request failed</h2><p>${escapeHtml(error.message)}</p></div>`;
  }
}

function renderDetail(data) {
  const v = data.vulnerability;
  const records = data.records || [];
  const severities = data.severities || [];
  const refs = data.references || [];
  const descriptions = data.descriptions || [];
  const affected = data.affectedComponents || [];
  const sourceTags = [...new Set(records.map(r => r.code).filter(Boolean))];

  el.detailPane.innerHTML = `
    <header class="detail-header">
      <div class="detail-title">
        <h2>${escapeHtml(v.primaryIdentifier)}</h2>
        ${severityBadge(v.severityLabel, v.maxCvssScore)}
        ${v.epssScore ? `<span class="badge warn">EPSS ${pct(v.epssScore)}</span>` : ''}
        ${v.kevDateAdded ? '<span class="badge risk">KEV</span>' : ''}
      </div>
      ${v.maxCvssVector ? cvssVectorBlock(v.maxCvssVersion, v.maxCvssVector) : ''}
      <p class="summary">${escapeHtml(v.title || v.description || '')}</p>
      <div class="detail-meta-row">
        <span class="kv-inline">Published <b>${date(v.publishedAt)}</b></span>
        <span class="kv-inline">Modified <b>${date(v.modifiedAt)}</b></span>
        <span class="kv-inline">Sources <b>${fmt(records.length)}</b></span>
        <span class="kv-inline">Affected <b>${fmt(v.affectedComponentCount)}</b></span>
      </div>
      <div class="chips" style="margin-top:8px">
        <span class="chip-label">Sources:</span>
        ${sourceTags.map(s => `<span class="badge tag-${escapeAttr(s)}">${escapeHtml(s)}</span>`).join('')}
      </div>
    </header>

    <div class="detail-sections">
      ${descriptions.length ? renderDescriptionCards(descriptions) : ''}
      ${severities.length ? renderSeverityCards(severities) : ''}
      ${affected.length ? renderAffectedCards(affected) : ''}
      ${refs.length ? renderReferenceCards(refs) : ''}
    </div>
  `;
}

function sourceTag(code) {
  return `<span class="badge tag-source">${escapeHtml(code || '?')}</span>`;
}

function renderDescriptionCards(descriptions) {
  if (!descriptions.length) return '';
  return `
    <section class="detail-section">
      <h3 class="section-h">Description</h3>
      <div class="card-stack">
        ${descriptions.map(d => `
          <div class="info-card">
            <p class="info-card-body">${escapeHtml(d.value || '')}</p>
            <div class="chips">${sourceTag(d.code)} ${d.lang ? `<span class="badge">${escapeHtml(d.lang)}</span>` : ''}</div>
          </div>
        `).join('')}
      </div>
    </section>
  `;
}

function renderSeverityCards(severities) {
  if (!severities.length) return '';
  return `
    <section class="detail-section">
      <h3 class="section-h">CVSS / Severity</h3>
      <div class="card-stack">
        ${severities.map(s => `
          <div class="info-card">
            <div class="info-card-row">
              <strong>${s.scoring_system || 'severity'} ${s.scoring_version || ''}</strong>
              ${s.score != null ? severityBadge(s.severity_label, s.score) : `<span class="badge">${escapeHtml(s.severity_label || 'N/A')}</span>`}
            </div>
            ${s.vector_string ? `<code class="cvss-vector-string">${escapeHtml(s.vector_string)}</code>` : ''}
            <div class="chips">${sourceTag(s.code)}</div>
          </div>
        `).join('')}
      </div>
    </section>
  `;
}

function renderAffectedCards(affected) {
  if (!affected.length) return '';
  const display = affected.slice(0, 50);
  return `
    <section class="detail-section">
      <h3 class="section-h">Affected Components (${fmt(affected.length)})</h3>
      <div class="card-stack">
        ${display.map(c => `
          <div class="info-card">
            <div class="info-card-row">
              <strong>${escapeHtml(c.display_name || c.package_name || c.primary_purl || 'component')}</strong>
              ${c.normalized_range ? `<span class="badge high">${escapeHtml(c.normalized_range)}</span>` : ''}
            </div>
            <div class="chips">
              ${c.ecosystem ? `<span class="badge">${escapeHtml(c.ecosystem)}</span>` : ''}
              ${c.range_type ? `<span class="badge">${escapeHtml(c.range_type)}</span>` : ''}
            </div>
          </div>
        `).join('')}
      </div>
    </section>
  `;
}

function renderReferenceCards(refs) {
  if (!refs.length) return '';
  const display = refs.slice(0, 30);
  return `
    <section class="detail-section">
      <h3 class="section-h">References (${fmt(refs.length)})</h3>
      <div class="card-stack">
        ${display.map(r => `
          <div class="info-card">
            <a href="${escapeAttr(r.url)}" target="_blank" rel="noreferrer" class="ref-link">${escapeHtml(shortUrl(r.url))}</a>
            <div class="chips">
              ${sourceTag(r.code)}
              ${r.ref_type ? `<span class="badge">${escapeHtml(r.ref_type)}</span>` : ''}
              ${Array.isArray(r.tags) ? r.tags.slice(0, 3).map(t => `<span class="badge">${escapeHtml(t)}</span>`).join('') : ''}
            </div>
          </div>
        `).join('')}
      </div>
    </section>
  `;
}

function vulnerabilityResult(item) {
  const names = (item.affectedComponentNames || []).slice(0, 3);
  return `
    <button class="result-item" type="button" data-vulnerability-id="${escapeAttr(item.id)}">
      <div class="result-main">
        <span class="result-title">${escapeHtml(item.primaryIdentifier)}</span>
        ${severityBadge(item.severityLabel, item.maxCvssScore)}
      </div>
      <div class="result-meta">
        ${names.length ? `<span class="badge" title="${escapeHtml(names.join(', '))}">${escapeHtml(names.join(', '))}</span>` : ''}
        ${item.affectedComponentCount ? `<span class="badge muted">${fmt(item.affectedComponentCount)} affected</span>` : ''}
      </div>
    </button>
  `;
}

function componentVulnerabilityResult(item) {
  const match = item.versionMatched === true ? 'version match' : item.versionMatched === false ? 'range miss' : 'range unknown';
  const matchKlass = item.versionMatched === true ? 'low' : item.versionMatched === false ? 'none' : '';
  return `
    <button class="result-item" type="button" data-vulnerability-id="${escapeAttr(item.vulnerabilityId)}">
      <div class="result-main">
        <span class="result-title">${escapeHtml(item.primaryIdentifier)}</span>
        ${severityBadge(item.severityLabel, item.cvssScore)}
      </div>
      <div class="muted">${escapeHtml(item.packageName || item.purl || '')}</div>
      <div class="chips"><span class="badge ${matchKlass}">${escapeHtml(match)}</span><span class="badge">${escapeHtml(item.versionRange || 'no range')}</span></div>
    </button>
  `;
}

function componentResult(item) {
  return `
    <div class="result-item">
      <div class="result-main">
        <span class="result-title">${escapeHtml(item.canonicalName)}</span>
        <span class="badge">${escapeHtml(item.componentType)}</span>
      </div>
      <div class="muted">${escapeHtml(item.primaryPurl || item.primaryCpe23Uri || '')}</div>
    </div>
  `;
}

function registryResult(item) {
  const name = item.namespaceName ? `${item.namespaceName}:${item.name}` : item.name;
  return `
    <div class="result-item">
      <div class="result-main">
        <span class="result-title">${escapeHtml(name)}</span>
        <span class="badge">${escapeHtml(item.ecosystem)}</span>
      </div>
      <div class="muted">${escapeHtml(item.purlWithoutVersion || '')}</div>
    </div>
  `;
}

function tableSection(title, headers, rows, allowHtml = false) {
  if (!rows.length) return '';
  return `
    <section class="section">
      <h3>${escapeHtml(title)}</h3>
      <table class="table">
        <thead><tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join('')}</tr></thead>
        <tbody>
          ${rows.map((row) => `<tr>${row.map((cell) => `<td>${allowHtml ? (cell ?? '') : escapeHtml(cell ?? '')}</td>`).join('')}</tr>`).join('')}
        </tbody>
      </table>
    </section>
  `;
}

function rawSection(title, value) {
  if (!value) return '';
  return `
    <section class="section">
      <h3>${escapeHtml(title)}</h3>
      <pre>${escapeHtml(JSON.stringify(value, null, 2))}</pre>
    </section>
  `;
}

function cardSection(title, items, allowHtml = false) {
  if (!items.length) return '';
  return `
    <section class="section">
      <h3>${escapeHtml(title)}</h3>
      <div class="source-card-list">
        ${items.map(item => `
          <article class="source-card">
            <div class="source-card-head">
              <strong>${allowHtml ? item.title : escapeHtml(item.title || '')}</strong>
              <div class="chips">${(item.meta || []).map(x => `<span class="badge">${escapeHtml(x)}</span>`).join('')}</div>
            </div>
            ${item.body ? `<p>${escapeHtml(item.body).slice(0, 1200)}</p>` : ''}
          </article>
        `).join('')}
      </div>
    </section>
  `;
}

function inferComponentInput(query, vendor) {
  const trimmed = query.trim();
  if (!trimmed || trimmed.startsWith('pkg:')) return { name: null, vendor: vendor || null };
  if (!vendor && trimmed.includes(':')) {
    const [left, ...rest] = trimmed.split(':');
    const name = rest.join(':');
    if (left && name) return { vendor: left, name };
  }
  return { name: trimmed, vendor: vendor || null };
}

function shortUrl(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.hostname}${parsed.pathname}`.slice(0, 90);
  } catch {
    return String(url).slice(0, 90);
  }
}

function severityBadge(label, score) {
  const numeric = Number(score ?? 0);
  const tag = (String(label || '')).toLowerCase();
  const klass = tag === 'critical' || numeric >= 9 ? 'critical' :
                tag === 'high' || numeric >= 7 ? 'high' :
                tag === 'medium' || numeric >= 4 ? 'medium' :
                tag === 'low' || numeric > 0 ? 'low' : 'none';
  const text = `${escapeHtml(label || 'CVSS')} ${score != null ? score : ''}`;
  return `<span class="badge ${klass}">${text}</span>`;
}

function fmt(value) {
  return Number(value ?? 0).toLocaleString();
}

function pct(value) {
  return `${(Number(value) * 100).toFixed(2)}%`;
}

function date(value) {
  if (!value) return '-';
  return new Date(value).toISOString().slice(0, 10);
}

function cvssVectorBlock(version, vectorString) {
  const metrics = parseCvssVector(vectorString);
  const id = `cvss-breakdown-${Math.random().toString(36).slice(2, 8)}`;
  return `
    <div class="cvss-vector">
      <code class="cvss-vector-string">${escapeHtml(vectorString)}</code>
      <button class="cvss-toggle" type="button" data-target="${id}" aria-expanded="false">Metrics &raquo;</button>
      <div class="cvss-breakdown" id="${id}" hidden>
        <table class="cvss-metrics">
          <tbody>
            ${metrics.map((m) => `<tr><th>${escapeHtml(m.metric)}</th><td>${escapeHtml(m.value)}</td><td class="muted">${escapeHtml(m.label)}</td></tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

const CVSS_LABELS = {
  AV: { label: 'Attack Vector', N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
  AC: { label: 'Attack Complexity', L: 'Low', H: 'High' },
  PR: { label: 'Privileges Required', N: 'None', L: 'Low', H: 'High' },
  UI: { label: 'User Interaction', N: 'None', R: 'Required' },
  S:  { label: 'Scope', U: 'Unchanged', C: 'Changed' },
  C:  { label: 'Confidentiality', N: 'None', L: 'Low', H: 'High' },
  I:  { label: 'Integrity', N: 'None', L: 'Low', H: 'High' },
  A:  { label: 'Availability', N: 'None', L: 'Low', H: 'High' },
  E:  { label: 'Exploit Code Maturity', X: 'Not Defined', U: 'Unproven', P: 'Proof-of-Concept', F: 'Functional', H: 'High' },
  RL: { label: 'Remediation Level', X: 'Not Defined', O: 'Official Fix', T: 'Temporary Fix', W: 'Workaround', U: 'Unavailable' },
  RC: { label: 'Report Confidence', X: 'Not Defined', U: 'Unknown', R: 'Reasonable', C: 'Confirmed' },
  CR: { label: 'Confidentiality Requirement', X: 'Not Defined', L: 'Low', M: 'Medium', H: 'High' },
  IR: { label: 'Integrity Requirement', X: 'Not Defined', L: 'Low', M: 'Medium', H: 'High' },
  AR: { label: 'Availability Requirement', X: 'Not Defined', L: 'Low', M: 'Medium', H: 'High' },
  MAV: { label: 'Modified Attack Vector', N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
  MAC: { label: 'Modified Attack Complexity', L: 'Low', H: 'High' },
  MPR: { label: 'Modified Privileges Required', N: 'None', L: 'Low', H: 'High' },
  MUI: { label: 'Modified User Interaction', N: 'None', R: 'Required' },
  MS:  { label: 'Modified Scope', U: 'Unchanged', C: 'Changed' },
  MC:  { label: 'Modified Confidentiality', N: 'None', L: 'Low', H: 'High' },
  MI:  { label: 'Modified Integrity', N: 'None', L: 'Low', H: 'High' },
  MA:  { label: 'Modified Availability', N: 'None', L: 'Low', H: 'High' }
};

function parseCvssVector(vectorString) {
  if (!vectorString) return [];
  const parts = vectorString.split('/');
  const version = parts.find((p) => p.startsWith('CVSS:'));
  const metrics = parts.filter((p) => p.includes(':') && !p.startsWith('CVSS:'));
  return metrics.map((m) => {
    const [key, value] = m.split(':');
    const def = CVSS_LABELS[key] || {};
    return {
      metric: `${key} - ${def.label || key}`,
      value: value,
      label: def[value] || value
    };
  });
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function escapeAttr(value) {
  return escapeHtml(value).replaceAll('`', '&#96;');
}

loadStatus();
// Initial load: show latest 10
el.queryInput.value = '';
setTimeout(() => runSearch(), 100);

// ===== SBOM Management =====

async function loadSbomList() {
  el.searchForm.hidden = true;
  el.detailPane.innerHTML = '';
  renderSbomUpload();
  try {
    const data = await api('/api/v1/sbom.list');
    renderSbomItems(data.items);
  } catch (e) {
    document.getElementById('sbomUploadStatus').textContent = `Error loading list: ${escapeHtml(e.message)}`;
  }
}

function renderSbomUpload() {
  el.resultList.innerHTML = `
    <div class="search-form">
      <label class="upload-area">
        <span>Upload CycloneDX SBOM (JSON)</span>
        <div style="display:flex;gap:8px;align-items:center">
          <input type="file" id="sbomFileInput" accept=".json,application/json" style="display:none">
          <button type="button" class="primary-button upload-btn" id="sbomUploadBtn">Choose file & Upload</button>
          <span class="muted" id="sbomUploadStatus"></span>
        </div>
      </label>
    </div>
    <div id="sbomListItems"></div>
  `;
  setupSbomUpload();
}

function renderSbomItems(items) {
  const list = document.getElementById('sbomListItems');
  if (!list) return;
  list.innerHTML = items.length
    ? `<div class="muted result-item" style="font-weight:600">Uploaded SBOMs (${items.length})</div>
       ${items.map(i => `
         <button class="result-item" type="button" data-sbom-id="${escapeAttr(i.id)}" style="display:grid;gap:4px">
           <div class="result-main"><span class="result-title">${escapeHtml(i.name)}</span></div>
           <div class="result-meta">
             <span class="badge">${i.componentCount} components</span>
             <span class="badge ${i.matchedCount > 0 ? 'high' : ''}">${i.matchedCount} vulns</span>
             <span class="badge">${date(i.uploadedAt)}</span>
           </div>
         </button>
       `).join('')}`
    : '<div class="muted result-item">No SBOMs uploaded yet</div>';
  list.querySelectorAll('[data-sbom-id]').forEach(btn => {
    btn.addEventListener('click', () => loadSbomDetail(btn.dataset.sbomId));
  });
}

function setupSbomUpload() {
  const btn = document.getElementById('sbomUploadBtn');
  const fileInput = document.getElementById('sbomFileInput');
  const status = document.getElementById('sbomUploadStatus');
  if (!btn || !fileInput) return;
  btn.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files[0];
    if (!file) return;
    status.textContent = 'Uploading...';
    try {
      const text = await file.text();
      const data = await api('/api/v1/sbom.upload', { method: 'POST', body: text });
      status.textContent = `Uploaded: ${data.name} (${data.componentCount} components)`;
      loadSbomList();
    } catch (e) {
      status.textContent = `Error: ${escapeHtml(e.message)}`;
    }
  });
}

async function loadSbomDetail(sbomId) {
  el.detailPane.innerHTML = '<div class="empty-state"><h2>Loading...</h2></div>';
  try {
    const data = await api(`/api/v1/sbom.get?id=${encodeURIComponent(sbomId)}`);
    renderSbomDetail(data);
  } catch (e) {
    el.detailPane.innerHTML = `<div class="empty-state"><h2>Error</h2><p>${escapeHtml(e.message)}</p></div>`;
  }
}

function renderSbomDetail(data) {
  const s = data.sbom;
  el.detailPane.innerHTML = `
    <header class="detail-header">
      <div class="detail-title"><h2>${escapeHtml(s.name)}</h2></div>
      <div class="detail-meta-row">
        <span class="kv-inline">Components <b>${s.componentCount}</b></span>
        <span class="kv-inline">Vulns matched <b>${s.matchedCount}</b></span>
        <span class="kv-inline">Format <b>${s.format}</b></span>
      </div>
      <div style="display:flex;gap:8px;margin-top:8px">
        <button class="tab" type="button" id="sbomMatchBtn" style="height:32px;padding:0 12px">Match Vulnerabilities</button>
        <button class="tab" type="button" id="sbomDeleteBtn" style="height:32px;padding:0 12px;color:var(--risk)">Delete</button>
      </div>
    </header>
    <div class="detail-sections" style="margin-top:16px">
      <section class="detail-section">
        <h3 class="section-h">Components</h3>
        <div class="card-stack">
          ${data.components.map(c => `
            <div class="info-card">
              <div class="info-card-row">
                <strong>${escapeHtml(c.name || c.purl)}</strong>
                ${c.version ? `<span class="badge">${escapeHtml(c.version)}</span>` : ''}
                ${c.vulnCount > 0 ? `<span class="badge high">${c.vulnCount} vulns</span>` : '<span class="badge">no vulns</span>'}
              </div>
              <div class="chips">
                ${c.ecosystem ? `<span class="badge">${escapeHtml(c.ecosystem)}</span>` : ''}
                <code style="font-size:11px;color:var(--muted)">${escapeHtml(c.purl)}</code>
              </div>
            </div>
          `).join('')}
        </div>
      </section>
      ${data.vulnerabilities.length ? `
      <section class="detail-section">
        <h3 class="section-h">Findings by Component</h3>
        ${renderGroupedFindings(data.vulnerabilities, data.components)}
      </section>` : ''}
    </div>
  `;

  document.getElementById('sbomMatchBtn')?.addEventListener('click', async () => {
    document.getElementById('sbomMatchBtn').textContent = 'Matching...';
    try {
      await api('/api/v1/sbom.match', { method: 'POST', body: JSON.stringify({ sbomId }) });
      loadSbomDetail(sbomId);
    } catch(e) { alert('Match failed: ' + e.message); }
  });

  document.getElementById('sbomDeleteBtn')?.addEventListener('click', async () => {
    if (!confirm('Delete this SBOM?')) return;
    try {
      await api('/api/v1/sbom.delete', { method: 'POST', body: JSON.stringify({ sbomId }) });
      el.detailPane.innerHTML = '<div class="empty-state"><h2>Deleted</h2></div>';
      loadSbomList();
    } catch(e) { alert('Delete failed: ' + e.message); }
  });

  // Make vuln cards AND table rows clickable
  el.detailPane.querySelectorAll('[data-vuln-id]').forEach(el => {
    el.addEventListener('click', () => loadVulnerabilityDetail(el.dataset.vulnId));
  });
}

function renderGroupedFindings(vulnerabilities, components) {
  const byComp = {};
  vulnerabilities.forEach(v => {
    const cid = v.componentId || 'other';
    if (!byComp[cid]) {
      const comp = components.find(c => c.id === cid) || {};
      byComp[cid] = { name: comp.name || v.componentName || 'component', version: comp.version || '', ecosystem: v.ecosystem || '', vulns: [] };
    }
    byComp[cid].vulns.push(v);
  });
  return Object.values(byComp).map(g => {
    const matched = g.vulns.filter(v => v.versionMatched === true).length;
    const notAffected = g.vulns.filter(v => v.versionMatched === false).length;
    return `<div style="margin-bottom:20px;border:1px solid var(--line);border-radius:10px;overflow:hidden">
      <div class="finding-header" style="padding:10px 14px;background:#f9faf7;border-bottom:1px solid var(--line)">
        <strong>${escapeHtml(g.name)}</strong>
        ${g.version ? `<span class="badge">v${escapeHtml(g.version)}</span>` : ''}
        <span class="badge tag-source">${escapeHtml(g.ecosystem)}</span>
        <span class="badge high">${matched} affected</span>
        ${notAffected > 0 ? `<span class="badge none">${notAffected} not affected</span>` : ''}
      </div>
      <table class="table" style="border:none;margin:0"><thead><tr><th>CVE</th><th>Severity</th><th>Range</th><th>Status</th></tr></thead><tbody>
      ${g.vulns.map(v => {
        const s = v.versionMatched === true ? 'AFFECTED' : v.versionMatched === false ? 'NOT AFFECTED' : '?';
        const kl = v.versionMatched === true ? 'risk' : v.versionMatched === false ? 'none' : '';
        return `<tr data-vuln-id="${escapeAttr(v.vulnerabilityId)}" class="finding-row" style="cursor:pointer">
          <td><span class="finding-cve">${escapeHtml(v.primaryIdentifier)}</span></td>
          <td>${severityBadge(v.severityLabel, v.cvssScore)}</td>
          <td><code style="font-size:11px">${escapeHtml(v.versionRange || 'no range')}</code></td>
          <td><span class="badge ${kl}">${s}</span></td></tr>`;
      }).join('')}
      </tbody></table></div>`;
  }).join('');
}
