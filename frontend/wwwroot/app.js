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
    el.queryLabel.textContent = state.mode === 'component' ? 'Component name or purl' : 'Identifier or keyword';
    el.queryInput.placeholder = state.mode === 'component' ? 'pkg:maven/org.apache.logging.log4j/log4j-core' : 'CVE-2021-44228';
    runSearch();
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
    body: JSON.stringify({ query, pageSize: 50 })
  });

  if (!data.items.length) {
    el.resultList.innerHTML = '<div class="muted result-item">No vulnerabilities found</div>';
    return;
  }

  el.resultList.innerHTML = data.items.map((item) => vulnerabilityResult(item)).join('');
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
  const sources = [...new Set((data.records || []).map(r => r.code || 'unknown').filter(Boolean))];
  const sourceTotal = Math.max(Number(v.sourceCount || 0), sources.length);

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
      <div class="chips">${(v.identifiers || []).slice(0, 20).map((id) => `<span class="badge">${escapeHtml(id)}</span>`).join('')}</div>
    </header>

    <div class="tabs source-tabs" role="tablist" aria-label="Source view">
      <button class="tab is-active" type="button" data-source="all">All sources (${fmt(sourceTotal)})</button>
      ${sources.map(s => `<button class="tab" type="button" data-source="${escapeAttr(s)}">${escapeHtml(s)} (${fmt((data.records||[]).filter(r=>r.code===s).length)})</button>`).join('')}
    </div>

    <div class="detail-grid">
      <div id="detailContent">
        ${renderSourceContent(data, 'all')}
      </div>
      <aside>
        <section class="section">
          <h3>Overview</h3>
          <div class="kv">
            <div>Sources</div><div>${fmt(sourceTotal)}</div>
            <div>Published</div><div>${date(v.publishedAt)}</div>
            <div>Modified</div><div>${date(v.modifiedAt)}</div>
            <div>Affected</div><div>${fmt(v.affectedComponentCount)}</div>
          </div>
        </section>
        ${tableSection('Severity facts', ['Source', 'System', 'Vector', 'Score'], (data.severities||[]).map((item) => [
          item.code, item.scoring_system + ' ' + (item.scoring_version||''), item.vector_string || '-', item.score ?? item.severity_label ?? ''
        ]))}
        ${rawSection('Source payload sample', (data.records||[])[0]?.source_specific)}
      </aside>
    </div>
  `;

  el.detailPane.querySelectorAll('.source-tabs .tab').forEach(tab => {
    tab.addEventListener('click', () => {
      el.detailPane.querySelectorAll('.source-tabs .tab').forEach(t => t.classList.remove('is-active'));
      tab.classList.add('is-active');
      const source = tab.dataset.source;
      const content = document.getElementById('detailContent');
      if (content) content.innerHTML = renderSourceContent(data, source);
    });
  });
}

function renderSourceContent(data, source) {
  const isAll = source === 'all';
  const records = isAll ? (data.records||[]) : (data.records||[]).filter(r => r.code === source);
  const severities = isAll ? (data.severities||[]) : (data.severities||[]).filter(r => r.code === source);
  const refs = isAll ? (data.references||[]) : (data.references||[]).filter(r => r.code === source);
  const descriptions = isAll ? (data.descriptions||[]) : (data.descriptions||[]).filter(r => r.code === source);
  const affected = isAll
    ? (data.affectedComponents||[]).map(item => ({ ...item, code: 'merged' }))
    : (data.affectedFacts||[]).filter(r => r.code === source);

  let html = '';

  if (records.length) {
    html += cardSection('Source records', records.map(r => ({
      title: r.source_record_id || r.id || r.code,
      meta: [r.code, r.status].filter(Boolean),
      body: r.title || r.description || ''
    })));
  }

  if (descriptions.length) {
    html += cardSection('Descriptions', descriptions.map(d => ({
      title: d.description_type || d.code,
      meta: [d.code, d.lang].filter(Boolean),
      body: d.value || ''
    })));
  }

  if (severities.length) {
    html += cardSection('Severity', severities.map(s => ({
      title: `${s.scoring_system || 'severity'} ${s.score ?? s.severity_label ?? ''}`.trim(),
      meta: [s.code, s.scoring_version].filter(Boolean),
      body: s.vector_string || ''
    })));
  }

  if (affected.length) {
    html += cardSection('Affected', affected.slice(0, 80).map(c => ({
      title: c.display_name || c.package_name || c.purl || c.primary_purl || c.cpe23_uri || c.primary_cpe23_uri || 'component',
      meta: [c.code, c.ecosystem, c.range_type].filter(Boolean),
      body: c.version_range_raw || c.normalized_range || c.purl || c.primary_purl || c.cpe23_uri || c.primary_cpe23_uri || ''
    })));
  }

  if (refs.length) {
    html += cardSection('References', refs.map(r => ({
      title: r.url ? `<a href="${escapeAttr(r.url)}" target="_blank" rel="noreferrer">${escapeHtml(shortUrl(r.url))}</a>` : 'reference',
      meta: [r.code, r.ref_type, ...(Array.isArray(r.tags) ? r.tags.slice(0, 3) : [])].filter(Boolean),
      body: ''
    })), true);
  }

  return html || '<div class="empty-state"><p>No data for this source</p></div>';
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
  if (!label && score == null) return '';
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
runSearch();
