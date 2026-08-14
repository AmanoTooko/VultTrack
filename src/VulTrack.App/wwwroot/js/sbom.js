import { api } from './api.js';
import {
  el,
  showDetailPane,
  hideDetailPane,
  setSbomDetailView,
  updateRoute,
  sbomRoute,
  cveRoute,
  modeRoute,
  modeDescription
} from './state.js';
import { escapeHtml, escapeAttr, date, severityBadge, renderSkeletonDetail } from './format.js';
import { bindVulnerabilityLinks, displayIdentifier } from './vulnerabilities.js';

export async function loadSbomList(options = {}) {
  setSbomDetailView(false);
  el.searchForm.hidden = true;
  if (el.resultsMeta) el.resultsMeta.textContent = modeDescription('sbom');
  hideDetailPane();
  renderSbomUpload();
  try {
    const data = await api('/api/v1/sbom.list');
    renderSbomItems(data.items);
    if (options.detailId) await loadSbomDetail(options.detailId, { updateRoute: false });
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
         <a class="result-item" href="${sbomRoute(i.id)}" data-sbom-id="${escapeAttr(i.id)}" style="display:grid;gap:4px">
           <div class="result-main"><span class="result-title">${escapeHtml(i.name)}</span></div>
           <div class="result-meta">
             <span class="badge">${i.componentCount} components</span>
             <span class="badge ${i.matchedCount > 0 ? 'high' : ''}">${i.matchedCount} vulns</span>
             <span class="badge">${date(i.uploadedAt)}</span>
           </div>
         </a>
       `).join('')}`
    : '<div class="muted result-item">No SBOMs uploaded yet</div>';
  list.querySelectorAll('[data-sbom-id]').forEach(link => {
    link.addEventListener('click', (event) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      loadSbomDetail(link.dataset.sbomId);
    });
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
      const data = await api(`/api/v1/sbom.upload?name=${encodeURIComponent(file.name)}`, { method: 'POST', body: text });
      status.textContent = `Uploaded: ${data.name} (${data.componentCount} components)`;
      loadSbomList();
    } catch (e) {
      status.textContent = `Error: ${escapeHtml(e.message)}`;
    }
  });
}

export async function loadSbomDetail(sbomId, options = {}) {
  setSbomDetailView(true);
  showDetailPane();
  el.detailPane.innerHTML = renderSkeletonDetail();
  try {
    const data = await api(`/api/v1/sbom.get?id=${encodeURIComponent(sbomId)}`);
    renderSbomDetail(data, sbomId);
    if (options.updateRoute !== false) updateRoute(sbomRoute(sbomId));
    el.detailPane.scrollIntoView({ block: 'start', behavior: 'smooth' });
  } catch (e) {
    el.detailPane.innerHTML = `<div class="empty-state"><h2>Error</h2><p>${escapeHtml(e.message)}</p></div>`;
  }
}

function renderSbomDetail(data, sbomId) {
  const s = data.sbom;
  const vulns = data.vulnerabilities || [];
  const comps = data.components || [];

  const grouped = {};
  vulns.forEach(v => {
    const cid = v.componentId || 'other';
    if (!grouped[cid]) grouped[cid] = [];
    grouped[cid].push(v);
  });

  const sorted = comps
    .map(c => ({ ...c, storeVulns: grouped[c.id] || [] }))
    .sort((a, b) => ((b.vulnCount || 0) - (a.vulnCount || 0)) || (a.name || '').localeCompare(b.name || ''));

  el.detailPane.innerHTML = `
    <header class="detail-header sbom-detail-header">
      <div class="detail-title"><h2>${escapeHtml(s.name)}</h2></div>
      <div class="detail-meta-row">
        <span class="kv-inline">Components <b>${s.componentCount}</b></span>
        <span class="kv-inline">Affected findings <b>${s.matchedCount}</b></span>
        <span class="kv-inline">Format <b>${s.format}</b></span>
      </div>
      <div class="sbom-actions">
        <button class="tab" type="button" id="sbomMatchBtn">Match PURL + CPE</button>
        <button class="tab" type="button" id="sbomExportBtn">Export Excel</button>
        <button class="tab risk-text" type="button" id="sbomDeleteBtn">Delete</button>
      </div>
    </header>
    <div class="detail-sections sbom-detail-sections">
      <section class="detail-section">
        <h3 class="section-h">Components (${sorted.length})</h3>
        <div class="card-stack">
          ${sorted.map(c => {
            const hasVulns = (c.vulnCount || 0) > 0;
            const displayVulns = c.storeVulns || [];
            return `
              <div class="info-card sbom-component-card ${hasVulns ? 'has-findings' : ''}">
                <div class="info-card-row sbom-component-head" ${hasVulns ? `data-expand="${escapeAttr(c.id)}"` : ''}>
                  <strong class="sbom-component-name">${escapeHtml(c.name || c.product || c.purl || c.cpe23Uri || 'component')}</strong>
                  <div class="sbom-component-badges">
                    ${c.version ? `<span class="badge">${escapeHtml(c.version)}</span>` : ''}
                    <span class="badge ${hasVulns ? 'risk' : ''}">${c.vulnCount || 0} affected</span>
                    ${hasVulns ? '<span class="badge sbom-expand-indicator">&#9660;</span>' : ''}
                  </div>
                </div>
                <div class="chips sbom-component-tags">
                  ${c.ecosystem ? `<span class="badge">${escapeHtml(c.ecosystem)}</span>` : ''}
                  ${c.vendor ? `<span class="badge">${escapeHtml(c.vendor)}</span>` : ''}
                  ${c.product ? `<span class="badge">${escapeHtml(c.product)}</span>` : ''}
                  ${c.purl ? `<code class="sbom-token">${escapeHtml(c.purl)}</code>` : ''}
                  ${c.cpe23Uri ? `<code class="sbom-token">${escapeHtml(c.cpe23Uri)}</code>` : ''}
                </div>
                ${hasVulns ? `
                <div class="sbom-expand" id="expand-${c.id}" hidden>
                  <table class="table sbom-finding-table"><thead><tr>
                    <th>CVE</th><th>Severity</th><th>Version Range</th><th>Status</th>
                  </tr></thead><tbody>
                  ${displayVulns.map(v => {
                    const isMatched = v.versionMatched === true;
                    const isFalse = v.versionMatched === false;
                    const hasRange = v.versionRange && v.versionRange !== '';
                    const status = isMatched ? 'AFFECTED' : isFalse ? 'FIXED' : (hasRange ? '?' : 'unknown');
                    const kl = isMatched ? 'risk' : isFalse ? 'none' : '';
                    const displayId = displayIdentifier(v);
                    const rangeDisplay = hasRange
                      ? `<code class="sbom-token">${escapeHtml(v.versionRange)}</code>`
                      : `<span class="muted sbom-small-note" title="Alpine secfixes: no version data">no version data</span>`;
                    return `<tr class="finding-row">
                      <td><a class="finding-cve" href="${cveRoute(displayId)}" data-vulnerability-id="${escapeAttr(v.vulnerabilityId)}" data-vulnerability-identifier="${escapeAttr(displayId)}">${escapeHtml(displayId)}</a></td>
                      <td>${severityBadge(v.severityLabel, v.cvssScore)}</td>
                      <td>${rangeDisplay}</td>
                      <td><span class="badge ${kl}">${status}</span></td></tr>`;
                  }).join('')}
                  ${displayVulns.length < (c.vulnCount || 0) ? `<tr><td colspan="4" class="muted sbom-more-row">+${(c.vulnCount || 0) - displayVulns.length} more CVEs (increase limit)</td></tr>` : ''}
                  </tbody></table>
                </div>` : ''}
              </div>`;
          }).join('')}
        </div>
      </section>
    </div>
  `;

  document.getElementById('sbomMatchBtn')?.addEventListener('click', async () => {
    document.getElementById('sbomMatchBtn').textContent = 'Matching...';
    try {
      await api('/api/v1/sbom.match', { method: 'POST', body: JSON.stringify({ sbomId }) });
      loadSbomDetail(sbomId);
    } catch(e) { alert('Match failed: ' + e.message); }
  });

  document.getElementById('sbomExportBtn')?.addEventListener('click', () => {
    window.location.href = `/api/v1/sbom.export?id=${encodeURIComponent(sbomId)}`;
  });

  document.getElementById('sbomDeleteBtn')?.addEventListener('click', async () => {
    if (!confirm('Delete this SBOM?')) return;
    try {
      await api('/api/v1/sbom.delete', { method: 'POST', body: JSON.stringify({ sbomId }) });
      el.detailPane.innerHTML = '<div class="empty-state"><h2>Deleted</h2></div>';
      updateRoute(modeRoute('sbom'), { replace: true });
      loadSbomList();
    } catch(e) { alert('Delete failed: ' + e.message); }
  });

  el.detailPane.querySelectorAll('[data-expand]').forEach(row => {
    row.addEventListener('click', () => {
      const target = document.getElementById('expand-' + row.dataset.expand);
      if (target) target.hidden = !target.hidden;
    });
  });

  bindVulnerabilityLinks(el.detailPane);
}
