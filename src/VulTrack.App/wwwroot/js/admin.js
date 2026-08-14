import { api } from './api.js';
import {
  state,
  el,
  showDetailPane,
  renderAuthRequired,
  bindLoginPrompt,
  modeDescription
} from './state.js';
import { escapeHtml, escapeAttr, fmt, dateTime } from './format.js';

const ADMIN_REFRESH_MS = 30_000;
let adminRefreshTimer = null;
let adminBusy = false;

export function stopAdminAutoRefresh() {
  if (adminRefreshTimer) {
    clearInterval(adminRefreshTimer);
    adminRefreshTimer = null;
  }
}

export async function loadAdminPage() {
  stopAdminAutoRefresh();
  if (el.resultsMeta) el.resultsMeta.textContent = modeDescription('admin');
  el.resultList.innerHTML = '<div class="muted result-item">Administration dashboard</div>';
  showDetailPane();
  if (!state.authenticated) {
    el.detailPane.innerHTML = renderAuthRequired('Administration is private');
    bindLoginPrompt();
    return;
  }
  el.detailPane.innerHTML = '<div class="empty-state"><h2>Loading dashboard</h2></div>';
  try {
    await refreshAdminDashboard({ silent: false });
    adminRefreshTimer = setInterval(() => {
      if (state.mode !== 'admin') {
        stopAdminAutoRefresh();
        return;
      }
      if (adminBusy) return;
      refreshAdminDashboard({ silent: true });
    }, ADMIN_REFRESH_MS);
  } catch (error) {
    el.detailPane.innerHTML = `<div class="empty-state"><h2>Admin unavailable</h2><p>${escapeHtml(error.message)}</p></div>`;
  }
}

async function refreshAdminDashboard({ silent }) {
  const [statsResult, statusResult, sourcesResult, coverageResult] = await Promise.allSettled([
    api('/api/v1/admin.duckdbEvidence.stats'),
    api('/api/v1/system.status'),
    api('/api/v1/admin.source.list'),
    api('/api/v1/admin.duckdbEvidence.coverage')
  ]);
  const data = {
    stats: statsResult.status === 'fulfilled' ? statsResult.value : null,
    status: statusResult.status === 'fulfilled' ? statusResult.value : null,
    sources: sourcesResult.status === 'fulfilled' ? sourcesResult.value : null,
    coverage: coverageResult.status === 'fulfilled' ? coverageResult.value : null
  };
  const failures = [statsResult, statusResult, sourcesResult, coverageResult]
    .filter(result => result.status === 'rejected')
    .map(result => result.reason?.message || 'Request failed');
  if (!data.stats && !data.status && !data.sources && !data.coverage) {
    throw new Error(failures[0] || 'Admin endpoints unavailable');
  }
  renderAdminDashboard(data, failures, silent);
}

function renderAdminDashboard(data, failures, silent) {
  const domestic = new Set(['cnnvd', 'cnvd', 'seebug', 'aliyun-avd', 'nsfocus-vulndb', 'chaitin-vuldb', 'cert-360']);
  el.detailPane.innerHTML = `
    <article class="status-page admin-dashboard">
      ${renderAdminHero(data)}
      ${failures.length ? `<div class="admin-alert" role="alert">${failures.map(message => `<p>${escapeHtml(message)}</p>`).join('')}</div>` : ''}
      ${renderOverviewSection(data)}
      ${renderOperationsSection()}
      ${renderSourcesSection(data.sources, domestic)}
      ${renderCoverageSection(data.coverage)}
      <p class="admin-refresh-note">Auto-refresh every ${ADMIN_REFRESH_MS / 1000}s while this tab is active${silent ? ' · refreshed' : ''} ${dateTime(new Date().toISOString())} UTC</p>
    </article>
  `;
  bindAdminOperations();
}

function renderAdminHero(data) {
  const database = data.status?.database || {};
  const fileBytes = Number(data.stats?.fileBytes ?? database.fileBytes ?? 0);
  const path = data.stats?.path || database.path || '';
  return `
    <header class="status-hero admin-hero">
      <div>
        <span class="eyebrow">Administration</span>
        <h2>Management dashboard</h2>
        <p class="summary">DuckDB-first evidence store, fetcher sources, and maintenance operations. All data is served from the embedded database; nothing here touches external services.</p>
      </div>
      <div class="admin-storage-card">
        <span class="admin-storage-label">Storage</span>
        <strong>${fmtBytes(fileBytes)}</strong>
        <small>${escapeHtml(data.status?.storageBackend || 'duckdb')} backend</small>
        <small class="admin-storage-path" title="${escapeAttr(path)}">${escapeHtml(path || 'unknown path')}</small>
      </div>
    </header>
  `;
}

function renderOverviewSection(data) {
  const database = data.status?.database || {};
  const queue = data.status?.queue || {};
  const scheduler = data.status?.scheduler || {};
  const cards = [
    ['Vulnerabilities', database.vulnerabilities, 'catalog entries'],
    ['Source records', database.sourceRecords, 'raw evidence rows'],
    ['Affected components', database.affectedComponents, 'query projection'],
    ['Exploits', database.exploits, 'active references'],
    ['Identifiers', database.identifiers, 'CVE / GHSA / OSV aliases']
  ];
  return `
    <section class="detail-section" aria-labelledby="adminOverviewHeading">
      <div class="section-title-row">
        <h3 class="section-h" id="adminOverviewHeading">Overview</h3>
        <span class="badge">${escapeHtml(scheduler.enabled ? 'scheduler on' : 'scheduler off')}</span>
      </div>
      <div class="admin-stat-grid">
        ${cards.map(([label, value, hint]) => `
          <div class="admin-stat-card">
            <span class="admin-stat-label">${escapeHtml(label)}</span>
            <strong>${fmt(value)}</strong>
            <small>${escapeHtml(hint)}</small>
          </div>
        `).join('')}
      </div>
      <div class="admin-runtime-grid">
        <div class="admin-runtime-item">
          <span>Spool queue</span>
          <strong>${fmt(queue.readyFiles)} ready · ${fmtBytes(queue.readyBytes)}</strong>
          <small>${fmt(queue.processingFiles)} processing</small>
        </div>
        <div class="admin-runtime-item">
          <span>Evidence detail</span>
          <strong>${fmt(data.stats?.affectedFacts ?? database.affectedFacts)} affected facts</strong>
          <small>${fmt(data.stats?.severityScores ?? database.severityScores)} severity scores · ${fmt(data.stats?.references ?? database.references)} references · ${fmt(data.stats?.weaknesses ?? database.weaknesses)} weaknesses</small>
        </div>
        <div class="admin-runtime-item">
          <span>Intelligence</span>
          <strong>${fmt(database.threatScores)} threat scores</strong>
          <small>${fmt(database.aiAnalyses)} AI analyses · ${fmt(database.sboms)} SBOM uploads</small>
        </div>
      </div>
    </section>
  `;
}

function renderOperationsSection() {
  return `
    <section class="detail-section" aria-labelledby="adminOpsHeading">
      <div class="section-title-row">
        <h3 class="section-h" id="adminOpsHeading">Operations</h3>
      </div>
      <div class="admin-op-grid">
        <div class="admin-op-card">
          <div class="admin-op-copy">
            <strong>Ingest spool now</strong>
            <p>Import every pending <code>*.ndjson.ready</code> spool file into DuckDB and rebuild affected catalog entries.</p>
          </div>
          <button class="primary-button admin-op-button" type="button" data-admin-op="ingest">
            <span class="admin-op-spinner" aria-hidden="true"></span>
            <span class="admin-op-text">Ingest spool</span>
          </button>
          <p class="admin-op-feedback" role="status" aria-live="polite" data-admin-feedback="ingest"></p>
        </div>
        <div class="admin-op-card">
          <div class="admin-op-copy">
            <strong>Rebuild catalog</strong>
            <p>Heavy operation: rebuilds the full vulnerability catalog and affected-component projection from all source records.</p>
          </div>
          <button class="primary-button admin-op-button admin-op-danger" type="button" data-admin-op="rebuild">
            <span class="admin-op-spinner" aria-hidden="true"></span>
            <span class="admin-op-text">Rebuild catalog</span>
          </button>
          <p class="admin-op-feedback" role="status" aria-live="polite" data-admin-feedback="rebuild"></p>
        </div>
      </div>
    </section>
  `;
}

function bindAdminOperations() {
  el.detailPane.querySelector('[data-admin-op="ingest"]')?.addEventListener('click', () => runAdminOperation('ingest'));
  el.detailPane.querySelector('[data-admin-op="rebuild"]')?.addEventListener('click', () => runAdminOperation('rebuild'));
}

async function runAdminOperation(kind) {
  if (adminBusy) return;
  if (kind === 'rebuild' && !window.confirm('Rebuild the full catalog from all source records? This is a heavy DuckDB operation that can take a long time and will block other writes.')) return;
  if (kind === 'ingest' && !window.confirm('Ingest all pending spool files into DuckDB now?')) return;
  adminBusy = true;
  setAdminOperationState(kind, true, '');
  try {
    if (kind === 'ingest') {
      const result = await api('/api/v1/admin.duckdbSpool.ingest', {
        method: 'POST',
        body: JSON.stringify({ maxFiles: 1000, batchSize: 5000 })
      });
      const files = Array.isArray(result?.files) ? result.files : [];
      const records = files.reduce((sum, file) => sum + Number(file.records || 0), 0);
      const facts = files.reduce((sum, file) => sum + Number(file.affectedFacts || 0), 0);
      const errors = files.reduce((sum, file) => sum + Number(file.errors || 0), 0);
      const catalog = result?.catalog || {};
      setAdminOperationState(kind, false, files.length
        ? `Ingested ${fmt(files.length)} files · ${fmt(records)} records · ${fmt(facts)} affected facts · ${fmt(errors)} errors · catalog now ${fmt(catalog.vulnerabilities)} vulnerabilities`
        : 'No pending spool files to ingest');
    } else {
      const result = await api('/api/v1/admin.duckdbCatalog.rebuild', { method: 'POST' });
      setAdminOperationState(kind, false,
        `Catalog rebuilt: ${fmt(result?.vulnerabilities)} vulnerabilities · ${fmt(result?.identifiers)} identifiers from ${fmt(result?.sourceRecords)} source records`);
    }
  } catch (error) {
    setAdminOperationState(kind, false, `Failed: ${error.message}`, true);
  } finally {
    adminBusy = false;
    if (state.mode === 'admin') refreshAdminDashboard({ silent: true });
  }
}

function setAdminOperationState(kind, running, message, isError = false) {
  el.detailPane.querySelectorAll('.admin-op-button').forEach(button => {
    button.disabled = running;
    button.classList.toggle('is-loading', running && button.dataset.adminOp === kind);
    button.setAttribute('aria-busy', running && button.dataset.adminOp === kind ? 'true' : 'false');
  });
  const feedback = el.detailPane.querySelector(`[data-admin-feedback="${kind}"]`);
  if (feedback) {
    feedback.textContent = running ? 'Running…' : message;
    feedback.classList.toggle('is-error', !running && isError);
    feedback.classList.toggle('is-ok', !running && !isError && Boolean(message));
  }
}

function renderSourcesSection(sources, domestic) {
  if (!sources) {
    return `
      <section class="detail-section" aria-labelledby="adminSourcesHeading">
        <div class="section-title-row"><h3 class="section-h" id="adminSourcesHeading">Sources</h3></div>
        <p class="muted">Source list unavailable.</p>
      </section>
    `;
  }
  const groups = adminSourceGroups(sources, domestic);
  return `
    <section class="detail-section" aria-labelledby="adminSourcesHeading">
      <div class="section-title-row">
        <h3 class="section-h" id="adminSourcesHeading">Sources</h3>
        <span class="badge">${fmt(sources.length)}</span>
      </div>
      <div class="admin-source-list">
        ${groups.map(([label, items]) => `
          <section class="admin-source-group" aria-label="${escapeAttr(label)}">
            <header class="admin-source-group-head">
              <strong>${escapeHtml(label)}</strong>
              <span class="badge">${fmt(items.length)}</span>
            </header>
            <div class="admin-source-grid">
              ${items.map(source => renderAdminSource(source, domestic.has(source.code))).join('')}
            </div>
          </section>
        `).join('')}
      </div>
    </section>
  `;
}

function adminSourceGroups(sources, domestic) {
  const groups = new Map();
  for (const source of sources) {
    const [order, label] = adminSourceCategory(source, domestic);
    if (!groups.has(label)) groups.set(label, { label, order, items: [] });
    groups.get(label).items.push(source);
  }
  return [...groups.values()]
    .sort((a, b) => a.order - b.order)
    .map(group => [
      group.label,
      group.items.sort((a, b) => String(a.name || a.code).localeCompare(String(b.name || b.code)))
    ]);
}

function adminSourceCategory(source, domestic) {
  const code = String(source.code || '').toLowerCase();
  const kind = String(source.kind || '').toLowerCase();
  if (domestic.has(code)) return [4, 'Domestic intelligence'];
  if (kind.includes('component') || code.includes('registry') || code === 'nvd-cpe') return [3, 'Component catalogs'];
  if (kind.includes('exploit') || ['metasploit', 'exploitdb', 'trickest-cve', 'poc-in-github', 'nuclei-templates'].includes(code)) {
    return [2, 'Exploit intelligence'];
  }
  if (code.includes('advisory') || code.includes('osv') || code.includes('csaf') || code.includes('secdb') || code.includes('tracker')) {
    return [1, 'Ecosystem advisories'];
  }
  return [0, 'Core vulnerability feeds'];
}

function checkpointSkipped(checkpoint) {
  const reason = checkpoint?.skipped;
  return Boolean(reason) && String(reason).toLowerCase() !== 'false';
}

function sourceRunTone(source) {
  const run = source.latestRun;
  const status = String(run?.status || '').toLowerCase();
  if (['failed', 'error'].includes(status)) return 'risk';
  if (checkpointSkipped(source.checkpoint) || status === 'skipped') return 'warn';
  if (['succeeded', 'success', 'ok', 'completed'].includes(status)) return 'ok';
  if (status === 'running') return 'run';
  return 'idle';
}

function renderAdminSource(source, domestic) {
  const run = source.latestRun || null;
  const tone = sourceRunTone(source);
  const statusLabel = run?.status || 'never run';
  const fetched = run ? Number(run.fetched_count ?? run.fetchedCount ?? 0) : 0;
  const parsed = run ? Number(run.parsed_count ?? run.parsedCount ?? 0) : 0;
  const errors = run ? Number(run.error_count ?? run.errorCount ?? 0) : 0;
  const finishedAt = run ? (run.finished_at || run.finishedAt || run.started_at || run.startedAt) : null;
  const checkpointAt = source.checkpoint?.lastFetched || source.checkpoint?.lastChecked || null;
  const skipReason = checkpointSkipped(source.checkpoint) ? String(source.checkpoint.skipped) : '';
  return `
    <div class="admin-source-card" data-admin-source="${escapeAttr(source.code)}">
      <div class="admin-source-card-head">
        <div class="admin-source-title">
          <span class="admin-dot ${tone}" aria-hidden="true"></span>
          <strong>${escapeHtml(source.name || source.code)}</strong>
        </div>
        <div class="chips">
          ${domestic ? '<span class="badge">CN intel</span>' : ''}
          <span class="badge ${source.enabled ? 'low' : 'none'}">${source.enabled ? 'enabled' : 'disabled'}</span>
          <span class="badge">${escapeHtml(source.kind)}</span>
        </div>
      </div>
      <div class="admin-source-meta">
        <span class="admin-source-status admin-tone-${tone}">${escapeHtml(statusLabel)}</span>
        <small>${escapeHtml(source.code)} · ${escapeHtml(source.runMode || 'incremental')}</small>
      </div>
      <div class="admin-source-run">
        ${run
          ? `<span>${fmt(fetched)} fetched · ${fmt(parsed)} parsed${errors ? ` · <span class="risk-text">${fmt(errors)} errors</span>` : ''}</span>
             <small>Last run ${dateTime(finishedAt)} UTC${run.trigger ? ` · ${escapeHtml(run.trigger)}` : ''}</small>`
          : '<span class="muted">No completed fetch run</span>'}
        ${checkpointAt ? `<small>Checkpoint ${dateTime(checkpointAt)} UTC</small>` : ''}
        ${skipReason ? `<small class="admin-skip-reason">Skipped: ${escapeHtml(skipReason)}</small>` : ''}
      </div>
    </div>
  `;
}

function renderCoverageSection(coverage) {
  if (!coverage) {
    return `
      <section class="detail-section" aria-labelledby="adminCoverageHeading">
        <div class="section-title-row"><h3 class="section-h" id="adminCoverageHeading">Coverage</h3></div>
        <p class="muted">Coverage data unavailable.</p>
      </section>
    `;
  }
  const sources = Array.isArray(coverage.sources) ? coverage.sources : [];
  const ecosystems = Array.isArray(coverage.ecosystems) ? coverage.ecosystems : [];
  const maxRecords = Math.max(1, ...sources.map(row => Number(row.records || 0)));
  return `
    <section class="detail-section" aria-labelledby="adminCoverageHeading">
      <div class="section-title-row">
        <h3 class="section-h" id="adminCoverageHeading">Coverage</h3>
        <span class="badge">${dateTime(coverage.generatedAt)} UTC</span>
      </div>
      <div class="admin-coverage-grid">
        <div class="admin-coverage-panel">
          <h4 class="admin-coverage-title">Records per source</h4>
          <div class="admin-table-scroll">
            <table class="table admin-coverage-table">
              <thead>
                <tr><th scope="col">Source</th><th scope="col">Records</th><th scope="col">Vulnerabilities</th><th scope="col">Latest modified</th></tr>
              </thead>
              <tbody>
                ${sources.length ? sources.map(row => {
                  const records = Number(row.records || 0);
                  const width = Math.max(2, Math.round((records / maxRecords) * 100));
                  return `
                    <tr>
                      <td>
                        <span class="admin-coverage-source">${escapeHtml(row.source_code)}</span>
                        <span class="admin-bar-track" aria-hidden="true"><span class="admin-bar" style="width:${width}%"></span></span>
                      </td>
                      <td>${fmt(records)}</td>
                      <td>${fmt(row.vulnerabilities)}</td>
                      <td>${dateTime(row.latest_modified_at)}</td>
                    </tr>
                  `;
                }).join('') : '<tr><td colspan="4" class="muted">No source records yet</td></tr>'}
              </tbody>
            </table>
          </div>
        </div>
        <div class="admin-coverage-panel">
          <h4 class="admin-coverage-title">Ecosystem coverage</h4>
          <div class="admin-table-scroll">
            <table class="table admin-coverage-table">
              <thead>
                <tr><th scope="col">Ecosystem</th><th scope="col">Components</th><th scope="col">Vulns</th><th scope="col">Ranged</th><th scope="col">PURL</th><th scope="col">CPE</th></tr>
              </thead>
              <tbody>
                ${ecosystems.length ? ecosystems.map(row => `
                  <tr>
                    <td>${escapeHtml(row.ecosystem)}</td>
                    <td>${fmt(row.components)}</td>
                    <td>${fmt(row.vulnerabilities)}</td>
                    <td>${pctShare(row.ranged_components, row.components)}</td>
                    <td>${pctShare(row.purl_components, row.components)}</td>
                    <td>${pctShare(row.cpe_components, row.components)}</td>
                  </tr>
                `).join('') : '<tr><td colspan="6" class="muted">No affected components yet</td></tr>'}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>
  `;
}

function pctShare(part, total) {
  const denominator = Number(total || 0);
  if (denominator <= 0) return '-';
  return `${((Number(part || 0) / denominator) * 100).toFixed(1)}%`;
}

function fmtBytes(bytes) {
  const value = Number(bytes || 0);
  if (!Number.isFinite(value) || value <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const exp = Math.min(units.length - 1, Math.floor(Math.log(value) / Math.log(1024)));
  return `${(value / 1024 ** exp).toFixed(exp === 0 ? 0 : 1)} ${units[exp]}`;
}
