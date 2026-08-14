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

export async function loadAdminPage() {
  if (el.resultsMeta) el.resultsMeta.textContent = modeDescription('admin');
  el.resultList.innerHTML = '<div class="muted result-item">Fetcher controls</div>';
  showDetailPane();
  if (!state.authenticated) {
    el.detailPane.innerHTML = renderAuthRequired('Fetcher administration is private');
    bindLoginPrompt();
    return;
  }
  el.detailPane.innerHTML = '<div class="empty-state"><h2>Loading fetchers</h2></div>';
  try {
    const sources = await api('/api/v1/admin.source.list');
    renderAdminPage(sources);
  } catch (error) {
    el.detailPane.innerHTML = `<div class="empty-state"><h2>Admin unavailable</h2><p>${escapeHtml(error.message)}</p></div>`;
  }
}

function renderAdminPage(sources) {
  const domestic = new Set(['cnnvd', 'cnvd', 'seebug', 'aliyun-avd', 'nsfocus-vulndb', 'chaitin-vuldb', 'cert-360']);
  const groups = adminSourceGroups(sources, domestic);
  el.detailPane.innerHTML = `
    <article class="status-page">
      <header class="status-hero admin-hero">
        <div>
          <span class="eyebrow">Administration</span>
          <h2>Fetcher controls</h2>
          <p class="summary">CNNVD runs on schedule. Other domestic intelligence sources stay manual until explicitly enabled.</p>
        </div>
      </header>
      <section class="detail-section">
        <div class="section-title-row">
          <h3 class="section-h">Sources</h3>
          <span class="badge">${fmt(sources.length)}</span>
        </div>
        <div class="admin-source-list">
          ${groups.map(([label, items]) => `
            <section class="admin-source-group">
              <header class="admin-source-group-head">
                <strong>${escapeHtml(label)}</strong>
                <span class="badge">${fmt(items.length)}</span>
              </header>
              <div class="admin-source-group-list">
                ${items.map(source => renderAdminSource(source, domestic.has(source.code))).join('')}
              </div>
            </section>
          `).join('')}
        </div>
      </section>
    </article>
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

function renderAdminSource(source, domestic) {
  const run = source.latestRun;
  return `
    <div class="admin-source-row" data-admin-source="${escapeAttr(source.code)}">
      <div class="admin-source-main">
        <div>
          <strong>${escapeHtml(source.name || source.code)}</strong>
          <small>${escapeHtml(source.code)}</small>
        </div>
        <div class="chips">
          ${domestic ? '<span class="badge">CN intel</span>' : ''}
          <span class="badge ${source.enabled ? 'low' : 'none'}">${source.enabled ? 'enabled' : 'disabled'}</span>
          <span class="badge">${escapeHtml(source.kind)}</span>
          <span class="badge">${fmt(source.rawTotal)} raw</span>
          <span class="badge">${escapeHtml(run?.status || 'idle')}</span>
        </div>
      </div>
      <small class="admin-source-feedback">${run ? `Latest ${escapeHtml(run.status)} · ${fmt(run.fetchedCount)} fetched · ${dateTime(run.finishedAt || run.startedAt)}` : 'No completed fetch run'}</small>
    </div>
  `;
}
