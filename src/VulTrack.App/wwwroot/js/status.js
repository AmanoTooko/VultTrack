import { api } from './api.js';
import {
  state,
  el,
  showDetailPane,
  renderAuthRequired,
  bindLoginPrompt
} from './state.js';
import { escapeHtml, escapeAttr, fmt, dateTime, slug } from './format.js';

export async function loadStatus() {
  try {
    const data = await api('/api/v1/system.status?fast=true');
    state.statusData = data;
    if (el.metricRaw) el.metricRaw.textContent = fmt(data.sourceRawRecords);
    el.metricVulns.textContent = fmt(data.vulnerabilities);
    el.metricComponents.textContent = fmt(data.components);
    const pending = data.normalizeStatus.find((item) => item.status === 'pending')?.count ?? 0;
    if (el.statusLine) el.statusLine.textContent = `${fmt(pending)} raw records pending normalization`;
    if (el.statusPending) el.statusPending.textContent = fmt(pending);
    if (state.mode === 'status') renderStatusPage(data);
  } catch (error) {
    if (el.statusLine) el.statusLine.textContent = error.message;
    if (el.statusPending) el.statusPending.textContent = '-';
  }
}

export async function loadStatusPage() {
  if (el.resultsMeta) el.resultsMeta.textContent = 'Fast source snapshot. Use exact refresh when you need full raw-row counts.';
  el.resultList.innerHTML = '<div class="muted result-item">Pipeline sources</div>';
  showDetailPane();
  if (!state.authenticated) {
    el.detailPane.innerHTML = renderAuthRequired('Pipeline status is private');
    bindLoginPrompt();
    return;
  }
  el.detailPane.innerHTML = '<div class="empty-state"><h2>Loading status</h2></div>';
  try {
    const data = await api('/api/v1/system.status?fast=true');
    state.statusData = data;
    renderStatusPage(data);
    renderStatusSourceList(data);
  } catch (error) {
    el.detailPane.innerHTML = `<div class="empty-state"><h2>Status unavailable</h2><p>${escapeHtml(error.message)}</p></div>`;
  }
}

async function loadExactStatusPage() {
  showDetailPane();
  el.detailPane.innerHTML = '<div class="empty-state"><h2>Loading exact status</h2><p>This scans raw status rows and can take a few seconds.</p></div>';
  try {
    const data = await api('/api/v1/system.status');
    state.statusData = data;
    renderStatusPage(data);
    renderStatusSourceList(data);
    loadStatus();
  } catch (error) {
    el.detailPane.innerHTML = `<div class="empty-state"><h2>Status unavailable</h2><p>${escapeHtml(error.message)}</p></div>`;
  }
}

function renderStatusSourceList(data) {
  const sources = data.sourceStatus || [];
  const active = sources.filter(s => s.enabled).length;
  el.resultList.innerHTML = `
    <div class="muted result-item" style="font-weight:700">Sources ${fmt(active)} / ${fmt(sources.length)} enabled</div>
    ${sources.slice(0, 80).map((source) => {
      const pending = Number(source.normalizePending || 0) + Number(source.normalizeFailed || 0);
      const klass = source.latestRun?.status === 'failed' || source.normalizeFailed > 0 ? 'risk' :
        pending > 0 ? 'warn' : 'low';
      return `
        <a class="result-item source-jump" href="#source-${escapeAttr(slug(source.code))}">
          <div class="result-main">
            <span class="result-title">${escapeHtml(source.code)}</span>
            <span class="badge ${klass}">${escapeHtml(source.latestRun?.status || 'idle')}</span>
          </div>
          <div class="result-meta">
            <span class="badge">${fmt(source.rawTotal)} raw</span>
            <span class="badge ${pending ? 'warn' : 'low'}">${fmt(pending)} pending</span>
          </div>
        </a>
      `;
    }).join('')}
  `;
}

function renderStatusPage(data) {
  const sources = data.sourceStatus || [];
  const active = sources.filter(s => s.enabled).length;
  const pending = data.normalizeStatus.find((item) => item.status === 'pending')?.count ?? 0;
  const failed = data.normalizeStatus.find((item) => item.status === 'failed')?.count ?? 0;
  const succeeded = data.normalizeStatus.find((item) => item.status === 'succeeded')?.count ?? 0;
  const totalRaw = Number(data.sourceRawRecords || 0);
  const progress = totalRaw > 0 ? Math.round(Number(succeeded) / totalRaw * 1000) / 10 : 0;
  const sortedSources = [...sources].sort((a, b) => {
    const ap = Number(a.normalizePending || 0) + Number(a.normalizeFailed || 0);
    const bp = Number(b.normalizePending || 0) + Number(b.normalizeFailed || 0);
    return bp - ap || String(a.code).localeCompare(String(b.code));
  });

  el.detailPane.innerHTML = `
    <article class="status-page">
      <header class="status-hero">
        <div>
          <span class="eyebrow">Pipeline Status</span>
          <h2>Source and normalizer health</h2>
          <p class="summary">Exact database counts, latest fetch runs, normalization backlog, and approximate next run times for every enabled source.</p>
        </div>
        <div class="status-score">
          <span>Normalized</span>
          <strong>${fmt(succeeded)} / ${fmt(totalRaw)}</strong>
          <div class="progress-track"><i style="width:${Math.min(100, progress)}%"></i></div>
          <small>${progress}% complete</small>
        </div>
      </header>

      <section class="status-kpi-grid">
        ${statusKpi('Vulnerabilities', data.vulnerabilities)}
        ${statusKpi('Source records', data.vulnerabilityRecords)}
        ${statusKpi('Raw source rows', data.sourceRawRecords)}
        ${statusKpi('Affected components', data.affectedComponents)}
        ${statusKpi('Components', data.components)}
        ${statusKpi('Sources enabled', `${active}/${sources.length}`)}
        ${statusKpi('Pending normalize', pending, pending ? 'warn' : 'low')}
        ${statusKpi('Failed normalize', failed, failed ? 'risk' : 'low')}
      </section>

      <section class="detail-section">
        <div class="section-title-row">
          <h3 class="section-h">Normalizer Queue</h3>
          <div class="chips">
            <span class="badge ${data.countsEstimated ? 'warn' : 'low'}">${data.countsEstimated ? 'estimated snapshot' : 'exact counts'}</span>
            <span class="badge">${dateTime(data.generatedAt)}</span>
            ${data.countsEstimated ? '<button class="tab" type="button" data-exact-status>Exact refresh</button>' : ''}
          </div>
        </div>
        <div class="queue-grid">
          ${(data.normalizeStatus || []).map(item => `
            <div class="queue-card">
              <span>${escapeHtml(item.status)}</span>
              <strong>${fmt(item.count)}</strong>
            </div>
          `).join('')}
        </div>
      </section>

      <section class="detail-section">
        <div class="section-title-row">
          <h3 class="section-h">Sources</h3>
          <span class="badge">${fmt(sortedSources.length)}</span>
        </div>
        <div class="source-status-table">
          <div class="source-status-head">
            <span>Source</span><span>Fetch</span><span>Raw</span><span>Normalizer</span><span>Updated</span><span>Next</span>
          </div>
          ${sortedSources.map(renderSourceStatusRow).join('')}
        </div>
      </section>
    </article>
  `;
  el.detailPane.querySelector('[data-exact-status]')?.addEventListener('click', loadExactStatusPage);
}

function statusKpi(label, value, tone = '') {
  return `
    <div class="status-kpi ${tone}">
      <span>${escapeHtml(label)}</span>
      <strong>${typeof value === 'number' ? fmt(value) : escapeHtml(value)}</strong>
    </div>
  `;
}

function renderSourceStatusRow(source) {
  const pending = Number(source.normalizePending || 0);
  const failed = Number(source.normalizeFailed || 0);
  const raw = Number(source.rawTotal || 0);
  const progress = raw > 0 ? Math.round(Number(source.normalizeSucceeded || 0) / raw * 100) : 0;
  const run = source.latestRun;
  const statusClass = run?.status === 'failed' || failed > 0 ? 'risk' : pending > 0 ? 'warn' : 'low';
  return `
    <div class="source-status-row" id="source-${escapeAttr(slug(source.code))}">
      <div class="source-name-cell">
        <strong>${escapeHtml(source.code)}</strong>
        <small>${escapeHtml(source.name || source.pluginName || '')}</small>
      </div>
      <div>
        <span class="badge ${statusClass}">${escapeHtml(run?.status || 'idle')}</span>
        <small>${run ? `${fmt(run.fetchedCount)} fetched / ${fmt(run.parsedCount)} parsed` : 'No run yet'}</small>
      </div>
      <div>
        <strong>${fmt(raw)}</strong>
        <small>${escapeHtml(source.kind || '')}</small>
      </div>
      <div>
        <strong>${fmt(source.normalizeSucceeded)} done</strong>
        <small>${fmt(pending)} pending / ${fmt(failed)} failed</small>
        <div class="progress-track mini"><i style="width:${Math.min(100, progress)}%"></i></div>
      </div>
      <div>
        <strong>${dateTime(source.rawUpdatedAt || run?.finishedAt || run?.startedAt)}</strong>
        <small>${source.lastSuccessAt ? `success ${dateTime(source.lastSuccessAt)}` : 'no success yet'}</small>
      </div>
      <div>
        <strong>${nextRunLabel(source)}</strong>
        <small>${escapeHtml(source.scheduleCron || source.runMode || 'manual')}</small>
      </div>
    </div>
  `;
}

function nextRunLabel(source) {
  if (!source.enabled) return 'disabled';
  if (String(source.runMode || '').toLowerCase() === 'init' && !source.scheduleCron) {
    return source.lastSuccessAt ? 'init closed' : 'init pending';
  }
  if (!source.scheduleCron) return 'manual';
  if (!source.lastSuccessAt) return 'due now';
  const next = new Date(new Date(source.lastSuccessAt).getTime() + cronMinimumMs(source.scheduleCron));
  return next <= new Date() ? 'due now' : dateTime(next.toISOString());
}

function cronMinimumMs(cron) {
  const parts = String(cron || '').split(/\s+/).filter(Boolean);
  const hour = parts[1] || '';
  if (hour.startsWith('*/')) {
    const hours = Number(hour.slice(2));
    if (Number.isFinite(hours) && hours > 0) return hours * 60 * 60 * 1000;
  }
  return 24 * 60 * 60 * 1000;
}
