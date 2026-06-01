const state = {
  mode: 'vulnerability',
  selectedId: null,
  themeColor: localStorage.getItem('vultrack.themeColor') || '#2f7da7',
  page: 1,
  pageSize: Number(localStorage.getItem('vultrack.pageSize') || 25),
  sort: localStorage.getItem('vultrack.sort') || 'modifiedDesc',
  hasMore: false,
  authenticated: false,
  username: null
};

const el = {
  shell: document.querySelector('.shell'),
  themeColorInput: document.querySelector('#themeColorInput'),
  themeSwatches: [...document.querySelectorAll('.theme-swatch')],
  statusLine: document.querySelector('#statusLine'),
  refreshButton: document.querySelector('#refreshButton'),
  statusButton: document.querySelector('#statusButton'),
  statusPending: document.querySelector('#statusPending'),
  metricVulns: document.querySelector('#metricVulns'),
  metricRecords: document.querySelector('#metricRecords'),
  metricAffected: document.querySelector('#metricAffected'),
  metricComponents: document.querySelector('#metricComponents'),
  metricSources: document.querySelector('#metricSources'),
  tabs: [...document.querySelectorAll('.tab')],
  searchForm: document.querySelector('#searchForm'),
  queryInput: document.querySelector('#queryInput'),
  vendorInput: document.querySelector('#vendorInput'),
  versionInput: document.querySelector('#versionInput'),
  ecosystemInput: document.querySelector('#ecosystemInput'),
  limitSelect: document.querySelector('#limitSelect'),
  sortSelect: document.querySelector('#sortSelect'),
  queryLabel: document.querySelector('#queryLabel'),
  componentFields: document.querySelector('#componentFields'),
  resultList: document.querySelector('#resultList'),
  detailPane: document.querySelector('#detailPane'),
  resultsTitle: document.querySelector('#resultsTitle'),
  resultsMeta: document.querySelector('#resultsMeta'),
  syntaxHint: document.querySelector('#syntaxHint'),
  pager: document.querySelector('#pager'),
  pageLabel: document.querySelector('#pageLabel'),
  prevPageButton: document.querySelector('#prevPageButton'),
  nextPageButton: document.querySelector('#nextPageButton'),
  authButton: document.querySelector('#authButton'),
  loginDialog: document.querySelector('#loginDialog'),
  loginForm: document.querySelector('#loginForm'),
  loginUsername: document.querySelector('#loginUsername'),
  loginPassword: document.querySelector('#loginPassword'),
  loginError: document.querySelector('#loginError'),
  loginCancelButton: document.querySelector('#loginCancelButton')
};

if (el.limitSelect) el.limitSelect.value = String(state.pageSize);
if (el.sortSelect) el.sortSelect.value = state.sort;
document.body.dataset.mode = state.mode;
if (el.syntaxHint) el.syntaxHint.innerHTML = syntaxHintHtml(state.mode);
applyThemeColor(state.themeColor);

el.themeSwatches.forEach((button) => {
  button.addEventListener('click', () => {
    applyThemeColor(button.dataset.themeColor);
  });
});

el.themeColorInput?.addEventListener('input', (event) => {
  applyThemeColor(event.target.value);
});

el.refreshButton.addEventListener('click', () => {
  loadStatus();
  if (state.mode === 'status') loadStatusPage();
  else runSearch();
});

el.statusButton?.addEventListener('click', () => {
  const tab = el.tabs.find((item) => item.dataset.mode === 'status');
  if (tab) activateMode(tab);
});

el.authButton?.addEventListener('click', async () => {
  if (state.authenticated) {
    await api('/api/v1/auth.logout', { method: 'POST' });
    state.authenticated = false;
    state.username = null;
    updateAuthUi();
    activateMode(el.tabs.find((item) => item.dataset.mode === 'vulnerability'));
    return;
  }
  openLogin();
});

el.loginCancelButton?.addEventListener('click', () => el.loginDialog?.close());

el.loginForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const data = await api('/api/v1/auth.login', {
      method: 'POST',
      body: JSON.stringify({ username: el.loginUsername.value, password: el.loginPassword.value })
    });
    state.authenticated = Boolean(data.authenticated);
    state.username = data.username;
    el.loginError.hidden = true;
    el.loginPassword.value = '';
    el.loginDialog.close();
    updateAuthUi();
    if (state.mode === 'status') loadStatusPage();
    if (state.mode === 'admin') loadAdminPage();
    else loadStatus();
  } catch (error) {
    el.loginError.textContent = error.message;
    el.loginError.hidden = false;
  }
});

el.tabs.forEach((tab) => {
  tab.addEventListener('click', () => {
    activateMode(tab);
  });
});

el.searchForm.addEventListener('submit', (event) => {
  event.preventDefault();
  state.page = 1;
  runSearch();
});

el.limitSelect?.addEventListener('change', () => {
  state.pageSize = Number(el.limitSelect.value || 25);
  localStorage.setItem('vultrack.pageSize', String(state.pageSize));
  state.page = 1;
  runSearch();
});

el.sortSelect?.addEventListener('change', () => {
  state.sort = el.sortSelect.value || 'modifiedDesc';
  localStorage.setItem('vultrack.sort', state.sort);
  state.page = 1;
  runSearch();
});

el.prevPageButton?.addEventListener('click', () => {
  if (state.page <= 1) return;
  state.page--;
  runSearch();
});

el.nextPageButton?.addEventListener('click', () => {
  if (!state.hasMore) return;
  state.page++;
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

function showDetailPane() {
  el.detailPane.hidden = false;
}

function hideDetailPane() {
  el.detailPane.hidden = true;
  el.detailPane.innerHTML = '';
}

function applyThemeColor(color) {
  const normalized = normalizeHexColor(color) || '#2f7da7';
  state.themeColor = normalized;
  localStorage.setItem('vultrack.themeColor', normalized);
  document.documentElement.style.setProperty('--accent', normalized);
  document.documentElement.style.setProperty('--accent-soft', mixHex(normalized, '#ffffff', 0.84));
  document.documentElement.style.setProperty('--accent-wash', mixHex(normalized, '#ffffff', 0.94));
  if (el.themeColorInput) el.themeColorInput.value = normalized;
  el.themeSwatches.forEach((button) => {
    button.classList.toggle('is-active', normalizeHexColor(button.dataset.themeColor) === normalized);
  });
}

function normalizeHexColor(color) {
  if (!color) return null;
  const match = String(color).trim().match(/^#?([0-9a-f]{6})$/i);
  return match ? `#${match[1].toLowerCase()}` : null;
}

function mixHex(color, base, baseWeight) {
  const a = hexToRgb(color);
  const b = hexToRgb(base);
  if (!a || !b) return base;
  const weight = Math.max(0, Math.min(1, baseWeight));
  const mixed = a.map((value, index) => Math.round(value * (1 - weight) + b[index] * weight));
  return `#${mixed.map(v => v.toString(16).padStart(2, '0')).join('')}`;
}

function hexToRgb(color) {
  const normalized = normalizeHexColor(color);
  if (!normalized) return null;
  return [1, 3, 5].map(index => parseInt(normalized.slice(index, index + 2), 16));
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'content-type': 'application/json' },
    ...options
  });
  const body = await res.json();
  if (!res.ok || body.ok === false) {
    if (res.status === 401) {
      state.authenticated = false;
      state.username = null;
      updateAuthUi();
    }
    throw new Error(body.error?.message ?? `Request failed: ${res.status}`);
  }
  return body.data;
}

async function loadAuthSession() {
  try {
    const data = await api('/api/v1/auth.session');
    state.authenticated = Boolean(data.authenticated);
    state.username = data.username;
  } catch {
    state.authenticated = false;
    state.username = null;
  }
  updateAuthUi();
}

function updateAuthUi() {
  if (!el.authButton) return;
  el.authButton.textContent = state.authenticated ? `Logout ${state.username || ''}`.trim() : 'Login';
  el.authButton.classList.toggle('is-active', state.authenticated);
}

function openLogin() {
  if (!el.loginDialog) return;
  el.loginError.hidden = true;
  el.loginDialog.showModal();
  setTimeout(() => el.loginUsername?.focus(), 0);
}

function renderAuthRequired(title = 'Login required') {
  return `
    <div class="empty-state auth-required">
      <h2>${escapeHtml(title)}</h2>
      <p>Administrator login is required for pipeline status and fetcher controls.</p>
      <button class="primary-button" type="button" data-open-login>Login</button>
    </div>
  `;
}

function bindLoginPrompt() {
  el.detailPane.querySelector('[data-open-login]')?.addEventListener('click', openLogin);
}

async function loadStatus() {
  try {
    const data = await api('/api/v1/system.status?fast=true');
    state.statusData = data;
    el.metricVulns.textContent = fmt(data.vulnerabilities);
    el.metricRecords.textContent = fmt(data.vulnerabilityRecords);
    el.metricAffected.textContent = fmt(data.affectedComponents);
    el.metricComponents.textContent = fmt(data.components);
    if (el.metricSources) el.metricSources.textContent = fmt(data.sources);
    const pending = data.normalizeStatus.find((item) => item.status === 'pending')?.count ?? 0;
    el.statusLine.textContent = `${fmt(pending)} raw records pending normalization`;
    if (el.statusPending) el.statusPending.textContent = `${fmt(pending)} pending`;
    if (state.mode === 'status') renderStatusPage(data);
  } catch (error) {
    el.statusLine.textContent = error.message;
    if (el.statusPending) el.statusPending.textContent = 'status error';
  }
}

function activateMode(tab) {
  if (!tab) return;
  state.mode = tab.dataset.mode;
  document.body.dataset.mode = state.mode;
  state.page = 1;
  state.hasMore = false;
  el.tabs.forEach((item) => item.classList.toggle('is-active', item === tab));
  el.componentFields.hidden = state.mode !== 'component';
  el.searchForm.hidden = state.mode === 'sbom' || state.mode === 'status' || state.mode === 'admin';
  el.queryLabel.textContent = state.mode === 'component' ? 'Component name, vendor, or purl' : 'Identifier or keyword';
  el.queryInput.placeholder = state.mode === 'component' ? 'pkg:maven/org.apache.logging.log4j/log4j-core' : 'CVE-2021-44228';
  if (el.sortSelect) el.sortSelect.disabled = state.mode !== 'vulnerability';
  if (el.pager) el.pager.hidden = state.mode === 'sbom' || state.mode === 'status' || state.mode === 'admin';
  if (el.syntaxHint) el.syntaxHint.innerHTML = syntaxHintHtml(state.mode);
  if (el.resultsTitle) el.resultsTitle.textContent = modeTitle(state.mode);
  if (el.resultsMeta) el.resultsMeta.textContent = modeDescription(state.mode);
  updatePager();
  if (state.mode === 'sbom') loadSbomList();
  else if (state.mode === 'status') loadStatusPage();
  else if (state.mode === 'admin') loadAdminPage();
  else runSearch();
}

function syntaxHintHtml(mode) {
  const items = {
    vulnerability: [
      ['CVE prefix', 'CVE-2021'],
      ['Exact CVE', 'CVE-2021-44228'],
      ['Keyword', 'log4j remote code execution'],
      ['Sort', 'Updated, Published, CVSS, CVE ID']
    ],
    component: [
      ['PURL', 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'],
      ['Name', 'log4j-core'],
      ['Vendor', 'org.apache.logging.log4j'],
      ['Version', '2.14.1']
    ],
    sbom: [
      ['Formats', 'CycloneDX JSON'],
      ['Matching', 'PURL + CPE'],
      ['Export', 'Excel-compatible .xls'],
      ['Output', 'Component, CVE, CVSS, CWE, URLs']
    ],
    status: [
      ['Default', 'Fast snapshot'],
      ['Exact', 'Exact refresh'],
      ['Queues', 'Normalizer and fetch status'],
      ['Sources', 'Schedule and latest run']
    ],
    admin: [
      ['Sources', 'Enable or disable'],
      ['Fetch', 'Run one source'],
      ['Normalize', 'Process pending rows'],
      ['Reprocess', 'Queue stored raw rows']
    ]
  }[mode] || [];
  return items.map(([label, value]) => `<span>${escapeHtml(label)} <code>${escapeHtml(value)}</code></span>`).join('');
}

function modeTitle(mode) {
  return {
    vulnerability: 'Vulnerabilities',
    component: 'Components',
    sbom: 'SBOM uploads',
    status: 'Pipeline status',
    admin: 'Fetcher administration'
  }[mode] || 'Vulnerabilities';
}

function modeDescription(mode) {
  return {
    vulnerability: 'Search CVE identifiers, affected packages, titles, and source aliases.',
    component: 'Search package names, purl coordinates, vendor hints, ecosystems, and versions.',
    sbom: 'Upload, match, inspect, and export CycloneDX SBOM findings with PURL and CPE evidence.',
    status: 'Fast source snapshot with optional exact counts for raw-row queues.',
    admin: 'Control fetcher schedules, run manual scans, normalize staged records, and queue stored raw rows again.'
  }[mode] || '';
}

function searchMetaText(query) {
  if (state.mode === 'component') return 'Search package names, purl coordinates, vendor hints, ecosystems, and versions.';
  if (state.mode === 'vulnerability') {
    const label = query ? `"${query}"` : 'latest indexed vulnerabilities';
    return `${label} · ${sortLabel(state.sort)} · ${state.pageSize} per page`;
  }
  return '';
}

function sortLabel(sort) {
  return {
    modifiedDesc: 'updated first',
    publishedDesc: 'published first',
    identifierDesc: 'CVE ID descending',
    cvssDesc: 'highest CVSS',
    cvssAsc: 'lowest CVSS'
  }[sort] || 'updated first';
}

function updatePager(itemCount = null) {
  if (el.pageLabel) {
    const suffix = itemCount == null ? '' : ` · ${fmt(itemCount)} shown`;
    el.pageLabel.textContent = `Page ${fmt(state.page)}${suffix}`;
  }
  if (el.prevPageButton) el.prevPageButton.disabled = state.page <= 1;
  if (el.nextPageButton) el.nextPageButton.disabled = !state.hasMore;
}

async function loadStatusPage() {
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

async function loadAdminPage() {
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
  const sorted = [...sources].sort((a, b) => Number(domestic.has(b.code)) - Number(domestic.has(a.code)) || String(a.code).localeCompare(String(b.code)));
  el.detailPane.innerHTML = `
    <article class="status-page">
      <header class="status-hero admin-hero">
        <div>
          <span class="eyebrow">Administration</span>
          <h2>Fetcher controls</h2>
          <p class="summary">CNNVD runs on schedule. Other domestic intelligence sources stay manual until explicitly enabled.</p>
        </div>
        <div class="admin-global-actions">
          <button class="tab" type="button" data-admin-run-due>Run due scan</button>
          <button class="tab" type="button" data-admin-normalize-all>Normalize pending</button>
        </div>
      </header>
      <section class="detail-section">
        <div class="section-title-row">
          <h3 class="section-h">Sources</h3>
          <span class="badge">${fmt(sorted.length)}</span>
        </div>
        <div class="admin-source-list">
          ${sorted.map((source) => renderAdminSource(source, domestic.has(source.code))).join('')}
        </div>
      </section>
    </article>
  `;
  bindAdminActions();
}

function renderAdminSource(source, domestic) {
  const run = source.latestRun;
  return `
    <div class="admin-source-row" data-admin-source="${escapeAttr(source.code)}">
      <div class="admin-source-main">
        <div>
          <strong>${escapeHtml(source.code)}</strong>
          <small>${escapeHtml(source.name || '')}</small>
        </div>
        <div class="chips">
          ${domestic ? '<span class="badge">CN intel</span>' : ''}
          <span class="badge ${source.enabled ? 'low' : 'none'}">${source.enabled ? 'enabled' : 'disabled'}</span>
          <span class="badge">${escapeHtml(source.kind)}</span>
          <span class="badge">${fmt(source.rawTotal)} raw</span>
          <span class="badge">${escapeHtml(run?.status || 'idle')}</span>
        </div>
      </div>
      <div class="admin-config-grid">
        <label><span>Enabled</span><input type="checkbox" data-source-enabled ${source.enabled ? 'checked' : ''}></label>
        <label><span>Run mode</span>
          <select data-source-run-mode>
            <option value="" ${!source.runMode ? 'selected' : ''}>scheduled</option>
            <option value="manual" ${source.runMode === 'manual' ? 'selected' : ''}>manual</option>
            <option value="init" ${source.runMode === 'init' ? 'selected' : ''}>init</option>
          </select>
        </label>
        <label><span>Schedule</span><input data-source-schedule value="${escapeAttr(source.scheduleCron || '')}" placeholder="0 */6 * * *"></label>
        <button class="tab" type="button" data-admin-save>Save</button>
        <button class="tab" type="button" data-admin-fetch>Fetch</button>
        <button class="tab" type="button" data-admin-normalize>Normalize</button>
        <button class="tab risk-text" type="button" data-admin-reprocess>Reprocess</button>
      </div>
      <small class="admin-source-feedback">${run ? `Latest ${escapeHtml(run.status)} · ${fmt(run.fetchedCount)} fetched · ${dateTime(run.finishedAt || run.startedAt)}` : 'No completed fetch run'}</small>
    </div>
  `;
}

function bindAdminActions() {
  el.detailPane.querySelector('[data-admin-run-due]')?.addEventListener('click', (event) =>
    runAdminAction(event.currentTarget, '/api/v1/admin.scheduler.runDue', {}, 'Due scan completed'));
  el.detailPane.querySelector('[data-admin-normalize-all]')?.addEventListener('click', (event) =>
    runAdminAction(event.currentTarget, '/api/v1/raw.normalizePending', { limitPerSource: 100 }, 'Pending rows normalized'));
  el.detailPane.querySelectorAll('[data-admin-source]').forEach((row) => {
    const sourceCode = row.dataset.adminSource;
    row.querySelector('[data-admin-save]')?.addEventListener('click', (event) => runAdminAction(event.currentTarget, '/api/v1/admin.source.update', {
      sourceCode,
      enabled: row.querySelector('[data-source-enabled]').checked,
      runMode: row.querySelector('[data-source-run-mode]').value || null,
      scheduleCron: row.querySelector('[data-source-schedule]').value || null
    }, 'Source settings saved', row));
    row.querySelector('[data-admin-fetch]')?.addEventListener('click', (event) =>
      runAdminAction(event.currentTarget, '/api/v1/admin.source.fetch', { sourceCode }, 'Fetch completed', row));
    row.querySelector('[data-admin-normalize]')?.addEventListener('click', (event) =>
      runAdminAction(event.currentTarget, '/api/v1/admin.source.normalize', { sourceCode, limit: 100 }, 'Normalize completed', row));
    row.querySelector('[data-admin-reprocess]')?.addEventListener('click', (event) => {
      if (confirm(`Queue all stored raw rows for ${sourceCode} again?`))
        runAdminAction(event.currentTarget, '/api/v1/admin.source.reprocess', { sourceCode }, 'Stored rows queued', row);
    });
  });
}

async function runAdminAction(button, path, body, successMessage, row = null) {
  const original = button.textContent;
  const feedback = row?.querySelector('.admin-source-feedback');
  button.disabled = true;
  button.textContent = 'Running';
  try {
    const data = await api(path, { method: 'POST', body: JSON.stringify(body) });
    if (feedback) feedback.textContent = successMessage;
    else alert(successMessage);
    if (path !== '/api/v1/admin.source.reprocess') setTimeout(loadAdminPage, 250);
    return data;
  } catch (error) {
    if (feedback) feedback.textContent = error.message;
    else alert(error.message);
  } finally {
    button.disabled = false;
    button.textContent = original;
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

async function runSearch() {
  const query = el.queryInput.value.trim();
  state.hasMore = false;
  hideDetailPane();
  updatePager();
  if (el.resultsMeta) el.resultsMeta.textContent = searchMetaText(query);
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
    body: JSON.stringify({
      query,
      page: state.page,
      pageSize: state.pageSize,
      sort: state.sort
    })
  });
  state.page = data.page || state.page;
  state.pageSize = data.pageSize || state.pageSize;
  state.sort = data.sort || state.sort;
  state.hasMore = Boolean(data.hasMore);
  updatePager(data.items.length);

  if (!data.items.length) {
    el.resultList.innerHTML = '<div class="muted result-item">No vulnerabilities found</div>';
    return;
  }

  if (!query) {
    el.resultList.innerHTML = '<div class="muted result-item" style="font-weight:600">Recently updated</div>';
  } else {
    el.resultList.innerHTML = '';
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
      pageSize: state.pageSize
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
      pageSize: state.pageSize
    })
  });
  state.hasMore = false;
  updatePager(vulns.items.length + catalog.components.length + catalog.registryPackages.length);

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
  showDetailPane();
  el.detailPane.innerHTML = '<div class="empty-state"><h2>Loading</h2></div>';
  try {
    const data = await api(`/api/v1/vulnerability.detail?id=${encodeURIComponent(id)}`);
    renderDetail(data);
    el.detailPane.scrollIntoView({ block: 'start', behavior: 'smooth' });
  } catch (error) {
    el.detailPane.innerHTML = `<div class="empty-state"><h2>Request failed</h2><p>${escapeHtml(error.message)}</p></div>`;
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

function renderDetail(data) {
  const v = data.vulnerability;
  const records = data.records || [];
  const severities = data.severities || [];
  const refs = data.references || [];
  const exploits = data.exploits || [];
  const descriptions = aggregateDescriptions(data.descriptions || []);
  const affected = data.affectedComponents || [];
  const sourceUrls = data.sourceUrls || {};
  const sourceTags = [...new Set(records.map(r => r.code).filter(Boolean))];
  const affectedByEco = groupByEco(affected);
  const primaryDescription = descriptions[0]?.value || v.description || v.title || '';

  el.detailPane.innerHTML = `
    <article class="cve-page">
      <header class="cve-hero">
        <div class="cve-hero-main">
          <div class="eyebrow-row">
            <span class="eyebrow">Vulnerability Details</span>
            ${sourceTags.slice(0, 6).map(s => `<span class="badge tag-source">${escapeHtml(s)}</span>`).join('')}
          </div>
          <div class="detail-title">
            <h2>${escapeHtml(v.primaryIdentifier)}</h2>
            ${severityBadge(v.severityLabel, v.maxCvssScore)}
            ${v.epssScore ? `<span class="badge warn">EPSS ${pct(v.epssScore)}</span>` : ''}
            ${v.kevDateAdded ? '<span class="badge risk">KEV</span>' : ''}
          </div>
          <p class="summary cve-summary">${escapeHtml(primaryDescription)}</p>
          ${v.maxCvssVector ? cvssVectorBlock(v.maxCvssVersion, v.maxCvssVector) : ''}
        </div>
          ${renderHeroFacts(v, affectedByEco, records, refs, exploits)}
      </header>

      ${renderDetailNav()}

      <section class="detail-section ai-analysis-card" id="ai-analysis">
        ${renderAiAnalysisPlan(v, affected, refs, records)}
      </section>

      <div class="detail-two-column">
        <div class="detail-main-column">
          ${descriptions.length ? renderDescriptionCards(descriptions) : ''}
          ${renderMitreData(v, records, sourceUrls)}
          ${renderExploitSignals(exploits)}
          ${renderCpeConfigurations(affected)}
          ${renderAffectedGrouped(affected)}
          ${renderAdvisories(refs)}
          ${refs.length ? renderReferenceCards(refs) : '<section class="detail-section" id="references"><h3 class="section-h">References</h3><p class="muted">No references</p></section>'}
          ${renderRecordsBySource(records)}
        </div>
        <aside class="detail-rail">
          ${renderEnrichmentPanel(v, severities)}
          ${renderTrackingPanel(v, records, refs)}
        </aside>
      </div>
    </article>
  `;

  const affectedFilter = el.detailPane.querySelector('[data-affected-filter]');
  affectedFilter?.addEventListener('input', () => {
    const value = affectedFilter.value.toLowerCase();
    el.detailPane.querySelectorAll('.aff-eco-group').forEach((group) => {
      group.style.display = !value || (group.textContent || '').toLowerCase().includes(value) ? '' : 'none';
    });
  });
}

function renderHeroFacts(v, affectedByEco, records, refs, exploits = []) {
  const sourceCount = new Set(records.map(r => r.code).filter(Boolean)).size;
  return `
    <div class="hero-facts" aria-label="Vulnerability facts">
      ${factCard('Published', date(v.publishedAt))}
      ${factCard('Score', v.maxCvssScore != null ? `${Number(v.maxCvssScore).toFixed(1)} ${v.severityLabel || ''}` : 'N/A', 'strong')}
      ${factCard('EPSS', v.epssScore ? `${pct(v.epssScore)}${v.epssPercentile ? ` / P${Math.round(Number(v.epssPercentile) * 100)}` : ''}` : 'No data')}
      ${factCard('KEV', v.kevDateAdded ? `Yes, ${date(v.kevDateAdded)}` : 'No')}
      ${factCard('Impact', deriveImpact(v))}
      ${factCard('Action', deriveAction(v), 'action')}
      ${factCard('Sources', fmt(sourceCount))}
      ${factCard('Affected', `${fmt(v.affectedComponentCount)} / ${fmt(Object.keys(affectedByEco).length)} ecosystems`)}
      ${factCard('PoC', exploits.length ? fmt(exploits.length) : 'No data', exploits.length ? 'warn' : '')}
      ${factCard('References', fmt(refs.length))}
    </div>
  `;
}

function factCard(label, value, tone = '') {
  return `
    <div class="fact-card ${tone}">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value || '-')}</strong>
    </div>
  `;
}

function renderDetailNav() {
  const items = [
    ['AI Analysis', 'ai-analysis'],
    ['Mitre Data', 'mitre-data'],
    ['PoC / Exploit', 'exploit-signals'],
    ['CPE Configurations', 'cpe-configurations'],
    ['Affected Packages', 'affected-packages'],
    ['Enrichment', 'enrichment'],
    ['Tracking', 'tracking'],
    ['References', 'references'],
    ['Raw Data', 'raw-data']
  ];
  return `
    <nav class="detail-nav" aria-label="Detail sections">
      ${items.map(([label, id]) => `<a href="#${id}">${escapeHtml(label)}</a>`).join('')}
    </nav>
  `;
}

function renderAiAnalysisPlan(v, affected, refs, records) {
  return `
    <div class="section-title-row">
      <h3 class="section-h">AI Analysis</h3>
      <span class="badge warn">Planned</span>
    </div>
    <div class="ai-grid">
      <div class="analysis-field">
        <span>Impact brief</span>
        <p>Pending AI-generated explanation based on descriptions, CVSS metrics, affected components, and source advisories.</p>
      </div>
      <div class="analysis-field">
        <span>Affected systems</span>
        <p>${fmt(affected.length)} current affected facts across ${fmt(new Set(affected.map(a => a.ecosystem || 'unknown')).size)} ecosystems.</p>
      </div>
      <div class="analysis-field">
        <span>Exploitability signals</span>
        <p>CVSS ${v.maxCvssScore ?? 'N/A'}, EPSS ${v.epssScore ? pct(v.epssScore) : 'not loaded'}, KEV ${v.kevDateAdded ? 'yes' : 'no'}.</p>
      </div>
      <div class="analysis-field">
        <span>Evidence inputs</span>
        <p>${fmt(records.length)} source records and ${fmt(refs.length)} references are available for the future AI pipeline.</p>
      </div>
    </div>
  `;
}

function renderExploitSignals(exploits) {
  if (!exploits.length) {
    return `
      <section class="detail-section" id="exploit-signals">
        <div class="section-title-row">
          <h3 class="section-h">PoC / Exploit</h3>
          <span class="badge none">No signal</span>
        </div>
        ${renderDataGap('No public PoC, exploit module, or detection template has been linked yet.')}
      </section>
    `;
  }
  const grouped = {};
  exploits.forEach((item) => {
    const key = item.code || 'source';
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(item);
  });
  return `
    <section class="detail-section" id="exploit-signals">
      <div class="section-title-row">
        <h3 class="section-h">PoC / Exploit</h3>
        <span class="badge warn">${fmt(exploits.length)} signal${exploits.length > 1 ? 's' : ''}</span>
      </div>
      <div class="exploit-grid">
        ${Object.entries(grouped).map(([source, items]) => `
          <div class="exploit-source-group">
            <div class="affected-group-head">
              <strong>${escapeHtml(source)}</strong>
              <span class="badge">${fmt(items.length)}</span>
            </div>
            <div class="exploit-list">
              ${items.slice(0, 12).map(renderExploitItem).join('')}
            </div>
          </div>
        `).join('')}
      </div>
    </section>
  `;
}

function renderExploitItem(item) {
  const title = item.title || item.source_key || item.sourceKey || 'PoC';
  const url = item.source_url || item.sourceUrl || item.artifact_url || item.artifactUrl || '';
  const maturity = item.maturity || 'poc';
  const type = item.exploit_type || item.exploitType || item.artifact_type || item.artifactType || 'artifact';
  const verification = item.verification_status || item.verificationStatus || 'unreviewed';
  return `
    <div class="exploit-item">
      <div>
        <strong>${url ? `<a href="${escapeAttr(url)}" target="_blank" rel="noreferrer">${escapeHtml(title)}</a>` : escapeHtml(title)}</strong>
        <small>${escapeHtml(item.source_key || item.sourceKey || '')}</small>
      </div>
      <div class="chips">
        <span class="badge risk">${escapeHtml(maturity)}</span>
        <span class="badge">${escapeHtml(type)}</span>
        <span class="badge ${verification === 'unreviewed' ? 'none' : 'warn'}">${escapeHtml(verification)}</span>
        ${item.requires_auth ? '<span class="badge">auth</span>' : ''}
        ${item.language ? `<span class="badge">${escapeHtml(item.language)}</span>` : ''}
      </div>
    </div>
  `;
}

function renderMitreData(v, records, sourceUrls) {
  const cveListRecords = records.filter(r => ['cve-list-v5', 'nvd-cve', 'nvd-cve-init'].includes(String(r.code || '').toLowerCase()));
  const aliases = [...new Set([...(v.identifiers || []), ...(v.aliases || [])].filter(Boolean))];
  return `
    <section class="detail-section" id="mitre-data">
      <div class="section-title-row">
        <h3 class="section-h">Mitre Data</h3>
        <span class="badge">${cveListRecords.length ? 'Loaded' : 'Partial'}</span>
      </div>
      <div class="kv-grid">
        <div><span>Status</span><strong>${escapeHtml(v.status || 'unknown')}</strong></div>
        <div><span>Published</span><strong>${date(v.publishedAt)}</strong></div>
        <div><span>Modified</span><strong>${date(v.modifiedAt)}</strong></div>
        <div><span>Updated</span><strong>${date(v.updatedAt)}</strong></div>
      </div>
      ${aliases.length ? `<div class="chips compact-chips">${aliases.slice(0, 14).map(a => `<span class="badge">${escapeHtml(a)}</span>`).join('')}</div>` : ''}
      ${Object.keys(sourceUrls).length ? `
        <div class="link-grid">
          ${Object.entries(sourceUrls).map(([k, u]) => `
            <a href="${escapeAttr(u)}" target="_blank" rel="noreferrer" class="source-link-pill">${escapeHtml(k)}</a>
          `).join('')}
        </div>
      ` : renderDataGap('CVE List / NVD source URLs are not attached to this normalized record yet.')}
    </section>
  `;
}

function renderCpeConfigurations(affected) {
  const cpeItems = affected.filter(a => a.primary_cpe23_uri);
  const purlOnly = affected.filter(a => !a.primary_cpe23_uri && a.primary_purl);
  if (!cpeItems.length) {
    return `
      <section class="detail-section" id="cpe-configurations">
        <div class="section-title-row">
          <h3 class="section-h">CPE Configurations</h3>
          <span class="badge none">No CPE tree</span>
        </div>
        ${renderDataGap(`No NVD CPE configuration tree is stored for this record yet. ${purlOnly.length ? `${fmt(purlOnly.length)} purl-based package facts are available below.` : 'Package facts are not available yet.'}`)}
      </section>
    `;
  }
  const grouped = {};
  cpeItems.forEach((item) => {
    const cpe = item.primary_cpe23_uri;
    if (!grouped[cpe]) grouped[cpe] = [];
    grouped[cpe].push(item);
  });
  return `
    <section class="detail-section" id="cpe-configurations">
      <div class="section-title-row">
        <h3 class="section-h">CPE Configurations</h3>
        <span class="badge">${fmt(cpeItems.length)} matches</span>
      </div>
      <div class="config-list">
        ${Object.entries(grouped).slice(0, 24).map(([cpe, items], index) => `
          <div class="config-row">
            <div class="config-op">OR</div>
            <div>
              <strong>Configuration ${index + 1}</strong>
              <code>${escapeHtml(cpe)}</code>
              <div class="chips">
                ${items.slice(0, 6).map(a => `<span class="badge">${escapeHtml(a.ecosystem || 'unknown')}</span>`).join('')}
              </div>
            </div>
          </div>
        `).join('')}
      </div>
    </section>
  `;
}

function renderAdvisories(refs) {
  const advisoryRefs = refs.filter(r => {
    const text = `${r.ref_type || ''} ${(r.tags || []).join(' ')} ${r.url || ''}`.toLowerCase();
    return text.includes('advisory') || text.includes('patch') || text.includes('vendor') || text.includes('errata') || text.includes('security');
  });
  const display = (advisoryRefs.length ? advisoryRefs : refs).slice(0, 12);
  return `
    <section class="detail-section" id="advisories">
      <div class="section-title-row">
        <h3 class="section-h">Advisories / Patches</h3>
        <span class="badge">${fmt(display.length)}</span>
      </div>
      ${display.length ? `
        <div class="mini-table">
          <div class="mini-table-head"><span>Source</span><span>Link</span><span>Type</span></div>
          ${display.map(r => `
            <div class="mini-table-row">
              <span>${escapeHtml(r.code || 'source')}</span>
              <a href="${escapeAttr(r.url)}" target="_blank" rel="noreferrer">${escapeHtml(shortUrl(r.url))}</a>
              <span>${escapeHtml(r.ref_type || (Array.isArray(r.tags) ? r.tags.slice(0, 2).join(', ') : '') || '-')}</span>
            </div>
          `).join('')}
        </div>
      ` : renderDataGap('No advisory or patch references are linked yet.')}
    </section>
  `;
}

function renderEnrichmentPanel(v, severities) {
  return `
    <section class="detail-section rail-section" id="enrichment">
      <h3 class="section-h">Enrichment</h3>
      <div class="rail-stack">
        <div class="rail-metric"><span>CVSS</span><strong>${v.maxCvssScore != null ? Number(v.maxCvssScore).toFixed(1) : 'N/A'}</strong><small>${escapeHtml(v.maxCvssVersion || v.severityLabel || '')}</small></div>
        <div class="rail-metric"><span>EPSS</span><strong>${v.epssScore ? pct(v.epssScore) : 'N/A'}</strong><small>${v.epssPercentile ? `Percentile ${pct(v.epssPercentile)}` : 'No score loaded'}</small></div>
        <div class="rail-metric"><span>KEV</span><strong>${v.kevDateAdded ? 'Yes' : 'No'}</strong><small>${v.knownRansomware ? 'Known ransomware use' : 'Ransomware unknown'}</small></div>
        <div class="rail-metric"><span>SSVC</span><strong>N/A</strong><small>Source not integrated</small></div>
      </div>
      ${severities.length ? renderSeverityCards(severities) : ''}
    </section>
  `;
}

function renderTrackingPanel(v, records, refs) {
  const dates = [
    ['Published', v.publishedAt],
    ['Modified', v.modifiedAt],
    ['Normalized', v.updatedAt],
    ['Latest source update', records.map(r => r.updatedAt).filter(Boolean).sort().at(-1)]
  ];
  return `
    <section class="detail-section rail-section" id="tracking">
      <h3 class="section-h">Tracking</h3>
      <div class="timeline-list">
        ${dates.map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${date(value)}</strong></div>`).join('')}
        <div><span>Source records</span><strong>${fmt(records.length)}</strong></div>
        <div><span>References</span><strong>${fmt(refs.length)}</strong></div>
      </div>
    </section>
  `;
}

function renderDataGap(message) {
  return `<div class="data-gap"><p>${escapeHtml(message)}</p></div>`;
}

function deriveAction(v) {
  const score = Number(v.maxCvssScore || 0);
  const severity = String(v.severityLabel || '').toLowerCase();
  if (v.kevDateAdded) return 'Patch or mitigate now';
  if (score >= 9 || severity === 'critical') return 'Emergency review';
  if (score >= 7 || severity === 'high') return 'High priority fix';
  if (v.epssScore && Number(v.epssScore) >= 0.1) return 'Raise priority';
  return 'Track exposure';
}

function deriveImpact(v) {
  if (!v.maxCvssVector) return 'N/A';
  const metrics = parseCvssVector(v.maxCvssVector);
  const wanted = new Set(['C', 'I', 'A']);
  const parts = metrics
    .map(m => {
      const key = m.metric.split(' - ')[0];
      return wanted.has(key) ? `${key}:${m.value}` : null;
    })
    .filter(Boolean);
  return parts.length ? parts.join(' ') : 'N/A';
}

function sourceTag(code) {
  return `<span class="badge tag-source">${escapeHtml(code || '?')}</span>`;
}

function aggregateDescriptions(descriptions) {
  const map = new Map();
  for (const item of descriptions) {
    const value = String(item.value || '').trim();
    if (!value) continue;
    const key = value.toLowerCase().replace(/\s+/g, ' ');
    const existing = map.get(key) || { ...item, value, sources: [], langs: new Set() };
    if (item.code && !existing.sources.includes(item.code)) existing.sources.push(item.code);
    if (item.lang) existing.langs.add(item.lang);
    existing.is_selected = existing.is_selected || item.is_selected;
    map.set(key, existing);
  }
  return [...map.values()]
    .sort((a, b) => Number(Boolean(b.is_selected)) - Number(Boolean(a.is_selected)) || b.sources.length - a.sources.length)
    .map(item => ({ ...item, langs: [...item.langs] }));
}

function renderDescriptionCards(descriptions) {
  if (!descriptions.length) return '';
  const [primary, ...rest] = descriptions;
  return `
    <section class="detail-section" id="description">
      <h3 class="section-h">Description</h3>
      <div class="info-card description-primary">
        <p class="info-card-body">${escapeHtml(primary.value || '')}</p>
        <div class="chips">
          ${(primary.sources || [primary.code]).filter(Boolean).map(sourceTag).join('')}
          ${(primary.langs || (primary.lang ? [primary.lang] : [])).map(lang => `<span class="badge">${escapeHtml(lang)}</span>`).join('')}
        </div>
      </div>
      ${rest.length ? `
        <details class="description-more">
          <summary>${fmt(rest.length)} additional description${rest.length > 1 ? 's' : ''}</summary>
          <div class="card-stack">
            ${rest.map(d => `
              <div class="info-card">
                <p class="info-card-body">${escapeHtml(d.value || '')}</p>
                <div class="chips">
                  ${(d.sources || [d.code]).filter(Boolean).map(sourceTag).join('')}
                  ${(d.langs || (d.lang ? [d.lang] : [])).map(lang => `<span class="badge">${escapeHtml(lang)}</span>`).join('')}
                </div>
              </div>
            `).join('')}
          </div>
        </details>
      ` : ''}
    </section>
  `;
}

function renderSeverityCards(severities) {
  if (!severities.length) return '';
  return `
    <div class="severity-list">
      ${severities.map(s => `
        <div class="severity-item">
          <div class="info-card-row">
            <strong>${escapeHtml(s.scoring_system || 'severity')} ${escapeHtml(s.scoring_version || '')}</strong>
            ${s.score != null ? severityBadge(s.severity_label, s.score) : `<span class="badge">${escapeHtml(s.severity_label || 'N/A')}</span>`}
          </div>
          ${s.vector_string ? `<code class="cvss-vector-string">${escapeHtml(s.vector_string)}</code>` : ''}
          <div class="chips">${sourceTag(s.code)}</div>
        </div>
      `).join('')}
    </div>
  `;
}

function renderAffectedGrouped(affected) {
  if (!affected.length) {
    return `
      <section class="detail-section" id="affected-packages">
        <h3 class="section-h">Affected Packages</h3>
        <p class="muted">No affected components</p>
      </section>
    `;
  }
  return `
    <section class="detail-section" id="affected-packages">
      <div class="section-title-row">
        <h3 class="section-h">Affected Packages</h3>
        <span class="badge">${fmt(affected.length)} facts</span>
      </div>
      <input class="filter-input" type="text" data-affected-filter placeholder="Filter packages, ecosystems, ranges">
      <div id="affectedGroups" class="affected-groups">
      ${Object.entries(groupByEco(affected)).sort((a,b)=>b[1].length-a[1].length).map(([eco,items])=>`
        <div class="aff-eco-group">
          <div class="affected-group-head">
            <strong>${escapeHtml(eco)}</strong>
            <span class="badge">${fmt(items.length)}</span>
          </div>
          <div class="affected-table">
            ${items.map(a=>`
              <div class="affected-row">
                <div>
                  <strong>${escapeHtml(a.display_name||a.package_name||'-')}</strong>
                  <small>${escapeHtml(a.primary_purl || a.primary_cpe23_uri || '')}</small>
                </div>
                <span class="badge ${a.normalized_range?'':'none'}">${escapeHtml(a.normalized_range||'no range')}</span>
                ${a.range_type?`<span class="badge tag-source">${escapeHtml(a.range_type)}</span>`:''}
                ${a.resolution_status?`<span class="badge">${escapeHtml(a.resolution_status)}</span>`:''}
              </div>
            `).join('')}
          </div>
        </div>
      `).join('')}
      </div>
    </section>`;
}
function groupByEco(affected) {
  const m={};
  affected.forEach(a=>{const e=a.ecosystem||'unknown';(m[e]=m[e]||[]).push(a)});
  return m;
}

function renderRecordsBySource(records) {
  if (!records.length) {
    return `
      <section class="detail-section" id="raw-data">
        <h3 class="section-h">Raw Data</h3>
        <p class="muted">No source records</p>
      </section>
    `;
  }
  const bySrc = {};
  records.forEach(r => {
    const code = r.code || '?';
    if (!bySrc[code]) bySrc[code] = [];
    bySrc[code].push(r);
  });
  return Object.entries(bySrc).map(([code, items]) => `
    <section class="detail-section" id="${code === Object.keys(bySrc)[0] ? 'raw-data' : ''}">
      <div class="section-title-row">
        <h3 class="section-h">Raw Data: ${escapeHtml(code)}</h3>
        <span class="badge">${fmt(items.length)}</span>
      </div>
      <div class="card-stack scroll-stack">
        ${items.map(r => `
          <div class="info-card">
            <div class="info-card-row"><strong>${escapeHtml(r.recordId || '-')}</strong></div>
            <p style="font-size:12px;color:var(--muted);margin:4px 0">${escapeHtml(r.title || '')}</p>
            <small class="muted">${date(r.updatedAt)}</small>
          </div>
        `).join('')}
      </div>
    </section>
  `).join('');
}

function renderReferenceCards(refs) {
  if (!refs.length) return '';
  const display = refs.slice(0, 30);
  return `
    <section class="detail-section" id="references">
      <div class="section-title-row">
        <h3 class="section-h">References</h3>
        <span class="badge">${fmt(refs.length)}</span>
      </div>
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
      <div class="result-summary">${escapeHtml(item.title || '')}</div>
      <div class="result-meta">
        ${item.publishedAt ? `<span class="badge">published ${date(item.publishedAt)}</span>` : ''}
        ${item.modifiedAt ? `<span class="badge">updated ${date(item.modifiedAt)}</span>` : ''}
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

function dateTime(value) {
  if (!value) return '-';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return '-';
  return parsed.toISOString().replace('T', ' ').slice(0, 16);
}

function slug(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'source';
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

async function bootstrap() {
  await loadAuthSession();
  loadStatus();
  el.queryInput.value = '';
  setTimeout(() => runSearch(), 100);
}

bootstrap();

// ===== SBOM Management =====

async function loadSbomList() {
  el.searchForm.hidden = true;
  if (el.resultsMeta) el.resultsMeta.textContent = modeDescription('sbom');
  hideDetailPane();
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
      const data = await api(`/api/v1/sbom.upload?name=${encodeURIComponent(file.name)}`, { method: 'POST', body: text });
      status.textContent = `Uploaded: ${data.name} (${data.componentCount} components)`;
      loadSbomList();
    } catch (e) {
      status.textContent = `Error: ${escapeHtml(e.message)}`;
    }
  });
}

async function loadSbomDetail(sbomId) {
  showDetailPane();
  el.detailPane.innerHTML = '<div class="empty-state"><h2>Loading...</h2></div>';
  try {
    const data = await api(`/api/v1/sbom.get?id=${encodeURIComponent(sbomId)}`);
    renderSbomDetail(data, sbomId);
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
    <header class="detail-header">
      <div class="detail-title"><h2>${escapeHtml(s.name)}</h2></div>
      <div class="detail-meta-row">
        <span class="kv-inline">Components <b>${s.componentCount}</b></span>
        <span class="kv-inline">Affected findings <b>${s.matchedCount}</b></span>
        <span class="kv-inline">Format <b>${s.format}</b></span>
      </div>
      <div style="display:flex;gap:8px;margin-top:8px">
        <button class="tab" type="button" id="sbomMatchBtn" style="height:32px;padding:0 12px">Match PURL + CPE</button>
        <button class="tab" type="button" id="sbomExportBtn" style="height:32px;padding:0 12px">Export Excel</button>
        <button class="tab" type="button" id="sbomDeleteBtn" style="height:32px;padding:0 12px;color:var(--risk)">Delete</button>
      </div>
    </header>
    <div class="detail-sections" style="margin-top:16px">
      <section class="detail-section">
        <h3 class="section-h">Components (${sorted.length})</h3>
        <div class="card-stack">
          ${sorted.map(c => {
            const hasVulns = (c.vulnCount || 0) > 0;
            const displayVulns = c.storeVulns || [];
            return `
              <div class="info-card" style="border-left:3px solid ${hasVulns ? 'var(--risk)' : 'var(--line)'}">
                <div class="info-card-row" ${hasVulns ? `style="cursor:pointer" data-expand="${escapeAttr(c.id)}"` : ''}>
                  <strong>${escapeHtml(c.name || c.product || c.purl || c.cpe23Uri || 'component')}</strong>
                  ${c.version ? `<span class="badge">${escapeHtml(c.version)}</span>` : ''}
                  <span class="badge ${hasVulns ? 'risk' : ''}">${c.vulnCount || 0} affected</span>
                  ${hasVulns ? '<span class="badge" style="font-size:10px">&#9660;</span>' : ''}
                </div>
                <div class="chips">
                  ${c.ecosystem ? `<span class="badge">${escapeHtml(c.ecosystem)}</span>` : ''}
                  ${c.vendor ? `<span class="badge">${escapeHtml(c.vendor)}</span>` : ''}
                  ${c.product ? `<span class="badge">${escapeHtml(c.product)}</span>` : ''}
                  ${c.purl ? `<code style="font-size:11px;color:var(--muted)">${escapeHtml(c.purl)}</code>` : ''}
                  ${c.cpe23Uri ? `<code style="font-size:11px;color:var(--muted)">${escapeHtml(c.cpe23Uri)}</code>` : ''}
                </div>
                ${hasVulns ? `
                <div class="sbom-expand" id="expand-${c.id}" style="display:none;margin-top:10px">
                  <table class="table" style="border:none;margin:0"><thead><tr>
                    <th>CVE</th><th>Severity</th><th>Version Range</th><th>Status</th>
                  </tr></thead><tbody>
                  ${displayVulns.map(v => {
                    const isMatched = v.versionMatched === true;
                    const isFalse = v.versionMatched === false;
                    const hasRange = v.versionRange && v.versionRange !== '';
                    const status = isMatched ? 'AFFECTED' : isFalse ? 'FIXED' : (hasRange ? '?' : 'unknown');
                    const kl = isMatched ? 'risk' : isFalse ? 'none' : '';
                    const rangeDisplay = hasRange
                      ? `<code style="font-size:11px">${escapeHtml(v.versionRange)}</code>`
                      : `<span class="muted" style="font-size:11px" title="Alpine secfixes: no version data">no version data</span>`;
                    return `<tr data-vuln-id="${escapeAttr(v.vulnerabilityId)}" class="finding-row" style="cursor:pointer">
                      <td><span class="finding-cve">${escapeHtml(v.primaryIdentifier)}</span></td>
                      <td>${severityBadge(v.severityLabel, v.cvssScore)}</td>
                      <td>${rangeDisplay}</td>
                      <td><span class="badge ${kl}">${status}</span></td></tr>`;
                  }).join('')}
                  ${displayVulns.length < (c.vulnCount || 0) ? `<tr><td colspan="4" class="muted" style="text-align:center">+${(c.vulnCount || 0) - displayVulns.length} more CVEs (increase limit)</td></tr>` : ''}
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
      loadSbomList();
    } catch(e) { alert('Delete failed: ' + e.message); }
  });

  el.detailPane.querySelectorAll('[data-expand]').forEach(row => {
    row.addEventListener('click', () => {
      const target = document.getElementById('expand-' + row.dataset.expand);
      if (target) target.style.display = target.style.display === 'none' ? 'block' : 'none';
    });
  });

  el.detailPane.querySelectorAll('[data-vuln-id]').forEach(el => {
    el.addEventListener('click', () => loadVulnerabilityDetail(el.dataset.vulnId));
  });
}
