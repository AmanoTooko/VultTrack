const state = {
  mode: 'vulnerability',
  selectedId: null,
  themeColor: localStorage.getItem('vultrack.themeColor') || '#1f5f8b',
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
  metricRaw: document.querySelector('#metricRaw'),
  metricVulns: document.querySelector('#metricVulns'),
  metricComponents: document.querySelector('#metricComponents'),
  tabs: [...document.querySelectorAll('button[data-mode]')],
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
  else if (state.mode === 'admin') loadAdminPage();
  else if (state.mode === 'sbom') loadSbomList();
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

function showDetailPane() {
  el.detailPane.hidden = false;
}

function hideDetailPane() {
  el.detailPane.hidden = true;
  el.detailPane.innerHTML = '';
  setSbomDetailView(false);
}

function setDetailOnlyView(enabled) {
  document.body.classList.toggle('detail-only-view', enabled);
  if (enabled) {
    el.searchForm.hidden = true;
    if (el.pager) el.pager.hidden = true;
    el.resultList.innerHTML = '';
    if (el.resultsTitle) el.resultsTitle.textContent = 'Vulnerability Detail';
    if (el.resultsMeta) el.resultsMeta.textContent = 'Dedicated CVE record';
  }
}

function setSbomDetailView(enabled) {
  document.body.classList.toggle('sbom-detail-view', enabled);
}

function applyThemeColor(color) {
  const normalized = normalizeHexColor(color) || '#1f5f8b';
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

function activateMode(tab, options = {}) {
  if (!tab) return;
  setDetailOnlyView(false);
  state.mode = tab.dataset.mode;
  if (state.mode !== 'sbom') setSbomDetailView(false);
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
  if (options.updateRoute !== false) updateRoute(modeRoute(state.mode));
  if (options.load === false) return;
  if (state.mode === 'sbom') loadSbomList();
  else if (state.mode === 'status') loadStatusPage();
  else if (state.mode === 'admin') loadAdminPage();
  else runSearch();
}

function modeRoute(mode) {
  return {
    vulnerability: searchRoute('vulnerability'),
    component: searchRoute('component'),
    sbom: '/sbom',
    status: '/status',
    admin: '/admin'
  }[mode] || '/';
}

function searchRoute(mode = state.mode) {
  const params = new URLSearchParams();
  params.set('type', mode === 'component' ? 'component' : 'vulnerability');
  const query = el.queryInput?.value?.trim() || '';
  if (query) params.set('q', query);
  if (state.page > 1) params.set('page', String(state.page));
  if (state.pageSize !== 25) params.set('pageSize', String(state.pageSize));
  if (mode !== 'component' && state.sort && state.sort !== 'modifiedDesc') params.set('sort', state.sort);
  if (mode === 'component') {
    const vendor = el.vendorInput?.value?.trim() || '';
    const version = el.versionInput?.value?.trim() || '';
    const ecosystem = el.ecosystemInput?.value?.trim() || '';
    if (vendor) params.set('vendor', vendor);
    if (version) params.set('version', version);
    if (ecosystem) params.set('ecosystem', ecosystem);
  }
  return `/search?${params.toString()}`;
}

function cveRoute(identifier) {
  return `/cve/${encodeURIComponent(identifier)}`;
}

function sbomRoute(id) {
  return `/sbom/${encodeURIComponent(id)}`;
}

function updateRoute(path, options = {}) {
  const current = `${window.location.pathname}${window.location.search}`;
  if (current === path) return;
  window.history[options.replace ? 'replaceState' : 'pushState']({}, '', path);
}

function parseRoute() {
  const parts = window.location.pathname.split('/').filter(Boolean).map(part => decodeURIComponent(part));
  const params = new URLSearchParams(window.location.search);
  if (parts[0] === 'cve' && parts[1]) return { mode: 'vulnerability', identifier: parts[1] };
  if (parts[0] === 'search') {
    const mode = params.get('type') === 'component' ? 'component' : 'vulnerability';
    return {
      mode,
      search: true,
      query: params.get('q') || '',
      vendor: params.get('vendor') || '',
      version: params.get('version') || '',
      ecosystem: params.get('ecosystem') || '',
      page: Number(params.get('page') || 1),
      pageSize: Number(params.get('pageSize') || state.pageSize),
      sort: params.get('sort') || state.sort
    };
  }
  if ((parts[0] === 'component' || parts[0] === 'components') && parts.length === 1) return { mode: 'component' };
  if (parts[0] === 'sbom') return { mode: 'sbom', sbomId: parts[1] || null };
  if (parts[0] === 'status' && parts.length === 1) return { mode: 'status' };
  if (parts[0] === 'admin' && parts.length === 1) return { mode: 'admin' };
  return { mode: 'vulnerability' };
}

async function applyRoute() {
  const route = parseRoute();
  const tab = el.tabs.find(item => item.dataset.mode === route.mode);
  activateMode(tab, { updateRoute: false, load: false });
  applySearchRouteState(route);
  if (route.identifier) {
    await loadVulnerabilityByIdentifier(route.identifier);
  } else if (route.mode === 'sbom') {
    await loadSbomList({ detailId: route.sbomId });
  } else if (route.mode === 'status') {
    await loadStatusPage();
  } else if (route.mode === 'admin') {
    await loadAdminPage();
  } else {
    await runSearch({ updateRoute: !route.search });
  }
}

function applySearchRouteState(route) {
  if (!route.search) return;
  el.queryInput.value = route.query || '';
  el.vendorInput.value = route.vendor || '';
  el.versionInput.value = route.version || '';
  el.ecosystemInput.value = route.ecosystem || '';
  state.page = Number.isFinite(route.page) && route.page > 0 ? route.page : 1;
  state.pageSize = Number.isFinite(route.pageSize) && route.pageSize > 0 ? route.pageSize : state.pageSize;
  state.sort = route.sort || state.sort;
  if (el.limitSelect) el.limitSelect.value = String(state.pageSize);
  if (el.sortSelect) el.sortSelect.value = state.sort;
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
  const groups = adminSourceGroups(sources, domestic);
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
  bindAdminActions();
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

async function runSearch(options = {}) {
  const query = el.queryInput.value.trim();
  state.hasMore = false;
  if (options.updateRoute !== false) updateRoute(searchRoute(state.mode));
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
  bindVulnerabilityLinks(el.resultList);
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
  bindVulnerabilityLinks(el.resultList);
}

function bindVulnerabilityLinks(container) {
  container.querySelectorAll('[data-vulnerability-id]').forEach((link) => {
    link.addEventListener('click', (event) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      loadVulnerabilityDetail(link.dataset.vulnerabilityId, { identifier: link.dataset.vulnerabilityIdentifier });
    });
  });
}

async function loadVulnerabilityByIdentifier(identifier) {
  setDetailOnlyView(true);
  showDetailPane();
  el.detailPane.innerHTML = '<div class="empty-state"><h2>Loading</h2></div>';
  try {
    const item = await api(`/api/v1/vulnerability.getByIdentifier?identifier=${encodeURIComponent(identifier)}`);
    const data = await loadVulnerabilityDetail(item.id, { identifier: item.primaryIdentifier, updateRoute: false });
    updateRoute(cveRoute(displayIdentifier(data?.vulnerability || item)), { replace: true });
  } catch (error) {
    el.detailPane.innerHTML = `<div class="empty-state"><h2>Request failed</h2><p>${escapeHtml(error.message)}</p></div>`;
  }
}

async function loadVulnerabilityDetail(id, options = {}) {
  state.selectedId = id;
  if (options.detailOnly !== false) setDetailOnlyView(true);
  el.resultList.querySelectorAll('.result-item').forEach((item) => {
    item.classList.toggle('is-active', item.dataset.vulnerabilityId === id);
  });
  showDetailPane();
  el.detailPane.innerHTML = '<div class="empty-state"><h2>Loading</h2></div>';
  try {
    const data = await api(`/api/v1/vulnerability.detail?id=${encodeURIComponent(id)}&source=duckdb`);
    renderDetail(data);
    if (options.updateRoute !== false) {
      updateRoute(cveRoute(displayIdentifier(data.vulnerability) || options.identifier || id));
    }
    el.detailPane.scrollIntoView({ block: 'start', behavior: 'smooth' });
    return data;
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
  const affectedExpressions = data.affectedExpressions || [];
  const history = data.history || [];
  const sourceUrls = data.sourceUrls || {};
  const sourceTags = [...new Set(records.map(r => r.code).filter(Boolean))];
  const affectedByEco = groupByEco(affected);
  const primaryDescription = descriptions[0] || { value: v.description || v.title || '', sources: [] };
  const descriptionIsLong = String(primaryDescription.value || '').length > 900;
  const title = selectDetailHeadline(v, data.descriptions || [], records);
  const displayId = displayIdentifier(v);

  el.detailPane.innerHTML = `
    <article class="cve-page">
      <header class="cve-hero">
        <div class="cve-hero-main">
          <div class="eyebrow-row">
            <span class="eyebrow">Vulnerability Details</span>
            ${sourceTags.slice(0, 6).map(s => `<span class="badge tag-source">${escapeHtml(s)}</span>`).join('')}
          </div>
          <div class="detail-title">
            <h2>${escapeHtml(displayId)}</h2>
            ${severityBadge(v.severityLabel, v.maxCvssScore)}
            ${v.epssScore ? `<span class="badge warn">EPSS ${pct(v.epssScore)}</span>` : ''}
            ${v.kevDateAdded ? '<span class="badge risk">KEV</span>' : ''}
          </div>
          <h3 class="cve-headline">${escapeHtml(title)}</h3>
          <div class="cve-page-actions" aria-label="Detail navigation">
            <a class="tab" href="${searchRouteFor('vulnerability')}">Vulnerability Search</a>
            <a class="tab" href="${searchRouteFor('vulnerability', displayId)}">Search ${escapeHtml(displayId)}</a>
          </div>
          <section class="hero-description" aria-label="Description">
            <div class="hero-description-head">
              <span>Description</span>
              ${(primaryDescription.sources || [primaryDescription.code]).filter(Boolean).map(sourceTag).join('')}
            </div>
            <div class="markdown-body cve-summary hero-description-body ${descriptionIsLong ? 'is-collapsed' : ''}" data-primary-description>${renderSafeMarkdown(primaryDescription.value)}</div>
            ${descriptionIsLong ? '<button class="description-toggle" type="button" data-description-toggle aria-expanded="false">Show full description</button>' : ''}
          </section>
        </div>
        ${renderHeroMetadata(v, affectedByEco, records, refs, exploits)}
      </header>

      ${renderCvssPanel(v, severities)}
      ${renderDetailNav()}

      <section class="detail-section ai-analysis-card" id="ai-analysis">
        ${renderAiAnalysisPlan(v, affected, refs, records)}
      </section>

      <div class="detail-two-column">
        <div class="detail-main-column">
          ${descriptions.length > 1 ? renderDescriptionCards(descriptions.slice(1)) : ''}
          ${renderMitreData(v, records, sourceUrls)}
          ${renderExploitSignals(exploits)}
          ${renderCpeConfigurations(affected, affectedExpressions)}
          ${renderAffectedGrouped(affected)}
          ${renderAdvisories(refs)}
          ${refs.length ? renderReferenceCards(refs) : '<section class="detail-section" id="references"><h3 class="section-h">References</h3><p class="muted">No references</p></section>'}
          ${renderSourceChanges(history.filter(item => isVulnerabilitySource(item.code)))}
          ${renderRecordsBySource(records)}
        </div>
        <aside class="detail-rail">
          ${renderEnrichmentPanel(v)}
          ${renderTrackingPanel(v, records, refs, history, exploits)}
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
  const descriptionToggle = el.detailPane.querySelector('[data-description-toggle]');
  descriptionToggle?.addEventListener('click', () => {
    const body = el.detailPane.querySelector('[data-primary-description]');
    if (!body) return;
    const expanded = descriptionToggle.getAttribute('aria-expanded') === 'true';
    descriptionToggle.setAttribute('aria-expanded', String(!expanded));
    descriptionToggle.textContent = expanded ? 'Show full description' : 'Show less';
    body.classList.toggle('is-collapsed', expanded);
  });
  bindDetailInteractions(el.detailPane);
  loadAiSummary(v.id);
}

function renderHeroMetadata(v, affectedByEco, records, refs, exploits = []) {
  const sourceCount = v.sourceCount ?? new Set(records.map(r => r.code).filter(Boolean)).size;
  return `
    <aside class="hero-metadata" aria-label="Vulnerability metadata">
      <div class="hero-date-block">
        <span>Published</span>
        <strong>${date(v.publishedAt)}</strong>
      </div>
      <div class="hero-date-block">
        <span>Modified</span>
        <strong>${date(v.modifiedAt)}</strong>
      </div>
      <div class="hero-signal-grid">
        <div><span>CVSS</span><strong>${v.maxCvssScore != null ? Number(v.maxCvssScore).toFixed(1) : 'N/A'}</strong></div>
        <div><span>EPSS</span><strong>${v.epssScore ? pct(v.epssScore) : 'N/A'}</strong></div>
        <div><span>KEV</span><strong>${v.kevDateAdded ? 'Yes' : 'No'}</strong></div>
      </div>
      <dl class="hero-meta-list">
        <div><dt>Status</dt><dd>${escapeHtml(v.status || 'unknown')}</dd></div>
        <div><dt>Affected</dt><dd>${fmt(v.affectedComponentCount)} / ${fmt(Object.keys(affectedByEco).length)} ecosystems</dd></div>
        <div><dt>Sources</dt><dd>${fmt(sourceCount)}</dd></div>
        <div><dt>References</dt><dd>${fmt(refs.length)}</dd></div>
        <div><dt>PoC signals</dt><dd>${exploits.length ? fmt(exploits.length) : 'No data'}</dd></div>
      </dl>
    </aside>
  `;
}

function renderDetailNav() {
  const items = [
    ['CVSS', 'cvss-scores'],
    ['AI Analysis', 'ai-analysis'],
    ['Mitre Data', 'mitre-data'],
    ['PoC / Exploit', 'exploit-signals'],
    ['CPE Configurations', 'cpe-configurations'],
    ['Affected Packages', 'affected-packages'],
    ['Enrichment', 'enrichment'],
    ['Tracking', 'tracking'],
    ['Source Changes', 'source-changes'],
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
      <span class="badge">Cache first</span>
    </div>
    <div class="ai-grid">
      <div class="analysis-field">
        <span>Status</span>
        <p data-ai-summary-status>Checking cached summary.</p>
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
        <p>${fmt(records.length)} source records and ${fmt(refs.length)} references are available for the cached AI pipeline.</p>
      </div>
    </div>
    <div class="ai-summary-output" data-ai-summary-output></div>
  `;
}

async function loadAiSummary(vulnerabilityId) {
  const section = el.detailPane.querySelector('#ai-analysis');
  if (!section) return;
  try {
    const summary = await api(`/api/v1/vulnerability.aiSummary?id=${encodeURIComponent(vulnerabilityId)}`);
    if (state.selectedId !== vulnerabilityId) return;
    renderAiSummary(section, vulnerabilityId, summary);
  } catch (error) {
    const status = section.querySelector('[data-ai-summary-status]');
    if (status) status.textContent = `AI summary unavailable: ${error.message}`;
  }
}

function renderAiSummary(section, vulnerabilityId, result) {
  const status = section.querySelector('[data-ai-summary-status]');
  const output = section.querySelector('[data-ai-summary-output]');
  if (!status || !output) return;

  if (result.summary) {
    status.textContent = `${result.cached ? 'Loaded from cache' : 'Generated'} with ${result.model}; evidence ${String(result.evidenceHash || '').slice(0, 12)}.`;
    output.innerHTML = `
      <div class="ai-json-card">
        ${renderAiJson(result.summary)}
      </div>
    `;
    return;
  }

  status.textContent = result.message || 'No cached AI summary exists for this evidence hash.';
  output.innerHTML = `
    <div class="ai-empty-actions">
      <span class="badge ${result.configured ? 'low' : 'warn'}">${result.configured ? 'configured' : 'not configured'}</span>
      <span class="badge">input ${fmt(result.inputChars || 0)} chars</span>
      ${state.authenticated ? '<button class="tab" type="button" data-ai-generate>Generate</button>' : '<span class="muted">Admin login required to generate.</span>'}
    </div>
  `;
  section.querySelector('[data-ai-generate]')?.addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    button.textContent = 'Generating';
    try {
      const generated = await api('/api/v1/admin.vulnerability.aiSummary', {
        method: 'POST',
        body: JSON.stringify({ id: vulnerabilityId, force: false })
      });
      renderAiSummary(section, vulnerabilityId, generated);
    } catch (error) {
      status.textContent = `Generation failed: ${error.message}`;
      button.disabled = false;
      button.textContent = 'Generate';
    }
  });
}

function renderAiJson(value, depth = 0, key = null) {
  const label = key ? `<span class="ai-json-key">${escapeHtml(formatJsonKey(key))}</span>` : '';
  if (Array.isArray(value)) {
    if (!value.length) return `${label}<span class="muted">[]</span>`;
    return `
      ${label}
      <ul class="ai-json-list">
        ${value.map(item => `<li>${renderAiJson(item, depth + 1)}</li>`).join('')}
      </ul>
    `;
  }

  if (value && typeof value === 'object') {
    const entries = Object.entries(value).filter(([, item]) => item !== undefined);
    if (!entries.length) return `${label}<span class="muted">{}</span>`;
    const body = entries.map(([childKey, item]) => `
      <div class="ai-json-row">
        ${renderAiJson(item, depth + 1, childKey)}
      </div>
    `).join('');
    if (key && depth > 0) {
      return `
        <details class="ai-json-object" open>
          <summary>${escapeHtml(formatJsonKey(key))}</summary>
          ${body}
        </details>
      `;
    }
    return `<div class="ai-json-object">${label}${body}</div>`;
  }

  return `
    ${label}
    <span class="ai-json-value">${escapeHtml(value == null || value === '' ? 'unknown' : String(value))}</span>
  `;
}

function formatJsonKey(value) {
  return String(value)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replaceAll('_', ' ')
    .replace(/\s+/g, ' ')
    .trim();
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
        <strong>${url ? renderExternalLink(url, title) : escapeHtml(title)}</strong>
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
  const displayId = displayIdentifier(v);
  const cveListRecords = records.filter(r =>
    ['cve-list-v5', 'nvd-cve', 'nvd-cve-init'].includes(String(r.code || '').toLowerCase()) &&
    String(r.recordId || '').toUpperCase() === String(displayId || '').toUpperCase());
  const aliases = [...new Set([...(v.identifiers || []), ...(v.aliases || [])].filter(Boolean).map(displayIdentifierValue))];
  return `
    <section class="detail-section" id="mitre-data">
      <div class="section-title-row">
        <h3 class="section-h">Mitre Data</h3>
        <span class="badge">${cveListRecords.length ? 'Loaded' : 'Partial'}</span>
      </div>
      <div class="kv-grid">
        <div><span>Status</span><strong>${escapeHtml(v.status || 'unknown')}</strong></div>
        <div><span>Source published</span><strong>${date(v.publishedAt)}</strong></div>
        <div><span>Source modified</span><strong>${date(v.modifiedAt)}</strong></div>
        <div><span>Local normalized</span><strong>${date(v.updatedAt)}</strong></div>
      </div>
      ${aliases.length ? `<div class="chips compact-chips">${aliases.slice(0, 14).map(a => `<span class="badge">${escapeHtml(a)}</span>`).join('')}</div>` : ''}
      ${Object.keys(sourceUrls).length ? `
        <div class="link-grid">
          ${Object.entries(sourceUrls).map(([k, u]) => `
            ${renderExternalLink(u, k, 'source-link-pill')}
          `).join('')}
        </div>
      ` : renderDataGap('CVE List / NVD source URLs are not attached to this normalized record yet.')}
    </section>
  `;
}

function renderCpeConfigurations(affected, expressions = []) {
  const expressionCpes = expressions
    .filter(a => a.cpe23_uri && a.vulnerable !== false)
    .map(a => ({
      cpe: a.cpe23_uri,
      range: a.version_range_raw,
      source: a.code
    }));
  const cpeItems = expressionCpes.length
    ? expressionCpes
    : affected.filter(a => a.primary_cpe23_uri).map(a => ({
      cpe: a.primary_cpe23_uri,
      range: a.normalized_range,
      source: a.ecosystem
    }));
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
    const cpe = item.cpe;
    if (!grouped[cpe]) grouped[cpe] = [];
    grouped[cpe].push(item);
  });
  const entries = Object.entries(grouped);
  const initialLimit = 12;
  return `
    <section class="detail-section" id="cpe-configurations">
      <div class="section-title-row">
        <h3 class="section-h">CPE Configurations</h3>
        <span class="badge">${fmt(entries.length)} expressions · ${fmt(cpeItems.length)} matches</span>
      </div>
      <div class="config-list">
        ${entries.map(([cpe, items], index) => `
          <div class="config-row" ${index >= initialLimit ? 'hidden data-overflow-group="cpe-configurations"' : ''}>
            <div class="config-op">CPE</div>
            <div>
              <strong>Match expression ${index + 1}</strong>
              <code>${escapeHtml(cpe)}</code>
              <div class="chips">
                ${items.slice(0, 6).map(a => `<span class="badge">${escapeHtml(a.range || 'no range')}</span>`).join('')}
                ${items.length > 6 ? `<span class="badge">+${fmt(items.length - 6)} ranges</span>` : ''}
                ${items.slice(0, 3).map(a => a.source ? sourceTag(a.source) : '').join('')}
              </div>
            </div>
          </div>
        `).join('')}
      </div>
      ${entries.length > initialLimit ? renderOverflowButton('cpe-configurations', `Show ${fmt(entries.length - initialLimit)} more CPE expressions`, 'Show fewer CPE expressions') : ''}
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
              ${renderExternalLink(r.url, shortUrl(r.url))}
              <span>${escapeHtml(r.ref_type || (Array.isArray(r.tags) ? r.tags.slice(0, 2).join(', ') : '') || '-')}</span>
            </div>
          `).join('')}
        </div>
      ` : renderDataGap('No advisory or patch references are linked yet.')}
    </section>
  `;
}

function renderEnrichmentPanel(v) {
  return `
    <section class="detail-section rail-section" id="enrichment">
      <h3 class="section-h">Enrichment</h3>
      <div class="rail-stack">
        <div class="rail-metric"><span>CVSS</span><strong>${v.maxCvssScore != null ? Number(v.maxCvssScore).toFixed(1) : 'N/A'}</strong><small>${escapeHtml(v.maxCvssVersion || v.severityLabel || '')}</small></div>
        <div class="rail-metric"><span>EPSS</span><strong>${v.epssScore ? pct(v.epssScore) : 'N/A'}</strong><small>${v.epssPercentile ? `Percentile ${pct(v.epssPercentile)}` : 'No score loaded'}</small></div>
        <div class="rail-metric"><span>KEV</span><strong>${v.kevDateAdded ? 'Yes' : 'No'}</strong><small>${v.knownRansomware ? 'Known ransomware use' : 'Ransomware unknown'}</small></div>
        <div class="rail-metric"><span>SSVC</span><strong>N/A</strong><small>Source not integrated</small></div>
      </div>
    </section>
  `;
}

function renderTrackingPanel(v, records, refs, history = [], exploits = []) {
  const vulnerabilityRecords = records.filter(record => isVulnerabilitySource(record.code));
  const enrichmentRecords = records.filter(record => isEnrichmentSource(record.code));
  const dates = [
    ['Vulnerability published', v.publishedAt],
    ['Vulnerability modified', v.modifiedAt],
    ['Local normalized', v.updatedAt],
    ['Latest vuln source modified', vulnerabilityRecords.map(r => r.sourceModifiedAt).filter(Boolean).sort().at(-1)],
    ['Latest enrichment modified', enrichmentRecords.map(r => r.sourceModifiedAt).filter(Boolean).sort().at(-1)],
    ['Latest exploit modified', exploits.map(exploitModifiedAt).filter(Boolean).sort().at(-1)],
    ['Latest ingest', records.map(r => r.ingestedAt).filter(Boolean).sort().at(-1)]
  ];
  return `
    <section class="detail-section rail-section" id="tracking">
      <h3 class="section-h">Tracking</h3>
      <div class="timeline-list">
        ${dates.map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${date(value)}</strong></div>`).join('')}
        <div><span>Vuln source records</span><strong>${fmt(vulnerabilityRecords.length)}</strong></div>
        <div><span>Enrichment records</span><strong>${fmt(enrichmentRecords.length)}</strong></div>
        <div><span>Source changes</span><strong>${fmt(history.filter(item => isVulnerabilitySource(item.code)).length)}</strong></div>
        <div><span>References</span><strong>${fmt(refs.length)}</strong></div>
      </div>
    </section>
  `;
}

function isVulnerabilitySource(code) {
  const value = String(code || '').toLowerCase();
  if (!value) return false;
  if (isEnrichmentSource(value)) return false;
  return true;
}

function isEnrichmentSource(code) {
  return [
    'first-epss',
    'cisa-kev',
    'metasploit',
    'exploitdb',
    'nuclei-templates',
    'poc-in-github',
    'trickest-cve'
  ].includes(String(code || '').toLowerCase());
}

function exploitModifiedAt(item) {
  return item?.modified_at || item?.modifiedAt || item?.published_at || item?.publishedAt || null;
}

function renderSourceChanges(history) {
  if (!history.length) return '';
  const initialLimit = 12;
  return `
    <section class="detail-section" id="source-changes">
      <div class="section-title-row">
        <h3 class="section-h">Source Changes</h3>
        <span class="badge">${fmt(history.length)}</span>
      </div>
      <div class="timeline-list source-change-list">
        ${history.map((item, index) => `
          <div class="source-change-item" ${index >= initialLimit ? 'hidden data-overflow-group="source-changes"' : ''}>
            <div class="source-change-head">
              <span>${escapeHtml(item.code || 'source')} · ${changeTypeBadge(item.change_type)}</span>
              <strong>source modified ${dateTime(item.source_modified_at || item.ingested_at)}</strong>
            </div>
            <small>local ingest ${dateTime(item.ingested_at)} · ${escapeHtml(displayIdentifierValue(item.source_record_id || ''))}${item.record_hash ? ` · ${escapeHtml(item.record_hash)}` : ''}</small>
            ${renderHistoryDiff(item)}
          </div>
        `).join('')}
      </div>
      ${history.length > initialLimit ? renderOverflowButton('source-changes', `Show ${fmt(history.length - initialLimit)} more changes`, 'Show fewer changes') : ''}
    </section>
  `;
}

function changeTypeBadge(type) {
  const normalized = String(type || 'updated').toLowerCase();
  const label = normalized === 'added' ? 'added' : normalized === 'removed' ? 'removed' : 'updated';
  const klass = normalized === 'added' ? 'low' : normalized === 'removed' ? 'critical' : 'medium';
  return `<span class="badge ${klass}">${escapeHtml(label)}</span>`;
}

function renderHistoryDiff(item) {
  const diff = Array.isArray(item.diff) ? item.diff : [];
  if (!diff.length) {
    return '<p class="muted source-diff-empty">Raw diff unavailable for this source snapshot.</p>';
  }
  const summary = item.diff_summary || {};
  return `
    <details class="source-diff">
      <summary>
        JSON diff
        <span class="badge low">+${fmt(summary.added || diff.filter(change => change.type === 'added').length)}</span>
        <span class="badge critical">-${fmt(summary.removed || diff.filter(change => change.type === 'removed').length)}</span>
        <span class="badge medium">~${fmt(summary.changed || diff.filter(change => change.type === 'changed').length)}</span>
      </summary>
      <div class="source-diff-list">
        ${diff.slice(0, 30).map(renderHistoryDiffRow).join('')}
      </div>
    </details>
  `;
}

function renderHistoryDiffRow(change) {
  const type = String(change.type || 'changed').toLowerCase();
  const klass = type === 'added' ? 'low' : type === 'removed' ? 'critical' : 'medium';
  const before = change.before != null ? `<small><b>Before</b> ${escapeHtml(change.before)}</small>` : '';
  const after = change.after != null ? `<small><b>After</b> ${escapeHtml(change.after)}</small>` : '';
  return `
    <div class="source-diff-row">
      <span class="badge ${klass}">${escapeHtml(type)}</span>
      <code>${escapeHtml(change.path || '$')}</code>
      <div>${before}${after}</div>
    </div>
  `;
}

function searchRouteFor(mode, query) {
  const params = new URLSearchParams();
  params.set('type', mode === 'component' ? 'component' : 'vulnerability');
  if (query) params.set('q', query);
  return `/search?${params.toString()}`;
}

function displayIdentifier(item) {
  const ids = [item?.primaryIdentifier, ...(item?.identifiers || []), ...(item?.aliases || [])]
    .filter(Boolean)
    .map(value => String(value).trim())
    .filter(Boolean);
  const embedded = ids.map(embeddedCve).find(Boolean);
  return ids.find(isCveIdentifier)
    || embedded
    || item?.primaryIdentifier
    || item?.vulnerabilityId
    || '';
}

function isCveIdentifier(value) {
  return /^CVE-\d{4}-\d{4,}$/i.test(String(value || ''));
}

function embeddedCve(value) {
  return String(value || '').match(/\bCVE-\d{4}-\d{4,}\b/i)?.[0] || null;
}

function displayIdentifierValue(value) {
  const text = String(value || '').trim();
  return embeddedCve(text) || text;
}

function renderDataGap(message) {
  return `<div class="data-gap"><p>${escapeHtml(message)}</p></div>`;
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
    .sort((a, b) => descriptionContentPriority(b) - descriptionContentPriority(a) ||
      descriptionSourcePriority(b) - descriptionSourcePriority(a) ||
      Number(Boolean(b.is_selected)) - Number(Boolean(a.is_selected)) ||
      b.value.length - a.value.length ||
      b.sources.length - a.sources.length)
    .map(item => ({ ...item, langs: [...item.langs] }));
}

function descriptionSourcePriority(item) {
  const sources = item.sources || [item.code];
  if (sources.includes('ghsa')) return 6;
  if (sources.includes('maven-osv') || sources.includes('maven-advisory')) return 5;
  if (sources.includes('nvd-cve')) return 4;
  if (sources.includes('nvd-cve-init')) return 3;
  if (sources.some(source => String(source || '').includes('osv'))) return 2;
  if (sources.includes('cve-list-v5')) return 1;
  return 0;
}

function descriptionContentPriority(item) {
  const value = String(item.value || '');
  const length = value.length;
  const langs = item.langs instanceof Set ? [...item.langs] : (item.langs || (item.lang ? [item.lang] : []));
  const isEnglish = langs.some(lang => String(lang || '').toLowerCase().startsWith('en'));
  const hasMarkdown = /(^|\n)\s{0,3}#{1,6}\s+\S|\[[^\]]+\]\([^)]+\)|(^|\n)\s*[-*]\s+\S/.test(value);
  return (isEnglish ? 100 : 0) + (hasMarkdown ? 40 : 0) + (length >= 1200 ? 20 : length >= 180 ? 10 : length >= 80 ? 5 : 0);
}

function selectDetailHeadline(v, descriptions, records) {
  const candidates = [];
  for (const item of descriptions || []) {
    const value = String(item.value || '').trim();
    const headline = headlineFromDescription(value);
    if (!headline) continue;
    candidates.push({
      value: headline,
      code: item.code,
      lang: item.lang,
      kind: item.description_type,
      score: headlineScore(item.code, item.lang, item.description_type, headline) + 10
    });
  }
  for (const record of records || []) {
    const value = String(record.title || '').trim();
    if (!value || value.length > 140 || isLowQualityHeadline(value)) continue;
    candidates.push({
      value,
      code: record.code,
      lang: 'en',
      kind: 'record-title',
      score: headlineScore(record.code, 'en', 'record-title', value)
    });
  }
  candidates.sort((a, b) => b.score - a.score || a.value.length - b.value.length);
  const selected = candidates.find(c => c.value && !isLowQualityHeadline(c.value)) || candidates[0];
  if (selected) return selected.value;
  const fallback = String(v.title || '').trim();
  const displayId = displayIdentifier(v);
  return headlineFromDescription(fallback) || displayId;
}

function headlineFromDescription(value) {
  const text = String(value || '')
    .replace(/\[[^\]]+\]\(([^)]+)\)/g, '$1')
    .replace(/(^|\n)\s{0,3}#{1,6}\s+/g, '$1')
    .replace(/\s+/g, ' ')
    .trim();
  if (!text || isLowQualityHeadline(text)) return null;
  if (text.length <= 140) return text;
  const sentence = text.match(/^.{24,180}?[.!?](?=\s|$)/)?.[0]?.trim();
  if (sentence && !isLowQualityHeadline(sentence)) return sentence;
  const clause = text.slice(0, 180).replace(/[,;:]\s+\S*$/, '').trim();
  return clause.length >= 24 && !isLowQualityHeadline(clause) ? `${clause}...` : null;
}

function isLowQualityHeadline(value) {
  const text = String(value || '').trim();
  return /^security update for /i.test(text)
    || /^log4shell http scanner$/i.test(text)
    || /^CVE-\d{4}-\d{4,}\s+(debian security tracker|ubuntu|osv|nvd|cve list)/i.test(text);
}

function headlineScore(code, lang, kind, value) {
  const source = String(code || '');
  const sourceScore =
    source === 'ghsa' ? 40 :
      source === 'maven-osv' || source === 'maven-advisory' ? 35 :
        source === 'nvd-cve' || source === 'nvd-cve-init' ? 25 :
          source.includes('osv') ? 15 : 0;
  const langScore = String(lang || '').toLowerCase().startsWith('en') ? 30 : 0;
  const kindScore = String(kind || '').includes('summary') ? 20 : 0;
  const qualityPenalty = isLowQualityHeadline(value) ? 50 : 0;
  return sourceScore + langScore + kindScore - qualityPenalty;
}

function renderDescriptionCards(descriptions) {
  if (!descriptions.length) return '';
  const [primary, ...rest] = descriptions;
  return `
    <section class="detail-section" id="description">
      <h3 class="section-h">Additional Descriptions</h3>
      <div class="info-card description-primary">
        <div class="info-card-body markdown-body">${renderSafeMarkdown(primary.value)}</div>
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
                <div class="info-card-body markdown-body">${renderSafeMarkdown(d.value)}</div>
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

function renderCvssPanel(v, severities) {
  const fallback = v.maxCvssScore == null ? [] : [{
    scoring_system: 'CVSS',
    scoring_version: v.maxCvssVersion,
    score: v.maxCvssScore,
    severity_label: v.severityLabel,
    vector_string: v.maxCvssVector,
    is_selected: true
  }];
  const scores = compactSeverities(severities.length ? severities : fallback);
  if (!scores.length) return '';
  const groups = groupCvssScores(scores);
  const tabs = Object.entries(groups).filter(([, items]) => items.length);
  const selectedKey = tabs.find(([, items]) => items.some(score => score.is_selected))?.[0] || tabs[0]?.[0];
  return `
    <section class="cvss-panel detail-section" id="cvss-scores">
      <div class="section-title-row">
        <h3 class="section-h">CVSS Scores</h3>
        <span class="badge">${fmt(scores.length)} source score${scores.length > 1 ? 's' : ''}</span>
      </div>
      <div class="cvss-tabs" role="tablist" aria-label="CVSS score versions">
        ${tabs.map(([key, items]) => `
          <button class="cvss-tab ${key === selectedKey ? 'is-active' : ''}" type="button" role="tab" aria-selected="${key === selectedKey}" data-cvss-tab="${escapeAttr(key)}">
            ${escapeHtml(cvssTabLabel(key))} <span>${fmt(items.length)}</span>
          </button>
        `).join('')}
      </div>
      ${tabs.map(([key, items]) => renderCvssTabPanel(key, items, key === selectedKey)).join('')}
    </section>
  `;
}

function compactSeverities(severities) {
  const seen = new Set();
  return severities.filter(score => {
    const key = [
      score.code,
      score.scoring_system,
      score.scoring_version,
      score.score,
      score.severity_label,
      score.vector_string
    ].map(value => String(value ?? '')).join('|');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function groupCvssScores(scores) {
  const groups = { v4: [], v3: [], v2: [], other: [] };
  scores.forEach((score) => {
    groups[cvssMajor(score)].push(score);
  });
  return groups;
}

function cvssMajor(score) {
  const text = `${score.scoring_version || ''} ${score.vector_string || ''}`.toUpperCase();
  if (/\bCVSS:4\.|^4\./.test(text) || text.includes('CVSS 4')) return 'v4';
  if (/\bCVSS:3\.|^3\./.test(text) || text.includes('CVSS 3')) return 'v3';
  if (/\bCVSS:2\.|^2\./.test(text) || text.includes('CVSS 2')) return 'v2';
  return 'other';
}

function cvssTabLabel(key) {
  return key === 'v4' ? 'CVSS v4'
    : key === 'v3' ? 'CVSS v3'
    : key === 'v2' ? 'CVSS v2'
    : 'Other';
}

function renderCvssTabPanel(key, items, active) {
  const selectedIndex = Math.max(0, items.findIndex(score => score.is_selected));
  return `
    <div class="cvss-tab-panel" data-cvss-panel="${escapeAttr(key)}" ${active ? '' : 'hidden'}>
      <div class="cvss-score-groups" role="list" aria-label="${escapeAttr(cvssTabLabel(key))} sources">
        ${items.map((score, index) => renderCvssSourceScore(key, score, index, index === selectedIndex)).join('')}
      </div>
      ${items.map((score, index) => renderCvssSourceDetail(key, score, index, index === selectedIndex)).join('')}
    </div>
  `;
}

function renderCvssSourceScore(groupKey, score, index, active) {
  const severity = severityClass(score.severity_label, score.score);
  const source = score.code || score.scoring_system || 'source';
  return `
    <button class="cvss-source-score ${active ? 'is-selected' : ''} severity-${severity}" type="button" data-cvss-source="${escapeAttr(groupKey)}:${index}" aria-pressed="${active}">
      <div>
        <strong>${score.score != null ? Number(score.score).toFixed(1) : 'N/A'}</strong>
        <span>${escapeHtml(score.severity_label || 'unrated')}</span>
      </div>
      <small>${escapeHtml(score.scoring_system || 'CVSS')} ${escapeHtml(score.scoring_version || '')}</small>
      ${sourceTag(source)}
    </button>
  `;
}

function renderCvssSourceDetail(groupKey, score, index, active) {
  return `
    <div class="cvss-source-detail" data-cvss-source-detail="${escapeAttr(groupKey)}:${index}" ${active ? '' : 'hidden'}>
      <div class="kv-grid compact-kv">
        <div><span>Source</span><strong>${escapeHtml(score.code || 'source')}</strong></div>
        <div><span>System</span><strong>${escapeHtml(score.scoring_system || 'CVSS')}</strong></div>
        <div><span>Version</span><strong>${escapeHtml(score.scoring_version || cvssTabLabel(groupKey))}</strong></div>
        <div><span>Score Type</span><strong>${escapeHtml(score.score_type || 'base')}</strong></div>
      </div>
      ${score.vector_string ? cvssVectorBlock(score.scoring_version || cvssTabLabel(groupKey), score.vector_string) : renderDataGap('This source provides a numeric score, but no CVSS vector string.')}
    </div>
  `;
}

function bindDetailInteractions(root) {
  root.querySelectorAll('[data-cvss-tab]').forEach((tab) => {
    tab.addEventListener('click', () => {
      const key = tab.getAttribute('data-cvss-tab');
      root.querySelectorAll('[data-cvss-tab]').forEach((item) => {
        const selected = item === tab;
        item.classList.toggle('is-active', selected);
        item.setAttribute('aria-selected', String(selected));
      });
      root.querySelectorAll('[data-cvss-panel]').forEach((panel) => {
        panel.hidden = panel.getAttribute('data-cvss-panel') !== key;
      });
    });
  });

  root.querySelectorAll('[data-cvss-source]').forEach((button) => {
    button.addEventListener('click', () => {
      const key = button.getAttribute('data-cvss-source');
      const panel = button.closest('[data-cvss-panel]');
      if (!panel) return;
      panel.querySelectorAll('[data-cvss-source]').forEach((item) => {
        const selected = item === button;
        item.classList.toggle('is-selected', selected);
        item.setAttribute('aria-pressed', String(selected));
      });
      panel.querySelectorAll('[data-cvss-source-detail]').forEach((detail) => {
        detail.hidden = detail.getAttribute('data-cvss-source-detail') !== key;
      });
    });
  });

  root.querySelectorAll('[data-toggle-overflow]').forEach((button) => {
    button.addEventListener('click', () => {
      const group = button.getAttribute('data-toggle-overflow');
      const expanded = button.getAttribute('aria-expanded') === 'true';
      root.querySelectorAll(`[data-overflow-group="${CSS.escape(group)}"]`).forEach((item) => {
        item.hidden = expanded;
      });
      button.setAttribute('aria-expanded', String(!expanded));
      button.textContent = expanded ? button.dataset.expandLabel : button.dataset.collapseLabel;
    });
  });
}

function renderOverflowButton(group, expandLabel, collapseLabel) {
  return `<button class="overflow-toggle" type="button" data-toggle-overflow="${escapeAttr(group)}" data-expand-label="${escapeAttr(expandLabel)}" data-collapse-label="${escapeAttr(collapseLabel)}" aria-expanded="false">${escapeHtml(expandLabel)}</button>`;
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
      ${Object.entries(groupByEco(affected)).sort((a,b)=>b[1].length-a[1].length).map(([eco,items])=>{
        const groupKey = `affected-${slug(eco)}`;
        const initialLimit = 24;
        return `
        <div class="aff-eco-group">
          <div class="affected-group-head">
            <strong>${escapeHtml(eco)}</strong>
            <span class="badge">${fmt(items.length)}</span>
          </div>
          <div class="affected-table">
            ${items.map((a,index)=>`
              <div class="affected-row" ${index >= initialLimit ? `hidden data-overflow-group="${escapeAttr(groupKey)}"` : ''}>
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
          ${items.length > initialLimit ? renderOverflowButton(groupKey, `Show ${fmt(items.length - initialLimit)} more`, 'Show fewer') : ''}
        </div>
      `}).join('')}
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
            <div class="info-card-row"><strong>${escapeHtml(displayIdentifierValue(r.recordId || '-'))}</strong></div>
            <p style="font-size:12px;color:var(--muted);margin:4px 0">${escapeHtml(r.title || '')}</p>
            <small class="muted">source ${date(r.sourceModifiedAt)} · ingested ${date(r.ingestedAt)} · normalized ${date(r.normalizedAt)}</small>
          </div>
        `).join('')}
      </div>
    </section>
  `).join('');
}

function renderReferenceCards(refs) {
  if (!refs.length) return '';
  const initialLimit = 16;
  return `
    <section class="detail-section" id="references">
      <div class="section-title-row">
        <h3 class="section-h">References</h3>
        <span class="badge">${fmt(refs.length)}</span>
      </div>
      <div class="card-stack">
        ${refs.map((r, index) => `
          <div class="info-card" ${index >= initialLimit ? 'hidden data-overflow-group="references"' : ''}>
            ${renderExternalLink(r.url, shortUrl(r.url), 'ref-link')}
            <div class="chips">
              ${sourceTag(r.code)}
              ${r.ref_type ? `<span class="badge">${escapeHtml(r.ref_type)}</span>` : ''}
              ${Array.isArray(r.tags) ? r.tags.slice(0, 3).map(t => `<span class="badge">${escapeHtml(t)}</span>`).join('') : ''}
            </div>
          </div>
        `).join('')}
      </div>
      ${refs.length > initialLimit ? renderOverflowButton('references', `Show ${fmt(refs.length - initialLimit)} more references`, 'Show fewer references') : ''}
    </section>
  `;
}

function vulnerabilityResult(item) {
  const names = (item.affectedComponentNames || []).slice(0, 3);
  const displayId = displayIdentifier(item);
  return `
    <a class="result-item" href="${cveRoute(displayId)}" data-vulnerability-id="${escapeAttr(item.id)}" data-vulnerability-identifier="${escapeAttr(displayId)}">
      <div class="result-main">
        <span class="result-title">${escapeHtml(displayId)}</span>
        ${severityBadge(item.severityLabel, item.maxCvssScore)}
      </div>
      <div class="result-summary">${escapeHtml(item.title || '')}</div>
      <div class="result-meta">
        ${item.publishedAt ? `<span class="badge">published ${date(item.publishedAt)}</span>` : ''}
        ${item.modifiedAt ? `<span class="badge">updated ${date(item.modifiedAt)}</span>` : ''}
        ${names.length ? `<span class="badge" title="${escapeAttr(names.join(', '))}">${escapeHtml(names.join(', '))}</span>` : ''}
        ${item.affectedComponentCount ? `<span class="badge muted">${fmt(item.affectedComponentCount)} affected</span>` : ''}
      </div>
    </a>
  `;
}

function componentVulnerabilityResult(item) {
  const match = item.versionMatched === true ? 'version match' : item.versionMatched === false ? 'range miss' : 'range unknown';
  const matchKlass = item.versionMatched === true ? 'low' : item.versionMatched === false ? 'none' : '';
  const displayId = displayIdentifier(item);
  return `
    <a class="result-item" href="${cveRoute(displayId)}" data-vulnerability-id="${escapeAttr(item.vulnerabilityId)}" data-vulnerability-identifier="${escapeAttr(displayId)}">
      <div class="result-main">
        <span class="result-title">${escapeHtml(displayId)}</span>
        ${severityBadge(item.severityLabel, item.cvssScore)}
      </div>
      <div class="muted">${escapeHtml(item.packageName || item.purl || '')}</div>
      <div class="chips"><span class="badge ${matchKlass}">${escapeHtml(match)}</span><span class="badge">${escapeHtml(item.versionRange || 'no range')}</span></div>
    </a>
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
  const klass = severityClass(label, score);
  const text = `${escapeHtml(label || 'CVSS')} ${score != null ? score : ''}`;
  return `<span class="badge ${klass}">${text}</span>`;
}

function severityClass(label, score) {
  const numeric = Number(score ?? 0);
  const tag = (String(label || '')).toLowerCase();
  return tag === 'critical' || numeric >= 9 ? 'critical' :
         tag === 'high' || numeric >= 7 ? 'high' :
         tag === 'medium' || numeric >= 4 ? 'medium' :
         tag === 'low' || numeric > 0 ? 'low' : 'none';
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
  const groups = [
    ['Base', metrics.filter(metric => ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'].includes(metric.key))],
    ['Temporal', metrics.filter(metric => ['E', 'RL', 'RC'].includes(metric.key))],
    ['Environmental', metrics.filter(metric => !['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A', 'E', 'RL', 'RC'].includes(metric.key))]
  ].filter(([, items]) => items.length);
  return `
    <div class="cvss-vector">
      <div class="cvss-vector-head">
        <span>${escapeHtml(version || 'CVSS vector')}</span>
        <code class="cvss-vector-string">${escapeHtml(vectorString)}</code>
      </div>
      ${groups.map(([label, items]) => `
        <div class="cvss-metric-group">
          <span>${escapeHtml(label)}</span>
          <div class="cvss-metric-chips">
            ${items.map(metric => `<span class="cvss-metric-chip" title="${escapeAttr(metric.metric)}"><b>${escapeHtml(metric.key)}</b>${escapeHtml(metric.label)}</span>`).join('')}
          </div>
        </div>
      `).join('')}
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
      key,
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

function renderSafeMarkdown(value) {
  const lines = String(value || '').replace(/\r\n?/g, '\n').split('\n');
  const html = [];
  let paragraph = [];
  let list = null;
  let code = null;

  const flushParagraph = () => {
    if (!paragraph.length) return;
    html.push(`<p>${paragraph.map(renderSafeMarkdownInline).join('<br>')}</p>`);
    paragraph = [];
  };
  const flushList = () => {
    if (!list) return;
    html.push(`<${list.type}>${list.items.map(item => `<li>${renderSafeMarkdownInline(item)}</li>`).join('')}</${list.type}>`);
    list = null;
  };
  const flushCode = () => {
    if (!code) return;
    html.push(`<pre><code>${escapeHtml(code.lines.join('\n'))}</code></pre>`);
    code = null;
  };

  for (const line of lines) {
    const fence = line.match(/^\s*```(?:\w+)?\s*$/);
    if (fence) {
      flushParagraph();
      flushList();
      if (code) flushCode();
      else code = { lines: [] };
      continue;
    }
    if (code) {
      code.lines.push(line);
      continue;
    }
    if (!line.trim()) {
      flushParagraph();
      flushList();
      continue;
    }
    const heading = line.match(/^\s*(#{1,3})\s+(.+)$/);
    if (heading) {
      flushParagraph();
      flushList();
      const level = heading[1].length + 3;
      html.push(`<h${level}>${renderSafeMarkdownInline(heading[2])}</h${level}>`);
      continue;
    }
    const bullet = line.match(/^\s*[-*+]\s+(.+)$/);
    const ordered = line.match(/^\s*\d+\.\s+(.+)$/);
    if (bullet || ordered) {
      flushParagraph();
      const type = bullet ? 'ul' : 'ol';
      if (list?.type !== type) {
        flushList();
        list = { type, items: [] };
      }
      list.items.push((bullet || ordered)[1]);
      continue;
    }
    if (line.startsWith('> ')) {
      flushParagraph();
      flushList();
      html.push(`<blockquote>${renderSafeMarkdownInline(line.slice(2))}</blockquote>`);
      continue;
    }
    paragraph.push(line);
  }
  flushParagraph();
  flushList();
  flushCode();
  return html.join('');
}

function renderSafeMarkdownInline(value) {
  const codeTokens = [];
  let text = escapeHtml(value);
  text = text.replace(/`([^`]+)`/g, (_, content) => {
    const token = `VTMDTOKEN${codeTokens.length}END`;
    codeTokens.push(`<code>${content}</code>`);
    return token;
  });
  text = text.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, label, href) => {
    const safeHref = safeExternalHref(href.replaceAll('&amp;', '&'));
    return safeHref ? `<a href="${escapeAttr(safeHref)}" target="_blank" rel="noreferrer">${label}</a>` : `${label} (${href})`;
  });
  text = text
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/__([^_]+)__/g, '<strong>$1</strong>')
    .replace(/(^|[^*])\*([^*]+)\*/g, '$1<em>$2</em>')
    .replace(/(^|[^_])_([^_]+)_/g, '$1<em>$2</em>');
  return text.replace(/VTMDTOKEN(\d+)END/g, (_, index) => codeTokens[Number(index)] || '');
}

function safeExternalHref(value) {
  try {
    const url = new URL(String(value || ''));
    return ['http:', 'https:'].includes(url.protocol) ? url.href : null;
  } catch {
    return null;
  }
}

function renderExternalLink(url, label, className = '') {
  const href = safeExternalHref(url);
  const text = escapeHtml(label);
  return href
    ? `<a href="${escapeAttr(href)}" target="_blank" rel="noreferrer"${className ? ` class="${escapeAttr(className)}"` : ''}>${text}</a>`
    : `<span${className ? ` class="${escapeAttr(className)}"` : ''}>${text}</span>`;
}

async function bootstrap() {
  await loadAuthSession();
  loadStatus();
  el.queryInput.value = '';
  await applyRoute();
}

bootstrap();
window.addEventListener('popstate', applyRoute);

// ===== SBOM Management =====

async function loadSbomList(options = {}) {
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

async function loadSbomDetail(sbomId, options = {}) {
  setSbomDetailView(true);
  showDetailPane();
  el.detailPane.innerHTML = '<div class="empty-state"><h2>Loading...</h2></div>';
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
