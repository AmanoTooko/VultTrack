import { escapeHtml, normalizeHexColor, mixHex, fmt } from './format.js';

export const state = {
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

export const el = {
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

export function showDetailPane() {
  el.detailPane.hidden = false;
}

export function hideDetailPane() {
  el.detailPane.hidden = true;
  el.detailPane.innerHTML = '';
  setSbomDetailView(false);
}

export function setDetailOnlyView(enabled) {
  document.body.classList.toggle('detail-only-view', enabled);
  if (enabled) {
    el.searchForm.hidden = true;
    if (el.pager) el.pager.hidden = true;
    el.resultList.innerHTML = '';
    if (el.resultsTitle) el.resultsTitle.textContent = 'Vulnerability Detail';
    if (el.resultsMeta) el.resultsMeta.textContent = 'Dedicated CVE record';
  }
}

export function setSbomDetailView(enabled) {
  document.body.classList.toggle('sbom-detail-view', enabled);
}

export function applyThemeColor(color) {
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

export function updateAuthUi() {
  if (!el.authButton) return;
  el.authButton.textContent = state.authenticated ? `Logout ${state.username || ''}`.trim() : 'Login';
  el.authButton.classList.toggle('is-active', state.authenticated);
}

export function openLogin() {
  if (!el.loginDialog) return;
  el.loginError.hidden = true;
  el.loginDialog.showModal();
  setTimeout(() => el.loginUsername?.focus(), 0);
}

export function renderAuthRequired(title = 'Login required') {
  return `
    <div class="empty-state auth-required">
      <h2>${escapeHtml(title)}</h2>
      <p>Administrator login is required for pipeline status and fetcher controls.</p>
      <button class="primary-button" type="button" data-open-login>Login</button>
    </div>
  `;
}

export function bindLoginPrompt() {
  el.detailPane.querySelector('[data-open-login]')?.addEventListener('click', openLogin);
}

export function modeRoute(mode) {
  return {
    vulnerability: searchRoute('vulnerability'),
    component: searchRoute('component'),
    sbom: '/sbom',
    status: '/status',
    admin: '/admin'
  }[mode] || '/';
}

export function searchRoute(mode = state.mode) {
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

export function searchRouteFor(mode, query) {
  const params = new URLSearchParams();
  params.set('type', mode === 'component' ? 'component' : 'vulnerability');
  if (query) params.set('q', query);
  return `/search?${params.toString()}`;
}

export function cveRoute(identifier, sectionId = '') {
  const hash = sectionId ? `#${encodeURIComponent(sectionId)}` : '';
  return `/cve/${encodeURIComponent(identifier)}${hash}`;
}

export function sbomRoute(id) {
  return `/sbom/${encodeURIComponent(id)}`;
}

export function updateRoute(path, options = {}) {
  const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  if (current === path) return;
  window.history[options.replace ? 'replaceState' : 'pushState']({}, '', path);
}

export function parseRoute() {
  const parts = window.location.pathname.split('/').filter(Boolean).map(part => decodeURIComponent(part));
  const params = new URLSearchParams(window.location.search);
  const section = decodeURIComponent((window.location.hash || '').replace(/^#/, ''));
  if (parts[0] === 'cve' && parts[1]) return { mode: 'vulnerability', identifier: parts[1], section };
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

export function applySearchRouteState(route) {
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

export function syntaxHintHtml(mode) {
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
      ['Run mode', 'scheduled, manual, or init'],
      ['Schedule', 'cron expression'],
      ['Save', 'Persist source settings']
    ]
  }[mode] || [];
  return items.map(([label, value]) => `<span>${escapeHtml(label)} <code>${escapeHtml(value)}</code></span>`).join('');
}

export function modeTitle(mode) {
  return {
    vulnerability: 'Vulnerabilities',
    component: 'Components',
    sbom: 'SBOM uploads',
    status: 'Pipeline status',
    admin: 'Fetcher administration'
  }[mode] || 'Vulnerabilities';
}

export function modeDescription(mode) {
  return {
    vulnerability: 'Search CVE identifiers, affected packages, titles, and source aliases.',
    component: 'Search package names, purl coordinates, vendor hints, ecosystems, and versions.',
    sbom: 'Upload, match, inspect, and export CycloneDX SBOM findings with PURL and CPE evidence.',
    status: 'Fast source snapshot with optional exact counts for raw-row queues.',
    admin: 'Review fetcher sources and save enablement, run mode, and schedule settings.'
  }[mode] || '';
}

export function searchMetaText(query) {
  if (state.mode === 'component') return 'Search package names, purl coordinates, vendor hints, ecosystems, and versions.';
  if (state.mode === 'vulnerability') {
    const label = query ? `"${query}"` : 'latest indexed vulnerabilities';
    return `${label} · ${sortLabel(state.sort)} · ${state.pageSize} per page`;
  }
  return '';
}

export function sortLabel(sort) {
  return {
    modifiedDesc: 'updated first',
    publishedDesc: 'published first',
    identifierDesc: 'CVE ID descending',
    cvssDesc: 'highest CVSS',
    cvssAsc: 'lowest CVSS'
  }[sort] || 'updated first';
}

export function updatePager(itemCount = null) {
  if (el.pageLabel) {
    const suffix = itemCount == null ? '' : ` · ${fmt(itemCount)} shown`;
    el.pageLabel.textContent = `Page ${fmt(state.page)}${suffix}`;
  }
  if (el.prevPageButton) el.prevPageButton.disabled = state.page <= 1;
  if (el.nextPageButton) el.nextPageButton.disabled = !state.hasMore;
}
