import { api, loadAuthSession } from './api.js';
import {
  state,
  el,
  applyThemeColor,
  openLogin,
  updateAuthUi,
  setDetailOnlyView,
  setSbomDetailView,
  hideDetailPane,
  updatePager,
  updateRoute,
  parseRoute,
  applySearchRouteState,
  syntaxHintHtml,
  modeTitle,
  modeDescription,
  searchMetaText,
  searchRoute,
  modeRoute
} from './state.js';
import { escapeHtml } from './format.js';
import { runVulnerabilitySearch, loadVulnerabilityByIdentifier, keepCurrentDetailSectionAnchored } from './vulnerabilities.js';
import { runComponentSearch } from './components.js';
import { loadSbomList } from './sbom.js';
import { loadStatus, loadStatusPage } from './status.js';
import { loadAdminPage, stopAdminAutoRefresh } from './admin.js';

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

function activateMode(tab, options = {}) {
  if (!tab) return;
  setDetailOnlyView(false);
  state.mode = tab.dataset.mode;
  if (state.mode !== 'admin') stopAdminAutoRefresh();
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

async function applyRoute() {
  const route = parseRoute();
  const tab = el.tabs.find(item => item.dataset.mode === route.mode);
  activateMode(tab, { updateRoute: false, load: false });
  applySearchRouteState(route);
  if (route.identifier) {
    await loadVulnerabilityByIdentifier(route.identifier, { section: route.section });
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

async function bootstrap() {
  await loadAuthSession();
  loadStatus();
  el.queryInput.value = '';
  await applyRoute();
}

bootstrap();
window.addEventListener('popstate', applyRoute);
window.addEventListener('hashchange', () => {
  if (window.location.pathname.split('/').filter(Boolean)[0] === 'cve') {
    keepCurrentDetailSectionAnchored();
  }
});
