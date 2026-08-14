import { api } from './api.js';
import { state, el, updatePager } from './state.js';
import { escapeHtml } from './format.js';
import { bindVulnerabilityLinks, componentVulnerabilityResult } from './vulnerabilities.js';

export async function runComponentSearch(query) {
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
