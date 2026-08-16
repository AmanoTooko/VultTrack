import { api } from './api.js';
import {
  state,
  el,
  showDetailPane,
  setDetailOnlyView,
  updatePager,
  updateRoute,
  cveRoute,
  searchRouteFor
} from './state.js';
import {
  escapeHtml,
  escapeAttr,
  fmt,
  pct,
  date,
  dateTime,
  slug,
  shortUrl,
  severityBadge,
  severityClass,
  renderSafeMarkdown,
  renderExternalLink,
  renderDataGap,
  sourceTag,
  formatJsonKey,
  renderSkeletonDetail
} from './format.js';

export async function runVulnerabilitySearch(query) {
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

export function bindVulnerabilityLinks(container) {
  container.querySelectorAll('[data-vulnerability-id]').forEach((link) => {
    link.addEventListener('click', (event) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      loadVulnerabilityDetail(link.dataset.vulnerabilityId, { identifier: link.dataset.vulnerabilityIdentifier });
    });
  });
}

export async function loadVulnerabilityByIdentifier(identifier, options = {}) {
  setDetailOnlyView(true);
  showDetailPane();
  el.detailPane.innerHTML = renderSkeletonDetail();
  try {
    const item = await api(`/api/v1/vulnerability.getByIdentifier?identifier=${encodeURIComponent(identifier)}`);
    const data = await loadVulnerabilityDetail(item.id, { identifier: item.primaryIdentifier, updateRoute: false, section: options.section });
    updateRoute(cveRoute(displayIdentifier(data?.vulnerability || item), options.section), { replace: true });
  } catch (error) {
    el.detailPane.innerHTML = `<div class="empty-state"><h2>Request failed</h2><p>${escapeHtml(error.message)}</p></div>`;
  }
}

export async function loadVulnerabilityDetail(id, options = {}) {
  state.selectedId = id;
  if (options.detailOnly !== false) setDetailOnlyView(true);
  el.resultList.querySelectorAll('.result-item').forEach((item) => {
    item.classList.toggle('is-active', item.dataset.vulnerabilityId === id);
  });
  showDetailPane();
  el.detailPane.innerHTML = renderSkeletonDetail();
  try {
    const data = await api(`/api/v1/vulnerability.detail?id=${encodeURIComponent(id)}&source=duckdb`);
    renderDetail(data);
    if (options.updateRoute !== false) {
      updateRoute(cveRoute(displayIdentifier(data.vulnerability) || options.identifier || id, options.section));
    }
    scrollToDetailSection(options.section, { replaceRoute: false }) || el.detailPane.scrollIntoView({ block: 'start', behavior: 'smooth' });
    return data;
  } catch (error) {
    el.detailPane.innerHTML = `<div class="empty-state"><h2>Request failed</h2><p>${escapeHtml(error.message)}</p></div>`;
  }
}

function vulnerabilityResult(item) {
  const allNames = item.affectedComponentNames || [];
  const names = allNames.slice(0, 2);
  const extraCount = Math.max(0, Number(item.affectedComponentCount || allNames.length) - names.length);
  const displayId = displayIdentifier(item);
  const klass = severityClass(item.severityLabel, item.maxCvssScore);
  return `
    <a class="result-item vuln-item" href="${cveRoute(displayId)}" data-vulnerability-id="${escapeAttr(item.id)}" data-vulnerability-identifier="${escapeAttr(displayId)}">
      <div class="vuln-sev">
        <span class="badge ${klass} vuln-sev-badge">${escapeHtml(item.severityLabel || 'unrated')}</span>
        <span class="cvss-chip" title="Max CVSS score">${item.maxCvssScore != null ? Number(item.maxCvssScore).toFixed(1) : 'N/A'}</span>
      </div>
      <div class="vuln-body">
        <div class="vuln-head">
          <span class="result-title vuln-id">${escapeHtml(displayId)}</span>
          <span class="vuln-date" title="published ${date(item.publishedAt)}">upd ${date(item.modifiedAt)}</span>
        </div>
        <div class="result-summary">${escapeHtml(item.title || '')}</div>
        ${names.length ? `
          <div class="result-meta vuln-chips">
            ${names.map(name => `<span class="badge vuln-chip" title="${escapeAttr(allNames.join(', '))}">${escapeHtml(name)}</span>`).join('')}
            ${extraCount ? `<span class="badge none vuln-chip-more">+${fmt(extraCount)}</span>` : ''}
          </div>
        ` : ''}
      </div>
    </a>
  `;
}

export function componentVulnerabilityResult(item) {
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
          ${renderRelationEvidence(v)}
          ${renderRelationshipReferences(v)}
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
    ['Relationships', 'relations'],
    ['Relationship References', 'relationship-references'],
    ['Raw Data', 'raw-data']
  ];
  return `
    <nav class="detail-nav" aria-label="Detail sections">
      ${items.map(([label, id]) => `<a href="#${id}" data-detail-section-link="${id}">${escapeHtml(label)}</a>`).join('')}
    </nav>
  `;
}

function renderAiAnalysisPlan() {
  return `
    <div class="section-title-row">
      <h3 class="section-h">AI Analysis</h3>
      <span class="badge">Read only</span>
    </div>
    <div class="ai-status-line"><span>Status</span><p data-ai-summary-status>Checking AI analysis.</p></div>
    <div class="ai-summary-output" data-ai-summary-output></div>
  `;
}

async function loadAiSummary(vulnerabilityId) {
  const section = el.detailPane.querySelector('#ai-analysis');
  if (!section) return;
  try {
    const summary = await api(`/api/v1/vulnerability.aiAnalysis?id=${encodeURIComponent(vulnerabilityId)}`);
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

  const analysis = result.analysis || result.summary;
  if (analysis) {
    status.textContent = `Analyzed with ${result.model || 'unknown model'}${result.updatedAt ? ` · ${dateTime(result.updatedAt)}` : ''}.`;
    output.innerHTML = `
      ${renderAutomotiveAiAnalysis(analysis)}
    `;
    bindAiAssessmentTabs(output);
    keepCurrentDetailSectionAnchored();
    return;
  }

  if (result.status === 'not_analyzed' && result.configured === undefined) {
    status.textContent = result.message || 'No AI analysis exists for this vulnerability.';
    output.innerHTML = `
      <div class="ai-empty-actions">
        <span class="badge warn">not analyzed</span>
      </div>
    `;
    keepCurrentDetailSectionAnchored();
    return;
  }

  status.textContent = result.message || 'No AI analysis exists for this vulnerability.';
  output.innerHTML = `
    <div class="ai-empty-actions">
      <span class="badge ${result.configured ? 'low' : 'warn'}">${result.configured ? 'configured' : 'not configured'}</span>
      <span class="badge">input ${fmt(result.inputChars || 0)} chars</span>
      ${state.authenticated ? '<button class="tab" type="button" data-ai-generate>Generate</button>' : '<span class="muted">Admin login required to generate.</span>'}
    </div>
  `;
  keepCurrentDetailSectionAnchored();
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

function renderAutomotiveAiAnalysis(analysis) {
  if (analysis.ai_summary && (analysis.connected_vehicle_backend_impact || analysis.in_vehicle_ecu_impact)) {
    return renderDualContextAiAnalysis(analysis);
  }

  const assessment = analysis.iso21434_assessment;
  if (!analysis.executive_summary || !assessment) {
    return `<div class="ai-json-card">${renderAiJson(analysis)}</div>`;
  }

  const feasibility = assessment.attack_feasibility || {};
  const impact = assessment.impact_level || {};
  const applicability = assessment.automotive_applicability || {};
  const intel = analysis.threat_intelligence || {};
  const risk = assessment.overall_risk_rating || 'Unknown';
  const target = assessment.target_architecture || 'Automotive ECU';

  return `
    <div class="ai-risk-panel">
      <div class="ai-risk-header">
        <div>
          <span class="eyebrow">AI Summary</span>
          <h4>${escapeHtml(analysis.executive_summary)}</h4>
        </div>
        <div class="ai-risk-score ${riskClass(risk)}">
          <span>Overall Risk</span>
          <strong>${escapeHtml(risk)}</strong>
        </div>
      </div>

      <div class="ai-risk-grid">
        <div class="analysis-field">
          <span>Target</span>
          <p>${escapeHtml(target)}</p>
        </div>
        <div class="analysis-field">
          <span>Automotive Use</span>
          <p><strong>${escapeHtml(applicability.component_usage_likelihood || 'Unknown')}</strong>${applicability.rationale ? ` · ${escapeHtml(applicability.rationale)}` : ''}</p>
        </div>
        <div class="analysis-field">
          <span>CVSS / EPSS</span>
          <p>CVSS ${escapeHtml(displayUnknown(intel.cvss_score))} · EPSS ${escapeHtml(displayUnknown(intel.epss_percentile))}</p>
        </div>
        <div class="analysis-field">
          <span>Public Exploit</span>
          <p>${escapeHtml(displayUnknown(intel.public_exploit_available))}</p>
        </div>
      </div>

      <div class="ai-assessment-tabs" role="tablist" aria-label="AI assessment sections">
        <button class="ai-assessment-tab is-active" type="button" data-ai-tab="feasibility">Attack Feasibility</button>
        <button class="ai-assessment-tab" type="button" data-ai-tab="impact">Impact</button>
        <button class="ai-assessment-tab" type="button" data-ai-tab="overall">Overall</button>
      </div>

      <div class="ai-assessment-panel" data-ai-panel="feasibility">
        <div class="ai-risk-grid three">
          ${riskMetric('Distance', feasibility.distance)}
          ${riskMetric('Expertise', feasibility.personnel_expertise)}
          ${riskMetric('Equipment', feasibility.equipment_required)}
        </div>
        <div class="analysis-field wide">
          <span>Feasibility Level</span>
          <p><strong>${escapeHtml(displayUnknown(feasibility.feasibility_level))}</strong></p>
        </div>
      </div>

      <div class="ai-assessment-panel" data-ai-panel="impact" hidden>
        <div class="ai-risk-grid two">
          ${riskMetric('Privacy', impact.privacy)}
          ${riskMetric('Financial', impact.financial)}
          ${riskMetric('Personal Safety', impact.personal_safety)}
          ${riskMetric('Reputation', impact.reputation)}
        </div>
        <div class="analysis-field wide">
          <span>Overall Impact</span>
          <p><strong>${escapeHtml(displayUnknown(impact.overall_impact))}</strong></p>
        </div>
      </div>

      <div class="ai-assessment-panel" data-ai-panel="overall" hidden>
        <div class="ai-risk-grid two">
          ${riskMetric('Risk Rating', risk)}
          ${riskMetric('Applicability', applicability.component_usage_likelihood)}
        </div>
        <div class="analysis-field wide">
          <span>Remediation Strategy</span>
          <p>${escapeHtml(displayUnknown(analysis.remediation_strategy))}</p>
        </div>
      </div>
    </div>
  `;
}

function renderDualContextAiAnalysis(analysis) {
  const summary = analysis.ai_summary || {};
  const backend = analysis.connected_vehicle_backend_impact || {};
  const ecu = analysis.in_vehicle_ecu_impact || {};
  const intel = analysis.threat_intelligence || {};

  return `
    <div class="ai-risk-panel">
      <div class="ai-risk-header compact">
        <div>
          <span class="eyebrow">AI Summary</span>
          <h4>${escapeHtml(displayUnknown(summary.description))}</h4>
        </div>
      </div>
      ${Array.isArray(summary.key_evidence) && summary.key_evidence.length ? `
        <ul class="ai-evidence-list">
          ${summary.key_evidence.slice(0, 6).map(item => `<li>${escapeHtml(displayUnknown(item))}</li>`).join('')}
        </ul>
      ` : ''}

      <div class="ai-assessment-tabs" role="tablist" aria-label="AI impact contexts">
        <button class="ai-assessment-tab is-active" type="button" data-ai-tab="backend">Connected Backend</button>
        <button class="ai-assessment-tab" type="button" data-ai-tab="ecu">Vehicle ECU</button>
      </div>

      <div class="ai-assessment-panel" data-ai-panel="backend">
        ${renderBackendImpactPanel(backend, intel)}
      </div>

      <div class="ai-assessment-panel" data-ai-panel="ecu" hidden>
        ${renderEcuImpactPanel(ecu, intel)}
      </div>
    </div>
  `;
}

function renderBackendImpactPanel(backend, intel) {
  const feasibility = backend.attack_feasibility || {};
  const impact = backend.impact || {};
  return `
    <div class="ai-risk-grid">
      ${riskMetric('Risk', backend.risk_rating)}
      ${riskMetric('Applicability', backend.applicability)}
      ${riskMetric('CVSS', intel.cvss_score)}
      ${riskMetric('EPSS', intel.epss_percentile)}
    </div>
    <div class="analysis-field wide">
      <span>Backend Summary</span>
      <p>${escapeHtml(displayUnknown(backend.summary))}</p>
    </div>
    <div class="analysis-field wide">
      <span>Attack Feasibility</span>
      <p><strong>${escapeHtml(displayUnknown(feasibility.level))}</strong> · ${escapeHtml(displayUnknown(feasibility.summary))}</p>
    </div>
    <div class="ai-risk-grid three">
      ${riskMetric('Distance', feasibility.distance)}
      ${riskMetric('Expertise', feasibility.personnel_expertise)}
      ${riskMetric('Equipment', feasibility.equipment_required)}
    </div>
    <div class="ai-risk-grid two">
      ${riskMetric('Data Privacy', impact.data_privacy)}
      ${riskMetric('Continuity', impact.service_continuity)}
      ${riskMetric('Fleet Ops', impact.fleet_operations)}
      ${riskMetric('Compliance', impact.reputation_compliance)}
    </div>
    <div class="analysis-field wide">
      <span>Remediation</span>
      <p>${escapeHtml(displayUnknown(backend.remediation_strategy))}</p>
    </div>
  `;
}

function renderEcuImpactPanel(ecu, intel) {
  const applicability = ecu.automotive_applicability || {};
  const feasibility = ecu.attack_feasibility || {};
  const impact = ecu.impact_level || {};
  const conditionalScenarios = Array.isArray(applicability.conditional_ecu_scenarios) ? applicability.conditional_ecu_scenarios.filter(Boolean) : [];
  const missingEvidence = Array.isArray(applicability.missing_evidence) ? applicability.missing_evidence.filter(Boolean) : [];
  return `
    <div class="ai-risk-grid">
      ${riskMetric('Risk', ecu.risk_rating)}
      ${riskMetric('ECU Use', applicability.component_usage_likelihood)}
      ${riskMetric('Assumption', applicability.deployment_assumption)}
      ${riskMetric('CVSS', intel.cvss_score)}
      ${riskMetric('Public Exploit', intel.public_exploit_available)}
    </div>
    <div class="analysis-field wide">
      <span>Automotive Applicability</span>
      <p>${escapeHtml(displayUnknown(applicability.rationale))}</p>
    </div>
    ${conditionalScenarios.length ? `
      <div class="analysis-field wide">
        <span>Conditional Scenarios</span>
        <p>${conditionalScenarios.slice(0, 5).map(item => escapeHtml(displayUnknown(item))).join(' · ')}</p>
      </div>
    ` : ''}
    ${missingEvidence.length ? `
      <div class="analysis-field wide">
        <span>Needed Evidence</span>
        <p>${missingEvidence.slice(0, 6).map(item => escapeHtml(displayUnknown(item))).join(' · ')}</p>
      </div>
    ` : ''}
    <div class="analysis-field wide">
      <span>Attack Feasibility</span>
      <p><strong>${escapeHtml(displayUnknown(feasibility.feasibility_level))}</strong> · ${escapeHtml(displayUnknown(feasibility.summary))}</p>
    </div>
    <div class="ai-risk-grid three">
      ${riskMetric('Distance', feasibility.distance)}
      ${riskMetric('Expertise', feasibility.personnel_expertise)}
      ${riskMetric('Equipment', feasibility.equipment_required)}
    </div>
    <div class="ai-risk-grid two">
      ${riskMetric('Privacy', impact.privacy)}
      ${riskMetric('Financial', impact.financial)}
      ${riskMetric('Safety', impact.personal_safety)}
      ${riskMetric('Reputation', impact.reputation)}
    </div>
    <div class="analysis-field wide">
      <span>Overall Impact</span>
      <p><strong>${escapeHtml(displayUnknown(impact.overall_impact))}</strong></p>
    </div>
    <div class="analysis-field wide">
      <span>Remediation</span>
      <p>${escapeHtml(displayUnknown(ecu.remediation_strategy))}</p>
    </div>
  `;
}

function bindAiAssessmentTabs(root) {
  root.querySelectorAll('[data-ai-tab]').forEach((tab) => {
    tab.addEventListener('click', () => {
      const key = tab.getAttribute('data-ai-tab');
      root.querySelectorAll('[data-ai-tab]').forEach((item) => item.classList.toggle('is-active', item === tab));
      root.querySelectorAll('[data-ai-panel]').forEach((panel) => {
        panel.hidden = panel.getAttribute('data-ai-panel') !== key;
      });
    });
  });
}

function riskMetric(label, value) {
  const text = metricLevel(value);
  const rationale = metricRationale(value);
  return `
    <div class="analysis-field ai-risk-metric ${riskClass(text)}">
      <span>${escapeHtml(label)}</span>
      <p>${escapeHtml(text)}</p>
      ${rationale ? `<small>${escapeHtml(rationale)}</small>` : ''}
    </div>
  `;
}

function metricLevel(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return displayUnknown(firstPresent(value, ['level', 'rating', 'severity', 'value', 'label', 'status', 'likelihood', 'overall']));
  }
  return displayUnknown(value);
}

function metricRationale(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return '';
  const rationale = displayUnknown(firstPresent(value, ['rationale', 'reason', 'summary', 'description', 'details', 'evidence']));
  return rationale === 'unknown' ? '' : rationale;
}

function displayUnknown(value) {
  if (value === null || value === undefined || value === '') return 'unknown';
  if (Array.isArray(value)) {
    const items = value.map(item => displayUnknown(item)).filter(item => item !== 'unknown');
    return items.length ? items.join(', ') : 'unknown';
  }
  if (typeof value === 'object') {
    const preferred = firstPresent(value, ['level', 'rating', 'severity', 'value', 'label', 'title', 'summary', 'description', 'rationale', 'status', 'likelihood', 'overall']);
    if (preferred !== undefined) return displayUnknown(preferred);
    const entries = Object.entries(value)
      .filter(([, item]) => item !== null && item !== undefined && item !== '')
      .slice(0, 4)
      .map(([key, item]) => `${formatJsonKey(key)}: ${displayUnknown(item)}`);
    return entries.length ? entries.join(' · ') : 'unknown';
  }
  return String(value);
}

function firstPresent(object, keys) {
  for (const key of keys) {
    if (object && object[key] !== null && object[key] !== undefined && object[key] !== '') return object[key];
  }
  return undefined;
}

function riskClass(value) {
  const normalized = String(value || '').toLowerCase();
  if (normalized.includes('critical') || normalized.includes('high')) return 'risk-high';
  if (normalized.includes('medium')) return 'risk-medium';
  if (normalized.includes('low')) return 'risk-low';
  if (normalized.includes('none')) return 'risk-none';
  return 'risk-unknown';
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

function renderRelationEvidence(v) {
  const maxVisible = 12;
  const groups = [
    ['Upstream', v.upstreamIdentifiers || []],
    ['Related', v.relatedIdentifiers || []],
    ['Downstream', v.downstreamIdentifiers || []]
  ].map(([label, identifiers]) => [
    label,
    [...new Set(identifiers.filter(Boolean).map(displayIdentifierValue))]
  ]).filter(([, identifiers]) => identifiers.length);
  if (!groups.length) return '';
  const groupMarkup = groups.map(([label, identifiers], groupIndex) => {
    const group = `relation-identifiers-${groupIndex}`;
    const visible = identifiers.slice(0, maxVisible);
    const hidden = identifiers.slice(maxVisible);
    return `
      <div class="info-card relation-group-card">
        <div class="info-card-row"><strong>${escapeHtml(label)}</strong><span class="badge">${fmt(identifiers.length)}</span></div>
        <div class="chips compact-chips">
          ${visible.map(identifier => `<a class="badge" href="${cveRoute(identifier)}" title="${escapeAttr(`${label}: ${identifier}`)}">${escapeHtml(identifier)}</a>`).join('')}
          ${hidden.map(identifier => `<a class="badge" hidden data-overflow-group="${group}" href="${cveRoute(identifier)}" title="${escapeAttr(`${label}: ${identifier}`)}">${escapeHtml(identifier)}</a>`).join('')}
        </div>
        ${hidden.length ? renderOverflowButton(group, `Show ${fmt(hidden.length)} more`, 'Show fewer') : ''}
      </div>
    `;
  }).join('');
  return `
    <section class="detail-section" id="relations">
      <div class="section-title-row">
        <h3 class="section-h">Relationships</h3>
        <span class="badge">${fmt(groups.reduce((total, [, identifiers]) => total + identifiers.length, 0))}</span>
      </div>
      <div class="card-stack">${groupMarkup}</div>
    </section>
  `;
}

function renderRelationshipReferences(v) {
  const references = (v.relationshipReferences || []).filter(item => item && item.identifier);
  if (!references.length) return '';
  const maxVisible = 12;
  return `
    <section class="detail-section" id="relationship-references">
      <div class="section-title-row">
        <h3 class="section-h">Relationship References</h3>
        <span class="badge">${fmt(references.length)}</span>
      </div>
      <div class="card-stack">
        ${references.map((reference, index) => {
          const label = reference.direction === 'downstream' ? 'Downstream' : reference.relationType;
          const source = [reference.sourceCode, reference.sourceRecordId].filter(Boolean).join(' / ');
          const identifier = displayIdentifierValue(reference.identifier);
          return `
            <div class="info-card" ${index >= maxVisible ? 'hidden data-overflow-group="relationship-references"' : ''}>
              <div class="info-card-row">
                <strong>${escapeHtml(label)}</strong>
                <a class="badge" href="${cveRoute(identifier)}" title="Open ${escapeAttr(identifier)}">
                  ${escapeHtml(identifier)}
                </a>
              </div>
              <div class="chips">
                ${source ? `<span class="badge">${escapeHtml(source)}</span>` : ''}
                ${reference.sourceUrl ? renderExternalLink(reference.sourceUrl, shortUrl(reference.sourceUrl)) : '<span class="muted">Source URL unavailable</span>'}
              </div>
            </div>
          `;
        }).join('')}
      </div>
      ${references.length > maxVisible ? renderOverflowButton('relationship-references', `Show ${fmt(references.length - maxVisible)} more relationships`, 'Show fewer relationships') : ''}
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

export function displayIdentifier(item) {
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
  bindDetailNav(root);

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

function bindDetailNav(root) {
  const nav = root.querySelector('.detail-nav');
  if (!nav) return;
  nav.querySelectorAll('[data-detail-section-link]').forEach((link) => {
    link.addEventListener('click', (event) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      scrollToDetailSection(link.dataset.detailSectionLink, { pushRoute: true, smooth: true });
    });
  });
  setActiveDetailNavLink(currentDetailSectionFromHash());
}

function currentDetailSectionFromHash() {
  return decodeURIComponent((window.location.hash || '').replace(/^#/, ''));
}

function scrollToDetailSection(sectionId, options = {}) {
  if (!sectionId) return false;
  const target = el.detailPane.querySelector(`#${CSS.escape(sectionId)}`);
  if (!target) return false;
  if (options.pushRoute) updateCurrentCveSection(sectionId);
  setActiveDetailNavLink(sectionId);
  target.scrollIntoView({ block: 'start', behavior: options.smooth === false ? 'auto' : 'smooth' });
  return true;
}

export function keepCurrentDetailSectionAnchored() {
  const sectionId = currentDetailSectionFromHash();
  if (!sectionId) return;
  requestAnimationFrame(() => scrollToDetailSection(sectionId, { smooth: false }));
}

function updateCurrentCveSection(sectionId) {
  const parts = window.location.pathname.split('/').filter(Boolean).map(part => decodeURIComponent(part));
  if (parts[0] !== 'cve' || !parts[1]) return;
  updateRoute(cveRoute(parts[1], sectionId));
}

function setActiveDetailNavLink(sectionId) {
  const nav = el.detailPane.querySelector('.detail-nav');
  if (!nav) return;
  nav.querySelectorAll('[data-detail-section-link]').forEach((link) => {
    const active = Boolean(sectionId) && link.dataset.detailSectionLink === sectionId;
    link.classList.toggle('is-active', active);
    if (active) link.scrollIntoView({ block: 'nearest', inline: 'center' });
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
