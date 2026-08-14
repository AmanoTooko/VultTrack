export function normalizeHexColor(color) {
  if (!color) return null;
  const match = String(color).trim().match(/^#?([0-9a-f]{6})$/i);
  return match ? `#${match[1].toLowerCase()}` : null;
}

export function mixHex(color, base, baseWeight) {
  const a = hexToRgb(color);
  const b = hexToRgb(base);
  if (!a || !b) return base;
  const weight = Math.max(0, Math.min(1, baseWeight));
  const mixed = a.map((value, index) => Math.round(value * (1 - weight) + b[index] * weight));
  return `#${mixed.map(v => v.toString(16).padStart(2, '0')).join('')}`;
}

export function hexToRgb(color) {
  const normalized = normalizeHexColor(color);
  if (!normalized) return null;
  return [1, 3, 5].map(index => parseInt(normalized.slice(index, index + 2), 16));
}

export function shortUrl(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.hostname}${parsed.pathname}`.slice(0, 90);
  } catch {
    return String(url).slice(0, 90);
  }
}

export function severityBadge(label, score) {
  const klass = severityClass(label, score);
  const text = `${escapeHtml(label || 'CVSS')} ${score != null ? score : ''}`;
  return `<span class="badge ${klass}">${text}</span>`;
}

export function severityClass(label, score) {
  const numeric = Number(score ?? 0);
  const tag = (String(label || '')).toLowerCase();
  return tag === 'critical' || numeric >= 9 ? 'critical' :
         tag === 'high' || numeric >= 7 ? 'high' :
         tag === 'medium' || numeric >= 4 ? 'medium' :
         tag === 'low' || numeric > 0 ? 'low' : 'none';
}

export function fmt(value) {
  return Number(value ?? 0).toLocaleString();
}

export function pct(value) {
  return `${(Number(value) * 100).toFixed(2)}%`;
}

export function date(value) {
  if (!value) return '-';
  return new Date(value).toISOString().slice(0, 10);
}

export function dateTime(value) {
  if (!value) return '-';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return '-';
  return parsed.toISOString().replace('T', ' ').slice(0, 16);
}

export function slug(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'source';
}

export function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export function escapeAttr(value) {
  return escapeHtml(value).replaceAll('`', '&#96;');
}

export function renderSafeMarkdown(value) {
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

export function renderSafeMarkdownInline(value) {
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

export function safeExternalHref(value) {
  try {
    const url = new URL(String(value || ''));
    return ['http:', 'https:'].includes(url.protocol) ? url.href : null;
  } catch {
    return null;
  }
}

export function renderExternalLink(url, label, className = '') {
  const href = safeExternalHref(url);
  const text = escapeHtml(label);
  return href
    ? `<a href="${escapeAttr(href)}" target="_blank" rel="noreferrer"${className ? ` class="${escapeAttr(className)}"` : ''}>${text}</a>`
    : `<span${className ? ` class="${escapeAttr(className)}"` : ''}>${text}</span>`;
}

export function renderDataGap(message) {
  return `<div class="data-gap"><p>${escapeHtml(message)}</p></div>`;
}

export function sourceTag(code) {
  return `<span class="badge tag-source">${escapeHtml(code || '?')}</span>`;
}

export function renderSkeletonRows(count = 6) {
  const rows = [];
  for (let i = 0; i < count; i += 1) {
    rows.push(`
      <div class="skeleton-row" aria-hidden="true">
        <div class="skeleton-side">
          <span class="skeleton skeleton-badge"></span>
          <span class="skeleton skeleton-chip"></span>
        </div>
        <div class="skeleton-lines">
          <span class="skeleton skeleton-line w-35"></span>
          <span class="skeleton skeleton-line w-90"></span>
          <span class="skeleton skeleton-line w-60"></span>
        </div>
      </div>
    `);
  }
  return `<div class="skeleton-list" role="status" aria-label="Loading">${rows.join('')}</div>`;
}

export function renderSkeletonDetail() {
  return `
    <div class="skeleton-detail" role="status" aria-label="Loading">
      <div class="skeleton skeleton-hero" aria-hidden="true"></div>
      <div class="skeleton-grid" aria-hidden="true">
        <span class="skeleton skeleton-card"></span>
        <span class="skeleton skeleton-card"></span>
        <span class="skeleton skeleton-card"></span>
        <span class="skeleton skeleton-card"></span>
      </div>
      <div class="skeleton-lines" aria-hidden="true">
        <span class="skeleton skeleton-line w-70"></span>
        <span class="skeleton skeleton-line w-90"></span>
        <span class="skeleton skeleton-line w-50"></span>
      </div>
    </div>
  `;
}

export function formatJsonKey(value) {
  return String(value)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replaceAll('_', ' ')
    .replace(/\s+/g, ' ')
    .trim();
}
