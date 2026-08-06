/**
 * breach.js — SecureGuard AI Breach Intelligence Center
 *
 * Responsibilities:
 *   • Render the risk distribution doughnut chart
 *   • Table search + sorting (client-side for current page; AJAX for pagination)
 *   • Row expand / collapse
 *   • Intelligence panel population on "Full Intelligence Report" click
 *   • AI recommendation panel refresh via /api/breach/recommendations/:risk
 *   • Pagination via /api/breach/history
 */

'use strict';

// ── Chart.js shared tooltip defaults ────────────────────────────────────────
const TT = {
  backgroundColor: 'rgba(15,23,42,0.92)',
  titleColor:      '#00e5ff',
  bodyColor:       '#f8fafc',
  borderColor:     'rgba(0,229,255,0.25)',
  borderWidth:     1,
  padding:         12,
};

// Risk tier → text colour
const RISK_COLOUR = {
  'Critical': '#ef4444',
  'High':     '#f97316',
  'Medium':   '#f59e0b',
  'Low':      '#3b82f6',
  'Safe':     '#2ecc71',
};

// ── Utility helpers ──────────────────────────────────────────────────────────

/** Read a data attribute from #breachPageData as parsed JSON. */
function pageData(attr) {
  const el = document.getElementById('breachPageData');
  if (!el) return null;
  try { return JSON.parse(el.dataset[attr] || 'null'); }
  catch { return null; }
}

/** Safely set textContent on an element by id. */
function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value ?? '—';
}

/** Show / hide an element by id. */
function show(id) { document.getElementById(id)?.classList.remove('d-none'); }
function hide(id) { document.getElementById(id)?.classList.add('d-none'); }

// ── Risk distribution doughnut chart ────────────────────────────────────────

function buildRiskChart() {
  const canvas = document.getElementById('breachRiskChart');
  if (!canvas) return;

  const labels  = pageData('riskLabels')  || ['Critical','High','Medium','Low'];
  const data    = pageData('riskData')    || [0, 0, 0, 0];
  const colours = pageData('riskColours') || ['#ef4444','#f97316','#f59e0b','#3b82f6'];

  // Show empty state message if no data
  const isEmpty = data.every(v => v === 0);
  if (isEmpty) {
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = 'rgba(203,213,225,0.3)';
    ctx.font = '12px Poppins,sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('No breached passwords yet.', canvas.width / 2, canvas.height / 2);
    return;
  }

  new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colours,
        borderWidth: 0,
        hoverOffset: 10,
      }],
    },
    options: {
      responsive:          true,
      maintainAspectRatio: false,
      cutout:              '68%',
      plugins: {
        legend:  { display: false },
        tooltip: {
          ...TT,
          callbacks: {
            label: (c) => `${c.label}: ${c.parsed} password${c.parsed !== 1 ? 's' : ''}`,
          },
        },
      },
    },
  });
}

// ── Row expand / collapse ────────────────────────────────────────────────────

function toggleRow(rowId) {
  const expandRow = document.getElementById(`expand-${rowId}`);
  const btn       = document.querySelector(`.breach-detail-btn[data-id="${rowId}"]`);
  if (!expandRow) return;

  const isOpen = !expandRow.classList.contains('d-none');
  // Close all other open rows first
  document.querySelectorAll('.breach-expand-row').forEach(r => {
    r.classList.add('d-none');
  });
  document.querySelectorAll('.breach-detail-btn i').forEach(i => {
    i.className = 'fas fa-chevron-down';
  });

  if (!isOpen) {
    expandRow.classList.remove('d-none');
    if (btn) btn.querySelector('i').className = 'fas fa-chevron-up';
  }
}

// ── Intelligence panel population ────────────────────────────────────────────

function openIntelPanel(rowData) {
  const panel = document.getElementById('breachIntelPanel');
  if (!panel) return;

  // Populate summary fields
  const labelEl = document.getElementById('intelLabel');
  if (labelEl) labelEl.textContent = rowData.label || '—';

  const riskEl = document.getElementById('intelRisk');
  if (riskEl) {
    riskEl.textContent = rowData.risk || '—';
    riskEl.style.color = RISK_COLOUR[rowData.risk] || '#00e5ff';
  }

  setText('intelSource', rowData.source || 'RockYou Sample');
  setText('intelScore',  rowData.score != null ? `${rowData.score}/100` : '—');

  // Technical analysis text
  const techEl = document.getElementById('intelTechnical');
  if (techEl) {
    const weaknesses = [];
    if (rowData.score < 20)         weaknesses.push('extremely low strength score');
    if (rowData.entropy < 2.5)      weaknesses.push('very low entropy (highly predictable)');
    if (rowData.dictionary_word)    weaknesses.push('contains a common dictionary word');
    if (rowData.keyboard_pattern)   weaknesses.push('contains a keyboard sequence');
    if ((rowData.length || 10) < 8) weaknesses.push('insufficient length (< 8 characters)');
    if (!rowData.uppercase)         weaknesses.push('no uppercase letters');
    if (!rowData.digits)            weaknesses.push('no numeric digits');
    if (!rowData.special)           weaknesses.push('no special characters');

    if (weaknesses.length > 0) {
      techEl.textContent =
        `Risk: ${rowData.risk}. Weaknesses: ${weaknesses.join('; ')}. ` +
        `Score: ${rowData.score}/100. Entropy: ${rowData.entropy} bits.`;
    } else {
      techEl.textContent =
        `Despite a ${rowData.risk} risk rating, this password was found in a breach ` +
        `dataset (score: ${rowData.score}/100, entropy: ${rowData.entropy} bits).`;
    }
  }

  // Show panel and scroll to it
  panel.classList.remove('d-none');
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Refresh AI recommendations for this risk tier
  refreshRecommendations(rowData.risk);
}

// ── AI Recommendations refresh ───────────────────────────────────────────────

function refreshRecommendations(risk) {
  const apiUrl   = `/api/breach/recommendations/${encodeURIComponent(risk)}`;
  const container = document.getElementById('recsContainer');
  const label     = document.getElementById('recsRiskLabel');

  if (label) label.textContent = risk;
  if (!container) return;

  fetch(apiUrl, { credentials: 'same-origin' })
    .then(r => r.json())
    .then(recs => {
      container.innerHTML = recs.map(rec => `
        <div class="col-md-6 col-lg-3">
          <div class="ai-insight-card h-100">
            <div class="ai-insight-icon">
              <i class="${rec.icon}"></i>
            </div>
            <div class="ai-insight-content">
              <h6 class="mb-1">${rec.title}</h6>
              <p class="text-muted small mb-2">${rec.body}</p>
              <span class="badge ${rec.badge}">${rec.badge_text}</span>
            </div>
          </div>
        </div>
      `).join('');
    })
    .catch(() => {});   // silently ignore — initial recs from server are still shown
}

// ── Table pagination (AJAX) ──────────────────────────────────────────────────

let _currentPage   = 1;
let _currentSearch = '';
let _currentSort   = 'date_desc';

function loadPage(page, search, sortBy) {
  const apiUrl = document.getElementById('breachPageData')?.dataset.apiHistory;
  if (!apiUrl) return;

  const params = new URLSearchParams({
    page,
    per_page: 10,
    search:   search || '',
    sort_by:  sortBy || 'date_desc',
  });

  fetch(`${apiUrl}?${params}`, { credentials: 'same-origin' })
    .then(r => r.json())
    .then(data => {
      renderTableRows(data.rows || []);
      renderPagination(data.page, data.pages, data.has_prev, data.has_next);
      _currentPage = data.page;
    })
    .catch(err => console.error('[breach.js] loadPage error:', err));
}

function renderTableRows(rows) {
  const tbody = document.getElementById('breachTableBody');
  if (!tbody) return;

  if (rows.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="text-center text-muted py-4">
          <i class="fas fa-shield-check text-success me-2"></i>
          No results found.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = rows.map(row => {
    const riskColour = {
      Critical: '#ef4444', High: '#f97316', Medium: '#f59e0b', Low: '#3b82f6'
    }[row.risk] || '#3b82f6';
    const scoreColour = row.score < 20 ? '#ef4444'
                      : row.score < 35 ? '#f97316' : '#f59e0b';

    return `
    <tr class="breach-table-row" data-id="${row.id}"
        data-row="${encodeURIComponent(JSON.stringify(row))}">
      <td>
        <div class="d-flex align-items-center gap-2">
          <i class="fas fa-lock text-danger" style="font-size:0.85rem;"></i>
          <code class="breach-label-code">${row.label}</code>
        </div>
      </td>
      <td class="text-center">
        <span class="${row.badge_class}">${row.risk}</span>
      </td>
      <td class="text-muted small">${row.source}</td>
      <td class="text-center">
        <span class="badge" style="background:rgba(239,68,68,0.15);color:${scoreColour};">
          ${row.score}/100
        </span>
      </td>
      <td class="text-muted small text-nowrap">${row.analyzed_at}</td>
      <td class="text-center">
        <span class="badge bg-danger" style="font-size:0.7rem;">
          <i class="fas fa-radiation me-1"></i>Breached
        </span>
      </td>
      <td class="text-center">
        <button class="btn btn-sm btn-outline-light breach-detail-btn py-1 px-2"
                data-id="${row.id}">
          <i class="fas fa-chevron-down"></i>
        </button>
      </td>
    </tr>
    <tr class="breach-expand-row d-none" id="expand-${row.id}">
      <td colspan="7" class="p-0">
        <div class="breach-expand-content p-3">
          <div class="row g-3">
            <div class="col-md-6">
              <p class="text-muted small mb-1">
                <strong>Entropy:</strong> ${row.entropy} bits
              </p>
              <p class="text-muted small mb-1">
                <strong>Length:</strong> ${row.length} characters
              </p>
              <p class="text-muted small mb-0">
                <strong>Detected:</strong> ${row.time_ago}
              </p>
            </div>
            <div class="col-md-6">
              <p class="text-muted small mb-1">
                <strong>Dictionary word:</strong>
                ${row.dictionary_word ? 'Yes ⚠' : 'No'}
              </p>
              <p class="text-muted small mb-1">
                <strong>Keyboard pattern:</strong>
                ${row.keyboard_pattern ? 'Yes ⚠' : 'No'}
              </p>
              <p class="text-muted small mb-0">
                <strong>Strength category:</strong> ${row.strength_category}
              </p>
            </div>
          </div>
          <button class="btn btn-accent btn-sm mt-2 breach-select-btn"
                  data-id="${row.id}"
                  data-row="${encodeURIComponent(JSON.stringify(row))}">
            <i class="fas fa-crosshairs me-1"></i>Full Intelligence Report
          </button>
        </div>
      </td>
    </tr>
    `;
  }).join('');

  // Re-attach event listeners after re-render
  attachRowListeners();
}

function renderPagination(page, pages, hasPrev, hasNext) {
  const nav = document.getElementById('breachPagination');
  if (!nav || pages <= 1) {
    if (nav) nav.innerHTML = '';
    return;
  }

  const items = [];
  items.push(`
    <li class="page-item ${hasPrev ? '' : 'disabled'}">
      <a class="page-link breach-page-link" href="#" data-page="${page - 1}">
        <i class="fas fa-chevron-left"></i>
      </a>
    </li>
  `);
  for (let p = 1; p <= pages; p++) {
    items.push(`
      <li class="page-item ${p === page ? 'active' : ''}">
        <a class="page-link breach-page-link" href="#" data-page="${p}">${p}</a>
      </li>
    `);
  }
  items.push(`
    <li class="page-item ${hasNext ? '' : 'disabled'}">
      <a class="page-link breach-page-link" href="#" data-page="${page + 1}">
        <i class="fas fa-chevron-right"></i>
      </a>
    </li>
  `);
  nav.innerHTML = `<ul class="pagination justify-content-end mb-0 gap-1">${items.join('')}</ul>`;
  attachPaginationListeners();
}

// ── Event listener attachment ─────────────────────────────────────────────────

function attachRowListeners() {
  // Expand / collapse buttons
  document.querySelectorAll('.breach-detail-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      toggleRow(btn.dataset.id);
    });
  });

  // Full intelligence report buttons
  document.querySelectorAll('.breach-select-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      let rowData;
      try {
        // Try data-row attribute first (encoded JSON)
        const raw = btn.dataset.row;
        rowData = raw ? JSON.parse(decodeURIComponent(raw)) : null;
      } catch {
        rowData = null;
      }
      if (!rowData) {
        // Fallback: read from parent table row's data-row attribute
        const tr = btn.closest('tr.breach-expand-row')
                      ?.previousElementSibling;
        if (tr) {
          try {
            rowData = JSON.parse(decodeURIComponent(tr.dataset.row || '{}'));
          } catch { rowData = {}; }
        }
      }
      if (rowData) openIntelPanel(rowData);
    });
  });
}

function attachPaginationListeners() {
  document.querySelectorAll('.breach-page-link').forEach(a => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      const page = parseInt(a.dataset.page, 10);
      if (!isNaN(page) && page > 0) {
        loadPage(page, _currentSearch, _currentSort);
      }
    });
  });
}

// ── Initialise ────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // 1. Draw the doughnut chart
  buildRiskChart();

  // 2. Attach listeners to server-rendered table rows
  attachRowListeners();
  attachPaginationListeners();

  // 3. Search input (debounced)
  let searchTimer;
  const searchInput = document.getElementById('breachSearchInput');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => {
        _currentSearch = searchInput.value.trim();
        _currentPage   = 1;
        loadPage(1, _currentSearch, _currentSort);
      }, 300);
    });
  }

  // 4. Sort dropdown
  const sortSelect = document.getElementById('breachSortSelect');
  if (sortSelect) {
    sortSelect.addEventListener('change', () => {
      _currentSort = sortSelect.value;
      _currentPage = 1;
      loadPage(1, _currentSearch, _currentSort);
    });
  }

  // 5. Close intelligence panel button
  const closeBtn = document.getElementById('closeIntelBtn');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      hide('breachIntelPanel');
    });
  }
});
