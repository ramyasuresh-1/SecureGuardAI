/**
 * analyzer.js — SecureGuard AI
 *
 * Wires the Password Analyzer page to the /api/analyze backend.
 * On "Simulate":
 *   1. POST password + settings to /api/analyze
 *   2. Render KPI cards, score gauge, feature grid, AI findings, crack time
 *   3. Refresh all dashboard charts via /api/charts/all
 *   4. Show saved-to-history banner
 *
 * No page reload. All DOM updates are in-place.
 */

'use strict';

// ── Shared Chart.js tooltip style ────────────────────────────────────────────
const TT = {
  backgroundColor: 'rgba(15,23,42,0.92)',
  titleColor: '#00e5ff',
  bodyColor: '#f8fafc',
  borderColor: 'rgba(0,229,255,0.25)',
  borderWidth: 1,
  padding: 12,
};

// ── Strength → colour maps ───────────────────────────────────────────────────
const STRENGTH_COLOUR = {
  'Very Weak': '#ef4444',
  'Weak':      '#f59e0b',
  'Moderate':  '#3b82f6',
  'Strong':    '#8b5cf6',
  'Excellent': '#2ecc71',
};
const STRENGTH_BG = {
  'Very Weak': 'bg-danger',
  'Weak':      'bg-warning',
  'Moderate':  'bg-info',
  'Strong':    'bg-primary',
  'Excellent': 'bg-success',
};
const THREAT_COLOUR_MAP = {
  'Critical': '#ef4444',
  'High':     '#f59e0b',
  'Medium':   '#3b82f6',
  'Low':      '#8b5cf6',
  'Very Low': '#2ecc71',
};

// ── Gauge chart instance (re-created each analysis) ──────────────────────────
let gaugeChart = null;
let radarChart = null;

// ── Helper: animate a counter from current displayed value → target ──────────
function animateTo(el, target, suffix = '') {
  const start  = parseFloat(el.textContent) || 0;
  const delta  = target - start;
  const steps  = 40;
  let   step   = 0;
  const tick   = () => {
    step++;
    const val = start + delta * (step / steps);
    el.textContent = (Number.isInteger(target) ? Math.round(val) : val.toFixed(2)) + suffix;
    if (step < steps) requestAnimationFrame(tick);
    else el.textContent = target + suffix;
  };
  requestAnimationFrame(tick);
}

// ── Gauge chart (doughnut used as a half-gauge) ───────────────────────────────
function buildGaugeChart(score, category) {
  const canvas = document.getElementById('scoreGaugeChart');
  if (!canvas) return;
  if (gaugeChart) { gaugeChart.destroy(); gaugeChart = null; }

  const colour = STRENGTH_COLOUR[category] || '#00e5ff';
  gaugeChart = new Chart(canvas, {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [score, 100 - score],
        backgroundColor: [colour, 'rgba(255,255,255,0.06)'],
        borderWidth: 0,
        hoverOffset: 0,
      }],
    },
    options: {
      responsive: false,
      cutout: '78%',
      rotation: -90,
      circumference: 180,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      animation: { duration: 900, easing: 'easeInOutQuart' },
    },
  });
}

// ── Radar chart for password composition ─────────────────────────────────────
function buildRadarChart(d) {
  const canvas = document.getElementById('analyzerRadarChart');
  if (!canvas) return;
  if (radarChart) { radarChart.destroy(); radarChart = null; }

  // Normalise raw counts to 0-100 for radar display
  const len     = d.password_length    || 0;
  const upper   = d.uppercase_count    || 0;
  const lower   = d.lowercase_count    || 0;
  const digits  = d.digit_count        || 0;
  const special = d.special_character_count || 0;
  const entropy = d.entropy            || 0;

  const actual = [
    Math.min(100, (upper  / Math.max(len, 1)) * 100 * 4),
    Math.min(100, (lower  / Math.max(len, 1)) * 100 * 2),
    Math.min(100, (digits / Math.max(len, 1)) * 100 * 4),
    Math.min(100, (special/ Math.max(len, 1)) * 100 * 6),
    Math.min(100, len / 20 * 100),
    Math.min(100, entropy / 5.0 * 100),
  ];

  radarChart = new Chart(canvas, {
    type: 'radar',
    data: {
      labels: ['Uppercase', 'Lowercase', 'Numbers', 'Symbols', 'Length', 'Entropy'],
      datasets: [
        {
          label: 'This Password',
          data: actual,
          borderColor: '#00e5ff',
          backgroundColor: 'rgba(0,229,255,0.18)',
          borderWidth: 2,
          pointBackgroundColor: '#00e5ff',
          pointBorderColor: '#0f172a',
          pointRadius: 5,
        },
        {
          label: 'Recommended',
          data: [80, 80, 80, 80, 80, 80],
          borderColor: '#7c4dff',
          backgroundColor: 'rgba(124,77,255,0.08)',
          borderWidth: 2,
          borderDash: [5, 5],
          pointRadius: 3,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: true, position: 'top',
          labels: { padding: 12, usePointStyle: true, color: '#cbd5e1' } },
        tooltip: { ...TT },
      },
      scales: {
        r: {
          beginAtZero: true, max: 100,
          ticks: { stepSize: 20, backdropColor: 'transparent', color: '#94a3b8', font: { size: 10 } },
          grid:        { color: 'rgba(255,255,255,0.08)' },
          angleLines:  { color: 'rgba(255,255,255,0.08)' },
          pointLabels: { color: '#cbd5e1', font: { size: 11 } },
        },
      },
    },
  });
}

// ── Feature grid builder ──────────────────────────────────────────────────────
function buildFeatureGrid(d) {
  const items = [
    { label: 'Length',         value: d.password_length,          icon: 'fas fa-ruler-horizontal' },
    { label: 'Uppercase',      value: d.uppercase_count,          icon: 'fas fa-font' },
    { label: 'Lowercase',      value: d.lowercase_count,          icon: 'fas fa-font' },
    { label: 'Digits',         value: d.digit_count,              icon: 'fas fa-hashtag' },
    { label: 'Symbols',        value: d.special_character_count,  icon: 'fas fa-at' },
    { label: 'Unique Chars',   value: d.unique_character_count,   icon: 'fas fa-star' },
    { label: 'Repeated Chars', value: d.repeated_character_count, icon: 'fas fa-sync' },
    { label: 'Entropy (bits)', value: d.entropy,                  icon: 'fas fa-chart-bar' },
    {
      label: 'Char Diversity',
      value: (d.char_diversity * 100).toFixed(0) + '%',
      icon: 'fas fa-th',
    },
    {
      label: 'Sequential',
      value: d.sequential_character_detected ? 'Yes' : 'No',
      icon:  'fas fa-sort-amount-up',
      bad:   d.sequential_character_detected,
    },
    {
      label: 'Dictionary Word',
      value: d.dictionary_word_detected ? 'Yes' : 'No',
      icon:  'fas fa-book',
      bad:   d.dictionary_word_detected,
    },
    {
      label: 'Keyboard Pattern',
      value: d.keyboard_pattern_detected ? 'Yes' : 'No',
      icon:  'fas fa-keyboard',
      bad:   d.keyboard_pattern_detected,
    },
  ];

  const container = document.getElementById('featureSummary');
  if (!container) return;
  container.innerHTML = items.map(item => `
    <div class="feature-item ${item.bad ? 'feature-item--bad' : ''}">
      <i class="${item.icon} feature-item-icon text-accent"></i>
      <div>
        <div class="feature-item-label">${item.label}</div>
        <div class="feature-item-value ${item.bad === true ? 'text-warning' : ''}">${item.value}</div>
      </div>
    </div>
  `).join('');
}

// ── AI Findings renderer ──────────────────────────────────────────────────────
function buildFindings(findings) {
  const container = document.getElementById('findingsList');
  if (!container) return;

  if (!findings || findings.length === 0) {
    container.innerHTML = '<p class="text-muted small">No findings generated.</p>';
    return;
  }

  // severity → Bootstrap alert class
  const cls = { danger: 'alert-danger', warning: 'alert-warning',
                info:   'alert-info',   success: 'alert-success' };

  container.innerHTML = findings.map(f => `
    <div class="finding-item alert ${cls[f.severity] || 'alert-info'}" role="alert">
      <i class="${f.icon} me-2"></i>${f.text}
    </div>
  `).join('');
}

// ── KPI card updater ──────────────────────────────────────────────────────────
function updateKpiCards(d) {
  const scoreEl    = document.getElementById('kpiScore');
  const strengthEl = document.getElementById('kpiStrength');
  const threatEl   = document.getElementById('kpiThreat');
  const entropyEl  = document.getElementById('kpiEntropy');
  const crackEl    = document.getElementById('kpiCrack');
  const crackOnEl  = document.getElementById('kpiCrackOnline');

  if (scoreEl) {
    scoreEl.textContent = d.strength_score + '/100';
    scoreEl.className = 'kpi-value';
    const col = STRENGTH_COLOUR[d.strength_category] || '#00e5ff';
    scoreEl.style.color = col;
  }
  if (strengthEl) {
    strengthEl.textContent = d.strength_category;
    strengthEl.style.color = STRENGTH_COLOUR[d.strength_category] || '#00e5ff';
  }
  if (threatEl) {
    threatEl.textContent = d.threat_level;
    threatEl.style.color = THREAT_COLOUR_MAP[d.threat_level] || '#00e5ff';
  }
  if (entropyEl) entropyEl.textContent = d.entropy + ' bits';
  if (crackEl)   crackEl.textContent   = d.crack_time;
  if (crackOnEl) crackOnEl.textContent = d.crack_time_online;
}

// ── Crack-time panel updater ──────────────────────────────────────────────────
function updateCrackPanel(d) {
  const off  = document.getElementById('ctOffline');
  const on   = document.getElementById('ctOnline');
  const comb = document.getElementById('ctCombos');
  if (off)  off.textContent  = d.crack_time;
  if (on)   on.textContent   = d.crack_time_online;
  if (comb) comb.textContent = d.crack_time_combinations;
}

// ── Live strength bar under input ────────────────────────────────────────────
function updateStrengthBar(score, category) {
  const fill  = document.getElementById('strengthBarFill');
  const label = document.getElementById('strengthBarLabel');
  if (!fill) return;

  const col = STRENGTH_COLOUR[category] || '#00e5ff';
  fill.style.width      = score + '%';
  fill.style.background = col;
  if (label) {
    label.textContent  = category ? `Strength: ${category} (${score}/100)` : '';
    label.style.color  = col;
  }
}

// ── Score gauge text ──────────────────────────────────────────────────────────
function updateGaugeText(score, category) {
  const el = document.getElementById('gaugeScoreText');
  if (el) {
    el.textContent = score;
    el.style.color = STRENGTH_COLOUR[category] || '#00e5ff';
  }
  const badge = document.getElementById('strengthBadge');
  if (badge) {
    badge.textContent = category;
    badge.className   = `badge fs-6 px-3 py-2 ${STRENGTH_BG[category] || 'bg-secondary'}`;
  }
}

// ── Breach Detection panel ───────────────────────────────────────────────────
function buildBreachPanel(d) {
  const alertDiv = document.getElementById('breachAlert');
  const safeDiv  = document.getElementById('breachSafe');
  if (!alertDiv || !safeDiv) return;

  // Risk level → colour class
  const riskColour = {
    'Critical': 'text-danger',
    'High':     'text-warning',
    'Medium':   'text-info',
    'Low':      'text-primary',
    'Safe':     'text-success',
  };

  // AI recommendation text keyed on risk level
  const recommendations = {
    'Critical': 'This password is one of the most commonly leaked passwords in the world. '
              + 'Change it immediately on every service where it is used.',
    'High':     'This password appears frequently in breach databases. '
              + 'Replace it with a unique, randomly generated password right away.',
    'Medium':   'This password has been exposed in a known data breach. '
              + 'Update it as soon as possible and enable two-factor authentication.',
    'Low':      'This password was found in a breach dataset. '
              + 'It is less common but still compromised — update it to stay safe.',
  };

  if (d.is_breached) {
    // Show the red breach alert, hide the safe panel
    alertDiv.classList.remove('d-none');
    safeDiv.classList.add('d-none');

    // Risk value with colour
    const riskEl = document.getElementById('breachRiskValue');
    if (riskEl) {
      riskEl.textContent  = d.breach_risk || '—';
      riskEl.className    = 'breach-meta-value fw-bold ' + (riskColour[d.breach_risk] || 'text-danger');
    }

    // Source
    const srcEl = document.getElementById('breachSourceValue');
    if (srcEl) srcEl.textContent = d.breach_source || '—';

    // AI Recommendation
    const recEl = document.getElementById('breachRecommendation');
    if (recEl) recEl.textContent = recommendations[d.breach_risk] || recommendations['Low'];

  } else {
    // Show the green safe message, hide the breach alert
    safeDiv.classList.remove('d-none');
    alertDiv.classList.add('d-none');

    // Source on safe panel
    const srcSafeEl = document.getElementById('breachSourceSafe');
    if (srcSafeEl) srcSafeEl.textContent = d.breach_source || '—';
  }
}

// ── Main entry point ──────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const metaEl   = document.getElementById('analyzerData');
  if (!metaEl) return;

  const analyzeUrl   = metaEl.dataset.analyzeUrl;
  const dashboardUrl = metaEl.dataset.dashboardUrl;

  const pwdInput      = document.getElementById('pwdInput');
  const simulateBtn   = document.getElementById('simulateBtn');
  const clearBtn      = document.getElementById('clearBtn');
  const toggleVisBtn  = document.getElementById('toggleVisBtn');
  const toggleVisIcon = document.getElementById('toggleVisIcon');
  const spinnerWrap   = document.getElementById('spinnerWrap');
  const errorBanner   = document.getElementById('errorBanner');
  const errorMsg      = document.getElementById('errorMsg');

  // ── Show / hide password toggle ─────────────────────────────────────────
  if (toggleVisBtn && pwdInput) {
    toggleVisBtn.addEventListener('click', () => {
      const isHidden = pwdInput.type === 'password';
      pwdInput.type = isHidden ? 'text' : 'password';
      if (toggleVisIcon) {
        toggleVisIcon.className = isHidden ? 'fas fa-eye-slash' : 'fas fa-eye';
      }
    });
  }

  // ── Clear button ─────────────────────────────────────────────────────────
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (pwdInput) pwdInput.value = '';
      updateStrengthBar(0, '');
      document.getElementById('resultsSection')?.classList.add('d-none');
      document.getElementById('kpiPanel')?.classList.add('d-none');
      document.getElementById('kpiPlaceholder')?.classList.remove('d-none');
      document.getElementById('breachAlert')?.classList.add('d-none');
      document.getElementById('breachSafe')?.classList.add('d-none');
      errorBanner?.classList.add('d-none');
    });
  }

  // ── Live strength bar as user types ─────────────────────────────────────
  if (pwdInput) {
    pwdInput.addEventListener('input', () => {
      const pw = pwdInput.value;
      if (!pw) { updateStrengthBar(0, ''); return; }

      // Simple client-side score for instant feedback (no server round-trip)
      let s = 0;
      s += Math.min(30, pw.length * 2.2);
      s += /[A-Z]/.test(pw) ? 10 : 0;
      s += /[0-9]/.test(pw) ? 10 : 0;
      s += /[^A-Za-z0-9]/.test(pw) ? 15 : 0;
      s = Math.min(100, Math.round(s));

      let cat = 'Very Weak';
      if (s >= 85) cat = 'Excellent';
      else if (s >= 70) cat = 'Strong';
      else if (s >= 50) cat = 'Moderate';
      else if (s >= 30) cat = 'Weak';

      updateStrengthBar(s, cat);
    });

    // Allow Enter key to trigger analysis
    pwdInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') simulateBtn?.click();
    });
  }

  // ── Simulate button ───────────────────────────────────────────────────────
  if (simulateBtn) {
    simulateBtn.addEventListener('click', async () => {
      const password = pwdInput?.value?.trim() || '';
      if (!password) {
        errorMsg.textContent = 'Please enter a password to analyse.';
        errorBanner.classList.remove('d-none');
        return;
      }

      errorBanner.classList.add('d-none');
      simulateBtn.disabled = true;
      spinnerWrap?.classList.remove('d-none');

      try {
        const resp = await fetch(analyzeUrl, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({
            password:     password,
            complexity:   document.getElementById('complexitySelect')?.value  || 'Standard',
            threat_model: document.getElementById('threatModelSelect')?.value || 'Consumer',
          }),
        });

        if (!resp.ok) {
          const err = await resp.json().catch(() => ({}));
          throw new Error(err.error || `Server error ${resp.status}`);
        }

        const d = await resp.json();

        // ── Reveal panels ───────────────────────────────────────────────
        document.getElementById('kpiPanel')?.classList.remove('d-none');
        document.getElementById('kpiPlaceholder')?.classList.add('d-none');
        document.getElementById('resultsSection')?.classList.remove('d-none');

        // ── Populate all widgets ─────────────────────────────────────────
        updateKpiCards(d);
        updateStrengthBar(d.strength_score, d.strength_category);
        buildGaugeChart(d.strength_score, d.strength_category);
        updateGaugeText(d.strength_score, d.strength_category);
        buildFeatureGrid(d);
        buildFindings(d.findings);
        updateCrackPanel(d);
        buildBreachPanel(d);

        // ── Radar chart ──────────────────────────────────────────────────
        buildRadarChart(d);

        // ── Saved banner ─────────────────────────────────────────────────
        const savedLabel = document.getElementById('savedLabel');
        if (savedLabel) savedLabel.textContent = `Record #${d.record_id} · ${d.label}`;

        // ── Refresh dashboard data (background) ──────────────────────────
        refreshDashboardCharts(dashboardUrl);

        // ── Smooth scroll to results ─────────────────────────────────────
        document.getElementById('resultsSection')
          ?.scrollIntoView({ behavior: 'smooth', block: 'start' });

      } catch (err) {
        errorMsg.textContent = err.message || 'Analysis failed. Please try again.';
        errorBanner.classList.remove('d-none');
      } finally {
        simulateBtn.disabled = false;
        spinnerWrap?.classList.add('d-none');
      }
    });
  }
});
