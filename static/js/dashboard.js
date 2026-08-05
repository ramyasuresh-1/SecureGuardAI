/**
 * dashboard.js — SecureGuard AI
 *
 * Fetches all chart data from /api/charts/all (live SQLite) and renders
 * five Chart.js charts.  Counter animations run from the data-count
 * attributes already written by Jinja2 into the DOM.
 */

'use strict';

// ---------------------------------------------------------------------------
// Shared Chart.js defaults
// ---------------------------------------------------------------------------

Chart.defaults.color = '#cbd5e1';
Chart.defaults.borderColor = 'rgba(255,255,255,0.08)';
Chart.defaults.font.family = 'Poppins, sans-serif';

const TOOLTIP_DEFAULTS = {
  backgroundColor: 'rgba(15,23,42,0.92)',
  titleColor: '#00e5ff',
  bodyColor: '#f8fafc',
  borderColor: 'rgba(0,229,255,0.25)',
  borderWidth: 1,
  padding: 12,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a vertical linear gradient for area charts.
 * @param {CanvasRenderingContext2D} ctx
 * @param {string} colorTop   rgba string with opacity
 * @param {string} colorBot   rgba string with opacity
 */
function makeGradient(ctx, colorTop, colorBot) {
  const grad = ctx.createLinearGradient(0, 0, 0, 400);
  grad.addColorStop(0, colorTop);
  grad.addColorStop(1, colorBot);
  return grad;
}

/**
 * Animate integer counter from 0 → target.
 * Expects elements with class `card-value` and `data-count` attribute.
 */
function animateCounters() {
  document.querySelectorAll('.card-value[data-count]').forEach((el) => {
    const target = Number(el.getAttribute('data-count'));
    if (Number.isNaN(target) || target === 0) { el.textContent = el.textContent || '0'; return; }
    let current = 0;
    const steps = 50;
    const inc = target / steps;
    const delay = 1200 / steps;   // finish in ~1.2 s
    const tick = () => {
      current += inc;
      if (current < target) {
        el.textContent = Math.ceil(current);
        setTimeout(tick, delay);
      } else {
        el.textContent = target;
      }
    };
    setTimeout(tick, 150);
  });
}

// ---------------------------------------------------------------------------
// Empty-state helper — renders a centred message when data is all zeros
// ---------------------------------------------------------------------------

function isEmpty(arr) {
  return !arr || arr.every((v) => v === 0);
}

function showEmpty(canvasId, message = 'No data yet — analyse a password to populate this chart.') {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  // Write centred placeholder text
  ctx.save();
  ctx.fillStyle = 'rgba(203,213,225,0.35)';
  ctx.font = '13px Poppins, sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(message, canvas.width / 2, canvas.height / 2);
  ctx.restore();
}

// ---------------------------------------------------------------------------
// Chart builders
// ---------------------------------------------------------------------------

function buildDailyTrendChart(payload) {
  const canvas = document.getElementById('dailyTrendChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  if (isEmpty(payload.data)) { showEmpty('dailyTrendChart'); return; }

  new Chart(ctx, {
    type: 'line',
    data: {
      labels: payload.labels,
      datasets: [{
        label: 'Analyses',
        data: payload.data,
        borderColor: '#00e5ff',
        backgroundColor: makeGradient(ctx, 'rgba(0,229,255,0.30)', 'rgba(0,229,255,0.03)'),
        borderWidth: 2.5,
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointBackgroundColor: '#00e5ff',
        pointBorderColor: '#0f172a',
        pointBorderWidth: 2,
        pointHoverRadius: 6,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          ...TOOLTIP_DEFAULTS,
          displayColors: false,
          callbacks: { label: (c) => `${c.parsed.y} analyses` },
        },
      },
      scales: {
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(255,255,255,0.05)', drawBorder: false },
          ticks: { padding: 8, precision: 0 },
        },
        x: {
          grid: { display: false },
          ticks: {
            padding: 8,
            maxTicksLimit: 10,
            maxRotation: 0,
          },
        },
      },
    },
  });
}

function buildStrengthPieChart(payload) {
  const canvas = document.getElementById('strengthPieChart');
  if (!canvas) return;

  if (isEmpty(payload.data)) { showEmpty('strengthPieChart'); return; }

  new Chart(canvas, {
    type: 'pie',
    data: {
      labels: payload.labels,           // ['Weak','Moderate','Strong','Excellent']
      datasets: [{
        data: payload.data,
        backgroundColor: ['#ef4444', '#f59e0b', '#2ecc71', '#00e5ff'],
        borderWidth: 0,
        hoverOffset: 12,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: true,
          position: 'bottom',
          labels: { padding: 14, usePointStyle: true, font: { size: 11 } },
        },
        tooltip: {
          ...TOOLTIP_DEFAULTS,
          callbacks: {
            label: (c) => {
              const total = c.dataset.data.reduce((a, b) => a + b, 0);
              const pct = total ? ((c.parsed / total) * 100).toFixed(1) : 0;
              return `${c.label}: ${c.parsed} (${pct}%)`;
            },
          },
        },
      },
    },
  });
}

function buildScoreBarChart(payload) {
  const canvas = document.getElementById('scoreBarChart');
  if (!canvas) return;

  if (isEmpty(payload.data)) { showEmpty('scoreBarChart'); return; }

  new Chart(canvas, {
    type: 'bar',
    data: {
      labels: payload.labels,           // ['0-20','21-40','41-60','61-80','81-100']
      datasets: [{
        label: 'Passwords',
        data: payload.data,
        backgroundColor: [
          'rgba(239,68,68,0.85)',
          'rgba(245,158,11,0.85)',
          'rgba(59,130,246,0.85)',
          'rgba(124,77,255,0.85)',
          'rgba(0,229,255,0.85)',
        ],
        borderRadius: 8,
        borderSkipped: false,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          ...TOOLTIP_DEFAULTS,
          callbacks: { label: (c) => `${c.parsed.y} passwords` },
        },
      },
      scales: {
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(255,255,255,0.05)', drawBorder: false },
          ticks: { padding: 8, precision: 0 },
        },
        x: { grid: { display: false }, ticks: { padding: 8 } },
      },
    },
  });
}

function buildThreatDoughnutChart(payload) {
  const canvas = document.getElementById('threatDoughnutChart');
  if (!canvas) return;

  if (isEmpty(payload.data)) { showEmpty('threatDoughnutChart'); return; }

  new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: payload.labels,
      datasets: [{
        data: payload.data,
        backgroundColor: ['#ef4444', '#dc2626', '#f59e0b', '#eab308', '#fb923c'],
        borderWidth: 0,
        hoverOffset: 10,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '65%',
      plugins: {
        legend: {
          display: true,
          position: 'right',
          labels: { padding: 12, usePointStyle: true, font: { size: 11 } },
        },
        tooltip: {
          ...TOOLTIP_DEFAULTS,
          callbacks: { label: (c) => `${c.label}: ${c.parsed}` },
        },
      },
    },
  });
}

function buildCompositionRadarChart(payload) {
  const canvas = document.getElementById('compositionRadarChart');
  if (!canvas) return;

  if (isEmpty(payload.actual)) { showEmpty('compositionRadarChart'); return; }

  new Chart(canvas, {
    type: 'radar',
    data: {
      labels: payload.labels,
      datasets: [
        {
          label: 'Your Passwords',
          data: payload.actual,
          borderColor: '#00e5ff',
          backgroundColor: 'rgba(0,229,255,0.18)',
          borderWidth: 2,
          pointBackgroundColor: '#00e5ff',
          pointBorderColor: '#0f172a',
          pointBorderWidth: 2,
          pointRadius: 5,
          pointHoverRadius: 7,
        },
        {
          label: 'Recommended',
          data: payload.recommended,
          borderColor: '#7c4dff',
          backgroundColor: 'rgba(124,77,255,0.08)',
          borderWidth: 2,
          borderDash: [5, 5],
          pointBackgroundColor: '#7c4dff',
          pointBorderColor: '#0f172a',
          pointBorderWidth: 2,
          pointRadius: 4,
          pointHoverRadius: 6,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: true,
          position: 'top',
          labels: { padding: 14, usePointStyle: true },
        },
        tooltip: { ...TOOLTIP_DEFAULTS },
      },
      scales: {
        r: {
          beginAtZero: true,
          max: 100,
          ticks: { stepSize: 20, backdropColor: 'transparent', font: { size: 10 } },
          grid: { color: 'rgba(255,255,255,0.08)' },
          angleLines: { color: 'rgba(255,255,255,0.08)' },
          pointLabels: { color: '#cbd5e1', font: { size: 11 } },
        },
      },
    },
  });
}

// ---------------------------------------------------------------------------
// Main initialisation
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {

  // 1. Animate counters (data already in DOM from Jinja2 data-count attrs)
  animateCounters();

  // 2. Resolve the API URL from the hidden data element written by Jinja2.
  //    This keeps all URL generation server-side and avoids hard-coding paths.
  const dataEl = document.getElementById('dashboard-data');
  if (!dataEl) return;
  const chartsUrl = dataEl.dataset.chartsUrl;

  // 3. Fetch all chart data in a single request, then render each chart.
  fetch(chartsUrl, { credentials: 'same-origin' })
    .then((res) => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    })
    .then((data) => {
      buildDailyTrendChart(data.daily_trend);
      buildStrengthPieChart(data.strength_pie);
      buildScoreBarChart(data.score_dist);
      buildThreatDoughnutChart(data.threat_categories);
      buildCompositionRadarChart(data.composition_radar);
    })
    .catch((err) => {
      console.error('[SecureGuard] Chart data fetch failed:', err);
      // Show graceful empty states for all charts
      ['dailyTrendChart', 'strengthPieChart', 'scoreBarChart',
        'threatDoughnutChart', 'compositionRadarChart'].forEach((id) => {
        showEmpty(id, 'Could not load chart data.');
      });
    });

  // 4. Search box focus effect
  const searchInput = document.querySelector('.search-box input');
  if (searchInput) {
    searchInput.addEventListener('focus', () => {
      searchInput.closest('.input-group').style.boxShadow = '0 0 0 0.2rem rgba(0,229,255,0.18)';
    });
    searchInput.addEventListener('blur', () => {
      searchInput.closest('.input-group').style.boxShadow = '';
    });
  }

  // 5. Intersection observer — subtle entrance animation for cards / panels
  const observer = new IntersectionObserver(
    (entries) => entries.forEach((e) => {
      if (e.isIntersecting) e.target.classList.add('card-visible');
    }),
    { threshold: 0.08 }
  );
  document.querySelectorAll('.dashboard-card, .glass-card').forEach((el) => observer.observe(el));
});
