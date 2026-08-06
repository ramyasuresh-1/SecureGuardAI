/**
 * coach.js — SecureGuard AI Security Coach
 *
 * Responsibilities:
 *   • Animate the health score counter
 *   • Progress bar entrance animations
 *   • Achievement card hover / unlock effects
 *   • Smooth accordion Q&A transitions
 *   • Attack card status pulse
 */

'use strict';

// ── Counter animation ─────────────────────────────────────────────────────────
function animateScore(el, target) {
  let current  = 0;
  const steps  = 60;
  const delay  = 20;
  const inc    = target / steps;
  const tick   = () => {
    current += inc;
    if (current < target) {
      el.textContent = Math.round(current);
      setTimeout(tick, delay);
    } else {
      el.textContent = target;
    }
  };
  setTimeout(tick, 400);
}

// ── Progress bars — animate width from 0 on first scroll into view ────────────
function animateProgressBars() {
  const bars = document.querySelectorAll('.progress-bar');
  if (!bars.length) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      const bar = entry.target;
      const target = bar.style.width;
      bar.style.width = '0%';
      setTimeout(() => { bar.style.width = target; }, 100);
      observer.unobserve(bar);
    });
  }, { threshold: 0.1 });

  bars.forEach(bar => {
    bar.style.transition = 'width 0.9s ease';
    observer.observe(bar);
  });
}

// ── Achievement cards — add glow on unlock ─────────────────────────────────────
function initAchievements() {
  document.querySelectorAll('.coach-achievement-card:not(.coach-achievement-locked)')
    .forEach(card => {
      card.addEventListener('mouseenter', () => {
        card.style.boxShadow = '0 0 18px rgba(0, 229, 255, 0.25)';
      });
      card.addEventListener('mouseleave', () => {
        card.style.boxShadow = '';
      });
    });
}

// ── Attack card status pulse ───────────────────────────────────────────────────
function initAttackCards() {
  document.querySelectorAll('.coach-attack-card').forEach(card => {
    const statusEl = card.querySelector('.text-danger');
    if (statusEl) {
      // Add subtle pulse animation to vulnerable indicators
      statusEl.style.animation = 'pulse 2.5s infinite';
    }
  });
}

// ── Q&A accordion — smooth icon flip ──────────────────────────────────────────
function initQnA() {
  document.querySelectorAll('.coach-qna-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const icon = btn.querySelector('.fa-question-circle');
      if (!icon) return;
      // Toggle between question and answer icon
      const isExpanded = btn.getAttribute('aria-expanded') === 'true';
      icon.className = isExpanded
        ? 'fas fa-question-circle text-accent me-2'
        : 'fas fa-check-circle text-success me-2';
    });
  });
}

// ── Weakness card hover ────────────────────────────────────────────────────────
function initWeaknessCards() {
  document.querySelectorAll('.coach-weakness-card').forEach(card => {
    card.addEventListener('mouseenter', () => {
      card.style.transform     = 'translateY(-3px)';
      card.style.borderColor   = 'rgba(0, 229, 255, 0.25)';
      card.style.transition    = 'all 0.25s ease';
    });
    card.addEventListener('mouseleave', () => {
      card.style.transform     = '';
      card.style.borderColor   = '';
    });
  });
}

// ── Entry point ───────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Animate the main health score number
  const scoreEl = document.querySelector('.coach-score-value');
  if (scoreEl) {
    const target = parseFloat(scoreEl.textContent) || 0;
    animateScore(scoreEl, target);
  }

  animateProgressBars();
  initAchievements();
  initAttackCards();
  initQnA();
  initWeaknessCards();
});
