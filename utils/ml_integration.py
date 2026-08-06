"""
utils/ml_integration.py — SecureGuard AI
==========================================

Thin integration layer between the Flask /api/analyze endpoint and the
independent ML + Hybrid Decision Engine pipeline.

This module owns:
  • Loading PasswordPredictionService + HybridDecisionEngine (once each)
  • Calling both in the correct order
  • Full failsafe: any exception → graceful fallback, never propagated
  • Logging every prediction, decision, confidence, and error

The Flask route only calls run_hybrid_pipeline() and receives a plain dict.
It never imports or instantiates ML classes directly.

Public API
----------
run_hybrid_pipeline(password, rule_category, rule_score,
                    threat_level, is_breached)
    → dict  (always returns, never raises)

Returned dict keys
------------------
ml_available     bool    False when ML is unavailable
ml_prediction    str     Strength label from the ML model
ml_confidence    float   ML probability for the predicted class
ml_probabilities dict    Full probability distribution
hybrid_decision  str     Final authoritative strength label
hybrid_agreement bool    True when rule and ML agreed
decision_source  str     Which engine(s) drove the final decision
hybrid_reason    str     Human-readable explanation
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path bootstrap — works regardless of cwd
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Dedicated log file
# ---------------------------------------------------------------------------
_LOG_DIR  = _PROJECT_ROOT / "ml" / "logs"
_LOG_DIR.mkdir(parents=True, exist_ok=True)
_LOG_FILE = _LOG_DIR / "ml_integration.log"

_fmt = logging.Formatter(
    "%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_fh = logging.FileHandler(_LOG_FILE, mode="a", encoding="utf-8")
_fh.setLevel(logging.DEBUG)
_fh.setFormatter(_fmt)

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
if not log.handlers:
    log.addHandler(_fh)

# ---------------------------------------------------------------------------
# Lazy-loaded singletons (never reloaded after first successful import)
# ---------------------------------------------------------------------------
_prediction_service: Any = None
_hybrid_engine:      Any = None
_ml_init_failed:     bool = False   # once True, skip ML on every request


def _ensure_services_loaded() -> bool:
    """
    Initialise PasswordPredictionService and HybridDecisionEngine once.

    Returns True on success, False if either component cannot be loaded.
    Sets _ml_init_failed=True on first failure so subsequent requests skip
    the ML pipeline without repeated disk I/O or error spam.
    """
    global _prediction_service, _hybrid_engine, _ml_init_failed

    if _ml_init_failed:
        return False

    if _prediction_service is not None and _hybrid_engine is not None:
        return True   # already loaded

    try:
        from ml.prediction_service import PasswordPredictionService
        from ml.hybrid_engine import HybridDecisionEngine

        if _prediction_service is None:
            _prediction_service = PasswordPredictionService()
            log.info("PasswordPredictionService loaded successfully.")

        if _hybrid_engine is None:
            _hybrid_engine = HybridDecisionEngine()
            log.info("HybridDecisionEngine loaded successfully.")

        return True

    except Exception as exc:
        _ml_init_failed = True
        log.error(
            "ML services failed to initialise — fallback mode active.  Error: %s",
            exc, exc_info=True,
        )
        return False


# ---------------------------------------------------------------------------
# Fallback payload
# ---------------------------------------------------------------------------

def _fallback_payload(rule_category: str, reason: str) -> dict[str, Any]:
    """Return a graceful fallback payload when ML is unavailable."""
    return {
        "ml_available":     False,
        "ml_prediction":    rule_category,
        "ml_confidence":    0.0,
        "ml_probabilities": {},
        "hybrid_decision":  rule_category,
        "hybrid_agreement": False,
        "decision_source":  "Rule Engine",
        "hybrid_reason":    reason,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_hybrid_pipeline(
    password:      str,
    rule_category: str,
    rule_score:    int,
    threat_level:  str,
    is_breached:   bool,
) -> dict[str, Any]:
    """
    Run the full ML + Hybrid Decision pipeline for one password.

    This function is the only public entry point for the Flask route.
    It NEVER raises — all exceptions produce a graceful fallback payload
    so the existing analyzer continues to work even if ML is unavailable.

    Parameters
    ----------
    password      : str   Plaintext password (used only for feature extraction;
                          never logged or stored by this function).
    rule_category : str   Strength label from the deterministic rule engine.
    rule_score    : int   Numeric score (0–100) from the rule engine.
    threat_level  : str   Threat label from the vulnerability predictor.
    is_breached   : bool  True if the password is in a breach dataset.

    Returns
    -------
    dict with keys:
        ml_available, ml_prediction, ml_confidence, ml_probabilities,
        hybrid_decision, hybrid_agreement, decision_source, hybrid_reason.
    """
    log.info(
        "run_hybrid_pipeline  rule_category=%s  rule_score=%d  "
        "threat=%s  breached=%s",
        rule_category, rule_score, threat_level, is_breached,
    )

    # ── Step 1: ensure services are loaded ────────────────────────────────
    if not _ensure_services_loaded():
        log.warning("ML unavailable — returning rule-engine fallback.")
        return _fallback_payload(
            rule_category,
            "Machine Learning temporarily unavailable. "
            "Rule Engine result used.",
        )

    # ── Step 2: build feature vector and run ML prediction ────────────────
    try:
        from ml.feature_builder import build_features
        features = build_features(password)
        ml_result = _prediction_service.predict(features)

        log.info(
            "ML prediction  label=%s  confidence=%.4f  time=%.1f ms",
            ml_result.prediction, ml_result.confidence,
            ml_result.inference_time_ms,
        )
    except Exception as exc:
        log.error("ML prediction failed: %s", exc, exc_info=True)
        return _fallback_payload(
            rule_category,
            f"Machine Learning temporarily unavailable ({type(exc).__name__}). "
            "Rule Engine result used.",
        )

    # ── Step 3: run hybrid decision engine ────────────────────────────────
    try:
        from ml.hybrid_engine import DecisionInputs

        inputs = DecisionInputs(
            rule_category    = rule_category,
            rule_score       = rule_score,
            threat_level     = threat_level,
            ml_prediction    = ml_result.prediction,
            ml_confidence    = ml_result.confidence,
            ml_probabilities = ml_result.probabilities,
            is_breached      = is_breached,
        )
        decision = _hybrid_engine.decide(inputs)

        log.info(
            "Hybrid decision  final=%s  source=%s  agreement=%s  "
            "reason=%.80s",
            decision.final_category,
            decision.decision_source,
            decision.agreement,
            decision.reason,
        )
    except Exception as exc:
        log.error("Hybrid engine failed: %s", exc, exc_info=True)
        # ML worked but hybrid failed → return ML result directly
        return {
            "ml_available":     True,
            "ml_prediction":    ml_result.prediction,
            "ml_confidence":    ml_result.confidence,
            "ml_probabilities": ml_result.probabilities,
            "hybrid_decision":  ml_result.prediction,
            "hybrid_agreement": ml_result.prediction == rule_category,
            "decision_source":  "Machine Learning",
            "hybrid_reason":    (
                f"Hybrid engine error ({type(exc).__name__}) — "
                "ML prediction used directly."
            ),
        }

    # ── Step 4: assemble and return ───────────────────────────────────────
    return {
        "ml_available":     True,
        "ml_prediction":    ml_result.prediction,
        "ml_confidence":    round(ml_result.confidence, 4),
        "ml_probabilities": {k: round(v, 4) for k, v in ml_result.probabilities.items()},
        "hybrid_decision":  decision.final_category,
        "hybrid_agreement": decision.agreement,
        "decision_source":  decision.decision_source,
        "hybrid_reason":    decision.reason,
    }
