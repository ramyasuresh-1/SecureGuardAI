"""
ml/hybrid_engine.py — SecureGuard AI
=======================================

Enterprise-grade Hybrid AI Decision Engine.

Combines the deterministic Rule Engine output with the probabilistic
Machine Learning prediction into a single, explainable security decision.

Architecture
------------
    Rule Engine output   (category, score, threat level)
          +
    ML Prediction output (category, confidence, probabilities)
          ↓
    HybridDecisionEngine.decide()
          ↓
    HybridDecision   (final_category, source, agreement, reason, …)

Decision rules (applied in priority order)
-------------------------------------------
    R0  Breach guard        — if is_breached AND rule score low,
                              always downgrade; skip all other rules.
    R1  Consensus           — both engines agree → accept unanimously.
    R2  ML high confidence  — ML conf ≥ ML_HIGH_CONFIDENCE → prefer ML.
    R3  Rule low confidence — ML conf < ML_LOW_CONFIDENCE  → prefer Rule.
    R4  Weighted blend      — ML conf in [ML_LOW, ML_HIGH) →
                              RULE_WEIGHT×rule + ML_WEIGHT×ML vote.
    R5  Safety guard        — never upgrade a score that is critically
                              low (rule_score < CRITICAL_SCORE_THRESHOLD)
                              even when ML is highly confident.

Configuration knobs (module-level constants — easy to tune)
------------------------------------------------------------
    ML_HIGH_CONFIDENCE          float   default 0.90
    ML_LOW_CONFIDENCE           float   default 0.70
    RULE_WEIGHT                 float   default 0.60
    ML_WEIGHT                   float   default 0.40
    BREACH_DOWNGRADE_THRESHOLD  str     default "Moderate"
                                        Categories at or above this level
                                        are downgraded when breached.
    CRITICAL_SCORE_THRESHOLD    int     default 20
                                        Rule scores below this prevent
                                        any ML-driven upgrade.

Public API
----------
    HybridDecisionEngine()           # instantiate
    engine.decide(inputs)            # → HybridDecision
    engine.decide_from_password(pw)  # convenience: runs full pipeline

Enums
-----
    SecurityCategory    Very Weak | Weak | Moderate | Strong | Excellent
    DecisionSource      HybridConsensus | RuleEngine | MachineLearning
                        | WeightedDecision | BreachGuard

Dataclasses
-----------
    DecisionInputs      All inputs required by the engine.
    HybridDecision      All outputs produced by the engine.

Exceptions
----------
    HybridEngineError   Base exception for this module.
    InvalidInputError   Bad / missing inputs.

Usage
-----
    from ml.hybrid_engine import HybridDecisionEngine, DecisionInputs

    engine = HybridDecisionEngine()
    inputs = DecisionInputs(
        rule_category  = "Very Weak",
        rule_score     = 22,
        threat_level   = "Critical",
        ml_prediction  = "Weak",
        ml_confidence  = 0.65,
        ml_probabilities = {"Very Weak": 0.35, "Weak": 0.65, ...},
        is_breached    = True,
    )
    decision = engine.decide(inputs)
    print(decision.final_category)    # "Very Weak"
    print(decision.reason)            # "Password found in breach …"
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from ml import LABEL_ORDER, LOGS_DIR

# ---------------------------------------------------------------------------
# Logging — dedicated log file
# ---------------------------------------------------------------------------
LOGS_DIR.mkdir(parents=True, exist_ok=True)
_LOG_FILE: Path = LOGS_DIR / "hybrid_engine.log"

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
# Configuration constants
# ---------------------------------------------------------------------------

#: ML probability threshold above which the ML prediction is trusted
#: exclusively (Rule 2).
ML_HIGH_CONFIDENCE: float = 0.90

#: ML probability threshold below which the Rule Engine is trusted
#: exclusively (Rule 3).
ML_LOW_CONFIDENCE: float = 0.70

#: Weight given to the Rule Engine in a weighted blend (Rule 4).
RULE_WEIGHT: float = 0.60

#: Weight given to the ML prediction in a weighted blend (Rule 4).
ML_WEIGHT: float = 0.40

#: Categories at or above this level that are downgraded when the password
#: appears in a breach dataset.
BREACH_DOWNGRADE_THRESHOLD: str = "Moderate"

#: Rule scores strictly below this value prevent any ML-driven upgrade
#: (Rule 5 safety guard).
CRITICAL_SCORE_THRESHOLD: int = 20

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class SecurityCategory(str, Enum):
    """
    Ordered strength tiers.  The integer value enables arithmetic comparison
    (higher = stronger).
    """
    VERY_WEAK  = "Very Weak"
    WEAK       = "Weak"
    MODERATE   = "Moderate"
    STRONG     = "Strong"
    EXCELLENT  = "Excellent"

    @classmethod
    def from_label(cls, label: str) -> "SecurityCategory":
        """
        Parse a string label (case-insensitive) into a SecurityCategory.

        Raises
        ------
        ValueError  If *label* does not match any tier.
        """
        for member in cls:
            if member.value.lower() == label.strip().lower():
                return member
        valid = [m.value for m in cls]
        raise ValueError(
            f"Unknown security category {label!r}. "
            f"Valid values: {valid}"
        )

    def rank(self) -> int:
        """Return the 0-based strength rank (Very Weak=0 … Excellent=4)."""
        return list(SecurityCategory).index(self)

    def downgrade(self) -> "SecurityCategory":
        """Return the next weaker category, or self if already Very Weak."""
        rank = self.rank()
        if rank == 0:
            return self
        return list(SecurityCategory)[rank - 1]

    def upgrade(self) -> "SecurityCategory":
        """Return the next stronger category, or self if already Excellent."""
        members = list(SecurityCategory)
        rank    = self.rank()
        if rank == len(members) - 1:
            return self
        return members[rank + 1]


class DecisionSource(str, Enum):
    """Identifies which component(s) produced the final decision."""

    HYBRID_CONSENSUS  = "Hybrid Consensus"
    RULE_ENGINE       = "Rule Engine"
    MACHINE_LEARNING  = "Machine Learning"
    WEIGHTED_DECISION = "Weighted Decision"
    BREACH_GUARD      = "Breach Guard"


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class HybridEngineError(RuntimeError):
    """Base exception for all errors raised by HybridDecisionEngine."""


class InvalidInputError(HybridEngineError):
    """Raised when required input fields are missing or contain invalid values."""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DecisionInputs:
    """
    All inputs required by the Hybrid Decision Engine.

    Attributes
    ----------
    rule_category    : str    Strength label from the rule engine.
    rule_score       : int    Numeric score (0–100) from the rule engine.
    threat_level     : str    Threat label from the vulnerability predictor.
    ml_prediction    : str    Strength label from the ML model.
    ml_confidence    : float  Probability of the ML prediction (0–1).
    ml_probabilities : dict   Full probability distribution over all classes.
    is_breached      : bool   True if the password is in a breach dataset.
    """

    rule_category:    str
    rule_score:       int
    threat_level:     str
    ml_prediction:    str
    ml_confidence:    float
    ml_probabilities: dict[str, float]   = field(default_factory=dict)
    is_breached:      bool               = False

    def validate(self) -> None:
        """
        Raise InvalidInputError if any field is out of range or unrecognised.
        """
        # rule_category
        try:
            SecurityCategory.from_label(self.rule_category)
        except ValueError as exc:
            raise InvalidInputError(str(exc)) from exc

        # rule_score
        if not (0 <= self.rule_score <= 100):
            raise InvalidInputError(
                f"rule_score must be 0–100, got {self.rule_score}."
            )

        # ml_prediction
        try:
            SecurityCategory.from_label(self.ml_prediction)
        except ValueError as exc:
            raise InvalidInputError(str(exc)) from exc

        # ml_confidence
        if not (0.0 <= self.ml_confidence <= 1.0):
            raise InvalidInputError(
                f"ml_confidence must be 0.0–1.0, got {self.ml_confidence}."
            )


@dataclass
class HybridDecision:
    """
    Full output of the Hybrid Decision Engine.

    Attributes
    ----------
    rule_category      : str   Original rule-engine category.
    rule_score         : int   Original rule-engine score.
    ml_prediction      : str   Original ML prediction.
    ml_confidence      : float Original ML confidence.
    agreement          : bool  True when both engines produced the same label.
    decision_source    : str   Which component(s) drove the final decision.
    final_category     : str   The authoritative strength label.
    reason             : str   Human-readable explanation.
    is_breached        : bool  Whether the password is known to be breached.
    decision_timestamp : str   ISO 8601 UTC timestamp of the decision.
    """

    rule_category:      str
    rule_score:         int
    ml_prediction:      str
    ml_confidence:      float
    agreement:          bool
    decision_source:    str
    final_category:     str
    reason:             str
    is_breached:        bool   = False
    decision_timestamp: str    = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of this decision."""
        return {
            "rule_category":      self.rule_category,
            "rule_score":         self.rule_score,
            "ml_prediction":      self.ml_prediction,
            "ml_confidence":      round(self.ml_confidence, 4),
            "agreement":          self.agreement,
            "decision_source":    self.decision_source,
            "final_category":     self.final_category,
            "reason":             self.reason,
            "is_breached":        self.is_breached,
            "decision_timestamp": self.decision_timestamp,
        }

    def __repr__(self) -> str:
        return (
            f"HybridDecision("
            f"final={self.final_category!r}, "
            f"source={self.decision_source!r}, "
            f"agree={self.agreement}, "
            f"breached={self.is_breached})"
        )


# ---------------------------------------------------------------------------
# Hybrid Decision Engine
# ---------------------------------------------------------------------------

class HybridDecisionEngine:
    """
    Combines Rule Engine and ML Prediction into an explainable decision.

    The engine is stateless — all state lives in the ``DecisionInputs``
    object passed to ``decide()``.  The same engine instance can be reused
    across thousands of requests.

    Decision rules (applied in priority order)
    -------------------------------------------
    R0  Breach guard        — always downgrade if breached and score low.
    R1  Consensus           — both agree → Hybrid Consensus.
    R2  ML high confidence  — ML conf ≥ ML_HIGH_CONFIDENCE → trust ML.
    R3  Rule low confidence — ML conf < ML_LOW_CONFIDENCE  → trust Rule.
    R4  Weighted blend      — 60/40 vote determines winner.
    R5  Safety guard        — no upgrade when rule_score < threshold.
    """

    # ── Category rank lookup (faster than calling .rank() repeatedly) ─────
    _RANK: dict[str, int] = {
        cat.value: idx for idx, cat in enumerate(SecurityCategory)
    }

    # ── Ordered list for rank-to-label conversion ─────────────────────────
    _LABELS: list[str] = [cat.value for cat in SecurityCategory]

    def __init__(self) -> None:
        log.info(
            "HybridDecisionEngine initialised  "
            "ML_HIGH=%.2f  ML_LOW=%.2f  "
            "rule_w=%.2f  ml_w=%.2f  "
            "breach_threshold=%s  critical_score=%d",
            ML_HIGH_CONFIDENCE, ML_LOW_CONFIDENCE,
            RULE_WEIGHT, ML_WEIGHT,
            BREACH_DOWNGRADE_THRESHOLD, CRITICAL_SCORE_THRESHOLD,
        )

    # ──────────────────────────────────────────────────────────────────────
    # Public entry points
    # ──────────────────────────────────────────────────────────────────────

    def decide(self, inputs: DecisionInputs) -> HybridDecision:
        """
        Run the full hybrid decision pipeline on pre-validated inputs.

        Parameters
        ----------
        inputs : DecisionInputs
            Rule-engine output + ML output for one password.

        Returns
        -------
        HybridDecision

        Raises
        ------
        InvalidInputError   If inputs fail field-level validation.
        HybridEngineError   On any unexpected internal error.
        """
        log.info(
            "decide() ▶  rule=%-12s score=%-3d  ml=%-12s conf=%.2f  breached=%s",
            inputs.rule_category, inputs.rule_score,
            inputs.ml_prediction, inputs.ml_confidence,
            inputs.is_breached,
        )

        # ── Validate inputs ───────────────────────────────────────────────
        try:
            inputs.validate()
        except InvalidInputError:
            raise
        except Exception as exc:
            raise HybridEngineError(f"Unexpected validation error: {exc}") from exc

        # Parse to enums (guaranteed valid after validate())
        rule_cat = SecurityCategory.from_label(inputs.rule_category)
        ml_cat   = SecurityCategory.from_label(inputs.ml_prediction)
        agreement = (rule_cat == ml_cat)

        # ── Apply rules in priority order ─────────────────────────────────
        decision = (
            self._rule_breach_guard(inputs, rule_cat, agreement)
            or self._rule_consensus(inputs, rule_cat, ml_cat, agreement)
            or self._rule_ml_high_confidence(inputs, rule_cat, ml_cat, agreement)
            or self._rule_low_confidence(inputs, rule_cat, ml_cat, agreement)
            or self._rule_weighted_blend(inputs, rule_cat, ml_cat, agreement)
        )

        # Defensive — should never be None after the weighted blend fallback
        if decision is None:
            raise HybridEngineError("Decision engine produced no output — internal error.")

        # ── R5: safety guard (post-process) ──────────────────────────────
        decision = self._apply_safety_guard(decision, inputs)

        log.info(
            "decide() ◀  final=%-12s source=%-20s agree=%s  reason=%r",
            decision.final_category, decision.decision_source,
            decision.agreement, decision.reason[:60],
        )
        return decision

    def decide_from_password(self, password: str) -> HybridDecision:
        """
        Convenience method: run the full pipeline for a raw password.

        Internally calls:
            1. ``utils.feature_extraction.analyze_password_full``  (rule engine)
            2. ``ml.prediction_service.PasswordPredictionService`` (ML)
            3. ``self.decide()``

        Parameters
        ----------
        password : str  Plaintext password (never stored externally).

        Returns
        -------
        HybridDecision
        """
        from ml.feature_builder import build_features
        from ml.prediction_service import PasswordPredictionService
        from utils.feature_extraction import analyze_password_full

        # Rule engine
        rule_result = analyze_password_full(password)

        # ML prediction
        svc    = PasswordPredictionService()
        feats  = build_features(password)
        ml_res = svc.predict(feats)

        # Assemble inputs
        inp = DecisionInputs(
            rule_category    = rule_result["strength_category"],
            rule_score       = rule_result["strength_score"],
            threat_level     = rule_result.get("threat_level", "Unknown"),
            ml_prediction    = ml_res.prediction,
            ml_confidence    = ml_res.confidence,
            ml_probabilities = ml_res.probabilities,
            is_breached      = rule_result.get("is_breached", False),
        )
        return self.decide(inp)

    # ──────────────────────────────────────────────────────────────────────
    # Private rule implementations
    # ──────────────────────────────────────────────────────────────────────

    def _rule_breach_guard(
        self,
        inputs:    DecisionInputs,
        rule_cat:  SecurityCategory,
        agreement: bool,
    ) -> HybridDecision | None:
        """
        R0 — Breach guard.

        If the password is in a breach dataset AND its score is below
        BREACH_DOWNGRADE_THRESHOLD, force a downgrade and skip all other rules.

        If already at the lowest tier, keep it there.
        """
        if not inputs.is_breached:
            return None

        threshold_cat = SecurityCategory.from_label(BREACH_DOWNGRADE_THRESHOLD)

        # Apply downgrade only when current category is at or above the threshold
        if rule_cat.rank() >= threshold_cat.rank():
            downgraded = rule_cat.downgrade()
            reason = (
                f"Password found in breach dataset. "
                f"Security level downgraded from '{rule_cat.value}' "
                f"to '{downgraded.value}' as a safety measure."
            )
        else:
            # Already below threshold — keep the rule category as-is
            downgraded = rule_cat
            reason = (
                f"Password found in breach dataset. "
                f"Category remains '{rule_cat.value}' "
                f"(already below downgrade threshold)."
            )

        log.debug("R0 Breach Guard applied  %s → %s", rule_cat.value, downgraded.value)
        return HybridDecision(
            rule_category   = inputs.rule_category,
            rule_score      = inputs.rule_score,
            ml_prediction   = inputs.ml_prediction,
            ml_confidence   = inputs.ml_confidence,
            agreement       = agreement,
            decision_source = DecisionSource.BREACH_GUARD.value,
            final_category  = downgraded.value,
            reason          = reason,
            is_breached     = True,
        )

    def _rule_consensus(
        self,
        inputs:    DecisionInputs,
        rule_cat:  SecurityCategory,
        ml_cat:    SecurityCategory,
        agreement: bool,
    ) -> HybridDecision | None:
        """
        R1 — Consensus.

        When both engines independently arrive at the same category,
        the decision is accepted with high confidence and no arbitration
        is needed.
        """
        if not agreement:
            return None

        reason = (
            f"Both the Rule Engine and Machine Learning model agree: "
            f"'{rule_cat.value}'. Hybrid consensus reached."
        )
        log.debug("R1 Consensus: %s", rule_cat.value)
        return HybridDecision(
            rule_category   = inputs.rule_category,
            rule_score      = inputs.rule_score,
            ml_prediction   = inputs.ml_prediction,
            ml_confidence   = inputs.ml_confidence,
            agreement       = True,
            decision_source = DecisionSource.HYBRID_CONSENSUS.value,
            final_category  = rule_cat.value,
            reason          = reason,
            is_breached     = inputs.is_breached,
        )

    def _rule_ml_high_confidence(
        self,
        inputs:    DecisionInputs,
        rule_cat:  SecurityCategory,
        ml_cat:    SecurityCategory,
        agreement: bool,
    ) -> HybridDecision | None:
        """
        R2 — ML high confidence override.

        When the engines disagree and ML confidence ≥ ML_HIGH_CONFIDENCE,
        the ML prediction is preferred.
        """
        if inputs.ml_confidence < ML_HIGH_CONFIDENCE:
            return None

        reason = (
            f"Engines disagreed (Rule: '{rule_cat.value}', "
            f"ML: '{ml_cat.value}'). "
            f"Machine Learning selected due to high confidence "
            f"({inputs.ml_confidence:.0%})."
        )
        log.debug(
            "R2 ML High Confidence: rule=%s ml=%s conf=%.2f",
            rule_cat.value, ml_cat.value, inputs.ml_confidence,
        )
        return HybridDecision(
            rule_category   = inputs.rule_category,
            rule_score      = inputs.rule_score,
            ml_prediction   = inputs.ml_prediction,
            ml_confidence   = inputs.ml_confidence,
            agreement       = False,
            decision_source = DecisionSource.MACHINE_LEARNING.value,
            final_category  = ml_cat.value,
            reason          = reason,
            is_breached     = inputs.is_breached,
        )

    def _rule_low_confidence(
        self,
        inputs:    DecisionInputs,
        rule_cat:  SecurityCategory,
        ml_cat:    SecurityCategory,
        agreement: bool,
    ) -> HybridDecision | None:
        """
        R3 — Rule Engine preference when ML confidence is below threshold.

        When ML confidence < ML_LOW_CONFIDENCE the deterministic rule engine
        is considered more reliable than an uncertain ML prediction.
        """
        if inputs.ml_confidence >= ML_LOW_CONFIDENCE:
            return None

        reason = (
            f"Engines disagreed (Rule: '{rule_cat.value}', "
            f"ML: '{ml_cat.value}'). "
            f"Rule Engine selected because ML confidence "
            f"({inputs.ml_confidence:.0%}) was below the "
            f"{ML_LOW_CONFIDENCE:.0%} threshold."
        )
        log.debug(
            "R3 Rule Engine preferred: conf=%.2f < threshold=%.2f",
            inputs.ml_confidence, ML_LOW_CONFIDENCE,
        )
        return HybridDecision(
            rule_category   = inputs.rule_category,
            rule_score      = inputs.rule_score,
            ml_prediction   = inputs.ml_prediction,
            ml_confidence   = inputs.ml_confidence,
            agreement       = False,
            decision_source = DecisionSource.RULE_ENGINE.value,
            final_category  = rule_cat.value,
            reason          = reason,
            is_breached     = inputs.is_breached,
        )

    def _rule_weighted_blend(
        self,
        inputs:    DecisionInputs,
        rule_cat:  SecurityCategory,
        ml_cat:    SecurityCategory,
        agreement: bool,
    ) -> HybridDecision:
        """
        R4 — Weighted blend (fallback when conf ∈ [ML_LOW, ML_HIGH)).

        Each category is mapped to a numeric rank (0–4).  A weighted average
        rank is computed using RULE_WEIGHT and ML_WEIGHT, then rounded to the
        nearest integer rank and decoded back to a label.

        This guarantees a decision is always produced — no further fallback
        is needed.
        """
        rule_rank    = self._RANK[rule_cat.value]
        ml_rank      = self._RANK[ml_cat.value]
        blended_rank = (rule_rank * RULE_WEIGHT) + (ml_rank * ML_WEIGHT)
        final_rank   = round(blended_rank)
        final_rank   = max(0, min(4, final_rank))          # clamp to [0,4]
        final_label  = self._LABELS[final_rank]

        reason = (
            f"ML confidence ({inputs.ml_confidence:.0%}) is between the "
            f"high-confidence threshold ({ML_HIGH_CONFIDENCE:.0%}) and the "
            f"low-confidence threshold ({ML_LOW_CONFIDENCE:.0%}). "
            f"Weighted decision: Rule Engine ({RULE_WEIGHT:.0%}) × "
            f"'{rule_cat.value}' + ML ({ML_WEIGHT:.0%}) × '{ml_cat.value}' "
            f"→ '{final_label}'."
        )
        log.debug(
            "R4 Weighted blend: rule=%s(rank=%d) ml=%s(rank=%d) "
            "blended=%.2f → %s",
            rule_cat.value, rule_rank, ml_cat.value, ml_rank,
            blended_rank, final_label,
        )
        return HybridDecision(
            rule_category   = inputs.rule_category,
            rule_score      = inputs.rule_score,
            ml_prediction   = inputs.ml_prediction,
            ml_confidence   = inputs.ml_confidence,
            agreement       = False,
            decision_source = DecisionSource.WEIGHTED_DECISION.value,
            final_category  = final_label,
            reason          = reason,
            is_breached     = inputs.is_breached,
        )

    # ──────────────────────────────────────────────────────────────────────
    # Post-processing: safety guard
    # ──────────────────────────────────────────────────────────────────────

    def _apply_safety_guard(
        self,
        decision: HybridDecision,
        inputs:   DecisionInputs,
    ) -> HybridDecision:
        """
        R5 — Safety guard (post-processor applied after all rules).

        Prevents the engine from upgrading a critically weak password
        (rule_score < CRITICAL_SCORE_THRESHOLD) regardless of ML confidence.

        This rule exists to protect against cases where ML produces a falsely
        optimistic prediction for a password the rule engine correctly
        identifies as extremely dangerous.
        """
        if inputs.rule_score >= CRITICAL_SCORE_THRESHOLD:
            return decision                        # score is not critical

        rule_cat  = SecurityCategory.from_label(inputs.rule_category)
        final_cat = SecurityCategory.from_label(decision.final_category)

        if final_cat.rank() <= rule_cat.rank():
            return decision                        # no upgrade happened — OK

        # An upgrade happened despite a critically low rule score — reverse it
        log.warning(
            "R5 Safety Guard: rule_score=%d < threshold=%d  "
            "blocking upgrade %s → %s  reverting to %s",
            inputs.rule_score, CRITICAL_SCORE_THRESHOLD,
            rule_cat.value, final_cat.value, rule_cat.value,
        )
        original_reason = decision.reason
        safe_reason = (
            f"Safety guard activated: rule score ({inputs.rule_score}) is "
            f"critically low (< {CRITICAL_SCORE_THRESHOLD}). "
            f"ML-driven upgrade to '{final_cat.value}' was blocked. "
            f"Password kept at '{rule_cat.value}'. "
            f"[Original: {original_reason}]"
        )
        from dataclasses import replace
        return replace(
            decision,
            final_category  = rule_cat.value,
            decision_source = DecisionSource.RULE_ENGINE.value,
            reason          = safe_reason,
        )
