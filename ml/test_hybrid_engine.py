"""
ml/test_hybrid_engine.py — SecureGuard AI
============================================

Standalone test suite for the Hybrid AI Decision Engine.

NO Flask.  NO database.  NO web application.

Covers:
    1.  Consensus case (both engines agree)
    2.  ML high-confidence override
    3.  Rule Engine preference (ML low confidence)
    4.  Weighted decision (confidence in mid-range)
    5.  Breach downgrade (at/above threshold)
    6.  Breach at floor (already at lowest tier)
    7.  Boundary: conf = exactly ML_HIGH_CONFIDENCE
    8.  Boundary: conf = exactly ML_LOW_CONFIDENCE
    9.  Safety guard (critical rule score blocks upgrade)
   10.  Invalid rule_category raises InvalidInputError
   11.  Invalid rule_score raises InvalidInputError
   12.  Invalid ml_confidence raises InvalidInputError
   13.  to_dict() format validation
   14.  DecisionSource enum coverage
   15.  SecurityCategory rank ordering

Usage
-----
    python ml/test_hybrid_engine.py

Exit codes
----------
    0  All tests passed.
    1  One or more tests failed.
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from ml.hybrid_engine import (
    BREACH_DOWNGRADE_THRESHOLD,
    CRITICAL_SCORE_THRESHOLD,
    ML_HIGH_CONFIDENCE,
    ML_LOW_CONFIDENCE,
    ML_WEIGHT,
    RULE_WEIGHT,
    DecisionInputs,
    DecisionSource,
    HybridDecision,
    HybridDecisionEngine,
    InvalidInputError,
    SecurityCategory,
)

# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------

_W = 70
_PASS = "✓"
_FAIL = "✗"

_pass_count = 0
_fail_count = 0


def _header(title: str) -> None:
    print()
    print("═" * _W)
    print(f"  {title}")
    print("═" * _W)


def _section(title: str) -> None:
    print()
    print("─" * _W)
    print(f"  {title}")
    print("─" * _W)


def _ok(label: str, detail: str = "") -> None:
    global _pass_count
    _pass_count += 1
    suffix = f"  → {detail}" if detail else ""
    print(f"  {_PASS}  {label}{suffix}")


def _fail(label: str, detail: str = "") -> None:
    global _fail_count
    _fail_count += 1
    suffix = f"  → {detail}" if detail else ""
    print(f"  {_FAIL}  FAIL: {label}{suffix}")


def _check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        _ok(label, detail)
    else:
        _fail(label, detail)


def _expect_exception(
    label: str,
    exc_type: type,
    inputs: DecisionInputs,
    engine: HybridDecisionEngine,
) -> None:
    """Assert that engine.decide(inputs) raises exc_type."""
    try:
        engine.decide(inputs)
        _fail(label, f"Expected {exc_type.__name__} but no exception raised")
    except exc_type as exc:
        _ok(label, f"{exc_type.__name__}: {exc}")
    except Exception as exc:
        _fail(label, f"Wrong exception type {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Shared engine instance (stateless — safe to reuse)
# ---------------------------------------------------------------------------
engine = HybridDecisionEngine()

# ---------------------------------------------------------------------------
# Shared probabilities helper
# ---------------------------------------------------------------------------

def _probs(dominant_label: str, dominant_value: float) -> dict[str, float]:
    """Build a probability dict with one dominant class and the rest split equally."""
    cats   = [c.value for c in SecurityCategory]
    others = len(cats) - 1
    other_share = round((1.0 - dominant_value) / others, 4) if others else 0.0
    return {c: (dominant_value if c == dominant_label else other_share) for c in cats}


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_consensus() -> None:
    """Both engines agree → Hybrid Consensus, agreement=True."""
    _section("Test 1 — Consensus Case")

    for cat in SecurityCategory:
        inp = DecisionInputs(
            rule_category    = cat.value,
            rule_score       = 50,
            threat_level     = "Medium",
            ml_prediction    = cat.value,
            ml_confidence    = 0.80,
            ml_probabilities = _probs(cat.value, 0.80),
            is_breached      = False,
        )
        d = engine.decide(inp)
        _check(f"Consensus {cat.value}",
               d.final_category == cat.value
               and d.agreement is True
               and d.decision_source == DecisionSource.HYBRID_CONSENSUS.value,
               f"final={d.final_category!r}  source={d.decision_source!r}")


def test_ml_high_confidence_override() -> None:
    """ML conf ≥ ML_HIGH_CONFIDENCE and disagreement → trust ML."""
    _section("Test 2 — ML High-Confidence Override")

    cases = [
        ("Very Weak", 20, "Strong",    0.95),
        ("Weak",      35, "Excellent", 0.93),
        ("Moderate",  55, "Strong",    0.92),
        ("Strong",    72, "Excellent", 0.91),
    ]
    for rule_cat, score, ml_cat, conf in cases:
        inp = DecisionInputs(
            rule_category    = rule_cat,
            rule_score       = score,
            threat_level     = "Medium",
            ml_prediction    = ml_cat,
            ml_confidence    = conf,
            ml_probabilities = _probs(ml_cat, conf),
            is_breached      = False,
        )
        d = engine.decide(inp)
        expected_source = DecisionSource.MACHINE_LEARNING.value
        # Safety guard may override if rule_score is critical
        if score < CRITICAL_SCORE_THRESHOLD:
            expected_final  = rule_cat
            expected_source = DecisionSource.RULE_ENGINE.value
        else:
            expected_final  = ml_cat

        _check(
            f"ML override  rule={rule_cat!r} score={score} ml={ml_cat!r} conf={conf}",
            d.final_category == expected_final and d.agreement is False,
            f"final={d.final_category!r}  source={d.decision_source!r}",
        )


def test_rule_engine_low_confidence() -> None:
    """ML conf < ML_LOW_CONFIDENCE → trust Rule Engine."""
    _section("Test 3 — Rule Engine Preference (Low ML Confidence)")

    cases = [
        ("Strong",    75, "Excellent", 0.50),
        ("Moderate",  60, "Strong",    0.45),
        ("Weak",      38, "Moderate",  0.30),
        ("Very Weak", 15, "Weak",      0.60),   # boundary: 0.60 < 0.70
    ]
    for rule_cat, score, ml_cat, conf in cases:
        inp = DecisionInputs(
            rule_category    = rule_cat,
            rule_score       = score,
            threat_level     = "Low",
            ml_prediction    = ml_cat,
            ml_confidence    = conf,
            ml_probabilities = _probs(ml_cat, conf),
            is_breached      = False,
        )
        d = engine.decide(inp)
        _check(
            f"Rule preferred  rule={rule_cat!r} conf={conf}",
            d.final_category == rule_cat
            and d.decision_source == DecisionSource.RULE_ENGINE.value,
            f"final={d.final_category!r}  source={d.decision_source!r}",
        )


def test_weighted_decision() -> None:
    """ML conf ∈ [ML_LOW, ML_HIGH) and disagreement → Weighted Decision."""
    _section("Test 4 — Weighted Decision (Mid-Range Confidence)")

    import math

    cases = [
        # (rule_cat, rule_score, ml_cat, ml_conf, expected_final)
        ("Weak",     40, "Moderate", 0.75, None),   # None = compute expected
        ("Moderate", 58, "Strong",   0.80, None),
        ("Strong",   75, "Moderate", 0.78, None),
    ]
    for rule_cat, score, ml_cat, conf, _ in cases:
        rule_rank    = SecurityCategory.from_label(rule_cat).rank()
        ml_rank      = SecurityCategory.from_label(ml_cat).rank()
        blended      = rule_rank * RULE_WEIGHT + ml_rank * ML_WEIGHT
        expected_rank = max(0, min(4, round(blended)))
        expected_final = [c.value for c in SecurityCategory][expected_rank]

        inp = DecisionInputs(
            rule_category    = rule_cat,
            rule_score       = score,
            threat_level     = "Medium",
            ml_prediction    = ml_cat,
            ml_confidence    = conf,
            ml_probabilities = _probs(ml_cat, conf),
            is_breached      = False,
        )
        d = engine.decide(inp)
        _check(
            f"Weighted  rule={rule_cat!r} ml={ml_cat!r} conf={conf}"
            f" → expected={expected_final!r}",
            d.final_category == expected_final
            and d.decision_source == DecisionSource.WEIGHTED_DECISION.value,
            f"final={d.final_category!r}  source={d.decision_source!r}",
        )


def test_breach_downgrade() -> None:
    """Breached passwords at/above threshold are downgraded by one tier."""
    _section("Test 5 — Breach Downgrade (At/Above Threshold)")

    threshold_cat = SecurityCategory.from_label(BREACH_DOWNGRADE_THRESHOLD)
    downgrade_cases = [c for c in SecurityCategory if c.rank() >= threshold_cat.rank()]

    for cat in downgrade_cases:
        expected = cat.downgrade().value
        inp = DecisionInputs(
            rule_category    = cat.value,
            rule_score       = 60,
            threat_level     = "High",
            ml_prediction    = cat.value,
            ml_confidence    = 0.80,
            ml_probabilities = _probs(cat.value, 0.80),
            is_breached      = True,
        )
        d = engine.decide(inp)
        _check(
            f"Breach downgrade  {cat.value!r} → {expected!r}",
            d.final_category == expected
            and d.decision_source == DecisionSource.BREACH_GUARD.value
            and d.is_breached is True,
            f"final={d.final_category!r}  source={d.decision_source!r}",
        )


def test_breach_floor() -> None:
    """Breached passwords already at Very Weak stay at Very Weak."""
    _section("Test 6 — Breach at Floor (Very Weak)")

    inp = DecisionInputs(
        rule_category    = "Very Weak",
        rule_score       = 10,
        threat_level     = "Critical",
        ml_prediction    = "Very Weak",
        ml_confidence    = 0.95,
        ml_probabilities = _probs("Very Weak", 0.95),
        is_breached      = True,
    )
    d = engine.decide(inp)
    _check(
        "Breach floor: Very Weak stays Very Weak",
        d.final_category == "Very Weak"
        and d.is_breached is True
        and d.decision_source == DecisionSource.BREACH_GUARD.value,
        f"final={d.final_category!r}",
    )


def test_boundary_high_confidence() -> None:
    """conf = ML_HIGH_CONFIDENCE exactly → ML override."""
    _section(f"Test 7 — Boundary: conf = ML_HIGH_CONFIDENCE ({ML_HIGH_CONFIDENCE})")

    inp = DecisionInputs(
        rule_category    = "Moderate",
        rule_score       = 55,
        threat_level     = "Medium",
        ml_prediction    = "Strong",
        ml_confidence    = ML_HIGH_CONFIDENCE,
        ml_probabilities = _probs("Strong", ML_HIGH_CONFIDENCE),
        is_breached      = False,
    )
    d = engine.decide(inp)
    _check(
        f"conf={ML_HIGH_CONFIDENCE} → ML override",
        d.decision_source == DecisionSource.MACHINE_LEARNING.value,
        f"source={d.decision_source!r}  final={d.final_category!r}",
    )


def test_boundary_low_confidence() -> None:
    """conf = ML_LOW_CONFIDENCE exactly → Weighted Decision (not Rule Engine)."""
    _section(f"Test 8 — Boundary: conf = ML_LOW_CONFIDENCE ({ML_LOW_CONFIDENCE})")

    # At exactly ML_LOW_CONFIDENCE:
    #   R3 fires only when conf < ML_LOW_CONFIDENCE → miss
    #   R4 weighted blend takes over
    inp = DecisionInputs(
        rule_category    = "Weak",
        rule_score       = 38,
        threat_level     = "High",
        ml_prediction    = "Moderate",
        ml_confidence    = ML_LOW_CONFIDENCE,
        ml_probabilities = _probs("Moderate", ML_LOW_CONFIDENCE),
        is_breached      = False,
    )
    d = engine.decide(inp)
    _check(
        f"conf={ML_LOW_CONFIDENCE} → Weighted Decision (not Rule Engine)",
        d.decision_source == DecisionSource.WEIGHTED_DECISION.value,
        f"source={d.decision_source!r}  final={d.final_category!r}",
    )

    # Just below threshold → Rule Engine
    inp2 = DecisionInputs(
        rule_category    = "Weak",
        rule_score       = 38,
        threat_level     = "High",
        ml_prediction    = "Moderate",
        ml_confidence    = ML_LOW_CONFIDENCE - 0.001,
        ml_probabilities = _probs("Moderate", ML_LOW_CONFIDENCE - 0.001),
        is_breached      = False,
    )
    d2 = engine.decide(inp2)
    _check(
        f"conf={ML_LOW_CONFIDENCE - 0.001:.3f} → Rule Engine",
        d2.decision_source == DecisionSource.RULE_ENGINE.value,
        f"source={d2.decision_source!r}",
    )


def test_safety_guard() -> None:
    """Critical rule score blocks ML from upgrading the category."""
    _section(f"Test 9 — Safety Guard (rule_score < {CRITICAL_SCORE_THRESHOLD})")

    # rule_score below threshold, ML tries to upgrade
    inp = DecisionInputs(
        rule_category    = "Very Weak",
        rule_score       = CRITICAL_SCORE_THRESHOLD - 1,
        threat_level     = "Critical",
        ml_prediction    = "Strong",
        ml_confidence    = 0.95,
        ml_probabilities = _probs("Strong", 0.95),
        is_breached      = False,
    )
    d = engine.decide(inp)
    _check(
        "Safety guard: critical rule score blocks ML upgrade",
        d.final_category  == "Very Weak"
        and d.decision_source == DecisionSource.RULE_ENGINE.value,
        f"final={d.final_category!r}  source={d.decision_source!r}",
    )
    _check(
        "Safety guard: reason mentions safety guard",
        "Safety guard" in d.reason or "safety guard" in d.reason.lower(),
        d.reason[:80],
    )

    # rule_score AT threshold (not critical) — upgrade is allowed
    inp2 = DecisionInputs(
        rule_category    = "Weak",
        rule_score       = CRITICAL_SCORE_THRESHOLD,
        threat_level     = "High",
        ml_prediction    = "Strong",
        ml_confidence    = 0.95,
        ml_probabilities = _probs("Strong", 0.95),
        is_breached      = False,
    )
    d2 = engine.decide(inp2)
    _check(
        "Safety guard: score AT threshold allows ML override",
        d2.final_category  == "Strong"
        and d2.decision_source == DecisionSource.MACHINE_LEARNING.value,
        f"final={d2.final_category!r}",
    )


def test_invalid_inputs() -> None:
    """Invalid inputs raise InvalidInputError."""
    _section("Test 10–12 — Invalid Input Handling")

    # Bad rule_category
    _expect_exception(
        "Invalid rule_category raises InvalidInputError",
        InvalidInputError,
        DecisionInputs(
            rule_category = "SuperStrong",   # not a valid tier
            rule_score    = 50,
            threat_level  = "Low",
            ml_prediction = "Strong",
            ml_confidence = 0.85,
        ),
        engine,
    )

    # rule_score out of range
    _expect_exception(
        "rule_score > 100 raises InvalidInputError",
        InvalidInputError,
        DecisionInputs(
            rule_category = "Strong",
            rule_score    = 101,
            threat_level  = "Low",
            ml_prediction = "Strong",
            ml_confidence = 0.85,
        ),
        engine,
    )

    _expect_exception(
        "rule_score < 0 raises InvalidInputError",
        InvalidInputError,
        DecisionInputs(
            rule_category = "Strong",
            rule_score    = -1,
            threat_level  = "Low",
            ml_prediction = "Strong",
            ml_confidence = 0.85,
        ),
        engine,
    )

    # ml_confidence out of range
    _expect_exception(
        "ml_confidence > 1 raises InvalidInputError",
        InvalidInputError,
        DecisionInputs(
            rule_category = "Strong",
            rule_score    = 75,
            threat_level  = "Low",
            ml_prediction = "Strong",
            ml_confidence = 1.1,
        ),
        engine,
    )

    _expect_exception(
        "ml_confidence < 0 raises InvalidInputError",
        InvalidInputError,
        DecisionInputs(
            rule_category = "Strong",
            rule_score    = 75,
            threat_level  = "Low",
            ml_prediction = "Strong",
            ml_confidence = -0.01,
        ),
        engine,
    )


def test_to_dict_format() -> None:
    """HybridDecision.to_dict() returns all required keys with correct types."""
    _section("Test 13 — to_dict() Format")

    inp = DecisionInputs(
        rule_category    = "Moderate",
        rule_score       = 60,
        threat_level     = "Medium",
        ml_prediction    = "Moderate",
        ml_confidence    = 0.80,
        ml_probabilities = _probs("Moderate", 0.80),
        is_breached      = False,
    )
    d = engine.decide(inp)
    dd = d.to_dict()

    print()
    print("  to_dict() output:")
    for k, v in dd.items():
        print(f"    {k:<22}: {v}")
    print()

    required_keys = {
        "rule_category", "rule_score", "ml_prediction", "ml_confidence",
        "agreement", "decision_source", "final_category", "reason",
        "is_breached", "decision_timestamp",
    }
    _check("All required keys present", required_keys.issubset(dd.keys()))
    _check("rule_score is int",          isinstance(dd["rule_score"],    int))
    _check("ml_confidence is float",     isinstance(dd["ml_confidence"], float))
    _check("agreement is bool",          isinstance(dd["agreement"],     bool))
    _check("is_breached is bool",        isinstance(dd["is_breached"],   bool))
    _check("reason is non-empty str",    isinstance(dd["reason"], str) and len(dd["reason"]) > 5)


def test_decision_source_enum_coverage() -> None:
    """All DecisionSource values can appear in real decisions."""
    _section("Test 14 — DecisionSource Enum Coverage")

    seen_sources: set[str] = set()

    # Consensus
    inp = DecisionInputs("Strong", 75, "Low", "Strong", 0.80,
                         _probs("Strong", 0.80), False)
    seen_sources.add(engine.decide(inp).decision_source)

    # ML override
    inp = DecisionInputs("Weak", 40, "Low", "Excellent", 0.95,
                         _probs("Excellent", 0.95), False)
    seen_sources.add(engine.decide(inp).decision_source)

    # Rule Engine
    inp = DecisionInputs("Strong", 75, "Low", "Excellent", 0.50,
                         _probs("Excellent", 0.50), False)
    seen_sources.add(engine.decide(inp).decision_source)

    # Weighted
    inp = DecisionInputs("Weak", 38, "Low", "Moderate", 0.75,
                         _probs("Moderate", 0.75), False)
    seen_sources.add(engine.decide(inp).decision_source)

    # Breach guard
    inp = DecisionInputs("Strong", 75, "High", "Strong", 0.85,
                         _probs("Strong", 0.85), True)
    seen_sources.add(engine.decide(inp).decision_source)

    expected = {ds.value for ds in DecisionSource}
    _check(
        "All DecisionSource values observed",
        expected == seen_sources,
        f"seen={seen_sources}",
    )


def test_security_category_rank_ordering() -> None:
    """SecurityCategory.rank() is strictly increasing Very Weak → Excellent."""
    _section("Test 15 — SecurityCategory Rank Ordering")

    cats     = list(SecurityCategory)
    ranks    = [c.rank() for c in cats]
    expected = list(range(len(cats)))

    _check("Ranks are [0,1,2,3,4]", ranks == expected, str(ranks))

    # downgrade / upgrade
    _check("Very Weak.downgrade() → Very Weak",
           SecurityCategory.VERY_WEAK.downgrade() == SecurityCategory.VERY_WEAK)
    _check("Excellent.upgrade() → Excellent",
           SecurityCategory.EXCELLENT.upgrade() == SecurityCategory.EXCELLENT)
    _check("Moderate.downgrade() → Weak",
           SecurityCategory.MODERATE.downgrade() == SecurityCategory.WEAK)
    _check("Moderate.upgrade() → Strong",
           SecurityCategory.MODERATE.upgrade() == SecurityCategory.STRONG)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    _header("SecureGuard AI — Hybrid Engine Test Suite")
    print(f"\n  Configuration:")
    print(f"    ML_HIGH_CONFIDENCE          : {ML_HIGH_CONFIDENCE}")
    print(f"    ML_LOW_CONFIDENCE           : {ML_LOW_CONFIDENCE}")
    print(f"    RULE_WEIGHT / ML_WEIGHT     : {RULE_WEIGHT} / {ML_WEIGHT}")
    print(f"    BREACH_DOWNGRADE_THRESHOLD  : {BREACH_DOWNGRADE_THRESHOLD!r}")
    print(f"    CRITICAL_SCORE_THRESHOLD    : {CRITICAL_SCORE_THRESHOLD}")

    tests = [
        test_consensus,
        test_ml_high_confidence_override,
        test_rule_engine_low_confidence,
        test_weighted_decision,
        test_breach_downgrade,
        test_breach_floor,
        test_boundary_high_confidence,
        test_boundary_low_confidence,
        test_safety_guard,
        test_invalid_inputs,
        test_to_dict_format,
        test_decision_source_enum_coverage,
        test_security_category_rank_ordering,
    ]

    for test_fn in tests:
        try:
            test_fn()
        except Exception as exc:
            _fail(f"Unhandled exception in {test_fn.__name__}", str(exc))
            traceback.print_exc()

    # ── Summary ───────────────────────────────────────────────────────────
    total = _pass_count + _fail_count
    print()
    print("═" * _W)
    print(f"  RESULTS : {_pass_count}/{total} passed")
    if _fail_count == 0:
        print("  STATUS  : ✓  ALL TESTS PASSED")
    else:
        print(f"  STATUS  : ✗  {_fail_count} TEST(S) FAILED")
    print("═" * _W)
    return _fail_count


if __name__ == "__main__":
    sys.exit(main())
