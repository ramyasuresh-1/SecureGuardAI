"""
Utilities for computing password strength scores and categories.

Strength categories (5 tiers)
------------------------------
  Very Weak  – score  0–29
  Weak       – score 30–49
  Moderate   – score 50–69
  Strong     – score 70–84
  Excellent  – score 85–100

The five-tier scale is used by the analyzer UI and threat predictor.
"""


def calculate_strength_score(
    length: int,
    uppercase: int,
    lowercase: int,
    digits: int,
    special: int,
    entropy: float,
    dictionary_word: bool = False,
    keyboard_pattern: bool = False,
    birth_year: bool = False,
    repeated: bool = False,
    sequential: bool = False,
) -> int:
    """
    Compute an overall password strength score from 0 to 100.

    Scoring breakdown
    -----------------
    Length                  up to 30 pts  (2.2 pts per char, capped at 30)
    Uppercase chars         up to 20 pts  (2.5 pts each)
    Lowercase chars         up to 20 pts  (1.5 pts each)
    Digits                  up to 15 pts  (3.0 pts each)
    Special chars           up to 15 pts  (5.0 pts each)
    Shannon entropy         up to 20 pts  (0.45 per bit)

    Penalties
    ---------
    Dictionary word         –12
    Keyboard pattern        –10
    Birth year              –8
    Repeated characters     –6
    Sequential characters   –6
    """
    score: float = 0.0

    # ── Positive contributions ────────────────────────────────────────────
    score += min(30.0, length    * 2.2)
    score += min(20.0, uppercase * 2.5)
    score += min(20.0, lowercase * 1.5)
    score += min(15.0, digits    * 3.0)
    score += min(15.0, special   * 5.0)
    score += min(20.0, entropy   * 0.45)

    # ── Penalties ─────────────────────────────────────────────────────────
    if dictionary_word:
        score -= 12
    if keyboard_pattern:
        score -= 10
    if birth_year:
        score -= 8
    if repeated:
        score -= 6
    if sequential:
        score -= 6

    return max(0, min(100, round(score)))


def get_strength_category(score: int) -> str:
    """
    Map a 0–100 score to one of five user-facing strength labels.

    Thresholds
    ----------
    0–29   Very Weak
    30–49  Weak
    50–69  Moderate
    70–84  Strong
    85–100 Excellent
    """
    if score < 30:
        return "Very Weak"
    if score < 50:
        return "Weak"
    if score < 70:
        return "Moderate"
    if score < 85:
        return "Strong"
    return "Excellent"


# ── Helper maps for UI rendering ─────────────────────────────────────────────

# Bootstrap / custom text-colour class per category
STRENGTH_COLOURS: dict[str, str] = {
    "Very Weak": "text-danger",
    "Weak":      "text-warning",
    "Moderate":  "text-info",
    "Strong":    "text-primary",
    "Excellent": "text-success",
}

# Progress-bar colour class per category
STRENGTH_BAR_COLOURS: dict[str, str] = {
    "Very Weak": "bg-danger",
    "Weak":      "bg-warning",
    "Moderate":  "bg-info",
    "Strong":    "bg-primary",
    "Excellent": "bg-success",
}


def get_strength_colour(category: str) -> str:
    """Return the CSS text-colour class for a strength category label."""
    return STRENGTH_COLOURS.get(category, "text-muted")


def get_strength_bar_colour(category: str) -> str:
    """Return the Bootstrap progress-bar bg-* class for a strength category."""
    return STRENGTH_BAR_COLOURS.get(category, "bg-secondary")
