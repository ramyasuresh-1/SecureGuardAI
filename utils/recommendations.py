"""
Utilities for generating human-readable AI password insights.

Each finding is a small dict with:
    icon      – FontAwesome class
    text      – one-sentence description
    severity  – "danger" | "warning" | "info" | "success"

Findings are ordered: critical issues first, positive notes last.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Individual finding builders
# ---------------------------------------------------------------------------

def _finding(icon: str, text: str, severity: str) -> dict[str, str]:
    return {"icon": icon, "text": text, "severity": severity}


# ── Negative findings ──────────────────────────────────────────────────────

def _check_length(length: int) -> dict | None:
    if length == 0:
        return _finding("fas fa-times-circle", "No password entered.", "danger")
    if length < 6:
        return _finding("fas fa-times-circle",
                        f"Too short ({length} chars). Use at least 12 characters.", "danger")
    if length < 8:
        return _finding("fas fa-exclamation-circle",
                        f"Short password ({length} chars). Aim for 12 or more.", "warning")
    if length < 12:
        return _finding("fas fa-info-circle",
                        f"Password length is acceptable ({length} chars) but 14+ is recommended.",
                        "info")
    return None


def _check_uppercase(uppercase: int, length: int) -> dict | None:
    if length == 0:
        return None
    if uppercase == 0:
        return _finding("fas fa-exclamation-circle",
                        "No uppercase letters. Add at least one capital letter.", "warning")
    return None


def _check_digits(digits: int, length: int) -> dict | None:
    if length == 0:
        return None
    if digits == 0:
        return _finding("fas fa-exclamation-circle",
                        "No digits found. Include numbers to increase complexity.", "warning")
    return None


def _check_special(special: int, length: int) -> dict | None:
    if length == 0:
        return None
    if special == 0:
        return _finding("fas fa-exclamation-circle",
                        "No special characters. Symbols like @, #, ! significantly raise strength.",
                        "warning")
    return None


def _check_dictionary(dictionary_word: bool) -> dict | None:
    if dictionary_word:
        return _finding("fas fa-book",
                        "Contains a common dictionary word. Attackers try these first.", "danger")
    return None


def _check_keyboard(keyboard_pattern: bool) -> dict | None:
    if keyboard_pattern:
        return _finding("fas fa-keyboard",
                        "Keyboard sequence detected (e.g. qwerty, 12345). Avoid predictable patterns.",
                        "danger")
    return None


def _check_birth_year(birth_year: bool) -> dict | None:
    if birth_year:
        return _finding("fas fa-calendar",
                        "Possible birth year found. Personal dates are easily guessed.", "warning")
    return None


def _check_repeated(repeated: bool, repeated_count: int) -> dict | None:
    if repeated and repeated_count > 2:
        return _finding("fas fa-sync",
                        f"Repeated characters detected ({repeated_count} repeats). "
                        "Use a wider variety of characters.", "warning")
    return None


def _check_sequential(sequential: bool) -> dict | None:
    if sequential:
        return _finding("fas fa-sort-amount-up",
                        "Sequential characters detected (abc, 123). These reduce entropy significantly.",
                        "warning")
    return None


def _check_entropy(entropy: float) -> dict | None:
    if entropy < 2.5:
        return _finding("fas fa-chart-bar",
                        f"Very low entropy ({entropy} bits). The password is highly predictable.",
                        "danger")
    if entropy < 3.2:
        return _finding("fas fa-chart-bar",
                        f"Low entropy ({entropy} bits). Password could be improved.", "warning")
    return None


def _check_diversity(char_diversity: float) -> dict | None:
    """char_diversity is a 0.0–1.0 ratio of unique / total chars."""
    if char_diversity < 0.4:
        return _finding("fas fa-clone",
                        f"Low character diversity ({round(char_diversity * 100)}% unique). "
                        "Use more varied characters.", "warning")
    return None


# ── Positive findings ──────────────────────────────────────────────────────

def _positive_length(length: int) -> dict | None:
    if length >= 16:
        return _finding("fas fa-check-circle",
                        f"Excellent length ({length} characters). Long passwords are much harder to crack.",
                        "success")
    if length >= 12:
        return _finding("fas fa-check-circle",
                        f"Good length ({length} characters).", "success")
    return None


def _positive_diversity(
    uppercase: int, lowercase: int, digits: int, special: int
) -> dict | None:
    classes = sum([uppercase > 0, lowercase > 0, digits > 0, special > 0])
    if classes == 4:
        return _finding("fas fa-check-circle",
                        "Uses all four character classes (upper, lower, digits, symbols).", "success")
    if classes == 3:
        return _finding("fas fa-check-circle",
                        "Uses three character classes — consider adding symbols.", "success")
    return None


def _positive_entropy(entropy: float) -> dict | None:
    if entropy >= 4.0:
        return _finding("fas fa-check-circle",
                        f"High entropy ({entropy} bits) — very unpredictable.", "success")
    if entropy >= 3.5:
        return _finding("fas fa-check-circle",
                        f"Good entropy ({entropy} bits).", "success")
    return None


def _positive_overall(strength_score: int) -> dict | None:
    if strength_score >= 85:
        return _finding("fas fa-shield-halved",
                        "Strong password — excellent protection against most attack types.", "success")
    if strength_score >= 70:
        return _finding("fas fa-shield-halved",
                        "Reasonably strong password. Minor improvements could make it excellent.",
                        "success")
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_findings(
    length: int,
    uppercase: int,
    lowercase: int,
    digits: int,
    special: int,
    entropy: float,
    char_diversity: float,
    dictionary_word: bool,
    keyboard_pattern: bool,
    birth_year: bool,
    repeated: bool,
    repeated_count: int,
    sequential: bool,
    strength_score: int,
    is_breached: bool = False,
) -> list[dict[str, str]]:
    """
    Return an ordered list of AI finding dicts for the given password attributes.

    Critical issues appear first; positive observations appear last.
    """
    findings: list[dict | None] = []

    # ── Critical first ────────────────────────────────────────────────────
    if is_breached:
        findings.append(_finding(
            "fas fa-radiation",
            "This password appears in known data-breach databases. Change it immediately.",
            "danger",
        ))

    # ── Negative checks (ordered by severity) ────────────────────────────
    findings.append(_check_length(length))
    findings.append(_check_dictionary(dictionary_word))
    findings.append(_check_keyboard(keyboard_pattern))
    findings.append(_check_entropy(entropy))
    findings.append(_check_uppercase(uppercase, length))
    findings.append(_check_digits(digits, length))
    findings.append(_check_special(special, length))
    findings.append(_check_birth_year(birth_year))
    findings.append(_check_repeated(repeated, repeated_count))
    findings.append(_check_sequential(sequential))
    findings.append(_check_diversity(char_diversity))

    # ── Positive checks ───────────────────────────────────────────────────
    findings.append(_positive_length(length))
    findings.append(_positive_diversity(uppercase, lowercase, digits, special))
    findings.append(_positive_entropy(entropy))
    findings.append(_positive_overall(strength_score))

    # Remove None entries and cap at 8 findings
    return [f for f in findings if f is not None][:8]
