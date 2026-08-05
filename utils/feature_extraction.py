"""
Feature extraction and full password analysis pipeline for SecureGuard AI.

Public API
----------
extract_password_features(password)  → dict  (basic composition metrics)
analyze_password(password)           → dict  (backward-compat summary, no crack/threat)
analyze_password_full(password)      → dict  (complete pipeline: all 10 steps)

The full pipeline is the single function that the /api/analyze endpoint calls.
It orchestrates every utility module so no logic is duplicated elsewhere.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .crack_time import estimate_crack_time, estimate_crack_time_detailed
from .entropy import calculate_entropy, get_entropy_category
from .pattern_detector import (
    detect_birth_year,
    detect_dictionary_word,
    detect_keyboard_pattern,
    detect_repeated_characters,
    detect_sequential_characters,
)
from .breach_checker import check_breach, get_breach_recommendation
from .recommendations import generate_findings
from .strength import calculate_strength_score, get_strength_category
from .vulnerability import (
    get_threat_colour,
    get_threat_icon,
    predict_threat_level,
)


# ---------------------------------------------------------------------------
# Step 1 — Basic composition features
# ---------------------------------------------------------------------------

def extract_password_features(password: str) -> dict[str, Any]:
    """
    Extract composition metrics for a password.

    Returns
    -------
    password_length       int   total character count
    uppercase_count       int   A-Z characters
    lowercase_count       int   a-z characters
    digit_count           int   0-9 characters
    special_character_count  int  non-alphanumeric printable characters
    unique_character_count   int  distinct characters
    repeated_character_count int  characters that appear more than once
    char_diversity        float unique / length  (0.0–1.0)

    Also retains the legacy keys (length, uppercase, …) for backward
    compatibility with existing callers.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    length    = len(password)
    uppercase = sum(1 for c in password if c.isupper())
    lowercase = sum(1 for c in password if c.islower())
    digits    = sum(1 for c in password if c.isdigit())
    special   = sum(1 for c in password if not c.isalnum())

    # Unique and repeated counts
    freq = Counter(password)
    unique_count   = len(freq)
    repeated_count = sum(1 for v in freq.values() if v > 1)

    # Character diversity: ratio of unique chars to total length
    char_diversity = round(unique_count / length, 4) if length > 0 else 0.0

    return {
        # ── New canonical keys ──────────────────────────────────────────
        "password_length":          length,
        "uppercase_count":          uppercase,
        "lowercase_count":          lowercase,
        "digit_count":              digits,
        "special_character_count":  special,
        "unique_character_count":   unique_count,
        "repeated_character_count": repeated_count,
        "char_diversity":           char_diversity,
        # ── Legacy keys (kept for backward compat) ──────────────────────
        "length":    length,
        "uppercase": uppercase,
        "lowercase": lowercase,
        "digits":    digits,
        "special":   special,
    }


# ---------------------------------------------------------------------------
# Step 2-3 — Backward-compatible summary (used by dashboard_data helpers)
# ---------------------------------------------------------------------------

def analyze_password(password: str) -> dict[str, Any]:
    """
    Return a password-analysis summary dictionary.

    Preserved exactly for callers that already use this function.
    Does NOT include crack_time or threat_level (use analyze_password_full).
    """
    features = extract_password_features(password)

    entropy_score    = calculate_entropy(password)
    entropy_category = get_entropy_category(entropy_score)

    dictionary_word  = detect_dictionary_word(password)
    keyboard_pattern = detect_keyboard_pattern(password)
    birth_year       = detect_birth_year(password)
    repeated         = detect_repeated_characters(password)
    sequential       = detect_sequential_characters(password)

    strength_score    = calculate_strength_score(
        length=features["length"],
        uppercase=features["uppercase"],
        lowercase=features["lowercase"],
        digits=features["digits"],
        special=features["special"],
        entropy=entropy_score,
        dictionary_word=dictionary_word,
        keyboard_pattern=keyboard_pattern,
        birth_year=birth_year,
        repeated=repeated,
        sequential=sequential,
    )
    strength_category = get_strength_category(strength_score)

    return {
        "length":            features["length"],
        "uppercase":         features["uppercase"],
        "lowercase":         features["lowercase"],
        "digits":            features["digits"],
        "special":           features["special"],
        "entropy":           entropy_score,
        "entropy_category":  entropy_category,
        "dictionary_word":   dictionary_word,
        "keyboard_pattern":  keyboard_pattern,
        "birth_year":        birth_year,
        "repeated":          repeated,
        "sequential":        sequential,
        "strength_score":    strength_score,
        "strength_category": strength_category,
    }


# ---------------------------------------------------------------------------
# Full pipeline  (Steps 1 – 9)
# ---------------------------------------------------------------------------

def analyze_password_full(
    password: str,
    is_breached: bool = False,
    complexity_mode: str = "Standard",
    threat_model: str = "Consumer",
) -> dict[str, Any]:
    """
    Run the complete analysis pipeline and return a single result dict.

    This is the authoritative entry point for the /api/analyze endpoint.
    Every field needed by the frontend, the database, and the dashboard
    is present in the returned dict.

    Parameters
    ----------
    password        The password candidate to analyse.
    is_breached     Supply True if a breach-database check already confirmed
                    this password was exposed.  (Future HaveIBeenPwned hook.)
    complexity_mode Hint from the UI selector; currently used in label only.
    threat_model    Hint from the UI selector; currently used in label only.

    Returned keys
    -------------
    ── Step 1 – Features ──────────────────────────────────────────────────
    password_length, uppercase_count, lowercase_count, digit_count,
    special_character_count, unique_character_count,
    repeated_character_count, char_diversity,
    sequential_character_detected, dictionary_word_detected,
    keyboard_pattern_detected, entropy, entropy_category,
    birth_year_detected,

    ── Step 2 – Score ─────────────────────────────────────────────────────
    strength_score   (0–100)

    ── Step 3 – Strength category ─────────────────────────────────────────
    strength_category  (Very Weak / Weak / Moderate / Strong / Excellent)

    ── Step 4 – Threat level ──────────────────────────────────────────────
    threat_level   (Critical / High / Medium / Low / Very Low)
    threat_colour  (Bootstrap text-* class)
    threat_icon    (FontAwesome class)

    ── Step 5 – Crack time ────────────────────────────────────────────────
    crack_time         (human label, offline model)
    crack_time_online  (human label, online model)
    crack_time_combinations  (display string)

    ── Step 6 – Findings ──────────────────────────────────────────────────
    findings  list[{icon, text, severity}]

    ── Meta ───────────────────────────────────────────────────────────────
    is_breached, complexity_mode, threat_model
    """
    # ── Guard ─────────────────────────────────────────────────────────────
    if not isinstance(password, str):
        password = ""

    # ── Step 1: feature extraction ────────────────────────────────────────
    features = extract_password_features(password)

    length    = features["password_length"]
    uppercase = features["uppercase_count"]
    lowercase = features["lowercase_count"]
    digits    = features["digit_count"]
    special   = features["special_character_count"]
    unique    = features["unique_character_count"]
    repeated_count = features["repeated_character_count"]
    char_diversity = features["char_diversity"]

    # Pattern detectors
    entropy_score    = calculate_entropy(password)
    entropy_category = get_entropy_category(entropy_score)
    dictionary_word  = detect_dictionary_word(password)
    keyboard_pattern = detect_keyboard_pattern(password)
    birth_year       = detect_birth_year(password)
    repeated_flag    = detect_repeated_characters(password)
    sequential_flag  = detect_sequential_characters(password)

    # ── Breach check (Step 0 — runs before scoring so threat level is aware) ──
    # Caller may supply is_breached=True to override (e.g. future HIBP API).
    # If not overridden, we run the local dataset check now.
    breach_result = check_breach(password)
    if breach_result["is_breached"]:
        is_breached = True   # override caller's default False

    # ── Step 2: security score ────────────────────────────────────────────
    strength_score = calculate_strength_score(
        length=length,
        uppercase=uppercase,
        lowercase=lowercase,
        digits=digits,
        special=special,
        entropy=entropy_score,
        dictionary_word=dictionary_word,
        keyboard_pattern=keyboard_pattern,
        birth_year=birth_year,
        repeated=repeated_flag,
        sequential=sequential_flag,
    )

    # ── Step 3: strength category (5 tiers) ───────────────────────────────
    strength_category = get_strength_category(strength_score)

    # ── Step 4: threat level ──────────────────────────────────────────────
    threat_level = predict_threat_level(
        strength_score=strength_score,
        entropy=entropy_score,
        length=length,
        is_breached=is_breached,
        dictionary_word=dictionary_word,
        keyboard_pattern=keyboard_pattern,
        birth_year=birth_year,
        repeated=repeated_flag,
        sequential=sequential_flag,
    )
    threat_colour = get_threat_colour(threat_level)
    threat_icon   = get_threat_icon(threat_level)

    # ── Step 5: crack time ────────────────────────────────────────────────
    crack_detail = estimate_crack_time_detailed(
        length=length,
        uppercase=uppercase,
        lowercase=lowercase,
        digits=digits,
        special=special,
        entropy=entropy_score,
    )
    crack_time        = crack_detail["offline_label"]
    crack_time_online = crack_detail["online_label"]
    crack_time_combos = crack_detail["combinations"]

    # ── Step 6: AI findings ───────────────────────────────────────────────
    findings = generate_findings(
        length=length,
        uppercase=uppercase,
        lowercase=lowercase,
        digits=digits,
        special=special,
        entropy=entropy_score,
        char_diversity=char_diversity,
        dictionary_word=dictionary_word,
        keyboard_pattern=keyboard_pattern,
        birth_year=birth_year,
        repeated=repeated_flag,
        repeated_count=repeated_count,
        sequential=sequential_flag,
        strength_score=strength_score,
        is_breached=is_breached,
    )

    # Prepend the breach-specific finding at the top (highest priority)
    breach_finding = get_breach_recommendation(breach_result)
    if breach_finding:
        findings.insert(0, breach_finding)

    # ── Assemble final result ─────────────────────────────────────────────
    return {
        # Step 1 – features
        "password_length":              length,
        "uppercase_count":              uppercase,
        "lowercase_count":              lowercase,
        "digit_count":                  digits,
        "special_character_count":      special,
        "unique_character_count":       unique,
        "repeated_character_count":     repeated_count,
        "char_diversity":               char_diversity,
        "sequential_character_detected": sequential_flag,
        "dictionary_word_detected":     dictionary_word,
        "keyboard_pattern_detected":    keyboard_pattern,
        "birth_year_detected":          birth_year,
        "entropy":                      entropy_score,
        "entropy_category":             entropy_category,

        # Step 2 – score
        "strength_score": strength_score,

        # Step 3 – strength category
        "strength_category": strength_category,

        # Step 4 – threat
        "threat_level":  threat_level,
        "threat_colour": threat_colour,
        "threat_icon":   threat_icon,

        # Step 5 – crack time
        "crack_time":             crack_time,
        "crack_time_online":      crack_time_online,
        "crack_time_combinations": crack_time_combos,

        # Step 6 – findings
        "findings": findings,

        # DB-compatible aliases (match PasswordAnalysis column names)
        "length":          length,
        "uppercase":       uppercase,
        "lowercase":       lowercase,
        "digits":          digits,
        "special":         special,
        "repeated":        repeated_flag,
        "sequential":      sequential_flag,
        "dictionary_word": dictionary_word,
        "keyboard_pattern": keyboard_pattern,
        "birth_year":      birth_year,

        # Meta
        "is_breached":     is_breached,
        "complexity_mode": complexity_mode,
        "threat_model":    threat_model,

        # Breach detail (from local dataset check)
        "breach_is_breached":  breach_result["is_breached"],
        "breach_count":        breach_result["breach_count"],
        "breach_risk":         breach_result["risk"],
        "breach_source":       breach_result["source"],
        "breach_message":      breach_result["message"],
        "breach_dataset_size": breach_result["dataset_size"],
    }
