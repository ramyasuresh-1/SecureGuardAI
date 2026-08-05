"""
ml/feature_builder.py — SecureGuard AI
=======================================

Converts a raw password string into a fixed-width numerical feature vector
ready for scikit-learn estimators.

All feature logic is delegated to the existing utils/ modules so there is
zero duplication with the live analyzer.

Public API
----------
build_features(password)  →  dict[str, float | int | bool]
build_features_df(passwords)  →  pandas.DataFrame

Feature columns (12 total, ordered to match ml.FEATURE_COLUMNS):
    password_length          int    total character count
    uppercase_count          int    A-Z characters
    lowercase_count          int    a-z characters
    digit_count              int    0-9 characters
    special_character_count  int    non-alphanumeric printable characters
    unique_character_count   int    number of distinct characters
    repeated_character_count int    characters that appear > once
    char_diversity           float  unique / total  (0.0 – 1.0)
    entropy                  float  Shannon entropy in bits
    dictionary_word          int    1 if common word detected, else 0
    sequential_chars         int    1 if sequential run detected, else 0
    keyboard_pattern         int    1 if keyboard sequence detected, else 0
"""

from __future__ import annotations

import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd

# ---------------------------------------------------------------------------
# Path bootstrap — safe to run directly or imported from any working dir
# ---------------------------------------------------------------------------
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from utils.entropy import calculate_entropy
from utils.pattern_detector import (
    detect_dictionary_word,
    detect_keyboard_pattern,
    detect_sequential_characters,
)

# Import the canonical column list from the package __init__
from ml import FEATURE_COLUMNS

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core feature extraction
# ---------------------------------------------------------------------------

def build_features(password: str) -> dict[str, Any]:
    """
    Extract a fixed feature dictionary from a single password string.

    Parameters
    ----------
    password : str
        The plaintext password to analyse.  Non-string values are coerced
        to empty string so the function never raises on bad input.

    Returns
    -------
    dict[str, int | float]
        Keys match ``ml.FEATURE_COLUMNS`` exactly so the result can be
        consumed directly by scikit-learn pipelines.

    Examples
    --------
    >>> build_features("Admin@123")
    {'password_length': 9, 'uppercase_count': 1, 'lowercase_count': 4,
     'digit_count': 3, 'special_character_count': 1, 'unique_character_count': 9,
     'repeated_character_count': 0, 'char_diversity': 1.0, 'entropy': 3.17,
     'dictionary_word': 1, 'sequential_chars': 0, 'keyboard_pattern': 0}
    """
    if not isinstance(password, str):
        log.debug("Non-string input coerced to empty string: %r", password)
        password = ""

    # ── Composition counts ────────────────────────────────────────────────
    length    = len(password)
    uppercase = sum(1 for c in password if c.isupper())
    lowercase = sum(1 for c in password if c.islower())
    digits    = sum(1 for c in password if c.isdigit())
    special   = sum(1 for c in password if not c.isalnum())

    # ── Uniqueness metrics ────────────────────────────────────────────────
    freq           = Counter(password)
    unique_count   = len(freq)                                   # distinct chars
    repeated_count = sum(1 for v in freq.values() if v > 1)     # chars used > once
    char_diversity = round(unique_count / length, 4) if length else 0.0

    # ── Entropy ───────────────────────────────────────────────────────────
    entropy = calculate_entropy(password)   # Shannon entropy (bits per char)

    # ── Pattern flags (cast to int for sklearn compatibility) ─────────────
    dict_word   = int(detect_dictionary_word(password))
    sequential  = int(detect_sequential_characters(password))
    keyboard    = int(detect_keyboard_pattern(password))

    return {
        "password_length":          length,
        "uppercase_count":          uppercase,
        "lowercase_count":          lowercase,
        "digit_count":              digits,
        "special_character_count":  special,
        "unique_character_count":   unique_count,
        "repeated_character_count": repeated_count,
        "char_diversity":           char_diversity,
        "entropy":                  entropy,
        "dictionary_word":          dict_word,
        "sequential_chars":         sequential,
        "keyboard_pattern":         keyboard,
    }


def build_features_df(passwords: list[str]) -> pd.DataFrame:
    """
    Build a feature DataFrame from a list of passwords.

    Parameters
    ----------
    passwords : list[str]
        Raw passwords (or any iterable of strings).

    Returns
    -------
    pd.DataFrame
        Shape (n_passwords, 12).  Column order is guaranteed to match
        ``ml.FEATURE_COLUMNS`` so the DataFrame can be fed directly into
        a fitted sklearn Pipeline without column-order issues.

    Raises
    ------
    ValueError
        If *passwords* is empty.
    """
    if not passwords:
        raise ValueError("passwords list must not be empty")

    rows = [build_features(pw) for pw in passwords]
    df   = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    log.debug("Built feature matrix: shape=%s", df.shape)
    return df


# ---------------------------------------------------------------------------
# Standalone smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    samples = [
        "abc",
        "password1",
        "Admin@123",
        "P@ssw0rdStrong!9",
        "Q7#xP!9Lm@2K",
        "Alpha!Bravo@Cobra#Delta1234!",
    ]

    log.info("Feature extraction smoke-test")
    log.info("%-30s  %s", "Password", "Features")
    log.info("-" * 90)
    for pw in samples:
        feats = build_features(pw)
        log.info(
            "%-30s  len=%-3d up=%-2d lo=%-2d d=%-2d sp=%-2d div=%.2f ent=%.2f"
            "  dict=%d seq=%d kbd=%d",
            repr(pw),
            feats["password_length"],
            feats["uppercase_count"],
            feats["lowercase_count"],
            feats["digit_count"],
            feats["special_character_count"],
            feats["char_diversity"],
            feats["entropy"],
            feats["dictionary_word"],
            feats["sequential_chars"],
            feats["keyboard_pattern"],
        )

    df = build_features_df(samples)
    log.info("DataFrame shape: %s", df.shape)
    log.info("Columns: %s", list(df.columns))
