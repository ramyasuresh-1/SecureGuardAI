"""
Dataset generator for SecureGuard AI ML pipeline.

Builds a balanced, labelled password dataset and writes it to
datasets/password_dataset.csv.

Labels come from the same scoring function used by the live analyzer so
the ML model learns to replicate that exact logic.

Target: 600 confirmed samples per class (3 000 total).

Run once:
    python ml/generate_dataset.py
"""

from __future__ import annotations

import csv
import logging
import random
import string
import sys
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# Path bootstrap — works from any working directory
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Reuse the same scoring logic as the live analyzer (no duplication)
# ---------------------------------------------------------------------------
from utils.strength import calculate_strength_score, get_strength_category
from utils.entropy import calculate_entropy
from utils.pattern_detector import (
    detect_birth_year,
    detect_dictionary_word,
    detect_keyboard_pattern,
    detect_repeated_characters,
    detect_sequential_characters,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DATASET_PATH: Path = PROJECT_ROOT / "datasets" / "password_dataset.csv"
TARGET_PER_CLASS: int = 600
SEED: int = 42
MAX_ATTEMPTS_MULTIPLIER: int = 50   # max_attempts = target * this

LOWER   = string.ascii_lowercase
UPPER   = string.ascii_uppercase
DIGITS  = string.digits
SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?"
ALL     = LOWER + UPPER + DIGITS + SPECIAL

random.seed(SEED)


# ---------------------------------------------------------------------------
# Ground-truth labeller
# ---------------------------------------------------------------------------

def _score_and_label(pw: str) -> tuple[int, str]:
    """Return (score, category) for *pw* using the live scoring formula."""
    l  = len(pw)
    u  = sum(1 for c in pw if c.isupper())
    lo = sum(1 for c in pw if c.islower())
    d  = sum(1 for c in pw if c.isdigit())
    s  = sum(1 for c in pw if not c.isalnum())
    e  = calculate_entropy(pw)
    sc = calculate_strength_score(
        length=l, uppercase=u, lowercase=lo, digits=d, special=s, entropy=e,
        dictionary_word=detect_dictionary_word(pw),
        keyboard_pattern=detect_keyboard_pattern(pw),
        birth_year=detect_birth_year(pw),
        repeated=detect_repeated_characters(pw),
        sequential=detect_sequential_characters(pw),
    )
    return sc, get_strength_category(sc)


# ---------------------------------------------------------------------------
# Character helpers
# ---------------------------------------------------------------------------

def _rnd(chars: str, n: int) -> str:
    return "".join(random.choices(chars, k=n))


def _shuffle(s: str) -> str:
    lst = list(s)
    random.shuffle(lst)
    return "".join(lst)


# ---------------------------------------------------------------------------
# Tier generators
#
# Each function returns a *candidate* string shaped to land in its tier.
# The caller verifies the actual score and discards mismatches.
#
# Score boundaries (from utils/strength.py):
#   Very Weak  :  0 – 29
#   Weak       : 30 – 49
#   Moderate   : 50 – 69
#   Strong     : 70 – 84
#   Excellent  : 85 – 100
# ---------------------------------------------------------------------------

def _gen_very_weak() -> str:
    """Score < 30: very short, all-same-class, or infamous dictionary words."""
    t = random.randint(0, 6)
    if t == 0:
        return _rnd(LOWER, random.randint(3, 5))
    if t == 1:
        return _rnd(DIGITS, random.randint(3, 6))
    if t == 2:
        return random.choice([
            "password", "qwerty", "letmein", "login", "admin", "welcome",
            "hello", "monkey", "dragon", "master", "abc", "pass", "test",
            "user", "root", "guest", "iloveyou", "sunshine", "princess",
        ])
    if t == 3:
        return random.choice(["qwerty", "asdf", "zxcv", "12345", "abcdef"])
    if t == 4:
        return _rnd(LOWER, 2) + _rnd(DIGITS, 2)        # total 4 chars
    if t == 5:
        c = random.choice(LOWER)
        return c * random.randint(4, 7)                 # aaaaaaa
    # single uppercase + lower, very short
    return _rnd(UPPER, 1) + _rnd(LOWER, random.randint(2, 4))


def _gen_weak() -> str:
    """Score 30–49: short, limited variety."""
    t = random.randint(0, 5)
    if t == 0:
        return _rnd(LOWER, random.randint(7, 9))
    if t == 1:
        return _rnd(LOWER, random.randint(5, 7)) + _rnd(DIGITS, 2)
    if t == 2:
        word = random.choice([
            "password", "dragon", "monkey", "sunshine", "flower",
            "shadow", "master", "michael", "jessica", "charlie",
            "thomas", "ranger", "jordan", "hunter", "buster",
        ])
        return word + str(random.randint(1, 999))
    if t == 3:
        return _rnd(UPPER, 1) + _rnd(LOWER, random.randint(6, 8))
    if t == 4:
        return _rnd(DIGITS, random.randint(7, 10))
    # lower + 1 digit
    return _rnd(LOWER, random.randint(6, 8)) + _rnd(DIGITS, 1)


def _gen_moderate() -> str:
    """
    Score 50–69: medium length, 2–3 char classes.

    Key insight from scoring formula:
      score += min(20, uppercase * 2.5)   → 8 uppercase = 20 pts
      score += min(15, special   * 5.0)   → 3 special   = 15 pts
    A 9-char password with 2 upper + 1 special scores ~55 reliably.
    """
    t = random.randint(0, 5)
    if t == 0:
        # upper + lower + digits, 9–11 chars
        return _shuffle(
            _rnd(UPPER, random.randint(2, 3))
            + _rnd(LOWER, random.randint(4, 6))
            + _rnd(DIGITS, random.randint(2, 3))
        )
    if t == 1:
        # lower + 1 special
        return _rnd(LOWER, random.randint(8, 11)) + _rnd(SPECIAL, 1)
    if t == 2:
        # capitalised word + 2-4 digits + 1 special
        word = random.choice([
            "Security", "Ranger", "Thunder", "Falcon", "Eclipse",
            "Blizzard", "Phoenix", "Jupiter", "Neptune", "Saturn",
        ])
        return word + _rnd(DIGITS, random.randint(2, 3)) + _rnd(SPECIAL, 1)
    if t == 3:
        # upper + lower + special, no digits
        return _shuffle(
            _rnd(UPPER, random.randint(2, 4))
            + _rnd(LOWER, random.randint(5, 7))
            + _rnd(SPECIAL, 1)
        )
    if t == 4:
        # pure random 9-11 chars — will score 50-65 range
        return _rnd(ALL, random.randint(9, 11))
    # digits sandwich
    return _rnd(DIGITS, 2) + _rnd(LOWER, random.randint(6, 8)) + _rnd(DIGITS, 2)


def _gen_strong() -> str:
    """
    Score 70–84: 12–15 chars, all four classes.

    Formula max points:
      length   : min(30, 12*2.2) = 26.4
      uppercase: min(20, 4*2.5)  = 10
      lowercase: min(20, 5*1.5)  = 7.5
      digits   : min(15, 3*3.0)  = 9
      special  : min(15, 2*5.0)  = 10
      entropy  : ~3.9 bits → 17.5
      total ≈ 80  (Strong tier)
    """
    t = random.randint(0, 3)
    if t == 0:
        # All four classes, 12–14 chars
        return _shuffle(
            _rnd(UPPER,   random.randint(3, 5))
            + _rnd(LOWER,   random.randint(4, 6))
            + _rnd(DIGITS,  random.randint(2, 3))
            + _rnd(SPECIAL, random.randint(2, 3))
        )
    if t == 1:
        # Random from full charset, 13–15 chars
        return _rnd(ALL, random.randint(13, 15))
    if t == 2:
        # Two-word + digits + specials
        words = ["Sky", "Blue", "Rock", "Fire", "Moon",
                 "Star", "Wind", "Wave", "Ice", "Gold"]
        return _shuffle(
            "".join(random.sample(words, 2))
            + _rnd(DIGITS,  random.randint(2, 4))
            + _rnd(SPECIAL, random.randint(1, 2))
        )
    # lower + upper + digits + specials, slightly shorter
    return _shuffle(
        _rnd(LOWER,   random.randint(5, 7))
        + _rnd(UPPER,   random.randint(3, 4))
        + _rnd(DIGITS,  2)
        + _rnd(SPECIAL, 2)
    )


def _gen_excellent() -> str:
    """
    Score >= 85: needs 21+ chars to cross the threshold reliably.

    Minimum confirmed recipe (from formula analysis):
        length 21 → min(30, 21*2.2) = 30
        upper   4 → min(20,  4*2.5) = 10
        lower   9 → min(20,  9*1.5) = 13.5
        digits  5 → min(15,  5*3.0) = 15
        special 3 → min(15,  3*5.0) = 15
        entropy ~3.5 → 1.6
        total ≈ 85.1  → Excellent

    We use 22–28 chars with guaranteed class representation.
    """
    t = random.randint(0, 2)
    if t == 0:
        # Exact recipe: 22–26 chars, all four classes
        length = random.randint(22, 26)
        n_sp = random.randint(3, 5)
        n_d  = random.randint(4, 6)
        n_up = random.randint(4, 6)
        n_lo = length - n_sp - n_d - n_up
        if n_lo < 1:
            n_lo = 1
        return _shuffle(
            _rnd(UPPER,   n_up)
            + _rnd(LOWER,   n_lo)
            + _rnd(DIGITS,  n_d)
            + _rnd(SPECIAL, n_sp)
        )
    if t == 1:
        # Full-random long password — with 22+ chars almost always hits 85+
        return _rnd(ALL, random.randint(22, 28))
    # Passphrase: Word!Word@Word#Word + digits + special
    words = ["Alpha", "Bravo", "Cobra", "Delta", "Eagle",
             "Foxtrot", "Hotel", "India", "Kilo", "Lima",
             "Mango", "Nobel", "Oscar", "Prime", "Queen"]
    w = random.sample(words, 4)
    seps = random.choices(list(SPECIAL), k=3)
    return (
        w[0] + seps[0]
        + w[1] + seps[1]
        + w[2] + seps[2]
        + w[3] + _rnd(DIGITS, 4)
    )


# ---------------------------------------------------------------------------
# Generation loop
# ---------------------------------------------------------------------------

_GENERATORS = {
    "Very Weak": _gen_very_weak,
    "Weak":      _gen_weak,
    "Moderate":  _gen_moderate,
    "Strong":    _gen_strong,
    "Excellent": _gen_excellent,
}


def generate_dataset(target_per_class: int = TARGET_PER_CLASS) -> list[tuple[str, str]]:
    """
    Generate a balanced, score-verified labelled dataset.

    Every password is run through the live scoring formula before being
    added to the dataset.  Passwords that score into the wrong tier are
    silently discarded so the ground-truth labels are always accurate.

    Returns
    -------
    list[tuple[str, str]]
        Each entry is (plaintext_password, strength_label).
    """
    records: list[tuple[str, str]] = []
    counts: dict[str, int] = {lbl: 0 for lbl in _GENERATORS}
    seen: set[str] = set()
    max_attempts = target_per_class * MAX_ATTEMPTS_MULTIPLIER

    for label, generator in _GENERATORS.items():
        attempts = 0
        log.info("Generating %-4d samples for class '%-10s' …", target_per_class, label)
        while counts[label] < target_per_class and attempts < max_attempts:
            attempts += 1
            pw = generator()
            if not pw or pw in seen:
                continue
            _, actual_label = _score_and_label(pw)
            if actual_label != label:
                continue          # wrong tier — discard
            seen.add(pw)
            records.append((pw, label))
            counts[label] += 1

        got = counts[label]
        if got < target_per_class:
            log.warning(
                "Class '%-10s': %d/%d after %d attempts  ⚠",
                label, got, target_per_class, attempts,
            )
        else:
            log.info("Class '%-10s': %d/%d  ✓", label, got, target_per_class)

    random.shuffle(records)
    return records


def write_csv(records: list[tuple[str, str]], path: Path) -> None:
    """Write (password, strength) rows to *path* as CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["password", "strength"])
        writer.writerows(records)
    log.info("CSV written → %s  (%d rows)", path, len(records))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    log.info("=" * 60)
    log.info("SecureGuard AI — Balanced Dataset Generator")
    log.info("=" * 60)

    records = generate_dataset(TARGET_PER_CLASS)
    dist    = Counter(lbl for _, lbl in records)

    log.info("Distribution: %s", dict(dist))
    log.info("Total rows  : %d", len(records))

    write_csv(records, DATASET_PATH)
    log.info("Done.")
