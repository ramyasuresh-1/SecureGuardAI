"""
Utilities for estimating password cracking time.

Strategy
--------
We estimate the keyspace size from character-set composition, then divide
by an assumed attacker guess rate.  Two attacker models are used:

  • Online  – throttled web-login:     100 guesses / second
  • Offline – modern GPU hash-cracker: 1,000,000,000 (1e9) guesses / second

The function returns a human-readable label based on the *offline* model,
which is the more realistic threat for data-breach scenarios.

Keyspace is calculated from the character classes present in the password:
  • Lowercase letters  : 26
  • Uppercase letters  : 26
  • Digits             : 10
  • Special characters : 32  (printable ASCII minus alphanumerics)

Total combinations = keyspace_size ^ password_length

We also incorporate Shannon entropy as a cross-check:
  effective_combinations = min(keyspace_combinations, 2 ** (entropy_bits * length))
"""

from __future__ import annotations

import math


# ---------------------------------------------------------------------------
# Attacker models (guesses per second)
# ---------------------------------------------------------------------------
_ONLINE_GPS  = 100          # online, throttled
_OFFLINE_GPS = 1_000_000_000  # offline GPU (bcrypt-equivalent adjusted)


def _keyspace_size(
    uppercase: int,
    lowercase: int,
    digits: int,
    special: int,
) -> int:
    """Return the character-set size based on which classes are present."""
    size = 0
    if lowercase > 0:
        size += 26
    if uppercase > 0:
        size += 26
    if digits > 0:
        size += 10
    if special > 0:
        size += 32
    return max(size, 1)  # guard against empty password


def estimate_combinations(
    length: int,
    uppercase: int,
    lowercase: int,
    digits: int,
    special: int,
    entropy: float,
) -> float:
    """Return the estimated number of unique guesses needed to crack the password."""
    keyspace = _keyspace_size(uppercase, lowercase, digits, special)

    # Brute-force combinations based on character set
    brute_force = keyspace ** length if length > 0 else 1.0

    # Entropy-based estimate: 2^(entropy * length) but capped to avoid overflow
    # Use log-space arithmetic to stay numerically stable
    entropy_exp = entropy * length
    if entropy_exp > 300:           # 2^300 is already "centuries" level
        entropy_combinations = 2.0 ** 300
    else:
        entropy_combinations = 2.0 ** entropy_exp if entropy_exp > 0 else 1.0

    # Take the more conservative (lower) estimate
    return min(brute_force, entropy_combinations)


def _seconds_to_label(seconds: float) -> str:
    """Convert a number of seconds into a human-readable crack-time label."""
    if seconds < 1:
        return "Instant"
    if seconds < 60:
        return "Seconds"
    if seconds < 3_600:
        return "Minutes"
    if seconds < 86_400:
        return "Hours"
    if seconds < 86_400 * 30:
        return "Days"
    if seconds < 86_400 * 365:
        return "Months"
    if seconds < 86_400 * 365 * 100:
        return "Years"
    return "Centuries"


def estimate_crack_time(
    length: int,
    uppercase: int,
    lowercase: int,
    digits: int,
    special: int,
    entropy: float,
) -> str:
    """
    Return a human-readable offline crack-time label for a password.

    Parameters match the fields stored in PasswordAnalysis so the function
    can be called directly from the feature-extraction pipeline.
    """
    if length == 0:
        return "Instant"

    combos = estimate_combinations(length, uppercase, lowercase, digits, special, entropy)

    # Offline model: divide by GPU guess rate
    seconds = combos / _OFFLINE_GPS

    return _seconds_to_label(seconds)


def estimate_crack_time_detailed(
    length: int,
    uppercase: int,
    lowercase: int,
    digits: int,
    special: int,
    entropy: float,
) -> dict:
    """
    Return both online and offline estimates plus the raw combination count.

    Useful for the analysis results panel.
    """
    if length == 0:
        return {
            "combinations": 1,
            "online_label":  "Instant",
            "offline_label": "Instant",
        }

    combos = estimate_combinations(length, uppercase, lowercase, digits, special, entropy)

    online_secs  = combos / _ONLINE_GPS
    offline_secs = combos / _OFFLINE_GPS

    # Format combination count for display (avoid scientific notation)
    if combos >= 1e18:
        combos_display = f">{1e18:.0e}"
    else:
        combos_display = f"{combos:.2e}"

    return {
        "combinations":  combos_display,
        "online_label":  _seconds_to_label(online_secs),
        "offline_label": _seconds_to_label(offline_secs),
    }
