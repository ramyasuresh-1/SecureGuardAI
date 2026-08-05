"""
Breach Detection module for SecureGuard AI.

Checks a submitted password against the local RockYou sample dataset
stored at datasets/rockyou_sample.txt.

Public API
----------
    check_breach(password) -> dict

The dataset is read once into a module-level set on the first call and
reused for every subsequent call (O(1) lookup, no repeated file I/O).

Return schema
-------------
    {
        "is_breached":  bool   - True if the password was found in the dataset
        "breach_count": int    - 1 if found, 0 if not
        "risk":         str    - "Critical" | "High" | "Medium" | "Low" | "Safe"
        "source":       str    - Human-readable dataset label
    }

Risk tiers are derived from the password's rank (line position) in the
file.  Passwords that appear earlier in the ranked list are more widely
known and therefore carry a higher risk.
"""

from __future__ import annotations

import os
from functools import lru_cache


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Absolute path to the dataset, derived from this file's location so the
# module works regardless of the current working directory.
_BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATASET_PATH  = os.path.join(_BASE_DIR, "datasets", "rockyou_sample.txt")

# Human-readable label returned in every result dict
SOURCE_LABEL = "RockYou Sample"

# Rank thresholds that determine the risk tier when a password IS found.
# rank = line number (1-based) in the file; lower rank = more common = worse.
_CRITICAL_RANK = 50    # rank  1 – 50   → Critical
_HIGH_RANK     = 150   # rank 51 – 150  → High
_MEDIUM_RANK   = 350   # rank 151 – 350 → Medium
                       # rank > 350     → Low  (still breached, less common)


# ---------------------------------------------------------------------------
# Dataset loader  (executed only once per process lifetime)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _load_dataset() -> dict[str, int]:
    """
    Read the breach dataset into a dict mapping password → rank (1-based).

    Using a dict instead of a set lets us return the rank so the caller
    can compute a meaningful risk tier.  lru_cache ensures the file is
    opened exactly once across all requests.

    Returns an empty dict if the file does not exist or cannot be read,
    so the rest of the application continues to function gracefully.
    """
    index: dict[str, int] = {}

    if not os.path.isfile(_DATASET_PATH):
        # Dataset file missing — breach detection silently disabled
        return index

    try:
        with open(_DATASET_PATH, "r", encoding="utf-8", errors="replace") as fh:
            for rank, raw_line in enumerate(fh, start=1):
                password = raw_line.rstrip("\r\n")
                if password and password not in index:
                    # Keep first occurrence so rank reflects original ordering
                    index[password] = rank
    except OSError:
        # Unreadable file — return empty dict, skip detection
        pass

    return index


# ---------------------------------------------------------------------------
# Risk tier helper
# ---------------------------------------------------------------------------

def _rank_to_risk(rank: int) -> str:
    """
    Map a 1-based rank to a risk tier string.

    Parameters
    ----------
    rank : int
        Position of the password in the breach file (1 = most common).

    Returns
    -------
    str
        One of "Critical", "High", "Medium", "Low".
    """
    if rank <= _CRITICAL_RANK:
        return "Critical"
    if rank <= _HIGH_RANK:
        return "High"
    if rank <= _MEDIUM_RANK:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def check_breach(password: str) -> dict:
    """
    Check whether *password* appears in the local breach dataset.

    The plaintext password is never logged, stored, or transmitted.
    It is used only for an in-memory lookup and then discarded.

    Parameters
    ----------
    password : str
        The candidate password to check.

    Returns
    -------
    dict
        {
            "is_breached":  bool  - True if found in the dataset
            "breach_count": int   - 1 if found, 0 if not
            "risk":         str   - "Critical"|"High"|"Medium"|"Low"|"Safe"
            "source":       str   - dataset label ("RockYou Sample")
        }

    Examples
    --------
    >>> check_breach("password")
    {'is_breached': True, 'breach_count': 1, 'risk': 'Critical', 'source': 'RockYou Sample'}

    >>> check_breach("Q7#xP!9Lm@2K")
    {'is_breached': False, 'breach_count': 0, 'risk': 'Safe', 'source': 'RockYou Sample'}
    """
    # Guard: empty or non-string input is treated as not found
    if not isinstance(password, str) or not password:
        return {
            "is_breached":  False,
            "breach_count": 0,
            "risk":         "Safe",
            "source":       SOURCE_LABEL,
        }

    index = _load_dataset()
    rank  = index.get(password, 0)   # 0 means not found

    if rank == 0:
        # Password not present in breach dataset
        return {
            "is_breached":  False,
            "breach_count": 0,
            "risk":         "Safe",
            "source":       SOURCE_LABEL,
        }

    # Password found — return breach details
    return {
        "is_breached":  True,
        "breach_count": 1,           # spec: 1 if found, 0 if not
        "risk":         _rank_to_risk(rank),
        "source":       SOURCE_LABEL,
    }
