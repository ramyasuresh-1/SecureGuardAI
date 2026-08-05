"""
Breach Detection Engine for SecureGuard AI.

Checks a password against a local breach dataset (RockYou sample) stored at
datasets/rockyou_sample.txt, relative to the project root.

Public API
----------
check_breach(password)  →  BreachResult dict

The dataset is loaded once into a module-level set on first call (lazy-load).
Subsequent calls are O(1) hash lookups — no file I/O after the first call.

Design decisions
----------------
* Case-sensitive matching: breach databases store passwords exactly as they
  were leaked, so "Password" and "password" are treated differently.
* We never log or persist the plaintext password — only the boolean result
  and the count returned to the caller.
* The "breach_count" field is the position in the ranked list (1-indexed)
  when found, giving a rough indication of how common the password is.
  For passwords not in the file it is 0.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any


# ---------------------------------------------------------------------------
# Dataset path
# ---------------------------------------------------------------------------

_BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATASET_PATH = os.path.join(_BASE_DIR, "datasets", "rockyou_sample.txt")

# ---------------------------------------------------------------------------
# Risk tier thresholds
# ---------------------------------------------------------------------------
# breach_count is the 1-based position in the file.
# Passwords that appear earlier in the ranked list are more dangerous.

_RISK_CRITICAL_THRESHOLD = 50    # top-50 most common → Critical
_RISK_HIGH_THRESHOLD     = 150   # top-150              → High
_RISK_MEDIUM_THRESHOLD   = 350   # top-350              → Medium
# beyond that                   → Low (still breached, but less common)

SOURCE_LABEL = "RockYou Sample"


# ---------------------------------------------------------------------------
# Dataset loader  (loaded once, never reloaded)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _load_dataset() -> tuple[dict[str, int], int]:
    """
    Load the breach dataset into memory.

    Returns
    -------
    index : dict[str, int]
        Maps each password to its 1-based rank position in the file.
    total : int
        Total number of entries loaded.

    On any I/O error an empty dataset is returned so the rest of the
    application continues to function without breach detection.
    """
    index: dict[str, int] = {}

    if not os.path.isfile(_DATASET_PATH):
        return index, 0

    try:
        with open(_DATASET_PATH, "r", encoding="utf-8", errors="replace") as fh:
            for position, line in enumerate(fh, start=1):
                word = line.rstrip("\n\r")
                if word and word not in index:      # keep first occurrence
                    index[word] = position
    except OSError:
        pass

    return index, len(index)


# ---------------------------------------------------------------------------
# Public helper
# ---------------------------------------------------------------------------

def check_breach(password: str) -> dict[str, Any]:
    """
    Check whether *password* appears in the local breach dataset.

    Parameters
    ----------
    password : str
        The plaintext password to check.  Never stored or logged by this
        function.

    Returns
    -------
    dict with keys:
        is_breached   bool    True  if the password was found in the dataset.
        breach_count  int     Rank position (1-based) if found, else 0.
                              Lower = more common = higher risk.
        risk          str     "Critical" | "High" | "Medium" | "Low" | "Safe"
        source        str     Human-readable source label.
        dataset_size  int     Total passwords checked against.
        message       str     Short human-readable summary.
    """
    if not isinstance(password, str) or not password:
        return _safe_result(dataset_size=0)

    index, total = _load_dataset()

    rank = index.get(password, 0)   # 0 → not found

    if rank == 0:
        # Not in breach database
        return {
            "is_breached":  False,
            "breach_count": 0,
            "risk":         "Safe",
            "source":       SOURCE_LABEL,
            "dataset_size": total,
            "message":      "Password not found in known breach databases.",
        }

    # Found — compute risk tier from rank
    if rank <= _RISK_CRITICAL_THRESHOLD:
        risk = "Critical"
        message = (
            f"This password is one of the {rank} most common leaked passwords. "
            "It will be cracked in under a second. Change it immediately."
        )
    elif rank <= _RISK_HIGH_THRESHOLD:
        risk = "High"
        message = (
            f"This password is ranked #{rank} in known breach lists. "
            "It is very commonly used and easily guessable."
        )
    elif rank <= _RISK_MEDIUM_THRESHOLD:
        risk = "Medium"
        message = (
            f"This password appears at position #{rank} in a breach dataset. "
            "Consider using a stronger, unique password."
        )
    else:
        risk = "Low"
        message = (
            f"This password was found in a breach dataset (rank #{rank}). "
            "Although not among the most common, it has been exposed."
        )

    return {
        "is_breached":  True,
        "breach_count": rank,
        "risk":         risk,
        "source":       SOURCE_LABEL,
        "dataset_size": total,
        "message":      message,
    }


def _safe_result(dataset_size: int) -> dict[str, Any]:
    """Return a 'safe' result when the password cannot be checked."""
    return {
        "is_breached":  False,
        "breach_count": 0,
        "risk":         "Safe",
        "source":       SOURCE_LABEL,
        "dataset_size": dataset_size,
        "message":      "Password not found in known breach databases.",
    }


def get_breach_recommendation(breach_result: dict[str, Any]) -> dict[str, str]:
    """
    Return an AI finding dict (same shape as recommendations.generate_findings)
    specifically for a breach hit.  Returns None when not breached.

    Used by the findings renderer so breach info appears as a top-priority
    finding in the AI Findings panel.
    """
    if not breach_result.get("is_breached"):
        return None                                     # type: ignore[return-value]

    risk  = breach_result["risk"]
    rank  = breach_result["breach_count"]
    src   = breach_result["source"]

    severity_map = {
        "Critical": "danger",
        "High":     "danger",
        "Medium":   "warning",
        "Low":      "warning",
    }

    return {
        "icon":     "fas fa-radiation",
        "text":     (
            f"BREACH DETECTED — Found in {src} at rank #{rank}. "
            f"Risk level: {risk}. {breach_result['message']}"
        ),
        "severity": severity_map.get(risk, "danger"),
    }
