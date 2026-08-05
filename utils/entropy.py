"""Utilities for password entropy calculations."""

import math
from collections import Counter


def calculate_entropy(password: str) -> float:
    """Calculate the Shannon entropy of a password in bits."""
    if not password or not isinstance(password, str):
        return 0.0

    length = len(password)
    if length == 0:
        return 0.0

    counts = Counter(password)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 2)


def get_entropy_category(entropy_score: float) -> str:
    """Map an entropy value to a human-readable confidence category."""
    if entropy_score < 28:
        return "Very Weak"
    if entropy_score < 36:
        return "Weak"
    if entropy_score < 44:
        return "Medium"
    if entropy_score < 52:
        return "Strong"
    return "Very Strong"
