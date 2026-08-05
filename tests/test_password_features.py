import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utils.feature_extraction import analyze_password


def test_analyze_password_returns_expected_structure():
    result = analyze_password("Password123!")

    assert set(result.keys()) == {
        "length",
        "uppercase",
        "lowercase",
        "digits",
        "special",
        "entropy",
        "entropy_category",
        "dictionary_word",
        "keyboard_pattern",
        "birth_year",
        "repeated",
        "sequential",
        "strength_score",
        "strength_category",
    }
    assert result["length"] == 12
    assert result["strength_category"] in {"Weak", "Moderate", "Strong", "Excellent"}
