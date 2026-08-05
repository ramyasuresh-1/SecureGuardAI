"""
ml — SecureGuard AI Machine Learning Package
=============================================

Provides a standalone, production-quality pipeline for training and serving
a password-strength classifier using scikit-learn.

Sub-modules
-----------
feature_builder   Extract numerical/boolean features from raw passwords.
preprocess        Clean data, encode labels, split and scale.
evaluate          Compute and persist all evaluation metrics.
predict           Load saved artifacts and predict on new passwords.
train_model       Top-level orchestrator — run this module directly.

Typical usage
-------------
    python ml/train_model.py

No Flask imports are used here; this package is fully independent of the
web application so it can be run, tested, and deployed separately.
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Package-level path constants used by every sub-module
# ---------------------------------------------------------------------------

# Root of the SecureGuard AI project  (two levels up from this file)
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent

# Well-known directories
ML_DIR:        Path = PROJECT_ROOT / "ml"
ARTIFACTS_DIR: Path = ML_DIR / "artifacts"
LOGS_DIR:      Path = ML_DIR / "logs"
MODELS_DIR:    Path = ML_DIR / "models"
DATASETS_DIR:  Path = PROJECT_ROOT / "datasets"

# Dataset
DATASET_CSV: Path = DATASETS_DIR / "password_dataset.csv"

# Saved artifact file-names
MODEL_FILE:   Path = ARTIFACTS_DIR / "password_strength_model.pkl"
ENCODER_FILE: Path = ARTIFACTS_DIR / "label_encoder.pkl"
COLUMNS_FILE: Path = ARTIFACTS_DIR / "feature_columns.pkl"
METRICS_FILE: Path = ARTIFACTS_DIR / "metrics.json"

# Ordered list of feature column names produced by feature_builder
FEATURE_COLUMNS: list[str] = [
    "password_length",
    "uppercase_count",
    "lowercase_count",
    "digit_count",
    "special_character_count",
    "unique_character_count",
    "repeated_character_count",
    "char_diversity",
    "entropy",
    "dictionary_word",
    "sequential_chars",
    "keyboard_pattern",
]

# Canonical label order (weakest → strongest)
LABEL_ORDER: list[str] = [
    "Very Weak",
    "Weak",
    "Moderate",
    "Strong",
    "Excellent",
]

# Ensure all runtime directories exist
for _d in (ARTIFACTS_DIR, LOGS_DIR, MODELS_DIR):
    _d.mkdir(parents=True, exist_ok=True)
