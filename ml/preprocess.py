"""
ml/preprocess.py — SecureGuard AI
===================================

Loads the raw password dataset and prepares it for model training.

Steps
-----
1. Load CSV  →  raw DataFrame
2. Validate columns and drop rows with missing / invalid values
3. Remove exact duplicates
4. Extract features via feature_builder.build_features_df()
5. Encode target labels with LabelEncoder (preserving LABEL_ORDER)
6. Train / test split  (stratified, 80 / 20)
7. Return X_train, X_test, y_train, y_test, fitted LabelEncoder

No feature scaling is applied here because Random Forest is
scale-invariant.  The scaler hook is left in place as a no-op so callers
that need it can swap it in without changing any other module.

Public API
----------
load_and_preprocess(csv_path, test_size, random_state)
    → PreprocessResult (namedtuple)
"""

from __future__ import annotations

import logging
import sys
from collections import Counter
from pathlib import Path
from typing import NamedTuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from ml import DATASET_CSV, FEATURE_COLUMNS, LABEL_ORDER
from ml.feature_builder import build_features_df

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------

class PreprocessResult(NamedTuple):
    """
    Container for all artefacts produced by load_and_preprocess().

    Attributes
    ----------
    X_train : pd.DataFrame   Feature matrix — training split
    X_test  : pd.DataFrame   Feature matrix — test split
    y_train : np.ndarray     Encoded integer labels — training split
    y_test  : np.ndarray     Encoded integer labels — test split
    encoder : LabelEncoder   Fitted encoder (use .inverse_transform to decode)
    feature_columns : list[str]  Ordered column names (= ml.FEATURE_COLUMNS)
    """

    X_train:         pd.DataFrame
    X_test:          pd.DataFrame
    y_train:         np.ndarray
    y_test:          np.ndarray
    encoder:         LabelEncoder
    feature_columns: list[str]


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def load_and_preprocess(
    csv_path: Path = DATASET_CSV,
    test_size: float = 0.20,
    random_state: int = 42,
) -> PreprocessResult:
    """
    Full preprocessing pipeline for the password strength dataset.

    Parameters
    ----------
    csv_path : Path
        Location of the CSV file produced by generate_dataset.py.
        Defaults to ml.DATASET_CSV.
    test_size : float
        Fraction of data reserved for testing (default 0.20 = 20 %).
    random_state : int
        Seed for reproducible splits (default 42).

    Returns
    -------
    PreprocessResult
        Named tuple with X_train, X_test, y_train, y_test, encoder,
        and feature_columns.

    Raises
    ------
    FileNotFoundError
        If *csv_path* does not exist.
    ValueError
        If required columns are missing or no usable rows remain.
    """
    log.info("=" * 55)
    log.info("Preprocessing pipeline started")
    log.info("Dataset : %s", csv_path)
    log.info("=" * 55)

    # ------------------------------------------------------------------
    # Step 1 — Load CSV
    # ------------------------------------------------------------------
    if not csv_path.is_file():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")

    raw_df = pd.read_csv(csv_path, encoding="utf-8")
    log.info("Step 1  Loaded  : %d rows × %d cols", *raw_df.shape)

    # ------------------------------------------------------------------
    # Step 2 — Validate required columns
    # ------------------------------------------------------------------
    required_cols = {"password", "strength"}
    missing_cols  = required_cols - set(raw_df.columns)
    if missing_cols:
        raise ValueError(f"CSV missing required columns: {missing_cols}")

    # Keep only the two columns we need
    df = raw_df[["password", "strength"]].copy()

    # ------------------------------------------------------------------
    # Step 3 — Handle missing / empty values
    # ------------------------------------------------------------------
    before = len(df)
    df = df.dropna(subset=["password", "strength"])
    df = df[df["password"].astype(str).str.strip() != ""]
    df = df[df["strength"].astype(str).str.strip() != ""]
    dropped_null = before - len(df)
    if dropped_null:
        log.warning("Step 3  Dropped %d rows with missing values", dropped_null)
    else:
        log.info("Step 3  No missing values found")

    # ------------------------------------------------------------------
    # Step 4 — Remove exact duplicates (same password + same label)
    # ------------------------------------------------------------------
    before = len(df)
    df = df.drop_duplicates(subset=["password"])
    dropped_dup = before - len(df)
    if dropped_dup:
        log.warning("Step 4  Removed %d duplicate passwords", dropped_dup)
    else:
        log.info("Step 4  No duplicates found")

    # ------------------------------------------------------------------
    # Step 5 — Keep only known label values
    # ------------------------------------------------------------------
    valid_labels = set(LABEL_ORDER)
    before = len(df)
    df = df[df["strength"].isin(valid_labels)]
    dropped_label = before - len(df)
    if dropped_label:
        log.warning(
            "Step 5  Removed %d rows with unknown label values", dropped_label
        )

    if len(df) == 0:
        raise ValueError("No usable rows remain after cleaning.")

    log.info("Step 5  Clean rows  : %d", len(df))
    dist = Counter(df["strength"].tolist())
    for lbl in LABEL_ORDER:
        log.info("         %-12s: %d", lbl, dist.get(lbl, 0))

    # ------------------------------------------------------------------
    # Step 6 — Feature extraction
    # ------------------------------------------------------------------
    log.info("Step 6  Extracting features …")
    X: pd.DataFrame = build_features_df(df["password"].tolist())
    log.info("Step 6  Feature matrix shape: %s", X.shape)

    # ------------------------------------------------------------------
    # Step 7 — Label encoding
    #
    # We fit on LABEL_ORDER so the integer codes are always:
    #   0 = Very Weak, 1 = Weak, 2 = Moderate, 3 = Strong, 4 = Excellent
    # ------------------------------------------------------------------
    encoder = LabelEncoder()
    encoder.fit(LABEL_ORDER)

    y_raw: np.ndarray = encoder.transform(df["strength"].tolist())
    log.info(
        "Step 7  Label encoding   : %s → %s",
        list(encoder.classes_),
        list(range(len(encoder.classes_))),
    )

    # ------------------------------------------------------------------
    # Step 8 — Stratified train / test split
    # ------------------------------------------------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_raw,
        test_size=test_size,
        random_state=random_state,
        stratify=y_raw,
    )

    log.info(
        "Step 8  Split: train=%d  test=%d  (%.0f/%.0f)",
        len(X_train), len(X_test),
        (1 - test_size) * 100, test_size * 100,
    )

    train_dist = Counter(encoder.inverse_transform(y_train).tolist())
    test_dist  = Counter(encoder.inverse_transform(y_test).tolist())
    for lbl in LABEL_ORDER:
        log.info(
            "         %-12s  train=%-4d  test=%-4d",
            lbl, train_dist.get(lbl, 0), test_dist.get(lbl, 0),
        )

    log.info("Preprocessing complete")
    log.info("=" * 55)

    return PreprocessResult(
        X_train=X_train,
        X_test=X_test,
        y_train=y_train,
        y_test=y_test,
        encoder=encoder,
        feature_columns=FEATURE_COLUMNS,
    )


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )
    result = load_and_preprocess()
    print("\nX_train columns :", list(result.X_train.columns))
    print("X_train shape   :", result.X_train.shape)
    print("y_train sample  :", result.y_train[:10])
    print("Label classes   :", list(result.encoder.classes_))
