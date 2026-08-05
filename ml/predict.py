"""
ml/predict.py — SecureGuard AI
================================

Loads the trained artifacts and provides a clean prediction interface
for single passwords or batches.

This module is completely independent of Flask — it can be imported by
the web application without pulling in any training dependencies.

Public API
----------
load_artifacts()            → PredictorArtifacts (namedtuple)
predict_password(password)  → PredictionResult   (namedtuple)
predict_batch(passwords)    → list[PredictionResult]
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, NamedTuple

import joblib
import numpy as np

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from ml import COLUMNS_FILE, ENCODER_FILE, LABEL_ORDER, MODEL_FILE
from ml.feature_builder import build_features_df

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Named-tuple types
# ---------------------------------------------------------------------------

class PredictorArtifacts(NamedTuple):
    """Container for the three required saved artifacts."""
    model:           Any       # fitted sklearn estimator
    encoder:         Any       # fitted LabelEncoder
    feature_columns: list[str] # ordered column names


class PredictionResult(NamedTuple):
    """
    Result of a single password strength prediction.

    Attributes
    ----------
    password         : str   Original input (never stored externally)
    predicted_label  : str   Strength category e.g. "Strong"
    confidence       : float Probability of the predicted class (0.0–1.0)
    all_probabilities: dict  Probability for every class label
    """
    password:          str
    predicted_label:   str
    confidence:        float
    all_probabilities: dict[str, float]


# ---------------------------------------------------------------------------
# Artifact loader  (cached at module level after first call)
# ---------------------------------------------------------------------------

_cached_artifacts: PredictorArtifacts | None = None


def load_artifacts(
    model_path:   Path = MODEL_FILE,
    encoder_path: Path = ENCODER_FILE,
    columns_path: Path = COLUMNS_FILE,
    force_reload: bool = False,
) -> PredictorArtifacts:
    """
    Load the three saved artifacts from disk.

    Results are cached in a module-level variable so subsequent calls
    within the same process are instantaneous (no disk I/O).

    Parameters
    ----------
    model_path   : Path to password_strength_model.pkl
    encoder_path : Path to label_encoder.pkl
    columns_path : Path to feature_columns.pkl
    force_reload : bool  Clear the cache and reload from disk (default False)

    Returns
    -------
    PredictorArtifacts

    Raises
    ------
    FileNotFoundError
        If any artifact file is missing.  Run ml/train_model.py first.
    """
    global _cached_artifacts

    if _cached_artifacts is not None and not force_reload:
        return _cached_artifacts

    for label, path in [
        ("model",   model_path),
        ("encoder", encoder_path),
        ("columns", columns_path),
    ]:
        if not path.is_file():
            raise FileNotFoundError(
                f"Artifact '{label}' not found at {path}. "
                "Run  python ml/train_model.py  first."
            )

    model:           Any       = joblib.load(model_path)
    encoder:         Any       = joblib.load(encoder_path)
    feature_columns: list[str] = joblib.load(columns_path)

    log.info("Artifacts loaded from %s", model_path.parent)
    log.debug("Model type   : %s", type(model).__name__)
    log.debug("Classes      : %s", list(encoder.classes_))
    log.debug("Feature cols : %s", feature_columns)

    _cached_artifacts = PredictorArtifacts(model, encoder, feature_columns)
    return _cached_artifacts


# ---------------------------------------------------------------------------
# Prediction helpers
# ---------------------------------------------------------------------------

def predict_password(
    password: str,
    artifacts: PredictorArtifacts | None = None,
) -> PredictionResult:
    """
    Predict the strength category of a single password.

    Parameters
    ----------
    password  : str
        The password to evaluate.
    artifacts : PredictorArtifacts | None
        Pre-loaded artifacts.  If None, load_artifacts() is called
        automatically.

    Returns
    -------
    PredictionResult
        Named tuple with predicted_label, confidence, all_probabilities.
    """
    if artifacts is None:
        artifacts = load_artifacts()

    # Build a single-row feature DataFrame
    df = build_features_df([password])

    # Reorder columns to match training order
    df = df[artifacts.feature_columns]

    # Raw prediction
    encoded_pred: np.ndarray = artifacts.model.predict(df)
    predicted_label: str     = artifacts.encoder.inverse_transform(encoded_pred)[0]

    # Class probabilities
    all_probs: dict[str, float] = {}
    if hasattr(artifacts.model, "predict_proba"):
        proba: np.ndarray = artifacts.model.predict_proba(df)[0]
        class_names: list[str] = list(artifacts.encoder.classes_)
        all_probs = {
            cls: round(float(p), 4)
            for cls, p in zip(class_names, proba)
        }
        confidence = all_probs.get(predicted_label, 1.0)
    else:
        # Fallback: model has no predict_proba
        all_probs   = {predicted_label: 1.0}
        confidence  = 1.0

    log.debug(
        "predict_password(%r) → %s  (confidence=%.2f)",
        password, predicted_label, confidence,
    )

    return PredictionResult(
        password=password,
        predicted_label=predicted_label,
        confidence=confidence,
        all_probabilities=all_probs,
    )


def predict_batch(
    passwords: list[str],
    artifacts: PredictorArtifacts | None = None,
) -> list[PredictionResult]:
    """
    Predict strength for a list of passwords.

    Uses a single model.predict() call for the entire batch, which is
    significantly faster than calling predict_password() in a loop.

    Parameters
    ----------
    passwords : list[str]
    artifacts : PredictorArtifacts | None

    Returns
    -------
    list[PredictionResult]
        Same length and order as *passwords*.
    """
    if not passwords:
        return []

    if artifacts is None:
        artifacts = load_artifacts()

    df = build_features_df(passwords)[artifacts.feature_columns]

    encoded_preds: np.ndarray = artifacts.model.predict(df)
    labels: list[str]         = list(
        artifacts.encoder.inverse_transform(encoded_preds)
    )

    results: list[PredictionResult] = []

    if hasattr(artifacts.model, "predict_proba"):
        probas: np.ndarray  = artifacts.model.predict_proba(df)
        class_names: list[str] = list(artifacts.encoder.classes_)
        for pw, label, proba in zip(passwords, labels, probas):
            all_probs = {
                cls: round(float(p), 4)
                for cls, p in zip(class_names, proba)
            }
            confidence = all_probs.get(label, 1.0)
            results.append(PredictionResult(pw, label, confidence, all_probs))
    else:
        for pw, label in zip(passwords, labels):
            results.append(PredictionResult(pw, label, 1.0, {label: 1.0}))

    log.debug("predict_batch: %d passwords processed", len(results))
    return results


# ---------------------------------------------------------------------------
# CLI quick-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    test_passwords = [
        "abc",
        "password1",
        "Admin@123",
        "P@ssw0rdStrong!9",
        "Q7#xP!9Lm@2K",
        "Alpha!Bravo@Cobra#Delta1234!",
    ]

    log.info("Loading artifacts …")
    arts = load_artifacts()
    log.info("Running predictions …")

    print(f"\n{'Password':<32}  {'Predicted':<12}  {'Confidence':>10}")
    print("-" * 60)
    for result in predict_batch(test_passwords, arts):
        print(
            f"{result.password:<32}  "
            f"{result.predicted_label:<12}  "
            f"{result.confidence:>10.4f}"
        )
