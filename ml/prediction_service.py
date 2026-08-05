"""
ml/prediction_service.py — SecureGuard AI
============================================

Enterprise-grade, standalone ML prediction service for password strength
classification.  Zero Flask dependencies — can be imported by any Python
process or microservice.

Classes
-------
    PasswordPredictionService    Main prediction class.

Custom exceptions
-----------------
    FeatureValidationError       Feature dict has wrong keys or count.
    PredictionError              Model inference failed unexpectedly.
    ModelLoadError               Re-exported from model_loader for convenience.

Return format
-------------
    Every predict() call returns a PredictionResult dataclass with:

        prediction       str    Strength label ("Very Weak" … "Excellent")
        confidence       float  Probability of the predicted class (0 – 1)
        probabilities    dict   {label: probability} for all 5 classes
        inference_time_ms float Wall-clock time in milliseconds

    The same data is also available as a plain dict via .to_dict().

Usage
-----
    from ml.prediction_service import PasswordPredictionService
    from ml.feature_builder    import build_features

    service = PasswordPredictionService()
    feats   = build_features("Admin@123")
    result  = service.predict(feats)

    print(result.prediction)          # "Very Weak"
    print(result.confidence)          # 0.97
    print(result.to_dict())           # full dict
"""

from __future__ import annotations

import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from ml import LABEL_ORDER, LOGS_DIR
from ml.model_loader import ModelLoadError, ModelLoader

# ---------------------------------------------------------------------------
# Logging — writes to the same prediction.log used by model_loader
# ---------------------------------------------------------------------------
LOGS_DIR.mkdir(parents=True, exist_ok=True)
_LOG_FILE: Path = LOGS_DIR / "prediction.log"

_fmt = logging.Formatter(
    "%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_fh = logging.FileHandler(_LOG_FILE, mode="a", encoding="utf-8")
_fh.setLevel(logging.DEBUG)
_fh.setFormatter(_fmt)

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
if not log.handlers:
    log.addHandler(_fh)

# Re-export so callers can catch all custom errors from one import
__all__ = [
    "PasswordPredictionService",
    "PredictionResult",
    "FeatureValidationError",
    "PredictionError",
    "ModelLoadError",
]


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class FeatureValidationError(ValueError):
    """
    Raised when the feature dictionary provided to predict() is invalid.

    Attributes
    ----------
    expected : list[str]   Features the model requires.
    received : list[str]   Features actually present in the input.
    """

    def __init__(
        self,
        message: str,
        expected: list[str] | None = None,
        received: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.expected: list[str] = expected or []
        self.received: list[str] = received or []

    def __str__(self) -> str:
        base = super().__str__()
        missing = sorted(set(self.expected) - set(self.received))
        extra   = sorted(set(self.received) - set(self.expected))
        parts   = [base]
        if missing:
            parts.append(f"missing={missing}")
        if extra:
            parts.append(f"extra={extra}")
        return "  ".join(parts)


class PredictionError(RuntimeError):
    """
    Raised when model inference raises an unexpected exception.

    Wraps the original exception as __cause__ so the full traceback
    is preserved.
    """


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------

@dataclass
class PredictionResult:
    """
    Immutable container for a single password strength prediction.

    Attributes
    ----------
    prediction        : str    Strength label ("Very Weak" … "Excellent")
    confidence        : float  Probability of the predicted class (0.0 – 1.0)
    probabilities     : dict   {label: float} for every known class
    inference_time_ms : float  Wall-clock inference time in milliseconds
    """

    prediction:        str
    confidence:        float
    probabilities:     dict[str, float]   = field(default_factory=dict)
    inference_time_ms: float              = 0.0

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serialisable dictionary matching the spec:

        {
            "prediction":        "Strong",
            "confidence":        0.92,
            "probabilities":     {"Very Weak": 0.01, ...},
            "inference_time_ms": 3.47
        }
        """
        return {
            "prediction":        self.prediction,
            "confidence":        round(self.confidence, 4),
            "probabilities":     {k: round(v, 4) for k, v in self.probabilities.items()},
            "inference_time_ms": round(self.inference_time_ms, 3),
        }

    def __repr__(self) -> str:
        return (
            f"PredictionResult("
            f"prediction={self.prediction!r}, "
            f"confidence={self.confidence:.4f}, "
            f"inference_time_ms={self.inference_time_ms:.2f})"
        )


# ---------------------------------------------------------------------------
# Prediction service
# ---------------------------------------------------------------------------

class PasswordPredictionService:
    """
    Standalone ML prediction service for password strength classification.

    This class is completely independent of Flask.  It loads the trained
    Random Forest model via the singleton ModelLoader and exposes a single
    predict() entry point that accepts a feature dictionary and returns a
    PredictionResult.

    Parameters
    ----------
    loader : ModelLoader | None
        An already-initialised ModelLoader.  If None (default) the
        singleton is obtained via ``ModelLoader.instance()``.

    Raises
    ------
    ModelLoadError
        If the artifacts cannot be loaded (propagated from ModelLoader).

    Example
    -------
    >>> from ml.prediction_service import PasswordPredictionService
    >>> from ml.feature_builder    import build_features
    >>>
    >>> svc    = PasswordPredictionService()
    >>> feats  = build_features("Admin@123")
    >>> result = svc.predict(feats)
    >>> print(result.to_dict())
    """

    def __init__(self, loader: ModelLoader | None = None) -> None:
        # Obtain (or reuse) the singleton artifact loader
        self._loader: ModelLoader = loader or ModelLoader.instance()

        # Cache the artifacts locally to avoid repeated method calls in hot path
        self._model           = self._loader.get_model()
        self._encoder         = self._loader.get_label_encoder()
        self._feature_columns = self._loader.get_feature_columns()
        self._n_features      = len(self._feature_columns)
        self._class_names: list[str] = list(self._encoder.classes_)

        log.info(
            "PasswordPredictionService ready  "
            "n_features=%d  classes=%s",
            self._n_features,
            self._class_names,
        )

    # ── Validation ────────────────────────────────────────────────────────

    def _validate_features(self, features: dict[str, Any]) -> None:
        """
        Verify that *features* contains exactly the required keys.

        Raises
        ------
        FeatureValidationError
            On count mismatch or missing/extra keys.
        """
        if not isinstance(features, dict):
            raise FeatureValidationError(
                f"features must be a dict, got {type(features).__name__}",
                expected=self._feature_columns,
                received=[],
            )

        received_keys  = list(features.keys())
        expected_keys  = self._feature_columns

        # Check count first (fast path)
        if len(received_keys) != self._n_features:
            raise FeatureValidationError(
                f"Expected {self._n_features} features, received {len(received_keys)}.",
                expected=expected_keys,
                received=received_keys,
            )

        # Check exact key set
        missing = sorted(set(expected_keys) - set(received_keys))
        extra   = sorted(set(received_keys) - set(expected_keys))

        if missing or extra:
            raise FeatureValidationError(
                "Feature key mismatch.",
                expected=expected_keys,
                received=received_keys,
            )

        log.debug("Feature validation passed  (%d features)", self._n_features)

    # ── Inference ─────────────────────────────────────────────────────────

    def predict(self, features: dict[str, Any]) -> PredictionResult:
        """
        Predict the strength of a password from its feature dictionary.

        Parameters
        ----------
        features : dict[str, int | float]
            Exactly 12 key-value pairs matching ml.FEATURE_COLUMNS.
            Use ``ml.feature_builder.build_features(password)`` to produce
            a valid input dictionary from a raw password string.

        Returns
        -------
        PredictionResult
            Contains prediction, confidence, all class probabilities,
            and inference wall-clock time in milliseconds.

        Raises
        ------
        FeatureValidationError   Feature dict is wrong shape or has wrong keys.
        PredictionError          Model inference raised an unexpected exception.

        Example
        -------
        >>> feats  = build_features("P@ssw0rd!Long99")
        >>> result = service.predict(feats)
        >>> result.prediction      # "Strong"
        >>> result.confidence      # 0.89
        >>> result.to_dict()       # full JSON-safe dict
        """
        log.debug("predict() called  features_count=%d", len(features) if features else 0)

        # ── Step 1: validate ──────────────────────────────────────────────
        self._validate_features(features)

        # ── Step 2: build DataFrame in exact column order ─────────────────
        row: list[Any] = [features[col] for col in self._feature_columns]
        X = pd.DataFrame([row], columns=self._feature_columns)

        # ── Step 3: run inference ─────────────────────────────────────────
        t_start = time.perf_counter()
        try:
            encoded_pred: np.ndarray = self._model.predict(X)
            proba:        np.ndarray = self._model.predict_proba(X)[0]
        except Exception as exc:
            msg = f"Model inference failed: {exc}"
            log.exception(msg)
            raise PredictionError(msg) from exc
        t_end = time.perf_counter()

        inference_ms = (t_end - t_start) * 1000.0

        # ── Step 4: decode label ──────────────────────────────────────────
        prediction: str = str(self._encoder.inverse_transform(encoded_pred)[0])

        # ── Step 5: build probability dict (all 5 classes) ───────────────
        # Reorder into LABEL_ORDER (Very Weak → Excellent) for readability
        raw_probs: dict[str, float] = dict(zip(self._class_names, proba.tolist()))
        probabilities: dict[str, float] = {
            label: raw_probs.get(label, 0.0)
            for label in LABEL_ORDER
            if label in raw_probs
        }
        # Include any classes not in LABEL_ORDER (future-proofing)
        for cls, prob in raw_probs.items():
            if cls not in probabilities:
                probabilities[cls] = prob

        confidence: float = float(raw_probs.get(prediction, 1.0))

        # ── Step 6: log and return ────────────────────────────────────────
        log.info(
            "Prediction: %-12s  confidence=%.4f  time=%.2f ms",
            prediction, confidence, inference_ms,
        )
        log.debug("Probabilities: %s", {k: round(v, 4) for k, v in probabilities.items()})

        return PredictionResult(
            prediction=prediction,
            confidence=confidence,
            probabilities=probabilities,
            inference_time_ms=inference_ms,
        )

    def predict_from_password(self, password: str) -> PredictionResult:
        """
        Convenience method: extract features from a raw password and predict.

        Equivalent to:
            predict(build_features(password))

        Parameters
        ----------
        password : str   Plaintext password to evaluate.

        Returns
        -------
        PredictionResult
        """
        from ml.feature_builder import build_features

        log.debug("predict_from_password(%r)", password[:3] + "***")
        features = build_features(password)
        return self.predict(features)

    def __repr__(self) -> str:
        return (
            f"PasswordPredictionService("
            f"n_features={self._n_features}, "
            f"classes={self._class_names})"
        )
