"""
ml/model_loader.py — SecureGuard AI
======================================

Thread-safe singleton that loads the three ML artifacts from disk exactly
once and caches them in memory for the entire process lifetime.

Artifacts managed
-----------------
    password_strength_model.pkl   RandomForestClassifier
    label_encoder.pkl             LabelEncoder (5 strength classes)
    feature_columns.pkl           list[str] of 12 ordered feature names

Singleton guarantee
-------------------
    The module uses a threading.Lock so concurrent callers (e.g. multiple
    Flask request threads) never trigger a double-load.  After the first
    load every subsequent call returns the cached objects in O(1) time.

Public API
----------
    ModelLoader.instance()          → ModelLoader   (singleton accessor)
    loader.get_model()              → RandomForestClassifier
    loader.get_label_encoder()      → LabelEncoder
    loader.get_feature_columns()    → list[str]
    loader.is_loaded                → bool
    ModelLoader.reset()             → None   (test / reload helper)

Custom exceptions
-----------------
    ModelLoadError   Raised when any artifact file is missing or corrupt.

Usage
-----
    from ml.model_loader import ModelLoader

    loader  = ModelLoader.instance()
    model   = loader.get_model()
    encoder = loader.get_label_encoder()
    columns = loader.get_feature_columns()
"""

from __future__ import annotations

import logging
import sys
import threading
from pathlib import Path
from typing import Any

import joblib

# ---------------------------------------------------------------------------
# Path bootstrap — works regardless of working directory
# ---------------------------------------------------------------------------
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from ml import COLUMNS_FILE, ENCODER_FILE, LOGS_DIR, MODEL_FILE

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOGS_DIR.mkdir(parents=True, exist_ok=True)

_LOG_FILE: Path = LOGS_DIR / "prediction.log"

_fmt = logging.Formatter(
    "%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

_file_handler = logging.FileHandler(_LOG_FILE, mode="a", encoding="utf-8")
_file_handler.setLevel(logging.DEBUG)
_file_handler.setFormatter(_fmt)

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
if not log.handlers:          # avoid duplicate handlers on re-import
    log.addHandler(_file_handler)


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------

class ModelLoadError(RuntimeError):
    """
    Raised when the ML artifacts cannot be loaded from disk.

    Attributes
    ----------
    artifact : str   Name of the artifact that caused the failure.
    path     : Path  File path that was expected.
    """

    def __init__(self, message: str, artifact: str = "", path: Path | None = None) -> None:
        super().__init__(message)
        self.artifact = artifact
        self.path     = path

    def __str__(self) -> str:
        base = super().__str__()
        parts = [base]
        if self.artifact:
            parts.append(f"artifact={self.artifact!r}")
        if self.path:
            parts.append(f"path={self.path}")
        return "  ".join(parts)


# ---------------------------------------------------------------------------
# Singleton ModelLoader
# ---------------------------------------------------------------------------

class ModelLoader:
    """
    Thread-safe singleton that manages the three ML artifacts.

    Pattern
    -------
    ``ModelLoader.instance()`` always returns the same object.  The first
    call loads the artifacts; subsequent calls return the cached instance.

    Example
    -------
    >>> loader = ModelLoader.instance()
    >>> model  = loader.get_model()
    >>> model.predict(X)
    """

    # ── Class-level state (shared across all callers) ─────────────────────
    _instance:  "ModelLoader | None" = None
    _lock:      threading.Lock        = threading.Lock()

    # ── Instance state (populated on first load) ──────────────────────────
    _model:           Any       = None   # RandomForestClassifier
    _label_encoder:   Any       = None   # LabelEncoder
    _feature_columns: list[str] = []

    # ── Private constructor ───────────────────────────────────────────────
    def __init__(
        self,
        model_path:   Path = MODEL_FILE,
        encoder_path: Path = ENCODER_FILE,
        columns_path: Path = COLUMNS_FILE,
    ) -> None:
        """
        Load artifacts from disk.  Do not call directly — use instance().

        Raises
        ------
        ModelLoadError
            If any artifact file is missing or cannot be deserialised.
        """
        self._model_path   = model_path
        self._encoder_path = encoder_path
        self._columns_path = columns_path
        self._loaded: bool = False

        self._load()

    # ── Singleton accessor ────────────────────────────────────────────────
    @classmethod
    def instance(
        cls,
        model_path:   Path = MODEL_FILE,
        encoder_path: Path = ENCODER_FILE,
        columns_path: Path = COLUMNS_FILE,
    ) -> "ModelLoader":
        """
        Return (and if necessary create) the singleton ModelLoader.

        Thread-safe: at most one instance is ever created even under
        concurrent access.

        Parameters
        ----------
        model_path   : Path  Override path for the model artifact.
        encoder_path : Path  Override path for the encoder artifact.
        columns_path : Path  Override path for the feature-columns artifact.

        Returns
        -------
        ModelLoader
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:      # double-checked locking
                    log.info("Creating ModelLoader singleton …")
                    cls._instance = cls(model_path, encoder_path, columns_path)
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """
        Clear the cached singleton.

        Intended for unit tests or forced reloads.  In production code
        this should never be called.
        """
        with cls._lock:
            cls._instance = None
        log.warning("ModelLoader singleton reset — next call will reload from disk.")

    # ── Internal loader ───────────────────────────────────────────────────
    def _load(self) -> None:
        """
        Deserialise all three artifact files.

        Raises
        ------
        ModelLoadError  If a file is missing or joblib raises on load.
        """
        log.info("=" * 55)
        log.info("ModelLoader: loading artifacts …")

        artifacts: list[tuple[str, Path, str]] = [
            ("model",   self._model_path,   "RandomForestClassifier"),
            ("encoder", self._encoder_path, "LabelEncoder"),
            ("columns", self._columns_path, "feature column list"),
        ]

        for name, path, desc in artifacts:
            if not path.is_file():
                msg = (
                    f"Artifact '{name}' not found at {path}. "
                    "Run  python ml/train_model.py  to generate it."
                )
                log.error(msg)
                raise ModelLoadError(msg, artifact=name, path=path)

            try:
                obj = joblib.load(path)
                log.info("  Loaded %-10s  ← %s  (%s)", name, path.name, desc)
            except Exception as exc:
                msg = f"Failed to deserialise artifact '{name}': {exc}"
                log.exception(msg)
                raise ModelLoadError(msg, artifact=name, path=path) from exc

            if name == "model":
                self._model = obj
            elif name == "encoder":
                self._label_encoder = obj
            else:
                self._feature_columns = list(obj)

        log.info(
            "ModelLoader: all artifacts loaded  "
            "classes=%s  n_features=%d  n_estimators=%d",
            list(self._label_encoder.classes_),
            len(self._feature_columns),
            getattr(self._model, "n_estimators", "?"),
        )
        log.info("=" * 55)
        self._loaded = True

    # ── Public accessors ──────────────────────────────────────────────────

    @property
    def is_loaded(self) -> bool:
        """True after artifacts have been successfully loaded."""
        return self._loaded

    def get_model(self) -> Any:
        """
        Return the fitted RandomForestClassifier.

        Raises
        ------
        ModelLoadError  If the loader was never successfully initialised.
        """
        if not self._loaded or self._model is None:
            raise ModelLoadError("Model is not loaded. Call ModelLoader.instance() first.")
        return self._model

    def get_label_encoder(self) -> Any:
        """
        Return the fitted LabelEncoder.

        Raises
        ------
        ModelLoadError  If the loader was never successfully initialised.
        """
        if not self._loaded or self._label_encoder is None:
            raise ModelLoadError("LabelEncoder is not loaded.")
        return self._label_encoder

    def get_feature_columns(self) -> list[str]:
        """
        Return the ordered list of feature column names.

        Raises
        ------
        ModelLoadError  If the loader was never successfully initialised.
        """
        if not self._loaded or not self._feature_columns:
            raise ModelLoadError("Feature column list is not loaded.")
        return list(self._feature_columns)   # defensive copy

    # ── Repr ──────────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        status = "loaded" if self._loaded else "not loaded"
        return (
            f"ModelLoader(status={status!r}, "
            f"n_features={len(self._feature_columns)}, "
            f"classes={list(getattr(self._label_encoder, 'classes_', []))})"
        )
