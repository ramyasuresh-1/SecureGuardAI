"""
ml/evaluate.py — SecureGuard AI
=================================

Computes, displays, and persists all evaluation metrics for a trained
password-strength classifier.

Metrics produced
----------------
- Accuracy
- Macro Precision, Recall, F1
- Per-class Precision, Recall, F1, Support
- Confusion Matrix (absolute counts)
- Cross-Validation scores (5-fold, accuracy)
- Feature Importances (ranked)

All metrics are also serialised to ml/artifacts/metrics.json so they can
be read programmatically by dashboards or CI checks.

Public API
----------
evaluate_model(model, X_test, y_test, encoder, X_train, y_train)
    → dict   (full metrics dict, also saved to METRICS_FILE)
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import LabelEncoder

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from ml import ARTIFACTS_DIR, FEATURE_COLUMNS, LABEL_ORDER, METRICS_FILE

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
log = logging.getLogger(__name__)

# Width constant for pretty console separators
_W = 60


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sep(char: str = "─", width: int = _W) -> str:
    return char * width


def _print_confusion_matrix(
    cm: np.ndarray, class_names: list[str]
) -> None:
    """Log the confusion matrix in a readable aligned table."""
    col_w = max(len(n) for n in class_names) + 2
    header = " " * col_w + "  ".join(f"{n:>{col_w}}" for n in class_names)
    log.info("Confusion Matrix (rows=actual, cols=predicted):")
    log.info(header)
    for i, row in enumerate(cm):
        row_str = f"{class_names[i]:<{col_w}}" + "  ".join(
            f"{v:>{col_w}d}" for v in row
        )
        log.info(row_str)


# ---------------------------------------------------------------------------
# Main evaluation function
# ---------------------------------------------------------------------------

def evaluate_model(
    model: Any,
    X_test: pd.DataFrame,
    y_test: np.ndarray,
    encoder: LabelEncoder,
    X_train: pd.DataFrame,
    y_train: np.ndarray,
    cv_folds: int = 5,
) -> dict[str, Any]:
    """
    Evaluate *model* on the held-out test set and via cross-validation.

    Parameters
    ----------
    model       : fitted sklearn estimator
    X_test      : feature DataFrame (test split)
    y_test      : encoded integer labels (test split)
    encoder     : fitted LabelEncoder (used to decode predictions)
    X_train     : feature DataFrame (training split, used for CV)
    y_train     : encoded integer labels (training split, used for CV)
    cv_folds    : number of cross-validation folds (default 5)

    Returns
    -------
    dict
        All metric values.  Also written to ml/artifacts/metrics.json.
    """
    log.info(_sep("="))
    log.info("Model Evaluation")
    log.info(_sep("="))

    class_names: list[str] = list(encoder.classes_)

    # ------------------------------------------------------------------
    # Test-set predictions
    # ------------------------------------------------------------------
    y_pred: np.ndarray = model.predict(X_test)

    # ------------------------------------------------------------------
    # Overall metrics
    # ------------------------------------------------------------------
    accuracy  = float(accuracy_score(y_test, y_pred))
    precision = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
    recall    = float(recall_score(y_test, y_pred,    average="macro", zero_division=0))
    f1_macro  = float(f1_score(y_test, y_pred,        average="macro", zero_division=0))
    f1_weighted = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    log.info(_sep())
    log.info("  Accuracy          : %.4f  (%d / %d correct)",
             accuracy, int(accuracy * len(y_test)), len(y_test))
    log.info("  Macro Precision   : %.4f", precision)
    log.info("  Macro Recall      : %.4f", recall)
    log.info("  Macro F1          : %.4f", f1_macro)
    log.info("  Weighted F1       : %.4f", f1_weighted)

    # ------------------------------------------------------------------
    # Per-class report
    # ------------------------------------------------------------------
    report_str  = classification_report(
        y_test, y_pred, target_names=class_names, zero_division=0
    )
    report_dict = classification_report(
        y_test, y_pred, target_names=class_names, zero_division=0,
        output_dict=True,
    )
    log.info(_sep())
    log.info("Classification Report:")
    for line in report_str.splitlines():
        log.info("  %s", line)

    # ------------------------------------------------------------------
    # Confusion matrix
    # ------------------------------------------------------------------
    cm = confusion_matrix(y_test, y_pred)
    log.info(_sep())
    _print_confusion_matrix(cm, class_names)

    # ------------------------------------------------------------------
    # Cross-validation (run on training data only to avoid data leakage)
    # ------------------------------------------------------------------
    log.info(_sep())
    log.info("Cross-Validation (%d-fold, metric=accuracy) …", cv_folds)

    cv_scores: np.ndarray = cross_val_score(
        model, X_train, y_train, cv=cv_folds, scoring="accuracy", n_jobs=-1
    )
    cv_mean = float(cv_scores.mean())
    cv_std  = float(cv_scores.std())
    log.info(
        "  CV scores : %s",
        "  ".join(f"{s:.4f}" for s in cv_scores),
    )
    log.info("  CV mean   : %.4f  (± %.4f)", cv_mean, cv_std)

    # ------------------------------------------------------------------
    # Feature importances (if the model exposes them)
    # ------------------------------------------------------------------
    feature_importances: dict[str, float] = {}
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        pairs = sorted(
            zip(FEATURE_COLUMNS, importances),
            key=lambda t: t[1], reverse=True,
        )
        log.info(_sep())
        log.info("Feature Importances (ranked):")
        for rank, (col, imp) in enumerate(pairs, start=1):
            bar = "█" * int(imp * 40)
            log.info("  %2d. %-30s  %.4f  %s", rank, col, imp, bar)
            feature_importances[col] = round(float(imp), 6)

    # ------------------------------------------------------------------
    # Assemble metrics dict
    # ------------------------------------------------------------------
    metrics: dict[str, Any] = {
        "accuracy":           round(accuracy,    4),
        "macro_precision":    round(precision,   4),
        "macro_recall":       round(recall,      4),
        "macro_f1":           round(f1_macro,    4),
        "weighted_f1":        round(f1_weighted, 4),
        "cv_mean_accuracy":   round(cv_mean,     4),
        "cv_std_accuracy":    round(cv_std,      4),
        "cv_scores":          [round(float(s), 4) for s in cv_scores],
        "per_class_report":   {
            cls: {
                "precision": round(report_dict[cls]["precision"], 4),
                "recall":    round(report_dict[cls]["recall"],    4),
                "f1_score":  round(report_dict[cls]["f1-score"],  4),
                "support":   int(report_dict[cls]["support"]),
            }
            for cls in class_names
            if cls in report_dict
        },
        "confusion_matrix":   cm.tolist(),
        "class_names":        class_names,
        "feature_importances": feature_importances,
        "test_size":          int(len(y_test)),
        "train_size":         int(len(y_train)),
    }

    # ------------------------------------------------------------------
    # Persist to JSON
    # ------------------------------------------------------------------
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(METRICS_FILE, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)
    log.info(_sep())
    log.info("Metrics saved → %s", METRICS_FILE)
    log.info(_sep("="))

    return metrics
