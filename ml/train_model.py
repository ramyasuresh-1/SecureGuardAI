"""
ml/train_model.py — SecureGuard AI
=====================================

Top-level training orchestrator.

Pipeline
--------
1.  Configure logging (file + console)
2.  Load and preprocess the password dataset
3.  Tune a Random Forest with GridSearchCV
4.  Evaluate on the held-out test set + 5-fold CV
5.  Save all artifacts to ml/artifacts/

Saved artifacts
---------------
ml/artifacts/password_strength_model.pkl   Trained RandomForestClassifier
ml/artifacts/label_encoder.pkl             Fitted LabelEncoder
ml/artifacts/feature_columns.pkl           Ordered feature column list
ml/artifacts/metrics.json                  Full evaluation metrics

Usage
-----
    python ml/train_model.py                   # train with defaults
    python ml/train_model.py --quick           # fast grid (dev / CI)
    python ml/train_model.py --no-grid         # skip tuning, use best defaults

Exit codes
----------
    0  Success
    1  Dataset missing or preprocessing failed
    2  Training or evaluation failed
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV

# ---------------------------------------------------------------------------
# Path bootstrap — must come before any ml.* imports
# ---------------------------------------------------------------------------
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from ml import (
    ARTIFACTS_DIR,
    COLUMNS_FILE,
    ENCODER_FILE,
    FEATURE_COLUMNS,
    LABEL_ORDER,
    LOGS_DIR,
    MODEL_FILE,
)
from ml.evaluate import evaluate_model
from ml.preprocess import load_and_preprocess

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _configure_logging(log_dir: Path, verbose: bool = False) -> logging.Logger:
    """
    Set up dual logging: rich console output + timestamped log file.

    Parameters
    ----------
    log_dir : Path   Directory where the log file is written.
    verbose : bool   If True, set console level to DEBUG.

    Returns
    -------
    logging.Logger   Root logger.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "train_model.log"

    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler — always DEBUG level
    fh = logging.FileHandler(log_file, mode="w", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(fh)
    root.addHandler(ch)

    root.info("Log file → %s", log_file)
    return root


# ---------------------------------------------------------------------------
# Grid search parameter spaces
# ---------------------------------------------------------------------------

# Full grid — used for production training
_FULL_PARAM_GRID: dict = {
    "n_estimators":      [100, 200, 300],
    "max_depth":         [None, 10, 20, 30],
    "min_samples_split": [2, 5, 10],
    "min_samples_leaf":  [1, 2, 4],
    "max_features":      ["sqrt", "log2"],
    "class_weight":      ["balanced", None],
}

# Quick grid — used for dev / CI (much faster, still finds a decent model)
_QUICK_PARAM_GRID: dict = {
    "n_estimators":      [100, 200],
    "max_depth":         [None, 20],
    "min_samples_split": [2, 5],
    "min_samples_leaf":  [1, 2],
    "max_features":      ["sqrt"],
    "class_weight":      ["balanced"],
}

# Best defaults — used when grid search is skipped (--no-grid)
_BEST_DEFAULTS: dict = {
    "n_estimators":      200,
    "max_depth":         None,
    "min_samples_split": 2,
    "min_samples_leaf":  1,
    "max_features":      "sqrt",
    "class_weight":      "balanced",
    "random_state":      42,
    "n_jobs":            -1,
}


# ---------------------------------------------------------------------------
# Training function
# ---------------------------------------------------------------------------

def train(
    use_grid: bool = True,
    quick_grid: bool = False,
    random_state: int = 42,
    cv_folds: int = 5,
    n_jobs: int = -1,
) -> dict:
    """
    Run the full training pipeline and return the metrics dict.

    Parameters
    ----------
    use_grid     : bool   Run GridSearchCV (True) or use fixed defaults (False)
    quick_grid   : bool   Use the smaller dev grid instead of the full grid
    random_state : int    Reproducibility seed
    cv_folds     : int    Number of folds for CV (in evaluate_model)
    n_jobs       : int    Parallelism (-1 = all cores)

    Returns
    -------
    dict   Evaluation metrics (same dict written to metrics.json)
    """
    log = logging.getLogger(__name__)
    wall_start = time.time()

    # ------------------------------------------------------------------
    # Step 1 — Preprocess
    # ------------------------------------------------------------------
    log.info("═" * 60)
    log.info("SecureGuard AI — Password Strength Classifier Training")
    log.info("═" * 60)

    try:
        prep = load_and_preprocess(random_state=random_state)
    except (FileNotFoundError, ValueError) as exc:
        log.error("Preprocessing failed: %s", exc)
        sys.exit(1)

    X_train, X_test = prep.X_train, prep.X_test
    y_train, y_test = prep.y_train, prep.y_test
    encoder         = prep.encoder

    log.info(
        "Training set : %d rows   Test set : %d rows",
        len(X_train), len(X_test),
    )

    # ------------------------------------------------------------------
    # Step 2 — Model selection / GridSearchCV
    # ------------------------------------------------------------------
    log.info("─" * 60)

    if use_grid:
        param_grid = _QUICK_PARAM_GRID if quick_grid else _FULL_PARAM_GRID
        grid_label = "quick" if quick_grid else "full"
        n_combos   = 1
        for v in param_grid.values():
            n_combos *= len(v)

        log.info(
            "GridSearchCV  (%s grid, %d combinations, %d-fold CV) …",
            grid_label, n_combos, cv_folds,
        )
        log.info("This may take several minutes on the full grid.")

        base_rf = RandomForestClassifier(random_state=random_state, n_jobs=n_jobs)
        grid_search = GridSearchCV(
            estimator=base_rf,
            param_grid=param_grid,
            cv=cv_folds,
            scoring="f1_macro",
            n_jobs=n_jobs,
            verbose=0,
            refit=True,
            return_train_score=False,
        )

        t0 = time.time()
        grid_search.fit(X_train, y_train)
        grid_time = time.time() - t0

        log.info("GridSearchCV finished in %.1f s", grid_time)
        log.info("Best params  : %s", grid_search.best_params_)
        log.info("Best CV F1   : %.4f", grid_search.best_score_)

        model = grid_search.best_estimator_

    else:
        log.info("Skipping GridSearchCV — using best-known defaults")
        model = RandomForestClassifier(**_BEST_DEFAULTS)
        model.fit(X_train, y_train)
        log.info("Model fitted with default parameters")

    # ------------------------------------------------------------------
    # Step 3 — Evaluate
    # ------------------------------------------------------------------
    log.info("─" * 60)

    try:
        metrics = evaluate_model(
            model=model,
            X_test=X_test,
            y_test=y_test,
            encoder=encoder,
            X_train=X_train,
            y_train=y_train,
            cv_folds=cv_folds,
        )
    except Exception as exc:
        log.error("Evaluation failed: %s", exc, exc_info=True)
        sys.exit(2)

    # ------------------------------------------------------------------
    # Step 4 — Save artifacts
    # ------------------------------------------------------------------
    log.info("─" * 60)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(model,           MODEL_FILE,   compress=3)
    log.info("Model saved   → %s", MODEL_FILE)

    joblib.dump(encoder,         ENCODER_FILE, compress=3)
    log.info("Encoder saved → %s", ENCODER_FILE)

    joblib.dump(FEATURE_COLUMNS, COLUMNS_FILE, compress=3)
    log.info("Columns saved → %s", COLUMNS_FILE)

    # metrics.json is already written by evaluate_model()
    log.info("Metrics saved → %s", ARTIFACTS_DIR / "metrics.json")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    wall_elapsed = time.time() - wall_start
    log.info("═" * 60)
    log.info("Training complete in %.1f s", wall_elapsed)
    log.info("  Accuracy   : %.4f", metrics["accuracy"])
    log.info("  Macro F1   : %.4f", metrics["macro_f1"])
    log.info("  CV Accuracy: %.4f  (± %.4f)",
             metrics["cv_mean_accuracy"], metrics["cv_std_accuracy"])
    log.info("═" * 60)

    return metrics


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="train_model",
        description="SecureGuard AI — train password strength classifier",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Use the smaller dev grid (faster, less thorough)",
    )
    parser.add_argument(
        "--no-grid",
        action="store_true",
        dest="no_grid",
        help="Skip GridSearchCV and use best-known default parameters",
    )
    parser.add_argument(
        "--cv",
        type=int,
        default=5,
        metavar="N",
        help="Number of cross-validation folds (default 5)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        metavar="N",
        help="Random seed for reproducibility (default 42)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Set console log level to DEBUG",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args()

    _configure_logging(LOGS_DIR, verbose=args.verbose)

    train(
        use_grid     = not args.no_grid,
        quick_grid   = args.quick,
        random_state = args.seed,
        cv_folds     = args.cv,
    )
