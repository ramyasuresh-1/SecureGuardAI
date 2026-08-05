"""
ml/test_prediction.py — SecureGuard AI
=========================================

Standalone test script for the ML Prediction Service.

NO Flask.  NO database.  NO web application.

Tests five passwords covering every strength tier, then runs validation
and error-handling edge-case tests.

Usage
-----
    python ml/test_prediction.py

Exit codes
----------
    0   All tests passed.
    1   One or more tests failed.
"""

from __future__ import annotations

import sys
import time
import traceback
from pathlib import Path

# ---------------------------------------------------------------------------
# Path bootstrap — works from any cwd
# ---------------------------------------------------------------------------
_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Imports (no Flask anywhere)
# ---------------------------------------------------------------------------
from ml.feature_builder    import build_features
from ml.model_loader       import ModelLoadError, ModelLoader
from ml.prediction_service import (
    FeatureValidationError,
    PasswordPredictionService,
    PredictionError,
    PredictionResult,
)

# ---------------------------------------------------------------------------
# Console formatting helpers
# ---------------------------------------------------------------------------

_W = 70   # output width

def _sep(char: str = "─", width: int = _W) -> str:
    return char * width


def _print_header(title: str) -> None:
    print()
    print(_sep("═"))
    print(f"  {title}")
    print(_sep("═"))


def _print_section(title: str) -> None:
    print()
    print(_sep())
    print(f"  {title}")
    print(_sep())


def _print_result(result: PredictionResult, password: str, expected: str) -> bool:
    """Pretty-print one prediction result. Returns True if label matches expected."""
    match = result.prediction == expected

    print(f"\n  Password  : {password!r}")
    print(f"  Expected  : {expected}")
    print(f"  Predicted : {result.prediction}  {'✓' if match else '✗ MISMATCH'}")
    print(f"  Confidence: {result.confidence:.4f}  ({result.confidence * 100:.1f} %)")
    print(f"  Inference : {result.inference_time_ms:.3f} ms")
    print("  Probabilities:")

    for label, prob in result.probabilities.items():
        bar    = "█" * int(prob * 30)
        marker = " ◄ predicted" if label == result.prediction else ""
        print(f"    {label:<12}  {prob:.4f}  {bar}{marker}")

    return match


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

def run_tests() -> int:
    """
    Run all prediction tests.

    Returns
    -------
    int   Number of failed tests (0 = all passed).
    """
    failures: int = 0
    total:    int = 0

    # ──────────────────────────────────────────────────────────────────────
    # Section 1: Model loading
    # ──────────────────────────────────────────────────────────────────────
    _print_header("SECTION 1 — Model Loading")

    try:
        loader = ModelLoader.instance()
        print(f"\n  {loader}")
        print(f"  is_loaded        : {loader.is_loaded}")
        print(f"  feature columns  : {loader.get_feature_columns()}")
        print(f"  label classes    : {list(loader.get_label_encoder().classes_)}")
        print(f"  n_estimators     : {loader.get_model().n_estimators}")
        print("\n  ✓ ModelLoader singleton initialised")
    except ModelLoadError as exc:
        print(f"\n  ✗ ModelLoadError: {exc}")
        print("    → Run  python ml/train_model.py  first.")
        return 1   # no point continuing without a model

    # ──────────────────────────────────────────────────────────────────────
    # Section 2: Service instantiation
    # ──────────────────────────────────────────────────────────────────────
    _print_header("SECTION 2 — Service Instantiation")

    try:
        service = PasswordPredictionService()
        print(f"\n  {service}")
        print("  ✓ PasswordPredictionService instantiated")
    except ModelLoadError as exc:
        print(f"\n  ✗ Failed to create service: {exc}")
        return 1

    # ──────────────────────────────────────────────────────────────────────
    # Section 3: Five tier predictions (core test)
    # ──────────────────────────────────────────────────────────────────────
    _print_header("SECTION 3 — Five-Tier Prediction Tests")

    # (password, expected_label)  — one representative per tier
    tier_tests: list[tuple[str, str]] = [
        ("abc",                            "Very Weak"),   # 3-char all-lower
        ("password1",                      "Weak"),        # dict word + digit
        ("Security99!",                    "Moderate"),    # mixed, medium length
        ("SkyFire!Blue@99xx",              "Strong"),      # long, 4 classes
        ("Alpha!Bravo@Cobra#Delta1234!",   "Excellent"),   # 26-char, all classes
    ]

    _print_section(f"Testing {len(tier_tests)} passwords")

    tier_pass = 0
    for password, expected in tier_tests:
        total += 1
        try:
            features = build_features(password)
            result   = service.predict(features)
            ok       = _print_result(result, password, expected)
            if ok:
                tier_pass += 1
            else:
                failures += 1
        except (FeatureValidationError, PredictionError, ModelLoadError) as exc:
            print(f"\n  ✗ ERROR for {password!r}: {exc}")
            failures += 1

    print(f"\n  Tier tests: {tier_pass}/{len(tier_tests)} passed")

    # ──────────────────────────────────────────────────────────────────────
    # Section 4: predict_from_password convenience method
    # ──────────────────────────────────────────────────────────────────────
    _print_header("SECTION 4 — predict_from_password() Convenience Method")

    convenience_tests: list[tuple[str, str]] = [
        ("aaaa",                               "Very Weak"),
        ("sunshine123",                        "Weak"),
        ("Ranger!99x",                         "Moderate"),
        ("Blue@Sky#Rock!99zz",                "Strong"),
        ("Foxtrot!India@Kilo#Lima2026!!star",  "Excellent"),
    ]

    _print_section(f"Testing {len(convenience_tests)} passwords via predict_from_password()")

    conv_pass = 0
    for password, expected in convenience_tests:
        total += 1
        try:
            result = service.predict_from_password(password)
            ok     = _print_result(result, password, expected)
            if ok:
                conv_pass += 1
            else:
                failures += 1
        except Exception as exc:
            print(f"\n  ✗ ERROR for {password!r}: {exc}")
            failures += 1

    print(f"\n  Convenience tests: {conv_pass}/{len(convenience_tests)} passed")

    # ──────────────────────────────────────────────────────────────────────
    # Section 5: Result dict format
    # ──────────────────────────────────────────────────────────────────────
    _print_header("SECTION 5 — PredictionResult.to_dict() Format")

    try:
        result = service.predict_from_password("Admin@123")
        d      = result.to_dict()

        print("\n  to_dict() output:")
        for key, val in d.items():
            print(f"    {key:<22}: {val}")

        required_keys = {"prediction", "confidence", "probabilities", "inference_time_ms"}
        assert required_keys.issubset(d.keys()), f"Missing keys: {required_keys - d.keys()}"
        assert isinstance(d["prediction"],        str),   "prediction must be str"
        assert isinstance(d["confidence"],        float), "confidence must be float"
        assert isinstance(d["probabilities"],     dict),  "probabilities must be dict"
        assert isinstance(d["inference_time_ms"], float), "inference_time_ms must be float"
        assert 0.0 <= d["confidence"] <= 1.0,             "confidence must be 0–1"
        assert abs(sum(d["probabilities"].values()) - 1.0) < 0.01, "probs must sum to ≈1"

        print("\n  ✓ All to_dict() assertions passed")
        total += 1
    except AssertionError as exc:
        print(f"\n  ✗ Format assertion failed: {exc}")
        failures += 1
        total += 1

    # ──────────────────────────────────────────────────────────────────────
    # Section 6: Error handling
    # ──────────────────────────────────────────────────────────────────────
    _print_header("SECTION 6 — Error Handling")

    error_tests: list[tuple[str, type, dict[str, object]]] = [
        ("Missing key",     FeatureValidationError, {"password_length": 5}),
        ("Extra key",       FeatureValidationError, {**build_features("abc"), "extra_col": 0}),
        ("Wrong type",      FeatureValidationError, "not_a_dict"),   # type: ignore[arg-type]
        ("Empty dict",      FeatureValidationError, {}),
    ]

    err_pass = 0
    for name, expected_exc, bad_input in error_tests:
        total += 1
        try:
            service.predict(bad_input)  # type: ignore[arg-type]
            print(f"\n  ✗ {name}: expected {expected_exc.__name__} but no exception raised")
            failures += 1
        except expected_exc as exc:
            print(f"\n  ✓ {name}: raised {type(exc).__name__} correctly")
            print(f"      {exc}")
            err_pass += 1
        except Exception as exc:
            print(f"\n  ✗ {name}: wrong exception type {type(exc).__name__}: {exc}")
            failures += 1

    print(f"\n  Error-handling tests: {err_pass}/{len(error_tests)} passed")

    # ──────────────────────────────────────────────────────────────────────
    # Section 7: Singleton identity
    # ──────────────────────────────────────────────────────────────────────
    _print_header("SECTION 7 — Singleton Identity")

    total += 1
    loader_a = ModelLoader.instance()
    loader_b = ModelLoader.instance()
    loader_c = ModelLoader.instance()

    if loader_a is loader_b is loader_c:
        print("\n  ✓ All three ModelLoader.instance() calls return the same object")
    else:
        print("\n  ✗ Singleton broken — different instances returned")
        failures += 1

    # ──────────────────────────────────────────────────────────────────────
    # Section 8: Performance baseline
    # ──────────────────────────────────────────────────────────────────────
    _print_header("SECTION 8 — Performance Baseline")

    N = 100
    features = build_features("Admin@123")
    t0 = time.perf_counter()
    for _ in range(N):
        service.predict(features)
    elapsed = (time.perf_counter() - t0) * 1000.0
    avg_ms  = elapsed / N

    print(f"\n  {N} predictions in {elapsed:.1f} ms  →  avg {avg_ms:.3f} ms/prediction")
    if avg_ms < 50.0:
        print(f"  ✓ Performance OK  (avg {avg_ms:.3f} ms < 50 ms threshold)")
    else:
        print(f"  ⚠ Performance slow  (avg {avg_ms:.3f} ms > 50 ms)")

    # ──────────────────────────────────────────────────────────────────────
    # Final summary
    # ──────────────────────────────────────────────────────────────────────
    print()
    print(_sep("═"))
    passed = total - failures
    print(f"  RESULTS:  {passed}/{total} tests passed")
    if failures == 0:
        print("  STATUS:   ✓  ALL TESTS PASSED")
    else:
        print(f"  STATUS:   ✗  {failures} TEST(S) FAILED")
    print(_sep("═"))

    return failures


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    exit_code = run_tests()
    sys.exit(exit_code)
