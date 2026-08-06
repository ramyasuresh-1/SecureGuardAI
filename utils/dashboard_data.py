"""
Dashboard data helpers for SecureGuard AI.

All functions accept a user_id so every query is scoped to the
logged-in user.  They return plain Python dicts / lists that are
safe to pass directly to Jinja2 templates or serialised as JSON.
Functions are grouped into four areas:

    1. Summary cards  – totals and KPIs
    2. Chart datasets – Chart.js-ready labels + data arrays
    3. Recent activity – latest N analyses as timeline rows
    4. Notifications  – dynamic notification items
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func

from extensions import db
from models import PasswordAnalysis

# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

_SCORE_BUCKETS = ["0-20", "21-40", "41-60", "61-80", "81-100"]
_RADAR_LABELS = ["Uppercase", "Lowercase", "Numbers", "Special Chars", "Length", "Entropy"]
_THREAT_LABELS = [
    "Weak Passwords",
    "Breached",
    "Keyboard Patterns",
    "Low Entropy",
    "Dictionary Words",
]


# ---------------------------------------------------------------------------
# 1. Summary cards
# ---------------------------------------------------------------------------


def get_card_stats(user_id: int) -> dict[str, Any]:
    """Return all six dashboard card values for *user_id*.

    Keys returned
    -------------
    total            – int   total analyses
    strong           – int   Excellent + Strong count
    weak             – int   Weak count
    breached         – int   is_breached == True count
    avg_score        – float rounded to 1 dp, 0.0 when no data
    threat_level     – str   "Critical" | "High" | "Medium" | "Low"
    strong_pct       – float percentage of strong out of total
    weak_pct         – float percentage of weak out of total
    breached_pct     – float percentage of breached out of total
    """
    base = PasswordAnalysis.query.filter_by(user_id=user_id)

    total: int = base.count()

    if total == 0:
        return {
            "total": 0,
            "strong": 0,
            "weak": 0,
            "breached": 0,
            "avg_score": 0.0,
            "threat_level": "Low",
            "strong_pct": 0.0,
            "weak_pct": 0.0,
            "breached_pct": 0.0,
        }

    # "Strong" = passwords rated Strong or Excellent.
    strong: int = base.filter(
        PasswordAnalysis.strength_category.in_(["Strong", "Excellent"])
    ).count()

    # "Weak" = passwords rated Weak OR Very Weak.
    # The strength scale was extended from 4 to 5 tiers (Very Weak / Weak /
    # Moderate / Strong / Excellent). Rows saved before the extension have
    # category = "Weak"; rows saved after may have category = "Very Weak".
    # Both must be counted here so the card never shows 0 incorrectly.
    weak: int = base.filter(
        PasswordAnalysis.strength_category.in_(["Weak", "Very Weak"])
    ).count()

    breached: int = base.filter(PasswordAnalysis.is_breached == True).count()  # noqa: E712

    avg_row = db.session.query(
        func.round(func.avg(PasswordAnalysis.strength_score), 1)
    ).filter_by(user_id=user_id).scalar()
    avg_score: float = float(avg_row) if avg_row is not None else 0.0

    threat_level = _compute_threat_level(weak, breached, total, avg_score)

    def pct(n: int) -> float:
        return round(n / total * 100, 1) if total else 0.0

    return {
        "total": total,
        "strong": strong,
        "weak": weak,
        "breached": breached,
        "avg_score": avg_score,
        "threat_level": threat_level,
        "strong_pct": pct(strong),
        "weak_pct": pct(weak),
        "breached_pct": pct(breached),
    }


def _compute_threat_level(
    weak: int, breached: int, total: int, avg_score: float
) -> str:
    """Derive a threat level label from breach / weak ratios and avg score."""
    if total == 0:
        return "Low"
    breach_pct = (breached / total) * 100
    weak_pct = (weak / total) * 100
    if breach_pct >= 20 or avg_score < 40:
        return "Critical"
    if breach_pct >= 10 or weak_pct >= 40 or avg_score < 55:
        return "High"
    if breach_pct >= 5 or weak_pct >= 20 or avg_score < 70:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# 2. Chart datasets
# ---------------------------------------------------------------------------


def get_strength_pie_data(user_id: int) -> dict[str, Any]:
    """Password Strength Distribution – pie / doughnut chart data."""
    rows = (
        db.session.query(
            PasswordAnalysis.strength_category,
            func.count(PasswordAnalysis.id).label("cnt"),
        )
        .filter_by(user_id=user_id)
        .group_by(PasswordAnalysis.strength_category)
        .all()
    )

    # All five strength tiers, weakest → strongest.
    # "Very Weak" is the new tier added when strength.py was extended.
    # Keeping it separate from "Weak" lets the chart show the full distribution.
    order = ["Very Weak", "Weak", "Moderate", "Strong", "Excellent"]
    counts: dict[str, int] = {cat: 0 for cat in order}
    for cat, cnt in rows:
        if cat in counts:
            counts[cat] = cnt

    total = sum(counts.values())

    # Legend percentages – group Very Weak + Weak under "Weak" for display
    weak_total = counts["Very Weak"] + counts["Weak"]
    strong_total = counts["Strong"] + counts["Excellent"]

    return {
        "labels": order,
        "data": [counts[c] for c in order],
        "total": total,
        "percentages": {
            c: round(counts[c] / total * 100, 1) if total else 0.0
            for c in order
        },
        # Convenience grouped percentages used by the dashboard legend
        "percentages_grouped": {
            "Weak":     round(weak_total  / total * 100, 1) if total else 0.0,
            "Moderate": round(counts["Moderate"] / total * 100, 1) if total else 0.0,
            "Strong":   round(strong_total / total * 100, 1) if total else 0.0,
        },
    }


def get_daily_trend_data(user_id: int, days: int = 30) -> dict[str, Any]:
    """Daily Analysis Trend – line chart data for the last *days* days."""
    since = datetime.utcnow() - timedelta(days=days - 1)

    rows = (
        db.session.query(
            func.date(PasswordAnalysis.analyzed_at).label("day"),
            func.count(PasswordAnalysis.id).label("cnt"),
        )
        .filter(
            PasswordAnalysis.user_id == user_id,
            PasswordAnalysis.analyzed_at >= since,
        )
        .group_by(func.date(PasswordAnalysis.analyzed_at))
        .order_by(func.date(PasswordAnalysis.analyzed_at))
        .all()
    )

    # Build a full date range filled with 0 for missing days
    day_map: dict[str, int] = {str(row.day): row.cnt for row in rows}
    labels: list[str] = []
    data: list[int] = []
    for i in range(days):
        day = (since + timedelta(days=i)).strftime("%Y-%m-%d")
        display = (since + timedelta(days=i)).strftime("%b %d")
        labels.append(display)
        data.append(day_map.get(day, 0))

    return {"labels": labels, "data": data}


def get_score_distribution_data(user_id: int) -> dict[str, Any]:
    """Security Score Distribution – bar chart data bucketed 0-20…81-100."""
    rows = (
        PasswordAnalysis.query
        .filter_by(user_id=user_id)
        .with_entities(PasswordAnalysis.strength_score)
        .all()
    )

    buckets: dict[str, int] = {b: 0 for b in _SCORE_BUCKETS}
    for (score,) in rows:
        if score <= 20:
            buckets["0-20"] += 1
        elif score <= 40:
            buckets["21-40"] += 1
        elif score <= 60:
            buckets["41-60"] += 1
        elif score <= 80:
            buckets["61-80"] += 1
        else:
            buckets["81-100"] += 1

    return {
        "labels": _SCORE_BUCKETS,
        "data": [buckets[b] for b in _SCORE_BUCKETS],
    }


def get_threat_category_data(user_id: int) -> dict[str, Any]:
    """Threat Categories – doughnut chart data."""
    base = PasswordAnalysis.query.filter_by(user_id=user_id)

    # Include "Very Weak" in the weak count so new rows are not silently ignored
    weak_count = base.filter(
        PasswordAnalysis.strength_category.in_(["Weak", "Very Weak"])
    ).count()
    breached_count    = base.filter(PasswordAnalysis.is_breached == True).count()      # noqa: E712
    keyboard_count    = base.filter(PasswordAnalysis.keyboard_pattern == True).count() # noqa: E712
    low_entropy_count = base.filter(PasswordAnalysis.entropy < 3.0).count()
    dict_count        = base.filter(PasswordAnalysis.dictionary_word == True).count()  # noqa: E712

    data = [weak_count, breached_count, keyboard_count, low_entropy_count, dict_count]

    return {
        "labels": _THREAT_LABELS,
        "data": data,
        "total": sum(data),
    }


def get_composition_radar_data(user_id: int) -> dict[str, Any]:
    """Password Composition – radar chart: avg per-feature as 0-100 score."""
    row = (
        db.session.query(
            func.avg(PasswordAnalysis.uppercase).label("avg_upper"),
            func.avg(PasswordAnalysis.lowercase).label("avg_lower"),
            func.avg(PasswordAnalysis.digits).label("avg_digits"),
            func.avg(PasswordAnalysis.special).label("avg_special"),
            func.avg(PasswordAnalysis.length).label("avg_length"),
            func.avg(PasswordAnalysis.entropy).label("avg_entropy"),
        )
        .filter_by(user_id=user_id)
        .first()
    )

    def _safe(val: Any, divisor: float, ceiling: float = 100.0) -> float:
        """Scale raw average to 0-100 range."""
        if val is None:
            return 0.0
        return round(min(float(val) / divisor * 100, ceiling), 1)

    # Divisors chosen so a "perfect" password maps to ~100.
    # uppercase / lowercase: assume max meaningful ≈ 6 chars each
    # digits: ≈ 4, special: ≈ 3, length: ≈ 20, entropy: ≈ 5.0 bits
    actual = [
        _safe(row.avg_upper, 6.0),
        _safe(row.avg_lower, 6.0),
        _safe(row.avg_digits, 4.0),
        _safe(row.avg_special, 3.0),
        _safe(row.avg_length, 20.0),
        _safe(row.avg_entropy, 5.0),
    ] if row and row.avg_length is not None else [0.0] * 6

    recommended = [80.0] * 6  # benchmark line

    return {
        "labels": _RADAR_LABELS,
        "actual": actual,
        "recommended": recommended,
    }


def get_all_chart_data(user_id: int) -> dict[str, Any]:
    """Bundle all five chart datasets in a single call (avoids repeated trips)."""
    return {
        "strength_pie": get_strength_pie_data(user_id),
        "daily_trend": get_daily_trend_data(user_id),
        "score_dist": get_score_distribution_data(user_id),
        "threat_categories": get_threat_category_data(user_id),
        "composition_radar": get_composition_radar_data(user_id),
    }


# ---------------------------------------------------------------------------
# 3. Recent activity
# ---------------------------------------------------------------------------


def get_recent_activity(user_id: int, limit: int = 6) -> list[dict[str, Any]]:
    """Return the *limit* most-recent analyses as timeline-row dicts.

    Each dict has:
        title     – str   e.g. "Strong Password Detected"
        sub       – str   e.g. "Score: 92/100"
        dot_class – str   Bootstrap bg-* colour class
        time_ago  – str   human-readable age
        icon      – str   FontAwesome class
    """
    rows = (
        PasswordAnalysis.query
        .filter_by(user_id=user_id)
        .order_by(PasswordAnalysis.analyzed_at.desc())
        .limit(limit)
        .all()
    )

    items: list[dict[str, Any]] = []
    for row in rows:
        cat = row.strength_category
        breached = row.is_breached

        if breached:
            title = "Breach Detected"
            dot = "bg-danger"
            icon = "fas fa-skull-crossbones"
        elif cat in ("Weak", "Very Weak"):
            title = "Weak Password Detected"
            dot = "bg-warning"
            icon = "fas fa-exclamation-triangle"
        elif cat in ("Strong", "Excellent"):
            title = "Strong Password Analysed"
            dot = "bg-success"
            icon = "fas fa-shield-check"
        else:
            title = "Password Analysed"
            dot = "bg-info"
            icon = "fas fa-lock"

        items.append(
            {
                "title": title,
                "sub": f"Score: {row.strength_score}/100 · {cat}",
                "dot_class": dot,
                "icon": icon,
                "time_ago": _time_ago(row.analyzed_at),
                "analyzed_at": row.analyzed_at.strftime("%Y-%m-%d %H:%M"),
            }
        )

    return items


# ---------------------------------------------------------------------------
# 4. Notifications
# ---------------------------------------------------------------------------


def get_notifications(user_id: int, limit: int = 8) -> list[dict[str, Any]]:
    """Return dynamic notification items derived from recent analyses."""
    from models import User  # local import to avoid circular references

    user = User.query.get(user_id)
    notes: list[dict[str, Any]] = []

    # --- Login notification ---
    if user and user.last_login:
        notes.append(
            {
                "icon": "fas fa-sign-in-alt",
                "icon_bg": "bg-gradient-info",
                "title": "Login Successful",
                "sub": f"Last login: {user.last_login.strftime('%b %d, %H:%M')}",
                "time_ago": _time_ago(user.last_login),
                "unread": False,
            }
        )

    # --- Analysis-based notifications ---
    recent = (
        PasswordAnalysis.query
        .filter_by(user_id=user_id)
        .order_by(PasswordAnalysis.analyzed_at.desc())
        .limit(20)
        .all()
    )

    breached_recent = [r for r in recent if r.is_breached]
    weak_recent = [r for r in recent if r.strength_category in ("Weak", "Very Weak")]

    if breached_recent:
        notes.append(
            {
                "icon": "fas fa-radiation",
                "icon_bg": "bg-gradient-danger",
                "title": f"{len(breached_recent)} Breached Password(s) Found",
                "sub": "Immediate action recommended",
                "time_ago": _time_ago(breached_recent[0].analyzed_at),
                "unread": True,
            }
        )

    if weak_recent:
        notes.append(
            {
                "icon": "fas fa-exclamation-triangle",
                "icon_bg": "bg-gradient-warning",
                "title": f"{len(weak_recent)} Weak Password(s) Detected",
                "sub": "Consider updating these passwords",
                "time_ago": _time_ago(weak_recent[0].analyzed_at),
                "unread": True,
            }
        )

    if recent:
        notes.append(
            {
                "icon": "fas fa-shield-halved",
                "icon_bg": "bg-gradient-primary",
                "title": "Password Analysed",
                "sub": f"Latest score: {recent[0].strength_score}/100",
                "time_ago": _time_ago(recent[0].analyzed_at),
                "unread": False,
            }
        )

    # --- Total analyses milestone ---
    total = PasswordAnalysis.query.filter_by(user_id=user_id).count()
    if total > 0 and total % 10 == 0:
        notes.append(
            {
                "icon": "fas fa-trophy",
                "icon_bg": "bg-gradient-success",
                "title": f"Milestone: {total} Analyses Completed",
                "sub": "Great security hygiene!",
                "time_ago": "just now",
                "unread": False,
            }
        )

    return notes[:limit]


def get_unread_notification_count(user_id: int) -> int:
    """Return the count of unread (actionable) notifications."""
    breached = PasswordAnalysis.query.filter_by(
        user_id=user_id, is_breached=True
    ).count()
    # Count both "Weak" and "Very Weak" categories
    weak = PasswordAnalysis.query.filter(
        PasswordAnalysis.user_id == user_id,
        PasswordAnalysis.strength_category.in_(["Weak", "Very Weak"]),
    ).count()
    return min(9, breached + (1 if weak > 0 else 0))


# ---------------------------------------------------------------------------
# 5. AI Insights
# ---------------------------------------------------------------------------


def get_ai_insights(user_id: int) -> list[dict[str, Any]]:
    """Generate dynamic AI insight cards based on the user's analysis data."""
    base = PasswordAnalysis.query.filter_by(user_id=user_id)
    total = base.count()
    insights: list[dict[str, Any]] = []

    if total == 0:
        return [
            {
                "icon": "fas fa-lightbulb",
                "title": "Get Started",
                "body": "Analyse your first password to receive personalised security insights.",
                "badge": "bg-info",
                "badge_text": "Tip",
            }
        ]

    avg_entropy = (
        db.session.query(func.avg(PasswordAnalysis.entropy))
        .filter_by(user_id=user_id)
        .scalar()
        or 0.0
    )
    weak_count = base.filter(
        PasswordAnalysis.strength_category.in_(["Weak", "Very Weak"])
    ).count()
    keyboard_count = base.filter(PasswordAnalysis.keyboard_pattern == True).count()  # noqa: E712
    dict_count = base.filter(PasswordAnalysis.dictionary_word == True).count()  # noqa: E712
    breached_count = base.filter(PasswordAnalysis.is_breached == True).count()  # noqa: E712
    avg_len_row = (
        db.session.query(func.avg(PasswordAnalysis.length))
        .filter_by(user_id=user_id)
        .scalar()
        or 0.0
    )
    avg_len = float(avg_len_row)

    # Entropy insight
    if avg_entropy < 3.5:
        insights.append(
            {
                "icon": "fas fa-lightbulb",
                "title": "Low Password Entropy",
                "body": (
                    f"Your average entropy is {round(avg_entropy, 2)} bits — below the "
                    "recommended 4.0. Increase character variety and length."
                ),
                "badge": "bg-warning text-dark",
                "badge_text": "Medium Priority",
            }
        )

    # Keyboard pattern insight
    if keyboard_count > 0:
        kb_pct = round(keyboard_count / total * 100, 1)
        insights.append(
            {
                "icon": "fas fa-keyboard",
                "title": "Keyboard Pattern Detected",
                "body": (
                    f"{kb_pct}% of passwords contain keyboard sequences like "
                    '"qwerty" or "12345". These are trivially guessable.'
                ),
                "badge": "bg-danger",
                "badge_text": "High Risk",
            }
        )

    # Dictionary word insight
    if dict_count > 0:
        d_pct = round(dict_count / total * 100, 1)
        insights.append(
            {
                "icon": "fas fa-book",
                "title": "Dictionary Words Found",
                "body": (
                    f"{d_pct}% of passwords use common dictionary words. "
                    "Replace them with random passphrases or symbols."
                ),
                "badge": "bg-warning text-dark",
                "badge_text": "Medium Priority",
            }
        )

    # Breach insight (highest priority — always show if any)
    if breached_count > 0:
        insights.insert(
            0,
            {
                "icon": "fas fa-radiation",
                "title": "Breached Passwords Detected",
                "body": (
                    f"{breached_count} password(s) appear in known data breach databases. "
                    "Change these immediately."
                ),
                "badge": "bg-danger",
                "badge_text": "Critical",
            },
        )

    # Short password insight
    if avg_len < 10:
        insights.append(
            {
                "icon": "fas fa-ruler-horizontal",
                "title": "Passwords Are Too Short",
                "body": (
                    f"Average password length is {round(avg_len, 1)} characters. "
                    "Aim for at least 14 characters for strong protection."
                ),
                "badge": "bg-warning text-dark",
                "badge_text": "Recommendation",
            }
        )

    # Weak password insight
    if weak_count > 0:
        w_pct = round(weak_count / total * 100, 1)
        insights.append(
            {
                "icon": "fas fa-shield-check",
                "title": "Weak Passwords in History",
                "body": (
                    f"{w_pct}% of your analysed passwords are rated Weak. "
                    "Use SecureGuard's password generator to create stronger ones."
                ),
                "badge": "bg-info",
                "badge_text": "Recommendation",
            }
        )

    # All-good insight when nothing critical found
    if not insights:
        insights.append(
            {
                "icon": "fas fa-check-circle",
                "title": "Great Password Hygiene",
                "body": (
                    "No critical issues detected. Continue monitoring new passwords "
                    "regularly to maintain your strong security posture."
                ),
                "badge": "bg-success",
                "badge_text": "All Clear",
            }
        )

    return insights[:3]  # cap at 3 cards


# ---------------------------------------------------------------------------
# 6. Analytics page helpers
# ---------------------------------------------------------------------------


def get_analytics_averages(user_id: int) -> dict[str, Any]:
    """Return average metrics used on the analytics page."""
    row = (
        db.session.query(
            func.round(func.avg(PasswordAnalysis.length), 1).label("avg_len"),
            func.round(func.avg(PasswordAnalysis.entropy), 2).label("avg_entropy"),
            func.round(func.avg(PasswordAnalysis.strength_score), 1).label("avg_score"),
        )
        .filter_by(user_id=user_id)
        .first()
    )

    if row is None or row.avg_len is None:
        return {"avg_len": 0.0, "avg_entropy": 0.0, "avg_score": 0.0}

    return {
        "avg_len": float(row.avg_len),
        "avg_entropy": float(row.avg_entropy),
        "avg_score": float(row.avg_score),
    }


def get_monthly_performance(user_id: int, months: int = 6) -> list[dict[str, Any]]:
    """Return per-month performance rows for the analytics table."""
    rows = (
        db.session.query(
            func.strftime("%Y-%m", PasswordAnalysis.analyzed_at).label("month"),
            func.count(PasswordAnalysis.id).label("total"),
            func.sum(
                db.case((PasswordAnalysis.strength_category.in_(["Strong", "Excellent"]), 1), else_=0)
            ).label("strong"),
            func.round(func.avg(PasswordAnalysis.strength_score), 1).label("avg_score"),
            func.sum(
                db.case((PasswordAnalysis.is_breached == True, 1), else_=0)  # noqa: E712
            ).label("breached"),
        )
        .filter_by(user_id=user_id)
        .group_by(func.strftime("%Y-%m", PasswordAnalysis.analyzed_at))
        .order_by(func.strftime("%Y-%m", PasswordAnalysis.analyzed_at).desc())
        .limit(months)
        .all()
    )

    result = []
    for row in rows:
        total = row.total or 0
        strong = row.strong or 0
        avg = float(row.avg_score or 0.0)
        breached = row.breached or 0
        strong_pct = round(strong / total * 100, 1) if total else 0.0

        # Status label
        if avg >= 75:
            status, status_cls = "Good", "text-accent"
        elif avg >= 60:
            status, status_cls = "Fair", "text-purple"
        elif avg >= 45:
            status, status_cls = "Needs Improvement", "text-warning"
        else:
            status, status_cls = "Critical", "text-danger"

        # Format month display: "2026-07" → "July 2026"
        try:
            month_dt = datetime.strptime(row.month, "%Y-%m")
            month_display = month_dt.strftime("%B %Y")
        except (ValueError, TypeError):
            month_display = row.month or "Unknown"

        result.append(
            {
                "month": month_display,
                "total": total,
                "strong_pct": strong_pct,
                "avg_score": avg,
                "breached": breached,
                "status": status,
                "status_cls": status_cls,
            }
        )

    return result


# ---------------------------------------------------------------------------
# 7. History / pagination
# ---------------------------------------------------------------------------


def get_history_page(
    user_id: int,
    page: int = 1,
    per_page: int = 15,
    search: str = "",
) -> dict[str, Any]:
    """Return a paginated history of analyses, optionally filtered by *search*.

    Returned dict keys
    ------------------
    items       – list[dict]  page of to_dict() rows
    page        – int
    per_page    – int
    total       – int         total matching rows
    pages       – int         total number of pages
    has_prev    – bool
    has_next    – bool
    """
    query = PasswordAnalysis.query.filter_by(user_id=user_id)

    if search:
        term = f"%{search.lower()}%"
        query = query.filter(
            db.or_(
                PasswordAnalysis.strength_category.ilike(term),
                PasswordAnalysis.label.ilike(term),
            )
        )

    total: int = query.count()
    pages: int = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, pages))

    rows = (
        query
        .order_by(PasswordAnalysis.analyzed_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "rows": [r.to_dict() for r in rows],
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages,
        "has_prev": page > 1,
        "has_next": page < pages,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _time_ago(dt: datetime) -> str:
    """Return a human-readable 'time ago' string for *dt*."""
    if dt is None:
        return "—"
    now = datetime.utcnow()
    diff = now - dt
    seconds = int(diff.total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        mins = seconds // 60
        return f"{mins} min{'s' if mins > 1 else ''} ago"
    if seconds < 86400:
        hrs = seconds // 3600
        return f"{hrs} hr{'s' if hrs > 1 else ''} ago"
    days = seconds // 86400
    if days == 1:
        return "yesterday"
    if days < 30:
        return f"{days} days ago"
    months = days // 30
    return f"{months} month{'s' if months > 1 else ''} ago"

# ---------------------------------------------------------------------------
# 8. Hybrid AI Analytics helpers
# ---------------------------------------------------------------------------

_HYBRID_DECISION_ORDER = [
    "Very Weak", "Weak", "Moderate", "Strong", "Excellent"
]

_DECISION_SOURCES = [
    "Hybrid Consensus",
    "Machine Learning",
    "Rule Engine",
    "Weighted Decision",
    "Breach Guard",
]


def get_hybrid_decision_distribution(user_id: int) -> dict[str, Any]:
    """
    Count how many analyses ended in each Hybrid AI final decision tier.

    Returns Chart.js-ready labels + data arrays.
    Rows with NULL hybrid_decision (saved before this feature) are excluded.
    """
    rows = (
        db.session.query(
            PasswordAnalysis.hybrid_decision,
            func.count(PasswordAnalysis.id).label("cnt"),
        )
        .filter(
            PasswordAnalysis.user_id == user_id,
            PasswordAnalysis.hybrid_decision.isnot(None),
        )
        .group_by(PasswordAnalysis.hybrid_decision)
        .all()
    )

    counts: dict[str, int] = {cat: 0 for cat in _HYBRID_DECISION_ORDER}
    for cat, cnt in rows:
        if cat in counts:
            counts[cat] = cnt

    return {
        "labels": _HYBRID_DECISION_ORDER,
        "data":   [counts[c] for c in _HYBRID_DECISION_ORDER],
        "total":  sum(counts.values()),
    }


def get_rule_ml_agreement_data(user_id: int) -> dict[str, Any]:
    """
    Count analyses where Rule Engine and ML agreed vs disagreed.

    Returns Chart.js-ready labels + data for a pie/doughnut chart.
    """
    base = PasswordAnalysis.query.filter(
        PasswordAnalysis.user_id == user_id,
        PasswordAnalysis.hybrid_agreement.isnot(None),
    )

    agreed    = base.filter(PasswordAnalysis.hybrid_agreement == True).count()   # noqa: E712
    disagreed = base.filter(PasswordAnalysis.hybrid_agreement == False).count()  # noqa: E712

    return {
        "labels": ["Agreed", "Disagreed"],
        "data":   [agreed, disagreed],
        "total":  agreed + disagreed,
    }


def get_avg_ml_confidence(user_id: int) -> dict[str, Any]:
    """
    Return the average ML confidence per strength category as a bar chart.

    Only rows with non-NULL ml_confidence are considered.
    """
    rows = (
        db.session.query(
            PasswordAnalysis.hybrid_decision,
            func.round(func.avg(PasswordAnalysis.ml_confidence), 3).label("avg_conf"),
        )
        .filter(
            PasswordAnalysis.user_id == user_id,
            PasswordAnalysis.ml_confidence.isnot(None),
            PasswordAnalysis.hybrid_decision.isnot(None),
        )
        .group_by(PasswordAnalysis.hybrid_decision)
        .all()
    )

    conf_map: dict[str, float] = {}
    for cat, avg_conf in rows:
        if cat and avg_conf is not None:
            conf_map[cat] = round(float(avg_conf), 3)

    return {
        "labels": _HYBRID_DECISION_ORDER,
        "data":   [conf_map.get(c, 0.0) for c in _HYBRID_DECISION_ORDER],
    }


def get_decision_source_distribution(user_id: int) -> dict[str, Any]:
    """
    Count analyses grouped by the Hybrid AI decision_source value.

    Returns Chart.js-ready labels + data.
    """
    rows = (
        db.session.query(
            PasswordAnalysis.decision_source,
            func.count(PasswordAnalysis.id).label("cnt"),
        )
        .filter(
            PasswordAnalysis.user_id == user_id,
            PasswordAnalysis.decision_source.isnot(None),
        )
        .group_by(PasswordAnalysis.decision_source)
        .all()
    )

    counts: dict[str, int] = {src: 0 for src in _DECISION_SOURCES}
    for src, cnt in rows:
        if src in counts:
            counts[src] = cnt

    # Filter to only sources that actually appear (keeps chart clean)
    active   = [(s, counts[s]) for s in _DECISION_SOURCES if counts[s] > 0]
    labels   = [s for s, _ in active]
    data     = [c for _, c in active]

    # Include "Other" bucket for any unknown sources
    other = sum(cnt for src, cnt in rows if src not in counts)
    if other:
        labels.append("Other")
        data.append(other)

    return {
        "labels": labels,
        "data":   data,
        "total":  sum(data),
    }


def get_hybrid_analytics_data(user_id: int) -> dict[str, Any]:
    """
    Bundle all four Hybrid AI chart datasets in one call.

    Used by the /api/hybrid/analytics endpoint so the frontend
    makes a single request for the analytics page.
    """
    return {
        "hybrid_decision_dist":  get_hybrid_decision_distribution(user_id),
        "rule_ml_agreement":     get_rule_ml_agreement_data(user_id),
        "avg_ml_confidence":     get_avg_ml_confidence(user_id),
        "decision_source_dist":  get_decision_source_distribution(user_id),
    }
