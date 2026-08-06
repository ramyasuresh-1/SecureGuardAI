"""
utils/breach_dashboard.py — SecureGuard AI Breach Intelligence Center
=======================================================================

All data-access helpers used exclusively by the /breach-detection page.

Design rules
------------
* No new SQL logic is introduced where dashboard_data.py already covers it.
* Only PasswordAnalysis rows with is_breached == True are queried.
* Plaintext passwords are never stored — only masked labels.
* All functions accept a user_id so queries are always scoped.

Public API
----------
get_breach_summary(user_id)          → dict   hero / status card KPIs
get_breach_history(user_id, …)       → dict   paginated breach table rows
get_breach_risk_chart(user_id)       → dict   doughnut chart dataset
get_breach_timeline(user_id, limit)  → list   vertical timeline items
get_breach_recommendations(risk)     → list   AI recommendation cards
get_breach_intelligence(row_dict)    → dict   selected-row detail panel
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func

from extensions import db
from models import PasswordAnalysis

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Risk colour / badge helpers (shared with the template)
# ---------------------------------------------------------------------------
RISK_BADGE_CLASS: dict[str, str] = {
    "Critical": "badge-risk-critical",
    "High":     "badge-risk-high",
    "Medium":   "badge-risk-medium",
    "Low":      "badge-risk-low",
    "Safe":     "badge-risk-safe",
}

RISK_COLOURS: dict[str, str] = {
    "Critical": "#ef4444",
    "High":     "#f97316",
    "Medium":   "#f59e0b",
    "Low":      "#3b82f6",
    "Safe":     "#2ecc71",
}

# Risk tier inferred from breach_count / strength_score stored at analysis time
# (the breach_risk field is NOT stored in the DB, so we infer it here)
def _infer_risk(row: PasswordAnalysis) -> str:
    """Infer a breach risk tier from a PasswordAnalysis row."""
    score = row.strength_score
    if score < 20:
        return "Critical"
    if score < 35:
        return "High"
    if score < 50:
        return "Medium"
    if score < 65:
        return "Low"
    return "Low"


def _time_ago(dt: datetime | None) -> str:
    """Return a human-readable 'time ago' string."""
    if dt is None:
        return "—"
    diff = datetime.utcnow() - dt
    secs = int(diff.total_seconds())
    if secs < 60:
        return "just now"
    if secs < 3600:
        m = secs // 60
        return f"{m} min{'s' if m > 1 else ''} ago"
    if secs < 86400:
        h = secs // 3600
        return f"{h} hr{'s' if h > 1 else ''} ago"
    d = secs // 86400
    if d == 1:
        return "yesterday"
    if d < 30:
        return f"{d} days ago"
    mo = d // 30
    return f"{mo} month{'s' if mo > 1 else ''} ago"


# ---------------------------------------------------------------------------
# 1. Hero / Summary KPIs
# ---------------------------------------------------------------------------

def get_breach_summary(user_id: int) -> dict[str, Any]:
    """
    Return KPI data for the Breach Intelligence Center hero section.

    Keys
    ----
    total_checks        int    total password analyses for this user
    total_breached      int    analyses where is_breached == True
    breach_rate_pct     float  breached / total * 100, 0 when no data
    overall_status      str    "Safe" | "Warning" | "Critical"
    last_scan_time      str    human-readable time of the most recent analysis
    last_scan_iso       str    ISO timestamp for tooltip
    latest_breach       dict | None   details of the most recent breached row
    """
    base = PasswordAnalysis.query.filter_by(user_id=user_id)

    total_checks: int = base.count()
    total_breached: int = base.filter(
        PasswordAnalysis.is_breached == True  # noqa: E712
    ).count()

    breach_rate = round(total_breached / total_checks * 100, 1) if total_checks else 0.0

    # Overall status
    if total_breached == 0:
        overall_status = "Safe"
    elif breach_rate >= 20:
        overall_status = "Critical"
    else:
        overall_status = "Warning"

    # Last scan time
    latest_row = base.order_by(PasswordAnalysis.analyzed_at.desc()).first()
    if latest_row:
        last_scan_time = _time_ago(latest_row.analyzed_at)
        last_scan_iso  = latest_row.analyzed_at.strftime("%Y-%m-%d %H:%M UTC")
    else:
        last_scan_time = "Never"
        last_scan_iso  = "—"

    # Latest breached row detail
    latest_breach_row = (
        base
        .filter(PasswordAnalysis.is_breached == True)  # noqa: E712
        .order_by(PasswordAnalysis.analyzed_at.desc())
        .first()
    )
    latest_breach: dict[str, Any] | None = None
    if latest_breach_row:
        risk = _infer_risk(latest_breach_row)
        latest_breach = {
            "label":        latest_breach_row.label or "—",
            "source":       "RockYou Sample",
            "risk":         risk,
            "badge_class":  RISK_BADGE_CLASS.get(risk, "badge-risk-low"),
            "detected":     _time_ago(latest_breach_row.analyzed_at),
            "detected_iso": latest_breach_row.analyzed_at.strftime("%Y-%m-%d %H:%M"),
            "score":        latest_breach_row.strength_score,
        }

    log.debug(
        "get_breach_summary user=%d  total=%d  breached=%d  status=%s",
        user_id, total_checks, total_breached, overall_status,
    )
    return {
        "total_checks":    total_checks,
        "total_breached":  total_breached,
        "breach_rate_pct": breach_rate,
        "overall_status":  overall_status,
        "last_scan_time":  last_scan_time,
        "last_scan_iso":   last_scan_iso,
        "latest_breach":   latest_breach,
    }


# ---------------------------------------------------------------------------
# 2. Breach history table (paginated)
# ---------------------------------------------------------------------------

def get_breach_history(
    user_id:  int,
    page:     int = 1,
    per_page: int = 10,
    search:   str = "",
    sort_by:  str = "date_desc",
) -> dict[str, Any]:
    """
    Return a paginated list of breached PasswordAnalysis rows.

    Parameters
    ----------
    user_id  : int
    page     : int   1-based page number
    per_page : int   rows per page (default 10)
    search   : str   filter on label (masked password)
    sort_by  : str   "date_desc" | "date_asc" | "risk_desc" | "risk_asc"

    Returns
    -------
    dict with keys: rows, page, pages, total, has_prev, has_next
    Each row dict: id, label, risk, badge_class, source, score,
                   analyzed_at, time_ago, strength_category
    """
    query = PasswordAnalysis.query.filter_by(
        user_id=user_id, is_breached=True
    )

    if search:
        term = f"%{search.lower()}%"
        query = query.filter(PasswordAnalysis.label.ilike(term))

    # Sorting
    if sort_by == "date_asc":
        query = query.order_by(PasswordAnalysis.analyzed_at.asc())
    elif sort_by == "risk_desc":
        query = query.order_by(PasswordAnalysis.strength_score.asc())   # lower = riskier
    elif sort_by == "risk_asc":
        query = query.order_by(PasswordAnalysis.strength_score.desc())
    else:   # default: newest first
        query = query.order_by(PasswordAnalysis.analyzed_at.desc())

    total: int  = query.count()
    pages: int  = max(1, (total + per_page - 1) // per_page)
    page        = max(1, min(page, pages))

    db_rows = (
        query
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    rows: list[dict[str, Any]] = []
    for r in db_rows:
        risk = _infer_risk(r)
        rows.append({
            "id":               r.id,
            "label":            r.label or "—",
            "risk":             risk,
            "badge_class":      RISK_BADGE_CLASS.get(risk, "badge-risk-low"),
            "source":           "RockYou Sample",
            "score":            r.strength_score,
            "analyzed_at":      r.analyzed_at.strftime("%Y-%m-%d %H:%M"),
            "time_ago":         _time_ago(r.analyzed_at),
            "strength_category": r.strength_category,
            # Extra fields for the intelligence panel
            "length":           r.length,
            "entropy":          round(r.entropy, 2),
            "dictionary_word":  r.dictionary_word,
            "keyboard_pattern": r.keyboard_pattern,
            "uppercase":        r.uppercase,
            "digits":           r.digits,
            "special":          r.special,
        })

    return {
        "rows":     rows,
        "page":     page,
        "pages":    pages,
        "total":    total,
        "has_prev": page > 1,
        "has_next": page < pages,
        "per_page": per_page,
    }


# ---------------------------------------------------------------------------
# 3. Risk distribution chart (doughnut)
# ---------------------------------------------------------------------------

def get_breach_risk_chart(user_id: int) -> dict[str, Any]:
    """
    Return doughnut chart data: count of breached rows per risk tier.

    Returns
    -------
    dict  labels, data, colours (all parallel lists)
    """
    breached_rows = (
        PasswordAnalysis.query
        .filter_by(user_id=user_id, is_breached=True)
        .with_entities(PasswordAnalysis.strength_score)
        .all()
    )

    counts: dict[str, int] = {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0
    }
    for (score,) in breached_rows:
        if score < 20:
            counts["Critical"] += 1
        elif score < 35:
            counts["High"] += 1
        elif score < 50:
            counts["Medium"] += 1
        else:
            counts["Low"] += 1

    labels   = list(counts.keys())
    data     = list(counts.values())
    colours  = [RISK_COLOURS[l] for l in labels]

    return {
        "labels":  labels,
        "data":    data,
        "colours": colours,
        "total":   sum(data),
    }


# ---------------------------------------------------------------------------
# 4. Breach timeline
# ---------------------------------------------------------------------------

def get_breach_timeline(user_id: int, limit: int = 10) -> list[dict[str, Any]]:
    """
    Build a vertical timeline of recent password analysis activity.

    Includes both breached and non-breached entries so the user sees
    context around breach events (e.g. "checked password, then breach found").

    Returns
    -------
    list of dicts: date_label, title, sub, icon, icon_class, is_breach
    """
    rows = (
        PasswordAnalysis.query
        .filter_by(user_id=user_id)
        .order_by(PasswordAnalysis.analyzed_at.desc())
        .limit(limit)
        .all()
    )

    today      = datetime.utcnow().date()
    yesterday  = today - timedelta(days=1)
    items: list[dict[str, Any]] = []

    for row in rows:
        row_date = row.analyzed_at.date()
        if row_date == today:
            date_label = "Today"
        elif row_date == yesterday:
            date_label = "Yesterday"
        elif (today - row_date).days < 7:
            date_label = row_date.strftime("%A")        # e.g. "Monday"
        elif (today - row_date).days < 30:
            date_label = f"{(today - row_date).days} days ago"
        else:
            date_label = row.analyzed_at.strftime("%b %Y")

        if row.is_breached:
            title      = "Breach Detected"
            sub        = f"Password '{row.label}' found in breach dataset"
            icon       = "fas fa-radiation"
            icon_class = "timeline-icon-danger"
        elif row.strength_category in ("Weak", "Very Weak"):
            title      = "Weak Password Analysed"
            sub        = f"Score: {row.strength_score}/100 — '{row.label}'"
            icon       = "fas fa-exclamation-triangle"
            icon_class = "timeline-icon-warning"
        elif row.strength_category in ("Strong", "Excellent"):
            title      = "Strong Password Analysed"
            sub        = f"Score: {row.strength_score}/100 — '{row.label}'"
            icon       = "fas fa-shield-check"
            icon_class = "timeline-icon-success"
        else:
            title      = "Password Analysed"
            sub        = f"Score: {row.strength_score}/100 — '{row.label}'"
            icon       = "fas fa-lock"
            icon_class = "timeline-icon-info"

        items.append({
            "date_label": date_label,
            "time":       row.analyzed_at.strftime("%H:%M"),
            "title":      title,
            "sub":        sub,
            "icon":       icon,
            "icon_class": icon_class,
            "is_breach":  row.is_breached,
        })

    return items


# ---------------------------------------------------------------------------
# 5. AI Security Recommendations
# ---------------------------------------------------------------------------

# Recommendation cards keyed by risk tier
_RECOMMENDATIONS: dict[str, list[dict[str, str]]] = {
    "Critical": [
        {
            "icon": "fas fa-fire",
            "title": "Change Immediately",
            "body": "This password is one of the most commonly leaked credentials worldwide. "
                    "Change it on every service that uses it right now.",
            "badge": "bg-danger",
            "badge_text": "Urgent",
        },
        {
            "icon": "fas fa-ban",
            "title": "Never Reuse This Password",
            "body": "Credential-stuffing attacks automatically try leaked passwords across "
                    "hundreds of sites. Reuse means every account is compromised.",
            "badge": "bg-danger",
            "badge_text": "Critical",
        },
        {
            "icon": "fas fa-mobile-alt",
            "title": "Enable Multi-Factor Authentication",
            "body": "Even if an attacker has your password, MFA blocks account takeover. "
                    "Enable it on email, banking, and social media immediately.",
            "badge": "bg-warning text-dark",
            "badge_text": "High Priority",
        },
        {
            "icon": "fas fa-key",
            "title": "Use a Password Manager",
            "body": "Generate and store unique 20+ character passwords for every site. "
                    "Recommended: Bitwarden, 1Password, KeePass.",
            "badge": "bg-info",
            "badge_text": "Best Practice",
        },
    ],
    "High": [
        {
            "icon": "fas fa-exclamation-triangle",
            "title": "Update This Password Soon",
            "body": "This password appears in high-frequency breach lists used by automated "
                    "attackers. Update it within 24 hours.",
            "badge": "bg-warning text-dark",
            "badge_text": "High Priority",
        },
        {
            "icon": "fas fa-shield-alt",
            "title": "Generate a Unique Replacement",
            "body": "Use SecureGuard's password generator to create a 16+ character random "
                    "password with uppercase, digits, and symbols.",
            "badge": "bg-info",
            "badge_text": "Recommended",
        },
        {
            "icon": "fas fa-mobile-alt",
            "title": "Enable MFA",
            "body": "Add a second factor to all accounts using this password as a temporary "
                    "safeguard while you rotate credentials.",
            "badge": "bg-warning text-dark",
            "badge_text": "Important",
        },
    ],
    "Medium": [
        {
            "icon": "fas fa-clock",
            "title": "Schedule a Password Rotation",
            "body": "This password has been exposed. Plan to replace it within the next week "
                    "and audit other accounts for reuse.",
            "badge": "bg-info",
            "badge_text": "Medium Priority",
        },
        {
            "icon": "fas fa-sync-alt",
            "title": "Rotate Across Reused Accounts",
            "body": "If the same or similar password is used elsewhere, change those accounts "
                    "too. Password reuse multiplies breach impact.",
            "badge": "bg-info",
            "badge_text": "Recommended",
        },
        {
            "icon": "fas fa-key",
            "title": "Adopt a Password Manager",
            "body": "A password manager eliminates reuse entirely by storing a unique credential "
                    "for every service.",
            "badge": "bg-secondary",
            "badge_text": "Best Practice",
        },
    ],
    "Low": [
        {
            "icon": "fas fa-info-circle",
            "title": "Monitor and Replace When Convenient",
            "body": "Although exposure is lower risk, this password was found in a breach dataset. "
                    "Replace it at your next opportunity.",
            "badge": "bg-primary",
            "badge_text": "Advisory",
        },
        {
            "icon": "fas fa-eye",
            "title": "Watch for Suspicious Activity",
            "body": "Enable login notifications on accounts using this password so you can "
                    "react quickly to any unauthorised access.",
            "badge": "bg-secondary",
            "badge_text": "Monitoring",
        },
    ],
    "Safe": [
        {
            "icon": "fas fa-check-circle",
            "title": "No Action Required",
            "body": "This password was not found in any known breach database. "
                    "Continue regular scans to stay protected.",
            "badge": "bg-success",
            "badge_text": "All Clear",
        },
        {
            "icon": "fas fa-shield-halved",
            "title": "Maintain Good Hygiene",
            "body": "Keep using unique passwords per service, update every 90 days, and "
                    "enable MFA wherever available.",
            "badge": "bg-info",
            "badge_text": "Best Practice",
        },
    ],
}


def get_breach_recommendations(risk: str) -> list[dict[str, str]]:
    """
    Return AI recommendation cards for the given risk tier.

    Parameters
    ----------
    risk : str   "Critical" | "High" | "Medium" | "Low" | "Safe"

    Returns
    -------
    list[dict]  Each dict has icon, title, body, badge, badge_text.
    """
    return _RECOMMENDATIONS.get(risk, _RECOMMENDATIONS["Low"])


def get_default_recommendations(user_id: int) -> list[dict[str, str]]:
    """
    Return recommendations based on the user's worst breach risk tier found.

    Used for the initial page load before the user selects a specific row.
    """
    worst_row = (
        PasswordAnalysis.query
        .filter_by(user_id=user_id, is_breached=True)
        .order_by(PasswordAnalysis.strength_score.asc())   # lowest score = worst
        .first()
    )
    if worst_row is None:
        return get_breach_recommendations("Safe")
    risk = _infer_risk(worst_row)
    return get_breach_recommendations(risk)


# ---------------------------------------------------------------------------
# 6. Selected breach intelligence panel data
# ---------------------------------------------------------------------------

# Attack scenario library — shown in the intelligence detail panel
_ATTACK_SCENARIOS: dict[str, str] = {
    "Credential Stuffing": (
        "Attackers take leaked username/password pairs and automatically test them "
        "against hundreds of other websites. One breached password can expose all "
        "accounts where the same credentials are reused."
    ),
    "Password Spraying": (
        "Rather than targeting one account, attackers spray the most common breached "
        "passwords across thousands of usernames. Common passwords like those found "
        "in RockYou are tried billions of times daily."
    ),
    "Account Takeover": (
        "Once an attacker gains access to one account with a leaked password, they "
        "search for password-reset emails, financial accounts, and corporate systems "
        "linked to the same identity."
    ),
    "Reuse Risk": (
        "The average person reuses passwords across 5 different services. A single "
        "breach multiplies into full identity exposure when the same password "
        "unlocks email, banking, and social accounts."
    ),
}

_BUSINESS_IMPACT: list[dict[str, str]] = [
    {"icon": "fas fa-dollar-sign", "text": "Financial account access and wire fraud"},
    {"icon": "fas fa-envelope",    "text": "Email takeover enabling phishing campaigns"},
    {"icon": "fas fa-database",    "text": "Corporate data exfiltration if work accounts reuse passwords"},
    {"icon": "fas fa-id-card",     "text": "Identity theft and fraudulent account creation"},
]


def get_breach_intelligence(row: dict[str, Any]) -> dict[str, Any]:
    """
    Enrich a breach history row dict with full intelligence panel data.

    Parameters
    ----------
    row : dict   A row dict from get_breach_history() rows list.

    Returns
    -------
    dict with additional keys:
        attack_scenarios  list[{name, description}]
        business_impact   list[{icon, text}]
        technical_summary str
        source_explanation str
    """
    risk = row.get("risk", "Low")
    score = row.get("score", 0)
    entropy = row.get("entropy", 0.0)

    # Technical explanation
    weaknesses = []
    if score < 30:
        weaknesses.append("extremely low strength score")
    if entropy < 2.5:
        weaknesses.append("very low Shannon entropy (highly predictable character pattern)")
    if row.get("dictionary_word"):
        weaknesses.append("contains a common dictionary word")
    if row.get("keyboard_pattern"):
        weaknesses.append("contains a keyboard sequence (e.g. qwerty, 12345)")
    if row.get("length", 10) < 8:
        weaknesses.append("insufficient length (below 8 characters)")
    if not row.get("uppercase"):
        weaknesses.append("no uppercase letters")
    if not row.get("digits"):
        weaknesses.append("no numeric digits")
    if not row.get("special"):
        weaknesses.append("no special characters")

    if weaknesses:
        technical_summary = (
            f"This password was flagged as {risk} risk. "
            f"Weaknesses detected: {'; '.join(weaknesses)}. "
            f"Strength score: {score}/100. Entropy: {entropy} bits."
        )
    else:
        technical_summary = (
            f"Despite a {risk} risk rating, this password was found in "
            f"a breach dataset (score: {score}/100, entropy: {entropy} bits). "
            "It may have been exposed through a third-party service breach."
        )

    source_explanation = (
        "This password was matched against the RockYou breach dataset — a corpus "
        "of over 14 million real-world passwords leaked from the RockYou social "
        "gaming platform in 2009. It remains the benchmark dataset used by security "
        "researchers and penetration testers worldwide. Any password appearing in "
        "this list is assumed to be known to automated attack tools."
    )

    return {
        **row,
        "attack_scenarios":    [
            {"name": k, "description": v}
            for k, v in _ATTACK_SCENARIOS.items()
        ],
        "business_impact":     _BUSINESS_IMPACT,
        "technical_summary":   technical_summary,
        "source_explanation":  source_explanation,
        "recommendations":     get_breach_recommendations(risk),
    }
