"""
utils/ai_security.py — SecureGuard AI Coach
=============================================
All data-access helpers for the AI Security Coach page.
Reuses existing PasswordAnalysis records — no new SQL tables.

Public API
----------
get_security_health(user_id)       → dict   overall health score + grade
get_coach_recommendations(user_id) → list   personalised action cards
get_weakness_analysis(user_id)     → list   common weakness breakdown
get_improvement_timeline(user_id)  → list   recent session milestones
get_improvement_suggestions(uid)   → list   concrete password tips
get_attack_insights(user_id)       → list   attack scenario awareness cards
get_achievements(user_id)          → list   gamified achievement badges
get_learning_modules()             → list   static learning content cards
get_qna()                          → list   predefined Q&A pairs
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func

from extensions import db
from models import PasswordAnalysis

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _time_ago(dt: datetime | None) -> str:
    """Return a human-readable relative time string."""
    if not dt:
        return "—"
    secs = int((datetime.utcnow() - dt).total_seconds())
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
    return f"{d // 30} month{'s' if d // 30 > 1 else ''} ago"

# ---------------------------------------------------------------------------
# 1. Overall Security Health Score
# ---------------------------------------------------------------------------

def get_security_health(user_id: int) -> dict[str, Any]:
    """
    Compute an overall security health score (0-100) and letter grade.

    Factors: avg strength score, breach rate, weak password %, consistency.
    Returns score, grade, colour, progress_bar_class, summary, and per-factor breakdown.
    """
    base  = PasswordAnalysis.query.filter_by(user_id=user_id)
    total = base.count()

    if total == 0:
        return {
            "score": 0, "grade": "N/A", "colour": "text-muted",
            "bar_class": "bg-secondary", "bar_pct": 0,
            "summary": "No analyses yet. Analyse a password to get your health score.",
            "factors": [], "total_analyses": 0,
        }

    avg_score_raw = db.session.query(
        func.avg(PasswordAnalysis.strength_score)
    ).filter_by(user_id=user_id).scalar() or 0.0
    avg_score = float(avg_score_raw)

    breached_cnt = base.filter(PasswordAnalysis.is_breached == True).count()  # noqa: E712
    weak_cnt     = base.filter(
        PasswordAnalysis.strength_category.in_(["Weak", "Very Weak"])
    ).count()
    strong_cnt   = base.filter(
        PasswordAnalysis.strength_category.in_(["Strong", "Excellent"])
    ).count()

    breach_rate = breached_cnt / total
    weak_rate   = weak_cnt    / total
    strong_rate = strong_cnt  / total

    # Weighted health score
    health = (
        avg_score            * 0.50 +
        (1 - breach_rate)    * 100 * 0.25 +
        (1 - weak_rate)      * 100 * 0.15 +
        strong_rate          * 100 * 0.10
    )
    health = round(max(0.0, min(100.0, health)), 1)

    if health >= 85:
        grade, colour, bar_class = "A", "text-success", "bg-success"
        summary = "Excellent security posture. Keep maintaining strong, unique passwords."
    elif health >= 70:
        grade, colour, bar_class = "B", "text-primary", "bg-primary"
        summary = "Good security habits. A few improvements will push you to excellent."
    elif health >= 55:
        grade, colour, bar_class = "C", "text-info", "bg-info"
        summary = "Moderate security. Several weaknesses need attention."
    elif health >= 40:
        grade, colour, bar_class = "D", "text-warning", "bg-warning"
        summary = "Below average security. Take action on weak and breached passwords."
    else:
        grade, colour, bar_class = "F", "text-danger", "bg-danger"
        summary = "Critical risk. Immediate remediation required."

    factors = [
        {
            "label":    "Avg Password Strength",
            "value":    f"{round(avg_score, 1)}/100",
            "pct":      round(avg_score),
            "colour":   "bg-success" if avg_score >= 70 else ("bg-warning" if avg_score >= 50 else "bg-danger"),
        },
        {
            "label":    "Breach-Free Rate",
            "value":    f"{round((1 - breach_rate)*100, 1)}%",
            "pct":      round((1 - breach_rate)*100),
            "colour":   "bg-success" if breach_rate == 0 else ("bg-warning" if breach_rate < 0.1 else "bg-danger"),
        },
        {
            "label":    "Strong Password Rate",
            "value":    f"{round(strong_rate*100, 1)}%",
            "pct":      round(strong_rate*100),
            "colour":   "bg-success" if strong_rate >= 0.6 else ("bg-warning" if strong_rate >= 0.3 else "bg-danger"),
        },
        {
            "label":    "Weak Password Rate",
            "value":    f"{round(weak_rate*100, 1)}%",
            "pct":      round(weak_rate*100),
            "colour":   "bg-success" if weak_rate == 0 else ("bg-warning" if weak_rate < 0.2 else "bg-danger"),
        },
    ]

    log.debug("get_security_health user=%d  score=%.1f  grade=%s", user_id, health, grade)
    return {
        "score":           health,
        "grade":           grade,
        "colour":          colour,
        "bar_class":       bar_class,
        "bar_pct":         round(health),
        "summary":         summary,
        "factors":         factors,
        "total_analyses":  total,
    }

# ---------------------------------------------------------------------------
# 2. Personalised AI Recommendations
# ---------------------------------------------------------------------------

def get_coach_recommendations(user_id: int) -> list[dict[str, Any]]:
    """
    Generate ranked, personalised action cards from the user's analysis history.
    Returns up to 6 recommendation dicts with icon, title, body, priority, badge.
    """
    base  = PasswordAnalysis.query.filter_by(user_id=user_id)
    total = base.count()
    recs: list[dict[str, Any]] = []

    if total == 0:
        return [{
            "icon": "fas fa-play-circle", "title": "Get Started",
            "body": "Analyse your first password to receive personalised coaching.",
            "badge": "bg-info", "badge_text": "Start Here", "priority": 0,
        }]

    breached     = base.filter(PasswordAnalysis.is_breached == True).count()         # noqa
    weak         = base.filter(PasswordAnalysis.strength_category.in_(["Weak","Very Weak"])).count()
    keyboard     = base.filter(PasswordAnalysis.keyboard_pattern == True).count()    # noqa
    dict_word    = base.filter(PasswordAnalysis.dictionary_word == True).count()     # noqa
    short_count  = base.filter(PasswordAnalysis.length < 8).count()
    no_special   = base.filter(PasswordAnalysis.special == 0).count()
    no_upper     = base.filter(PasswordAnalysis.uppercase == 0).count()
    no_digits    = base.filter(PasswordAnalysis.digits == 0).count()
    avg_len_raw  = db.session.query(func.avg(PasswordAnalysis.length)).filter_by(user_id=user_id).scalar() or 0.0

    if breached:
        recs.append({
            "icon": "fas fa-radiation", "title": "Change Breached Passwords Immediately",
            "body": f"{breached} of your passwords appear in known breach databases. "
                    "Change them now on every service where they are used.",
            "badge": "bg-danger", "badge_text": "Critical", "priority": 1,
        })
    if keyboard:
        pct = round(keyboard / total * 100)
        recs.append({
            "icon": "fas fa-keyboard", "title": "Eliminate Keyboard Patterns",
            "body": f"{pct}% of your passwords contain keyboard sequences (qwerty, 12345). "
                    "Automated tools guess these in milliseconds.",
            "badge": "bg-danger", "badge_text": "High Risk", "priority": 2,
        })
    if dict_word:
        pct = round(dict_word / total * 100)
        recs.append({
            "icon": "fas fa-book", "title": "Remove Dictionary Words",
            "body": f"{pct}% of your passwords use common dictionary words. "
                    "Attackers include these in every wordlist attack.",
            "badge": "bg-warning text-dark", "badge_text": "High Risk", "priority": 3,
        })
    if short_count:
        recs.append({
            "icon": "fas fa-ruler-horizontal", "title": "Increase Password Length",
            "body": f"{short_count} passwords are under 8 characters. "
                    "Use a minimum of 14 characters for strong protection.",
            "badge": "bg-warning text-dark", "badge_text": "Medium", "priority": 4,
        })
    if no_special:
        pct = round(no_special / total * 100)
        recs.append({
            "icon": "fas fa-at", "title": "Add Special Characters",
            "body": f"{pct}% of your passwords have no symbols. "
                    "Adding !, @, # dramatically increases cracking resistance.",
            "badge": "bg-info", "badge_text": "Recommended", "priority": 5,
        })
    if float(avg_len_raw) < 10:
        recs.append({
            "icon": "fas fa-shield-alt", "title": "Use a Password Manager",
            "body": "Your average password length is only "
                    f"{round(float(avg_len_raw), 1)} characters. "
                    "A password manager generates and stores 20+ character unique passwords.",
            "badge": "bg-info", "badge_text": "Best Practice", "priority": 6,
        })
    if not recs:
        recs.append({
            "icon": "fas fa-check-circle", "title": "Great Security Habits!",
            "body": "No critical weaknesses detected. Keep analysing new passwords "
                    "regularly and enable MFA on all important accounts.",
            "badge": "bg-success", "badge_text": "All Clear", "priority": 0,
        })
    return sorted(recs, key=lambda x: x["priority"])[:6]

# ---------------------------------------------------------------------------
# 3. Weakness Analysis
# ---------------------------------------------------------------------------

def get_weakness_analysis(user_id: int) -> list[dict[str, Any]]:
    """
    Return a breakdown of detected weakness types with counts, percentages,
    and a severity label.  Each entry also includes a fix tip.
    """
    base  = PasswordAnalysis.query.filter_by(user_id=user_id)
    total = base.count()
    if total == 0:
        return []

    def _pct(n: int) -> float:
        return round(n / total * 100, 1)

    checks = [
        ("Keyboard Patterns",   base.filter(PasswordAnalysis.keyboard_pattern == True).count(),   # noqa
         "fas fa-keyboard", "danger",
         "Avoid sequences like qwerty, asdf, 12345. Use random characters."),
        ("Dictionary Words",    base.filter(PasswordAnalysis.dictionary_word  == True).count(),   # noqa
         "fas fa-book",     "danger",
         "Replace common words with random passphrases or character substitutions."),
        ("Breached Passwords",  base.filter(PasswordAnalysis.is_breached      == True).count(),   # noqa
         "fas fa-radiation","danger",
         "Immediately change any password found in breach databases."),
        ("No Special Chars",    base.filter(PasswordAnalysis.special == 0).count(),
         "fas fa-at",       "warning",
         "Add at least 2 symbols (!, @, #) to every password."),
        ("No Uppercase",        base.filter(PasswordAnalysis.uppercase == 0).count(),
         "fas fa-font",     "warning",
         "Include at least 2 uppercase letters in every password."),
        ("Short Passwords",     base.filter(PasswordAnalysis.length < 8).count(),
         "fas fa-ruler-horizontal", "warning",
         "Use a minimum of 14 characters. Length is the most impactful factor."),
        ("Repeated Characters", base.filter(PasswordAnalysis.repeated == True).count(),   # noqa
         "fas fa-sync",     "info",
         "Avoid repeating the same character more than twice consecutively."),
        ("Sequential Characters", base.filter(PasswordAnalysis.sequential == True).count(), # noqa
         "fas fa-sort-amount-up", "info",
         "Avoid abc, 123 runs — mix character classes randomly."),
    ]

    result = []
    for label, count, icon, severity, tip in checks:
        if count == 0:
            continue
        result.append({
            "label":    label,
            "count":    count,
            "pct":      _pct(count),
            "icon":     icon,
            "severity": severity,
            "tip":      tip,
            "bar_colour": {
                "danger":  "bg-danger",
                "warning": "bg-warning",
                "info":    "bg-info",
            }.get(severity, "bg-secondary"),
        })
    return sorted(result, key=lambda x: x["count"], reverse=True)


# ---------------------------------------------------------------------------
# 4. Improvement Timeline
# ---------------------------------------------------------------------------

def get_improvement_timeline(user_id: int, limit: int = 10) -> list[dict[str, Any]]:
    """
    Derive a coaching timeline from the user's last *limit* analyses.
    Each entry summarises what happened in that session and whether it
    was an improvement.
    """
    rows = (
        PasswordAnalysis.query
        .filter_by(user_id=user_id)
        .order_by(PasswordAnalysis.analyzed_at.desc())
        .limit(limit)
        .all()
    )
    if not rows:
        return []

    items: list[dict[str, Any]] = []
    prev_score: int | None = None

    for row in rows:
        score = row.strength_score
        if prev_score is None:
            trend_icon  = "fas fa-minus-circle"
            trend_class = "timeline-icon-info"
            trend_text  = "First Analysis"
        elif score > prev_score:
            trend_icon  = "fas fa-arrow-up"
            trend_class = "timeline-icon-success"
            trend_text  = f"+{score - prev_score} pts improvement"
        elif score < prev_score:
            trend_icon  = "fas fa-arrow-down"
            trend_class = "timeline-icon-warning"
            trend_text  = f"{score - prev_score} pts decline"
        else:
            trend_icon  = "fas fa-equals"
            trend_class = "timeline-icon-info"
            trend_text  = "Same score"

        items.append({
            "label":       row.label or "—",
            "score":       score,
            "category":    row.strength_category,
            "time_ago":    _time_ago(row.analyzed_at),
            "date":        row.analyzed_at.strftime("%b %d, %H:%M"),
            "trend_icon":  trend_icon,
            "trend_class": trend_class,
            "trend_text":  trend_text,
            "is_breached": row.is_breached,
        })
        prev_score = score

    return items

# ---------------------------------------------------------------------------
# 5. Improvement Suggestions
# ---------------------------------------------------------------------------

def get_improvement_suggestions(user_id: int) -> list[dict[str, str]]:
    """
    Return concrete, actionable password improvement tips tailored to the
    user's specific gaps.  Up to 6 suggestions.
    """
    base  = PasswordAnalysis.query.filter_by(user_id=user_id)
    total = base.count()

    suggestions = [
        {
            "icon": "fas fa-wand-magic-sparkles", "title": "Use Passphrases",
            "body": "Combine 4 random words with symbols: Correct$Horse#Battery!Staple. "
                    "Easy to remember, extremely hard to crack.",
            "example": "Correct$Horse#Battery!9",
        },
        {
            "icon": "fas fa-dice", "title": "Randomise Every Password",
            "body": "Each service should have a completely unique password. "
                    "Use SecureGuard's generator or a dedicated password manager.",
            "example": "4xK!9mRp@vL2#Qs",
        },
        {
            "icon": "fas fa-layer-group", "title": "Use All Four Character Classes",
            "body": "Combine uppercase (A–Z), lowercase (a–z), digits (0–9) "
                    "and symbols (!@#$). Coverage beats complexity.",
            "example": "Tiger!Blue@99xx",
        },
        {
            "icon": "fas fa-calendar-alt", "title": "Never Include Personal Dates",
            "body": "Birthdays, anniversaries, and years (e.g. 1998, 2023) are the "
                    "first things social-engineering attackers guess.",
            "example": "Instead of 'john1990', use 'jX!k9@pQ'",
        },
        {
            "icon": "fas fa-mobile-alt", "title": "Enable MFA Everywhere",
            "body": "Multi-factor authentication makes a stolen password useless "
                    "on its own. Enable it on email, banking, and social accounts first.",
            "example": "Google Authenticator, Authy, or hardware keys",
        },
        {
            "icon": "fas fa-rotate", "title": "Rotate Credentials Regularly",
            "body": "High-value accounts (email, banking, work) should be rotated "
                    "at least every 90 days. Use a password manager to track this.",
            "example": "Set a calendar reminder every 90 days",
        },
    ]

    if total == 0:
        return suggestions[:3]

    # Personalise order based on detected weaknesses
    no_special  = base.filter(PasswordAnalysis.special   == 0).count()
    no_upper    = base.filter(PasswordAnalysis.uppercase == 0).count()
    dict_word   = base.filter(PasswordAnalysis.dictionary_word  == True).count()  # noqa
    birth_year  = base.filter(PasswordAnalysis.birth_year       == True).count()  # noqa

    if no_special or no_upper:
        suggestions.insert(0, suggestions.pop(2))   # bump "all four classes"
    if dict_word:
        suggestions.insert(0, suggestions.pop(0))   # passphrases first
    if birth_year:
        idx = next((i for i, s in enumerate(suggestions) if "Date" in s["title"]), 3)
        suggestions.insert(0, suggestions.pop(idx))

    return suggestions[:6]


# ---------------------------------------------------------------------------
# 6. Attack Simulation Insights
# ---------------------------------------------------------------------------

def get_attack_insights(user_id: int) -> list[dict[str, Any]]:
    """
    Return attack scenario cards informed by the user's weaknesses.
    Each card explains an attack type and whether the user is currently
    vulnerable based on their analysis history.
    """
    base  = PasswordAnalysis.query.filter_by(user_id=user_id)
    total = base.count()

    keyboard_cnt  = base.filter(PasswordAnalysis.keyboard_pattern == True).count() if total else 0  # noqa
    dict_cnt      = base.filter(PasswordAnalysis.dictionary_word  == True).count() if total else 0  # noqa
    breached_cnt  = base.filter(PasswordAnalysis.is_breached      == True).count() if total else 0  # noqa
    weak_cnt      = base.filter(PasswordAnalysis.strength_category.in_(["Weak","Very Weak"])).count() if total else 0

    def _status(vulnerable: bool) -> tuple[str, str]:
        if not total:
            return "text-muted", "Unknown — run an analysis first"
        return ("text-danger", "Vulnerable") if vulnerable else ("text-success", "Protected")

    return [
        {
            "icon":        "fas fa-bolt",
            "title":       "Brute Force Attack",
            "description": "Automated tools try every possible character combination. "
                           "Short or low-entropy passwords fall in seconds.",
            "status_col":  _status(bool(total) and (weak_cnt / total) > 0.3)[0],
            "status_text": _status(bool(total) and (weak_cnt / total) > 0.3)[1],
            "mitigation":  "Use 14+ character passwords with all character classes.",
        },
        {
            "icon":        "fas fa-list",
            "title":       "Dictionary Attack",
            "description": "Attackers iterate through lists of common words, names, "
                           "and phrases. Any recognisable word is a target.",
            "status_col":  _status(dict_cnt > 0)[0],
            "status_text": _status(dict_cnt > 0)[1],
            "mitigation":  "Replace dictionary words with random character strings or passphrases.",
        },
        {
            "icon":        "fas fa-recycle",
            "title":       "Credential Stuffing",
            "description": "Breached username/password pairs are tested against "
                           "hundreds of other websites automatically.",
            "status_col":  _status(breached_cnt > 0)[0],
            "status_text": _status(breached_cnt > 0)[1],
            "mitigation":  "Use a unique password per service. Change breached passwords immediately.",
        },
        {
            "icon":        "fas fa-keyboard",
            "title":       "Pattern Recognition",
            "description": "Keyboard walks (qwerty, 12345) and sequential runs "
                           "are detected instantly by modern password-cracking tools.",
            "status_col":  _status(keyboard_cnt > 0)[0],
            "status_text": _status(keyboard_cnt > 0)[1],
            "mitigation":  "Avoid any predictable keyboard or character sequence.",
        },
        {
            "icon":        "fas fa-user-secret",
            "title":       "Social Engineering",
            "description": "Attackers guess passwords using publicly available personal "
                           "data: names, birthdays, pet names, favourite teams.",
            "status_col":  _status(
                bool(total) and base.filter(PasswordAnalysis.birth_year == True).count() > 0  # noqa
            )[0],
            "status_text": _status(
                bool(total) and base.filter(PasswordAnalysis.birth_year == True).count() > 0  # noqa
            )[1],
            "mitigation":  "Never use personal information in passwords.",
        },
        {
            "icon":        "fas fa-layer-group",
            "title":       "Password Spraying",
            "description": "A small set of the most common passwords (e.g. Password1!) "
                           "is tried against a large number of accounts.",
            "status_col":  _status(bool(total) and dict_cnt > 0)[0],
            "status_text": _status(bool(total) and dict_cnt > 0)[1],
            "mitigation":  "Even one instance of a common password leaves you exposed.",
        },
    ]

# ---------------------------------------------------------------------------
# 7. Security Achievements
# ---------------------------------------------------------------------------

def get_achievements(user_id: int) -> list[dict[str, Any]]:
    """
    Return gamified achievement badges unlocked by the user's analysis history.
    Each achievement has: icon, title, description, unlocked (bool), progress_pct.
    """
    base  = PasswordAnalysis.query.filter_by(user_id=user_id)
    total = base.count()

    breached = base.filter(PasswordAnalysis.is_breached == True).count()   # noqa
    strong   = base.filter(
        PasswordAnalysis.strength_category.in_(["Strong", "Excellent"])
    ).count()
    excellent = base.filter(PasswordAnalysis.strength_category == "Excellent").count()

    avg_score_raw = db.session.query(
        func.avg(PasswordAnalysis.strength_score)
    ).filter_by(user_id=user_id).scalar() or 0.0
    avg_score = float(avg_score_raw)

    return [
        {
            "icon":        "fas fa-rocket",
            "title":       "First Analysis",
            "description": "Completed your first password analysis.",
            "unlocked":    total >= 1,
            "progress_pct": min(100, total * 100),
            "colour":      "#00e5ff",
        },
        {
            "icon":        "fas fa-shield-halved",
            "title":       "Security Explorer",
            "description": "Analysed 10 or more passwords.",
            "unlocked":    total >= 10,
            "progress_pct": min(100, round(total / 10 * 100)),
            "colour":      "#7c4dff",
        },
        {
            "icon":        "fas fa-trophy",
            "title":       "Password Master",
            "description": "Analysed 50 or more passwords.",
            "unlocked":    total >= 50,
            "progress_pct": min(100, round(total / 50 * 100)),
            "colour":      "#f59e0b",
        },
        {
            "icon":        "fas fa-star",
            "title":       "Excellence Achieved",
            "description": "Created at least one password rated Excellent.",
            "unlocked":    excellent >= 1,
            "progress_pct": min(100, round(excellent / 1 * 100)),
            "colour":      "#2ecc71",
        },
        {
            "icon":        "fas fa-shield-check",
            "title":       "Breach-Free Record",
            "description": "All analysed passwords are breach-free.",
            "unlocked":    total > 0 and breached == 0,
            "progress_pct": 100 if (total > 0 and breached == 0) else (
                round(max(0, (total - breached) / max(total, 1) * 100)) if total > 0 else 0
            ),
            "colour":      "#2ecc71",
        },
        {
            "icon":        "fas fa-fire",
            "title":       "High Performer",
            "description": "Achieved an average strength score above 70.",
            "unlocked":    avg_score >= 70,
            "progress_pct": min(100, round(avg_score / 70 * 100)),
            "colour":      "#ef4444",
        },
        {
            "icon":        "fas fa-graduation-cap",
            "title":       "Security Student",
            "description": "Had 5 or more Strong or Excellent passwords.",
            "unlocked":    strong >= 5,
            "progress_pct": min(100, round(strong / 5 * 100)),
            "colour":      "#3b82f6",
        },
        {
            "icon":        "fas fa-crown",
            "title":       "Security Champion",
            "description": "Analysed 25+ passwords with no breaches and avg score ≥ 60.",
            "unlocked":    total >= 25 and breached == 0 and avg_score >= 60,
            "progress_pct": min(100, round(
                (total / 25 * 0.5 + (0 if breached else 0.3) + (avg_score / 60 * 0.2)) * 100
            )),
            "colour":      "#f59e0b",
        },
    ]


# ---------------------------------------------------------------------------
# 8. Learning Modules (static content)
# ---------------------------------------------------------------------------

def get_learning_modules() -> list[dict[str, str]]:
    """Return the cybersecurity learning cards displayed in the Learning Center."""
    return [
        {
            "icon":     "fas fa-lock",
            "title":    "Password Strength Fundamentals",
            "body":     "Length, character diversity, and unpredictability are the "
                        "three pillars of a strong password. A 14-character random "
                        "password is exponentially harder to crack than an 8-character one.",
            "level":    "Beginner",
            "level_cls": "bg-success",
            "read_time": "3 min",
        },
        {
            "icon":     "fas fa-database",
            "title":    "How Password Breaches Happen",
            "body":     "Most breaches occur when attackers compromise a website's "
                        "database and extract hashed passwords. Weak hashing algorithms "
                        "(MD5, SHA-1) allow rapid cracking, while bcrypt and Argon2 are slow.",
            "level":    "Beginner",
            "level_cls": "bg-success",
            "read_time": "4 min",
        },
        {
            "icon":     "fas fa-chart-bar",
            "title":    "Understanding Password Entropy",
            "body":     "Entropy measures unpredictability in bits. A 4-character "
                        "lowercase password has ~18 bits. A 16-character mixed-case "
                        "password exceeds 100 bits — requiring centuries to brute-force.",
            "level":    "Intermediate",
            "level_cls": "bg-warning text-dark",
            "read_time": "5 min",
        },
        {
            "icon":     "fas fa-shield-virus",
            "title":    "Credential Stuffing Explained",
            "body":     "When leaked credentials from one site are tested automatically "
                        "against others, it is called credential stuffing. "
                        "Unique passwords per service is the only complete defence.",
            "level":    "Intermediate",
            "level_cls": "bg-warning text-dark",
            "read_time": "4 min",
        },
        {
            "icon":     "fas fa-mobile-alt",
            "title":    "Multi-Factor Authentication Deep Dive",
            "body":     "MFA requires something you know (password), something you "
                        "have (phone/hardware key), or something you are (biometric). "
                        "TOTP apps (Authy, Google Authenticator) are strongly preferred over SMS.",
            "level":    "Intermediate",
            "level_cls": "bg-warning text-dark",
            "read_time": "6 min",
        },
        {
            "icon":     "fas fa-robot",
            "title":    "AI in Password Security",
            "body":     "Machine learning models can predict password strength, "
                        "detect patterns invisible to rule-based systems, and identify "
                        "passwords likely to appear in future breach datasets.",
            "level":    "Advanced",
            "level_cls": "bg-danger",
            "read_time": "7 min",
        },
    ]


# ---------------------------------------------------------------------------
# 9. Q&A Pairs
# ---------------------------------------------------------------------------

def get_qna() -> list[dict[str, str]]:
    """Return predefined educational Q&A pairs for the coach page."""
    return [
        {
            "q": "What makes a password strong?",
            "a": "Length (14+ characters), character diversity (upper, lower, digits, symbols), "
                 "high entropy (unpredictability), and the absence of dictionary words, "
                 "personal information, or keyboard patterns.",
        },
        {
            "q": "How do I know if my password was breached?",
            "a": "SecureGuard AI checks every analysed password against the RockYou breach "
                 "dataset. A red 'Breached' indicator means the password appears in known "
                 "leak databases and must be changed immediately.",
        },
        {
            "q": "Is it safe to reuse passwords?",
            "a": "No. If one service is breached, attackers use credential stuffing to test "
                 "the same password on hundreds of other sites. Every account should have "
                 "a unique password.",
        },
        {
            "q": "What is a passphrase and is it secure?",
            "a": "A passphrase is 4+ random words combined: 'Correct$Horse#Battery!9'. "
                 "At 25+ characters with symbols, it exceeds the entropy of most random "
                 "8-character passwords and is significantly easier to remember.",
        },
        {
            "q": "What does entropy mean in the context of passwords?",
            "a": "Entropy (measured in bits) quantifies how unpredictable a password is. "
                 "Shannon entropy above 4.0 bits per character indicates a well-randomised "
                 "password. Low entropy means many characters repeat or follow patterns.",
        },
        {
            "q": "Should I change my password regularly?",
            "a": "For high-value accounts (email, banking, work), rotating every 90 days "
                 "reduces exposure from undetected breaches. Use a password manager to "
                 "make this practical.",
        },
        {
            "q": "What is the safest way to store passwords?",
            "a": "Use a reputable password manager (Bitwarden, 1Password, KeePass). "
                 "They encrypt your vault with a master password and generate unique, "
                 "high-entropy credentials for every site.",
        },
        {
            "q": "How does the Hybrid AI engine work?",
            "a": "SecureGuard combines a deterministic rule engine (scoring length, entropy, "
                 "patterns) with a trained Random Forest ML model. The Hybrid Decision Engine "
                 "weighs both outputs and selects the most reliable verdict.",
        },
    ]
