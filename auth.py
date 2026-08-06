"""Authentication and application blueprint for SecureGuard AI."""

from datetime import datetime

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from extensions import db
from forms import ChangePasswordForm, LoginForm, ProfileForm, RegisterForm
from models import PasswordAnalysis, User
from utils.dashboard_data import (
    get_ai_insights,
    get_all_chart_data,
    get_analytics_averages,
    get_card_stats,
    get_composition_radar_data,
    get_daily_trend_data,
    get_history_page,
    get_monthly_performance,
    get_notifications,
    get_recent_activity,
    get_score_distribution_data,
    get_strength_pie_data,
    get_threat_category_data,
    get_unread_notification_count,
)

auth_bp = Blueprint("auth", __name__)


# ---------------------------------------------------------------------------
# Authentication routes  (unchanged logic, no modifications)
# ---------------------------------------------------------------------------


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """Create a new user account with validated registration details."""
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            full_name=form.full_name.data.strip(),
            email=form.email.data.lower().strip(),
            avatar=form.avatar.data,
            role="user",
            is_active=True,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        flash("Registration Successful. Please Login.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate a user and establish a session."""
    if current_user.is_authenticated:
        return redirect(url_for("auth.welcome"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower().strip()).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            user.last_login = datetime.utcnow()
            db.session.commit()
            session["dark_mode"] = session.get("dark_mode", False)
            flash("Login Successful.", "success")
            return redirect(url_for("auth.welcome"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    """Destroy the current user session and clear authentication state."""
    logout_user()
    flash("Successfully Logged Out.", "info")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------


@auth_bp.route("/welcome")
@login_required
def welcome():
    """Render a protected welcome page for authenticated users."""
    return render_template("welcome.html")


@auth_bp.route("/dashboard")
@login_required
def dashboard():
    """Render the dashboard with live data from SQLite."""
    uid = current_user.id

    # Single-pass data gathering — all queries in one call where possible.
    stats = get_card_stats(uid)
    activity = get_recent_activity(uid, limit=6)
    insights = get_ai_insights(uid)
    notifications = get_notifications(uid, limit=6)
    notif_count = get_unread_notification_count(uid)

    # Strength pie legend values (shown as static text below pie chart)
    pie = get_strength_pie_data(uid)

    return render_template(
        "dashboard.html",
        stats=stats,
        activity=activity,
        insights=insights,
        notifications=notifications,
        notif_count=notif_count,
        pie=pie,
    )


@auth_bp.route("/analyzer")
@login_required
def analyzer():
    """Render the analyzer page for authenticated users."""
    notif_count = get_unread_notification_count(current_user.id)
    return render_template("analyze.html", notif_count=notif_count)


@auth_bp.route("/ai-security-coach")
@login_required
def ai_security_coach():
    """Render the AI Security Coach page with personalised coaching data."""
    from utils.ai_security import (
        get_security_health,
        get_coach_recommendations,
        get_weakness_analysis,
        get_improvement_timeline,
        get_improvement_suggestions,
        get_attack_insights,
        get_achievements,
        get_learning_modules,
        get_qna,
    )

    uid = current_user.id
    notif_count  = get_unread_notification_count(uid)
    health       = get_security_health(uid)
    recs         = get_coach_recommendations(uid)
    weaknesses   = get_weakness_analysis(uid)
    timeline     = get_improvement_timeline(uid, limit=10)
    suggestions  = get_improvement_suggestions(uid)
    attacks      = get_attack_insights(uid)
    achievements = get_achievements(uid)
    learning     = get_learning_modules()
    qna          = get_qna()

    return render_template(
        "ai_security_coach.html",
        health=health,
        recs=recs,
        weaknesses=weaknesses,
        timeline=timeline,
        suggestions=suggestions,
        attacks=attacks,
        achievements=achievements,
        learning=learning,
        qna=qna,
        notif_count=notif_count,
    )


@auth_bp.route("/breach-detection")
@login_required
def breach_detection():
    """Render the Breach Intelligence Center page."""
    from utils.breach_dashboard import (
        get_breach_summary,
        get_breach_history,
        get_breach_risk_chart,
        get_breach_timeline,
        get_default_recommendations,
    )

    uid = current_user.id
    notif_count = get_unread_notification_count(uid)

    summary       = get_breach_summary(uid)
    history       = get_breach_history(uid, page=1, per_page=10)
    risk_chart    = get_breach_risk_chart(uid)
    timeline      = get_breach_timeline(uid, limit=12)
    recs          = get_default_recommendations(uid)

    return render_template(
        "breach_detection.html",
        summary=summary,
        history=history,
        risk_chart=risk_chart,
        timeline=timeline,
        recs=recs,
        notif_count=notif_count,
    )


@auth_bp.route("/api/analyze", methods=["POST"])
@login_required
def api_analyze():
    """
    Run the full AI-powered password analysis pipeline.

    Accepts JSON  { "password": "...", "complexity": "Standard", "threat_model": "Consumer" }
    or form data with the same field names.

    Steps performed
    ---------------
    1. Extract features from the submitted password.
    2. Compute security score (0-100).
    3. Classify strength (Very Weak … Excellent).
    4. Predict threat level (Critical … Very Low).
    5. Estimate crack time (Instant … Centuries).
    6. Generate AI findings (human-readable insights).
    7. Persist a PasswordAnalysis row to SQLite.
    8. Return the full result as JSON so the frontend can update
       all dashboard widgets without a page reload.
    """
    from datetime import datetime
    from utils.breach_detection import check_breach
    from utils.feature_extraction import analyze_password_full

    # ── 1. Parse request ──────────────────────────────────────────────────
    payload      = request.get_json(silent=True) or {}
    password     = (payload.get("password") or request.form.get("password") or "").strip()
    complexity   = payload.get("complexity")   or request.form.get("complexity")   or "Standard"
    threat_model = payload.get("threat_model") or request.form.get("threat_model") or "Consumer"

    if not password:
        return jsonify({"error": "No password provided."}), 400

    # ── 2. Breach check (runs first so the pipeline knows is_breached) ────
    breach = check_breach(password)

    # ── 3–7. Full analysis pipeline ───────────────────────────────────────
    result = analyze_password_full(
        password=password,
        is_breached=breach["is_breached"],  # pass real breach status
        complexity_mode=complexity,
        threat_model=threat_model,
    )

    # ── 7. Persist to PasswordAnalysis table ─────────────────────────────
    # Build a masked label: first char + stars + last char
    if len(password) <= 2:
        label = "*" * len(password)
    else:
        label = password[0] + "*" * (len(password) - 2) + password[-1]

    row = PasswordAnalysis(
        user_id           = current_user.id,
        analyzed_at       = datetime.utcnow(),
        length            = result["length"],
        uppercase         = result["uppercase"],
        lowercase         = result["lowercase"],
        digits            = result["digits"],
        special           = result["special"],
        entropy           = result["entropy"],
        strength_score    = result["strength_score"],
        strength_category = result["strength_category"],
        dictionary_word   = result["dictionary_word"],
        keyboard_pattern  = result["keyboard_pattern"],
        birth_year        = result["birth_year"],
        repeated          = result["repeated"],
        sequential        = result["sequential"],
        is_breached       = result["is_breached"],
        label             = label,
    )
    db.session.add(row)
    db.session.commit()

    # ── 8. Hybrid AI pipeline (wraps ML + HybridEngine with full failsafe) ─
    # The analyzer must NEVER fail because of ML unavailability.
    # All errors are caught, logged, and a graceful fallback payload is used.
    from utils.ml_integration import run_hybrid_pipeline
    hybrid_payload = run_hybrid_pipeline(
        password=password,
        rule_category=result["strength_category"],
        rule_score=result["strength_score"],
        threat_level=result.get("threat_level", "Unknown"),
        is_breached=breach["is_breached"],
    )

    # ── 9. Persist Hybrid AI fields into the already-committed row ────────
    if hybrid_payload["ml_available"]:
        row.ml_prediction    = hybrid_payload["ml_prediction"]
        row.ml_confidence    = hybrid_payload["ml_confidence"]
        row.hybrid_decision  = hybrid_payload["hybrid_decision"]
        row.hybrid_agreement = hybrid_payload["hybrid_agreement"]
        row.decision_source  = hybrid_payload["decision_source"]
        row.hybrid_reason    = hybrid_payload["hybrid_reason"]
        db.session.commit()
    return jsonify({
        # Core metrics
        "strength_score":    result["strength_score"],
        "strength_category": result["strength_category"],
        "threat_level":      result["threat_level"],
        "threat_colour":     result["threat_colour"],
        "threat_icon":       result["threat_icon"],
        "entropy":           result["entropy"],
        "entropy_category":  result["entropy_category"],

        # Crack time
        "crack_time":              result["crack_time"],
        "crack_time_online":       result["crack_time_online"],
        "crack_time_combinations": result["crack_time_combinations"],

        # Feature summary
        "password_length":              result["password_length"],
        "uppercase_count":              result["uppercase_count"],
        "lowercase_count":              result["lowercase_count"],
        "digit_count":                  result["digit_count"],
        "special_character_count":      result["special_character_count"],
        "unique_character_count":       result["unique_character_count"],
        "repeated_character_count":     result["repeated_character_count"],
        "char_diversity":               result["char_diversity"],
        "sequential_character_detected": result["sequential_character_detected"],
        "dictionary_word_detected":     result["dictionary_word_detected"],
        "keyboard_pattern_detected":    result["keyboard_pattern_detected"],

        # AI findings
        "findings": result["findings"],

        # Saved record ID (for history link)
        "record_id": row.id,

        # Label shown in history
        "label": label,

        # Breach detection result
        "is_breached":  breach["is_breached"],
        "breach_risk":  breach["risk"],
        "breach_source": breach["source"],

        # Hybrid AI fields (always present; ml_available=False on fallback)
        "ml_available":     hybrid_payload["ml_available"],
        "ml_prediction":    hybrid_payload["ml_prediction"],
        "ml_confidence":    hybrid_payload["ml_confidence"],
        "ml_probabilities": hybrid_payload["ml_probabilities"],
        "hybrid_decision":  hybrid_payload["hybrid_decision"],
        "hybrid_agreement": hybrid_payload["hybrid_agreement"],
        "decision_source":  hybrid_payload["decision_source"],
        "hybrid_reason":    hybrid_payload["hybrid_reason"],
    })


@auth_bp.route("/analytics")
@login_required
def analytics():
    """Render the analytics page with live aggregate data."""
    uid = current_user.id

    stats = get_card_stats(uid)
    averages = get_analytics_averages(uid)
    monthly = get_monthly_performance(uid, months=6)
    notif_count = get_unread_notification_count(uid)

    return render_template(
        "analytics.html",
        stats=stats,
        averages=averages,
        monthly=monthly,
        notif_count=notif_count,
    )


@auth_bp.route("/history")
@login_required
def history():
    """Render the history page with paginated and searchable analyses."""
    uid = current_user.id
    page = request.args.get("page", 1, type=int)
    search = request.args.get("search", "", type=str).strip()
    per_page = 15

    paged = get_history_page(uid, page=page, per_page=per_page, search=search)
    notif_count = get_unread_notification_count(uid)

    return render_template(
        "history.html",
        paged=paged,
        search=search,
        notif_count=notif_count,
    )


@auth_bp.route("/reports")
@login_required
def reports():
    """Render the reports page for authenticated users."""
    notif_count = get_unread_notification_count(current_user.id)
    return render_template("report.html", notif_count=notif_count)


@auth_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """Render the settings page for authenticated users."""
    password_form = ChangePasswordForm()
    notif_count = get_unread_notification_count(current_user.id)
    return render_template("settings.html", password_form=password_form, notif_count=notif_count)


@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """Render the profile page with dynamic analysis statistics."""
    uid = current_user.id
    form = ProfileForm()
    form.name.data = current_user.full_name
    form.email.data = current_user.email
    form.avatar.data = current_user.avatar or "icons/cyber-shield.svg"

    stats = get_card_stats(uid)
    notif_count = get_unread_notification_count(uid)

    return render_template(
        "profile.html",
        form=form,
        stats=stats,
        notif_count=notif_count,
    )


# ---------------------------------------------------------------------------
# JSON API endpoints  (consumed by dashboard.js via fetch)
# ---------------------------------------------------------------------------


@auth_bp.route("/api/charts/all")
@login_required
def api_charts_all():
    """Return all five chart datasets in a single JSON response."""
    data = get_all_chart_data(current_user.id)
    return jsonify(data)


@auth_bp.route("/api/charts/strength-pie")
@login_required
def api_strength_pie():
    """Password strength distribution — pie chart data."""
    return jsonify(get_strength_pie_data(current_user.id))


@auth_bp.route("/api/charts/daily-trend")
@login_required
def api_daily_trend():
    """Daily analysis trend — line chart data (last 30 days)."""
    days = request.args.get("days", 30, type=int)
    return jsonify(get_daily_trend_data(current_user.id, days=days))


@auth_bp.route("/api/charts/score-distribution")
@login_required
def api_score_distribution():
    """Security score distribution — bar chart data."""
    return jsonify(get_score_distribution_data(current_user.id))


@auth_bp.route("/api/charts/threat-categories")
@login_required
def api_threat_categories():
    """Threat category breakdown — doughnut chart data."""
    return jsonify(get_threat_category_data(current_user.id))


@auth_bp.route("/api/charts/composition-radar")
@login_required
def api_composition_radar():
    """Password composition averages — radar chart data."""
    return jsonify(get_composition_radar_data(current_user.id))


@auth_bp.route("/api/dashboard/stats")
@login_required
def api_dashboard_stats():
    """Live card KPIs — polled by the frontend for real-time refresh."""
    return jsonify(get_card_stats(current_user.id))


@auth_bp.route("/api/notifications")
@login_required
def api_notifications():
    """Dynamic notification list."""
    return jsonify(get_notifications(current_user.id))


@auth_bp.route("/api/breach/history")
@login_required
def api_breach_history():
    """
    Paginated breach history for the Breach Intelligence Center.

    Query params: page, per_page, search, sort_by
    """
    from utils.breach_dashboard import get_breach_history, get_breach_recommendations

    uid      = current_user.id
    page     = request.args.get("page",     1,    type=int)
    per_page = request.args.get("per_page", 10,   type=int)
    search   = request.args.get("search",   "",   type=str).strip()
    sort_by  = request.args.get("sort_by",  "date_desc", type=str)

    data = get_breach_history(uid, page=page, per_page=per_page,
                              search=search, sort_by=sort_by)
    return jsonify(data)


@auth_bp.route("/api/breach/recommendations/<risk>")
@login_required
def api_breach_recommendations(risk: str):
    """Return AI recommendations for a given risk tier."""
    from utils.breach_dashboard import get_breach_recommendations
    return jsonify(get_breach_recommendations(risk))


@auth_bp.route("/api/hybrid/analytics")
@login_required
def api_hybrid_analytics():
    """Return all four Hybrid AI chart datasets for the Analytics page."""
    from utils.dashboard_data import get_hybrid_analytics_data
    return jsonify(get_hybrid_analytics_data(current_user.id))


@auth_bp.route("/api/history/hybrid")
@login_required
def api_history_hybrid():
    """
    Return all analyses that have Hybrid AI fields populated.
    Used by the Reports page to build the Hybrid AI report table.
    """
    uid      = current_user.id
    page     = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)

    query = (
        PasswordAnalysis.query
        .filter(
            PasswordAnalysis.user_id == uid,
            PasswordAnalysis.hybrid_decision.isnot(None),
        )
        .order_by(PasswordAnalysis.analyzed_at.desc())
    )

    total = query.count()
    rows  = query.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "total": total,
        "rows":  [r.to_dict() for r in rows],
    })


@auth_bp.route("/api/report/pdf")
@login_required
def api_report_pdf():
    """
    Generate and stream a professional cybersecurity PDF assessment report.

    Pulls all PasswordAnalysis rows for the current user, computes stats,
    and passes everything to the ReportLab generator.
    """
    from flask import Response
    from utils.report_generator import generate_pdf_report

    uid = current_user.id
    user = current_user

    # Fetch all analyses newest-first
    analyses = (
        PasswordAnalysis.query
        .filter_by(user_id=uid)
        .order_by(PasswordAnalysis.analyzed_at.desc())
        .all()
    )

    stats = get_card_stats(uid)

    pdf_bytes = generate_pdf_report(
        user_name  = user.full_name,
        user_email = user.email,
        analyses   = [r.to_dict() for r in analyses],
        stats      = stats,
    )

    filename = (
        f"secureguard_report_"
        f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    )
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": len(pdf_bytes),
        },
    )


@auth_bp.route("/api/report/csv")
@login_required
def api_report_csv():
    """
    Stream a comprehensive CSV export of all password analyses.
    Includes Hybrid AI fields for records that have them.
    """
    from flask import Response
    from utils.report_generator import generate_csv_export

    uid = current_user.id

    analyses = (
        PasswordAnalysis.query
        .filter_by(user_id=uid)
        .order_by(PasswordAnalysis.analyzed_at.desc())
        .all()
    )

    csv_text = generate_csv_export([r.to_dict() for r in analyses])

    filename = (
        f"secureguard_export_"
        f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    )
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


# ---------------------------------------------------------------------------
# Download routes  (/download/pdf, /download/csv, /download/excel)
# ---------------------------------------------------------------------------

@auth_bp.route("/download/pdf")
@login_required
def download_pdf_report():
    """Generate and download the full 7-page enterprise PDF report."""
    import io as _io
    from flask import send_file
    from utils.report_generator import generate_pdf_report

    uid      = current_user.id
    analyses = (
        PasswordAnalysis.query
        .filter_by(user_id=uid)
        .order_by(PasswordAnalysis.analyzed_at.desc())
        .all()
    )
    stats    = get_card_stats(uid)
    pdf_bytes = generate_pdf_report(
        user_name  = current_user.full_name,
        user_email = current_user.email,
        analyses   = [r.to_dict() for r in analyses],
        stats      = stats,
    )
    filename = f"secureguard_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(
        _io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


@auth_bp.route("/download/csv")
@login_required
def download_csv_report():
    """Download a comprehensive CSV export of all analyses."""
    import io as _io
    from flask import send_file
    from utils.report_generator import generate_csv_export

    uid      = current_user.id
    analyses = (
        PasswordAnalysis.query
        .filter_by(user_id=uid)
        .order_by(PasswordAnalysis.analyzed_at.desc())
        .all()
    )
    csv_text = generate_csv_export([r.to_dict() for r in analyses])
    filename = f"secureguard_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(
        _io.BytesIO(csv_text.encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename,
    )


@auth_bp.route("/download/excel")
@login_required
def download_excel_report():
    """Generate and download a multi-sheet professional Excel report."""
    import io as _io
    from flask import send_file
    from utils.report_generator import generate_excel_export

    uid      = current_user.id
    analyses = (
        PasswordAnalysis.query
        .filter_by(user_id=uid)
        .order_by(PasswordAnalysis.analyzed_at.desc())
        .all()
    )
    stats    = get_card_stats(uid)
    xlsx_bytes = generate_excel_export(
        user_name = current_user.full_name,
        analyses  = [r.to_dict() for r in analyses],
        stats     = stats,
    )
    filename = f"secureguard_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return send_file(
        _io.BytesIO(xlsx_bytes),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name=filename,
    )
