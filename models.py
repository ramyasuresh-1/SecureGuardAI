"""SQLAlchemy models for SecureGuard AI."""

from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db


class User(db.Model, UserMixin):
    """Represents a user account stored in the SQLite database."""

    __tablename__ = "users"

    # Primary key for the user record.
    id = db.Column(db.Integer, primary_key=True)

    # User profile fields.
    full_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    avatar = db.Column(db.String(255), default="")
    role = db.Column(db.String(40), default="user")

    # Audit and status fields.
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, default=None)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Relationship to password analyses.
    analyses = db.relationship(
        "PasswordAnalysis", backref="user", lazy="dynamic", cascade="all, delete-orphan"
    )

    def set_password(self, password: str) -> None:
        """Hash a plaintext password and store it securely."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify a plaintext password against the stored hash."""
        return check_password_hash(self.password_hash, password)


class PasswordAnalysis(db.Model):
    """Stores the result of a single password analysis for a user."""

    __tablename__ = "password_analyses"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Timestamp of the analysis.
    analyzed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Password composition metrics.
    length = db.Column(db.Integer, nullable=False, default=0)
    uppercase = db.Column(db.Integer, nullable=False, default=0)
    lowercase = db.Column(db.Integer, nullable=False, default=0)
    digits = db.Column(db.Integer, nullable=False, default=0)
    special = db.Column(db.Integer, nullable=False, default=0)

    # Computed scores.
    entropy = db.Column(db.Float, nullable=False, default=0.0)
    strength_score = db.Column(db.Integer, nullable=False, default=0)

    # Strength label: Weak / Moderate / Strong / Excellent.
    strength_category = db.Column(db.String(20), nullable=False, default="Weak")

    # Boolean pattern flags.
    dictionary_word = db.Column(db.Boolean, default=False, nullable=False)
    keyboard_pattern = db.Column(db.Boolean, default=False, nullable=False)
    birth_year = db.Column(db.Boolean, default=False, nullable=False)
    repeated = db.Column(db.Boolean, default=False, nullable=False)
    sequential = db.Column(db.Boolean, default=False, nullable=False)

    # Breach detection flag.
    is_breached = db.Column(db.Boolean, default=False, nullable=False)

    # Optional masked label stored for display (never store plaintext passwords).
    label = db.Column(db.String(120), default="", nullable=False)

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary of this analysis."""
        return {
            "id": self.id,
            "analyzed_at": self.analyzed_at.strftime("%Y-%m-%d %H:%M"),
            "length": self.length,
            "strength_score": self.strength_score,
            "strength_category": self.strength_category,
            "entropy": self.entropy,
            "is_breached": self.is_breached,
            "label": self.label or "—",
            "uppercase": self.uppercase,
            "lowercase": self.lowercase,
            "digits": self.digits,
            "special": self.special,
            "dictionary_word": self.dictionary_word,
            "keyboard_pattern": self.keyboard_pattern,
        }
