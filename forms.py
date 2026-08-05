"""WTForms definitions for SecureGuard AI authentication."""

from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

from models import User


class RegisterForm(FlaskForm):
    """Form for creating a new user account."""

    full_name = StringField("Full Name", validators=[DataRequired(), Length(min=2, max=80)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password")],
    )
    avatar = SelectField(
        "Choose Avatar",
        choices=[
            ("icons/male.svg", "Male"),
            ("icons/female.svg", "Female"),
            ("icons/hacker.svg", "Hacker"),
            ("icons/cyber-shield.svg", "Cyber Shield"),
            ("icons/ai-robot.svg", "AI Robot"),
            ("icons/security-officer.svg", "Security Officer"),
        ],
        default="icons/cyber-shield.svg",
    )
    submit = SubmitField("Create Account")

    def validate_email(self, field):
        """Ensure the supplied email address is unique."""
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError("Email already registered.")


class LoginForm(FlaskForm):
    """Form for authenticating an existing user."""

    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Remember Me")
    submit = SubmitField("Sign In")


class ProfileForm(FlaskForm):
    """Minimal profile editor form for authenticated placeholder views."""

    name = StringField("Name", validators=[DataRequired(), Length(min=2, max=80)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    avatar = SelectField(
        "Choose Avatar",
        choices=[
            ("icons/male.svg", "Male"),
            ("icons/female.svg", "Female"),
            ("icons/hacker.svg", "Hacker"),
            ("icons/cyber-shield.svg", "Cyber Shield"),
            ("icons/ai-robot.svg", "AI Robot"),
            ("icons/security-officer.svg", "Security Officer"),
        ],
        default="icons/cyber-shield.svg",
    )
    submit = SubmitField("Save Changes")


class ChangePasswordForm(FlaskForm):
    """Minimal password change form for authenticated placeholder views."""

    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField("New Password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("new_password")],
    )
    submit = SubmitField("Update Password")
