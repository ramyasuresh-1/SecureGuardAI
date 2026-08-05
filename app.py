"""Flask application factory for the SecureGuard AI platform."""

from flask import Flask, render_template

from auth import auth_bp
from extensions import db, login_manager
from models import User


@login_manager.user_loader
def load_user(user_id: str):
    """Return the logged-in user for Flask-Login."""
    return User.query.get(int(user_id))


def create_app(config_object=None):
    """Create and configure the Flask application instance."""
    app = Flask(__name__)
    app.config.from_object(config_object or "config.Config")

    # Initialize extensions with the Flask application instance.
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    app.register_blueprint(auth_bp)

    @app.route("/")
    def index():
        """Render the landing page."""
        return render_template("index.html")

    # Ensure the SQLite database and ALL tables are created automatically.
    # PasswordAnalysis must be imported so SQLAlchemy registers the mapper
    # before db.create_all() runs; otherwise the table is silently skipped.
    with app.app_context():
        from models import PasswordAnalysis, User  # noqa: F401

        db.create_all()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
