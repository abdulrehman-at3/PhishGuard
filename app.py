"""
app.py

PhishGuard - Flask application entry point.
Handles routing, form validation, security headers, and rate limiting.
"""

import os

from flask import Flask, flash, redirect, render_template, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import TextAreaField
from wtforms.validators import DataRequired, Length

from analyzer import analyze_email
from utils import MAX_INPUT_LENGTH, sanitize_input, setup_logger, validate_input

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-key-change-this-in-production")
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024  # 256 KB max request size
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "False") == "True"

csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)
logger = setup_logger()


class EmailForm(FlaskForm):
    email_text = TextAreaField(
        "Email Content",
        validators=[
            DataRequired(message="Please paste an email to analyze."),
            Length(max=MAX_INPUT_LENGTH, message=f"Maximum {MAX_INPUT_LENGTH} characters allowed."),
        ],
    )


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

@app.after_request
def set_secure_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
        "img-src 'self' data:;"
    )
    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    form = EmailForm()
    return render_template("index.html", form=form)


@app.route("/analyze", methods=["POST"])
@limiter.limit("10 per minute")
def analyze():
    form = EmailForm()

    if not form.validate_on_submit():
        flash("Please paste a valid email or message before analyzing.")
        logger.warning("Rejected submission: form validation failed")
        return redirect(url_for("index"))

    raw_text = sanitize_input(form.email_text.data)
    is_valid, error_message = validate_input(raw_text)

    if not is_valid:
        flash(error_message)
        logger.warning("Rejected submission: %s", error_message)
        return redirect(url_for("index"))

    try:
        result = analyze_email(raw_text)
    except Exception:
        logger.exception("Unexpected error during analysis")
        return render_template(
            "error.html",
            error_message="Something went wrong while analyzing this message. Please try again.",
        ), 500

    logger.info(
        "Analyzed message | verdict=%s | score=%s | urls=%s",
        result["verdict"], result["score"], result["url_count"],
    )

    return render_template("result.html", result=result)


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", error_message="Page not found."), 404


@app.errorhandler(429)
def rate_limited(_error):
    return render_template(
        "error.html",
        error_message="Too many requests. Please wait a moment before trying again.",
    ), 429


@app.errorhandler(500)
def server_error(_error):
    return render_template("error.html", error_message="Internal server error. Please try again later."), 500


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "False") == "True"
    app.run(debug=debug_mode)
