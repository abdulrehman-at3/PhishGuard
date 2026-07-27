"""
test_app.py

Test suite for PhishGuard v2.

Covers:
  - Pure unit tests for the analyzer's category classifier and
    context-aware scoring (including the specific false-positive
    patterns reported and fixed: marketing urgency, OTP delivery vs
    credential solicitation, short-lived-code expiry wording).
  - Unit tests for utils.py sanitisation/validation.
  - Integration tests for the Flask routes, including CSRF behaviour,
    run against all five bundled sample emails.

Run with:
    pip install pytest
    pytest test_app.py -v
"""

import re

import pytest

import analyzer
import utils
from app import app as flask_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    flask_app.config.update(TESTING=True)
    with flask_app.test_client() as test_client:
        yield test_client


def _get_csrf_token(client):
    html = client.get("/").data.decode()
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match, "csrf_token input not found on index page"
    return match.group(1)


def _analyze_sample(client, filename):
    token = _get_csrf_token(client)
    with open(f"sample_emails/{filename}", encoding="utf-8") as f:
        text = f.read()
    response = client.post("/analyze", data={"email_text": text, "csrf_token": token})
    assert response.status_code == 200
    return response.data.decode()


# ---------------------------------------------------------------------------
# Unit tests - utils.py
# ---------------------------------------------------------------------------

def test_sanitize_input_strips_html():
    assert utils.sanitize_input("<script>alert(1)</script>hello") == "alert(1)hello"


def test_sanitize_input_enforces_max_length():
    long_text = "a" * (utils.MAX_INPUT_LENGTH + 500)
    assert len(utils.sanitize_input(long_text)) == utils.MAX_INPUT_LENGTH


def test_validate_input_rejects_empty():
    is_valid, message = utils.validate_input("")
    assert is_valid is False
    assert "paste" in message.lower()


def test_validate_input_rejects_too_short():
    is_valid, _ = utils.validate_input("hi")
    assert is_valid is False


def test_validate_input_accepts_reasonable_text():
    is_valid, message = utils.validate_input("This is a perfectly normal length message.")
    assert is_valid is True
    assert message is None


# ---------------------------------------------------------------------------
# Unit tests - analyzer.py - extraction helpers
# ---------------------------------------------------------------------------

def test_extract_urls_finds_and_cleans_links():
    text = "Please visit http://example-test.xyz/verify. Thanks."
    assert analyzer.extract_urls(text) == ["http://example-test.xyz/verify"]


def test_extract_sender_from_header_line():
    text = "From: security@paypa1-support.com\nSubject: test"
    assert analyzer.extract_sender(text) == "security@paypa1-support.com"


def test_extract_sender_returns_none_when_absent():
    assert analyzer.extract_sender("No email address in here at all.") is None


def test_lookalike_domain_detection():
    assert analyzer._char_substitution_lookalike("paypa1-support.com", "paypal") is True
    assert analyzer._char_substitution_lookalike("micr0soft-login.com", "microsoft") is True
    assert analyzer._char_substitution_lookalike("paypal.com", "paypal") is False


# ---------------------------------------------------------------------------
# Unit tests - analyzer.py - sender / link evidence
# ---------------------------------------------------------------------------

def test_analyze_url_flags_http_and_suspicious_tld():
    flags, _ = analyzer.analyze_url("http://secure-bank-login.xyz/verify")
    flag_texts = [text for text, _ in flags]
    assert any("HTTPS" in text for text in flag_texts)
    assert any(".xyz" in text for text in flag_texts)


def test_analyze_url_clean_and_credited_for_official_domain():
    flags, brand = analyzer.analyze_url("https://github.com/settings/security-log")
    assert flags == []
    assert brand == "github"


def test_analyze_sender_flags_free_mail_impersonation():
    flags, positives, brand = analyzer.analyze_sender("amazon-support@hotmail.com")
    assert any("amazon" in text.lower() for text, _ in flags)
    assert positives == []
    assert brand is None


def test_analyze_sender_clean_and_credited_for_official_domain():
    flags, positives, brand = analyzer.analyze_sender("no-reply@github.com")
    assert flags == []
    assert brand == "github"
    assert any("github" in p for p in positives)


# ---------------------------------------------------------------------------
# Unit tests - the specific false positives that were reported and fixed
# ---------------------------------------------------------------------------

def test_otp_delivery_is_not_flagged_as_solicitation():
    """'Your OTP is 123456' must NOT trigger the credential-solicitation flag."""
    body = "Your one-time password (OTP) is: 738291. This code will expire in 10 minutes."
    flags, positives, category = analyzer.analyze_text(body, hard_evidence_present=False)
    assert not any("credentials" in text for text, _ in flags)
    assert category == "Security / Account Notice"


def test_explicit_credential_solicitation_is_flagged():
    """Asking someone to reply with/provide a password is still flagged - unconditionally."""
    body = "Please provide:\n\n- Username\n- Password\n- ATM PIN\n- One-Time Password (OTP)"
    flags, _, _ = analyzer.analyze_text(body, hard_evidence_present=False)
    assert any("send or enter sensitive credentials" in text for text, _ in flags)


def test_short_code_expiry_alone_is_not_account_threat():
    """A normal 'this code expires in 10 minutes' must not read as an account threat."""
    assert analyzer.ACCOUNT_THREAT_PATTERN.search("this code will expire in 10 minutes") is None


def test_real_account_suspension_threat_is_detected():
    assert analyzer.ACCOUNT_THREAT_PATTERN.search("your account has been temporarily suspended")
    assert analyzer.ACCOUNT_THREAT_PATTERN.search("this will result in permanent suspension")


def test_marketing_urgency_alone_scores_zero_risk():
    """Marketing pressure language with NO sender/link evidence must not be flagged as risk."""
    body = "Limited time offer! Free shipping! Act now, this deal won't last!"
    flags, _, category = analyzer.analyze_text(body, hard_evidence_present=False)
    assert flags == []
    assert category == "Marketing / Promotional"


def test_marketing_urgency_counts_only_when_corroborating():
    """The same language DOES contribute once hard evidence already exists elsewhere."""
    body = "Limited time offer! Free shipping! Act now, this deal won't last!"
    flags, _, _ = analyzer.analyze_text(body, hard_evidence_present=True)
    assert any("promotional pressure" in text for text, _ in flags)


def test_positive_signals_detected_and_reduce_score():
    body = "Never share this code with anyone. If you didn't request this, you can safely ignore this email."
    flags, positives, _ = analyzer.analyze_text(body, hard_evidence_present=False)
    assert len(positives) >= 2
    score = analyzer.calculate_risk_score(flags, len(positives))
    assert score == 0


# ---------------------------------------------------------------------------
# Unit tests - category classification
# ---------------------------------------------------------------------------

def test_classify_category_marketing():
    assert analyzer.classify_category("limited time offer, 30% off, free shipping") == "Marketing / Promotional"


def test_classify_category_security_notice():
    assert analyzer.classify_category("your one-time password otp is 12345") == "Security / Account Notice"


def test_classify_category_transactional():
    assert analyzer.classify_category("your order has shipped, tracking number 123") == "Transactional / Order Update"


def test_classify_category_defaults_to_personal():
    assert analyzer.classify_category("hi, want to grab lunch tomorrow?") == "Personal / General Correspondence"


def test_get_verdict_thresholds():
    assert analyzer.get_verdict(0)[0] == "Legitimate"
    assert analyzer.get_verdict(30)[0] == "Suspicious"
    assert analyzer.get_verdict(75)[0] == "Phishing"


def test_calculate_risk_score_clamps_to_100():
    flags = [("finding", "high")] * 10
    assert analyzer.calculate_risk_score(flags, 0) == 100


# ---------------------------------------------------------------------------
# Integration tests - Flask routes
# ---------------------------------------------------------------------------

def test_index_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"PhishGuard" in response.data


def test_analyze_without_csrf_token_is_rejected(client):
    response = client.post("/analyze", data={"email_text": "test message"})
    assert response.status_code == 400


def test_analyze_empty_submission_redirects_home(client):
    token = _get_csrf_token(client)
    response = client.post(
        "/analyze", data={"email_text": "", "csrf_token": token}, follow_redirects=True
    )
    assert response.status_code == 200
    assert b"PhishGuard" in response.data


def test_404_page(client):
    response = client.get("/this-route-does-not-exist")
    assert response.status_code == 404
    assert b"Page not found" in response.data


# ---------------------------------------------------------------------------
# Integration tests - all five bundled sample emails, end to end
# ---------------------------------------------------------------------------

def test_sample_phishing_is_flagged_as_phishing(client):
    html = _analyze_sample(client, "phishing.txt")
    assert "medallion-danger" in html
    assert ">Phishing<" in html


def test_sample_legitimate_personal_email(client):
    html = _analyze_sample(client, "legitimate.txt")
    assert "medallion-success" in html
    assert ">Legitimate<" in html
    assert "Personal / General Correspondence" in html


def test_sample_marketing_email_is_legitimate_not_phishing(client):
    """The core bug report: marketing language must not be misread as phishing."""
    html = _analyze_sample(client, "marketing.txt")
    assert "medallion-success" in html
    assert ">Legitimate<" in html
    assert "Marketing / Promotional" in html


def test_sample_verification_email_is_legitimate_not_phishing(client):
    """The core bug report: a routine OTP email must not be misread as phishing."""
    html = _analyze_sample(client, "verification.txt")
    assert "medallion-success" in html
    assert ">Legitimate<" in html
    assert "Security / Account Notice" in html
    assert "Positive Indicators" in html


def test_sample_transactional_email_is_legitimate(client):
    html = _analyze_sample(client, "transactional.txt")
    assert "medallion-success" in html
    assert ">Legitimate<" in html
    assert "Transactional / Order Update" in html
