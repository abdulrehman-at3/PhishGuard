# 🛡️ PhishGuard

Professional Phishing Email Detection System built using **Python**, **Flask**, and **Cybersecurity Best Practices**.

---

## v2 — Context-Aware Detection

The original engine scored any message containing words like *"verify,"* *"OTP,"* *"limited time,"* or *"click here"* as suspicious — which meant ordinary marketing emails and routine verification codes were flagged right alongside real phishing. v2 fixes this by answering two questions separately:

1. **What kind of message is this?** — Marketing/Promotional, Security/Account Notice, Transactional/Order Update, Newsletter, or Personal correspondence. (`classify_category`)
2. **Given that kind of message, is there real evidence of an attack?** — a spoofed sender, a lookalike or insecure link, or an explicit request to send credentials back over email. (`analyze_email`)

Marketing language ("30% off," "limited time") and routine security language ("your OTP is 482913," "this code expires in 10 minutes") are now treated as normal content that only counts against a message when it's paired with hard evidence — a bad sender or a bad link. On their own, they contribute nothing. The report also now surfaces **Positive Indicators** (e.g. "sender domain matches the official github domain," "reminds you never to share this code") so it's visibly clear *why* something reads as legitimate, not just that it wasn't flagged.

---

## Features

- Phishing Email Detection with context-aware, evidence-weighted scoring
- Message-type classification (Marketing / Security / Transactional / Newsletter / Personal)
- Positive-indicator reporting, not just red flags
- URL Analysis (lookalike domains, character substitution, insecure protocols, suspicious TLDs)
- Sender Verification against known brand domains and free-mail providers
- Risk Score Calculation (0–100) with a clear verdict
- Secure Flask Backend — CSRF Protection, Rate Limiting, Secure HTTP Headers
- Private-inspection styled UI (obsidian + gold, serif display type, medallion verdict seal)
- Responsive Dashboard
- Error Handling

---

## Project Structure

```
PhishGuard/
│
├── app.py
├── analyzer.py
├── utils.py
├── test_app.py
├── requirements.txt
│
├── templates/
│   ├── index.html
│   ├── result.html
│   └── error.html
│
├── static/
│   ├── style.css
│   └── script.js
│
├── sample_emails/
│   ├── phishing.txt          (phishing)
│   ├── legitimate.txt        (personal correspondence)
│   ├── marketing.txt         (legitimate marketing)
│   ├── verification.txt      (legitimate OTP/verification)
│   └── transactional.txt     (legitimate order update)
│
├── logs/
│
└── README.md
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/PhishGuard.git
```

Navigate to the project:

```bash
cd PhishGuard
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python app.py
```

Open:

```
http://127.0.0.1:5000
```

---

## Security Features

- CSRF Protection (Flask-WTF)
- Rate Limiting (Flask-Limiter, 10 analyses/minute)
- Secure Session Cookies (HttpOnly, SameSite)
- Input Validation
- HTML Sanitization (bleach)
- Secure Headers (CSP, X-Frame-Options, X-Content-Type-Options)
- XSS Prevention (Jinja2 autoescaping + sanitization)
- OWASP Inspired Practices

The `SECRET_KEY` is read from the `SECRET_KEY` environment variable (falling
back to a dev-only default), so you should set your own before deploying:

```bash
export SECRET_KEY="replace-with-a-long-random-value"
```

---

## Technology Stack

- Python / Flask
- Bootstrap 5 (layout utilities) + Bootstrap Icons
- Fraunces (display serif), Source Sans 3 (body), IBM Plex Mono (data/evidence)
- HTML5 / CSS3 / JavaScript

---

## Sample Workflow

1. Open the application.
2. Paste an email into the analyzer.
3. Click **Analyze Email**.
4. View:
   - Message category (what it claims to be)
   - Verdict and risk score
   - Positive indicators (why it looks legitimate, if it does)
   - Findings (red flags, if any)
   - URLs and recommendations

Five ready-made samples are included in `sample_emails/` covering every
category the engine recognizes, so you can see the discrimination in
action immediately — including two legitimate emails (marketing, OTP)
that use the same "urgent," "click here," "limited time" style language
a phishing email might, to demonstrate that context — not just keywords —
drives the verdict.

---

## Running Tests

35 tests cover the category classifier, the specific false-positive
patterns that were reported and fixed (marketing urgency, OTP delivery
vs. credential solicitation, short-lived-code expiry wording), sanitisation,
and the full Flask request/response cycle including CSRF:

```bash
pip install pytest
pytest test_app.py -v
```

---

## Future Improvements

- Machine Learning Classifier
- VirusTotal API Integration
- WHOIS Domain Lookup
- SPF / DKIM / DMARC Checks
- PDF Report Generation
- Email File (.eml) Upload
- User Authentication
- Scan History Dashboard

---

## Author

**Abdul Rehman Tahir**

Cybersecurity Student | Python Developer | Flask Developer

---

## License

This project is released under the MIT License.
