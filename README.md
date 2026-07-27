# 🛡️ PhishGuard

> **Professional Context-Aware Phishing Email Detection System**
>
> Built with **Python**, **Flask**, and **Cybersecurity Best Practices** to intelligently distinguish between legitimate emails and phishing attempts using evidence-based analysis rather than simple keyword matching.

---

## 📖 Overview

**PhishGuard** is a cybersecurity-focused web application designed to analyze email content and determine whether it is legitimate or potentially malicious.

Unlike traditional keyword-based phishing detectors, **PhishGuard v2** introduces **context-aware detection**, allowing it to recognize the difference between:

- Promotional marketing emails
- Account security notifications
- Transactional emails
- Newsletters
- Personal correspondence

Instead of flagging every email containing words such as **"verify"**, **"OTP"**, **"limited time"**, or **"click here"**, PhishGuard evaluates the **context** of the message and searches for genuine phishing indicators such as spoofed senders, malicious links, and credential requests.


### 2️⃣ Is there actual evidence of phishing?

The analyzer searches for meaningful security indicators, including:

- Spoofed sender addresses
- Lookalike domains
- Character substitution attacks
- Insecure URLs (HTTP)
- Suspicious top-level domains
- Credential harvesting attempts
- Requests to send passwords or OTPs over email

Only **real evidence** contributes significantly to the phishing score.

---

## 🎯 Why Context Matters

Older phishing detectors often produced false positives.

For example:

❌ **Old Behavior**

> "Your OTP expires in 10 minutes"

⬇

Flagged as phishing simply because it contains:

- OTP
- expires
- urgent language

---

✅ **PhishGuard v2**

Recognizes this as a legitimate security notification unless additional evidence exists such as:

- Fake sender
- Fake website
- Credential request

The result is dramatically fewer false positives.

---

# 🚀 Features

- 🛡️ Context-aware phishing detection
- 📂 Automatic email category classification
- 📊 Evidence-weighted risk scoring (0–100)
- ✅ Positive indicator reporting
- 🌐 URL security analysis
- 👤 Sender verification
- 🔍 Lookalike domain detection
- 🔠 Character substitution detection
- 🌍 Suspicious TLD detection
- 🔒 Insecure HTTP detection
- ⚠ Credential solicitation detection
- 💡 Security recommendations
- 📱 Responsive dashboard
- 🎨 Modern inspection-style interface
- 📝 Logging support
- ❌ Robust error handling

---

# 🔍 Detection Categories

PhishGuard automatically classifies emails into one of five categories.

| Category | Description |
|----------|-------------|
| 📢 Marketing | Promotions, offers, discounts |
| 🔐 Security | Login alerts, verification codes, password resets |
| 📦 Transactional | Orders, invoices, shipping updates |
| 📰 Newsletter | News digests and subscriptions |
| 👤 Personal | Human-to-human communication |

---

# 🔎 Detection Techniques

The engine combines multiple layers of analysis.

### 📧 Sender Analysis

- Trusted domain verification
- Brand domain matching
- Free email provider detection
- Suspicious sender identification

---

### 🌐 URL Analysis

- Lookalike domains
- Character substitution attacks
- Suspicious TLDs
- HTTP detection
- Shortened URLs
- Domain mismatch analysis

---

### 🛡️ Phishing Indicators

- Credential requests
- Password requests
- Banking credential requests
- Email reply credential harvesting
- Fake login pages
- Spoofing attempts

---

### ✅ Positive Indicators

Unlike most phishing detectors, PhishGuard also explains **why an email appears legitimate**.

Examples include:

- Sender domain matches official organization
- HTTPS links
- Reminder not to share OTP
- No credential requests
- Trusted domain references

This makes the final decision transparent and easier to understand.

# 🖥️ User Interface

The application includes a professionally designed interface featuring:

- Obsidian & gold theme
- Responsive design
- Verdict medallion
- Evidence panels
- Positive indicators
- Risk score visualization
- Mobile-friendly layout

---

# 🔐 Security Features

The application follows modern secure coding practices.

### Backend Security

- CSRF Protection
- Rate Limiting (10 requests/minute)
- Secure HTTP Headers
- Secure Session Cookies
- Input Validation
- HTML Sanitization
- XSS Protection
- OWASP-inspired secure coding practices

### Security Headers

- Content Security Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- SameSite Cookies
- HttpOnly Cookies



---

# ⚙️ Installation

## Clone the repository

```bash
git clone https://github.com/abdulrehman-at3/PhishGuard.git
```

---

## Navigate into the project

```bash
cd PhishGuard
```

---

## Install dependencies

```bash
pip install -r requirements.txt
```

---

## Configure Secret Key

Linux/macOS

```bash
export SECRET_KEY="your-long-random-secret-key"
```

Windows PowerShell

```powershell
$env:SECRET_KEY="your-long-random-secret-key"
```

---

## Run the application

```bash
python app.py
```

---

---

# 📋 Sample Workflow

1. Launch the application.
2. Paste an email into the analyzer.
3. Click **Analyze Email**.
4. View:

- Email category
- Risk score
- Final verdict
- Positive indicators
- Findings
- Suspicious URLs
- Security recommendations

Five sample emails are included to demonstrate every supported category and show how PhishGuard distinguishes between legitimate messages and phishing attempts—even when both contain urgency-related language.

---

# 🧪 Running Tests

The project includes **35 automated tests** covering:

- Email classification
- False-positive regression cases
- URL analysis
- Credential solicitation detection
- HTML sanitization
- Flask routes
- CSRF protection
- Complete request/response lifecycle

Install pytest:

```bash
pip install pytest
```

Run the test suite:

```bash
pytest test_app.py -v
```

---

# 🛠️ Technology Stack

- Python
- Flask
- Flask-WTF
- Flask-Limiter
- Bootstrap 5
- Bootstrap Icons
- HTML5
- CSS3
- JavaScript
- Bleach
- Jinja2

### Typography

- Fraunces
- Source Sans 3
- IBM Plex Mono

---

# 🚀 Future Improvements

- 🤖 Machine Learning Classifier
- 🌐 VirusTotal API Integration
- 🌍 WHOIS Domain Lookup
- 📧 SPF/DKIM/DMARC Validation
- 📄 PDF Report Generation
- 📂 `.eml` File Upload Support
- 👤 User Authentication
- 📊 Scan History Dashboard
- 📈 Detection Analytics
- ☁ Docker Deployment

---

# 👨‍💻 Author

## Abdul Rehman Tahir

**Cybersecurity Student | Python Developer | Flask Developer**

Passionate about cybersecurity, secure software development, phishing detection, and building practical defensive security tools.

---

# ⭐ Support

If you found this project useful, consider giving it a **⭐ Star** on GitHub. It helps others discover the project and motivates future development.

---

## 📄 License

This project is licensed under the **MIT License**. See the `LICENSE` file for more information.
