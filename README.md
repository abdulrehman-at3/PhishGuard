# 🛡️ PhishGuard

<div align="center">

### Professional Context-Aware Phishing Email Detection System

Built with **Python**, **Flask**, and **Cybersecurity Best Practices** to intelligently distinguish between legitimate emails and phishing attempts using evidence-based analysis rather than simple keyword matching.

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-black?style=for-the-badge&logo=flask)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5-purple?style=for-the-badge&logo=bootstrap)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

</div>

---

# 📖 Overview

**PhishGuard** is a cybersecurity-focused web application designed to analyze email content and determine whether an email is legitimate or a potential phishing attempt.

Unlike traditional phishing detectors that rely primarily on suspicious keywords, PhishGuard evaluates the **context** of an email before making a decision. The system analyzes the email's purpose, verifies sender authenticity, inspects embedded URLs, searches for phishing indicators, and generates an evidence-based risk score with a clear verdict.

The goal is to significantly reduce false positives while providing users with transparent explanations through both **positive indicators** and **security findings**.

---

# 🎯 How PhishGuard Works

PhishGuard analyzes every email in two intelligent stages.

## 1️⃣ Email Classification

The application first determines what kind of email it is.

Supported categories include:

- 📢 Marketing / Promotional
- 🔐 Security / Account Notice
- 📦 Transactional / Order Update
- 📰 Newsletter
- 👤 Personal Correspondence

Understanding the purpose of an email allows the analyzer to interpret common phrases appropriately instead of treating every keyword as suspicious.

---

## 2️⃣ Security Analysis

After identifying the email category, PhishGuard performs a comprehensive security inspection by analyzing:

- Sender authenticity
- Embedded URLs
- Lookalike domains
- Character substitution attacks
- Suspicious top-level domains
- Insecure HTTP links
- Credential harvesting attempts
- Requests for passwords or OTPs
- Email spoofing indicators

Rather than relying on isolated keywords, PhishGuard weighs multiple security indicators together to produce a more accurate phishing assessment.

---

## ✅ Transparent Decision Making

Most phishing detectors only report what appears suspicious.

PhishGuard also highlights **positive indicators**, allowing users to understand **why an email appears legitimate**.

Examples include:

- Sender domain matches the official organization
- Secure HTTPS links
- No credential requests detected
- Legitimate verification reminders
- Trusted domain references

This transparency makes the final verdict easier to understand and trust.

---

# ✨ Features

- 🛡️ Context-aware phishing detection
- 📂 Automatic email classification
- 📊 Evidence-based risk scoring (0–100)
- ✅ Positive indicator reporting
- 🌐 URL security analysis
- 👤 Sender verification
- 🔍 Lookalike domain detection
- 🔤 Character substitution detection
- 🌍 Suspicious TLD detection
- 🔒 Insecure HTTP detection
- ⚠ Credential solicitation detection
- 💡 Security recommendations
- 📱 Responsive dashboard
- 🎨 Professional inspection-style UI
- 📝 Logging support
- ❌ Robust error handling

---

# 🔍 Email Categories

PhishGuard automatically classifies incoming emails into one of the following categories.

| Category | Description |
|-----------|-------------|
| 📢 Marketing | Promotions, offers, coupons, discounts |
| 🔐 Security | Login alerts, verification codes, password resets |
| 📦 Transactional | Orders, invoices, shipping updates |
| 📰 Newsletter | News digests and subscriptions |
| 👤 Personal | Human-to-human communication |

---

# 🔎 Detection Techniques

PhishGuard combines multiple security checks to improve detection accuracy.

## 📧 Sender Analysis

- Official brand verification
- Trusted domain matching
- Free email provider detection
- Suspicious sender identification
- Sender-domain consistency checks

---

## 🌐 URL Analysis

- Lookalike domain detection
- Character substitution attacks
- Suspicious TLD identification
- HTTP vs HTTPS verification
- Shortened URL detection
- Domain mismatch analysis

---

## 🛡️ Phishing Indicators

The detection engine searches for indicators such as:

- Credential harvesting attempts
- Password requests
- Banking credential requests
- Fake login pages
- Email reply credential theft
- Social engineering language
- Spoofing attempts

---

## ✅ Positive Indicators

To reduce false positives, PhishGuard also detects legitimate characteristics.

Examples include:

- Sender domain matches official organization
- HTTPS links detected
- No credential requests
- Security reminders advising users not to share OTPs
- Trusted company domains
- Expected transactional language

---

# 📈 Risk Scoring

Every analyzed email receives a risk score between **0 and 100**.

| Score | Verdict |
|--------|----------|
| **0 – 20** | 🟢 Safe |
| **21 – 49** | 🟡 Low Risk |
| **50 – 74** | 🟠 Suspicious |
| **75 – 100** | 🔴 High Risk / Phishing |

The final score is generated using multiple weighted security indicators instead of simple keyword matching.

---

# 🖥️ User Interface

The application features a modern inspection-style dashboard with:

- Obsidian & Gold theme
- Responsive layout
- Verdict medallion
- Risk score visualization
- Evidence panels
- Positive indicators
- Detailed findings
- Mobile-friendly design

---

# 🔐 Security Features

PhishGuard follows modern secure coding practices inspired by OWASP recommendations.

### Backend Security

- CSRF Protection (Flask-WTF)
- Rate Limiting (10 requests/minute)
- Secure Session Cookies
- Input Validation
- HTML Sanitization (Bleach)
- XSS Prevention
- Secure Error Handling
- OWASP-inspired secure coding practices

---

## Security Headers

- Content Security Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- HttpOnly Cookies
- SameSite Cookies

---

# 📂 Project Architecture

```text
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
│   ├── phishing.txt
│   ├── legitimate.txt
│   ├── marketing.txt
│   ├── verification.txt
│   └── transactional.txt
│
├── logs/
│
└── README.md
```

---

# ⚙️ Installation

## Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/PhishGuard.git
```

---

## Navigate into the Project

```bash
cd PhishGuard
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Configure Environment Variable

### Linux / macOS

```bash
export SECRET_KEY="your-long-random-secret-key"
```

### Windows PowerShell

```powershell
$env:SECRET_KEY="your-long-random-secret-key"
```

---

## Run the Application

```bash
python app.py
```

---

## Open Your Browser

```
http://127.0.0.1:5000
```

---

# 🚀 How It Works

1. Launch the application.
2. Paste an email into the analyzer.
3. Click **Analyze Email**.
4. View the generated report containing:

- Email category
- Risk score
- Final verdict
- Positive indicators
- Security findings
- URL analysis
- Security recommendations

---

# 📄 Sample Emails

Five sample emails are included to demonstrate the analyzer across different scenarios.

| File | Category |
|------|----------|
| phishing.txt | Phishing Email |
| legitimate.txt | Personal Email |
| marketing.txt | Marketing Email |
| verification.txt | Security / OTP Email |
| transactional.txt | Order / Transaction Email |

These examples demonstrate how PhishGuard distinguishes legitimate emails from phishing attempts using contextual analysis.

---

# 🧪 Running Tests

The project includes **35 automated tests** covering:

- Email classification
- URL analysis
- Credential solicitation detection
- HTML sanitization
- False-positive prevention
- Flask routes
- CSRF protection
- Complete request-response lifecycle

Install pytest:

```bash
pip install pytest
```

Run the tests:

```bash
pytest test_app.py -v
```

---

# 🛠️ Technology Stack

### Backend

- Python
- Flask
- Flask-WTF
- Flask-Limiter

### Frontend

- HTML5
- CSS3
- JavaScript
- Bootstrap 5
- Bootstrap Icons

### Security

- Bleach
- Jinja2 Autoescaping

### Typography

- Fraunces
- Source Sans 3
- IBM Plex Mono

---

# 🚀 Future Improvements

- 🤖 Machine Learning Classification
- 🌐 VirusTotal API Integration
- 🌍 WHOIS Domain Lookup
- 📧 SPF / DKIM / DMARC Validation
- 📄 PDF Report Generation
- 📂 Email (.eml) Upload Support
- 👤 User Authentication
- 📊 Scan History Dashboard
- 📈 Detection Analytics
- ☁️ Docker Deployment
- 🔌 REST API Support

---

# 👨‍💻 Author

## Abdul Rehman Tahir

**Cybersecurity Student | Python Developer | Flask Developer**

Passionate about cybersecurity, secure software development, phishing detection, and building practical defensive security tools.

- GitHub: https://github.com/YOUR_USERNAME
- LinkedIn: https://linkedin.com/in/YOUR_PROFILE

---

# 🤝 Contributing

Contributions, feature requests, and suggestions are welcome.

If you'd like to improve PhishGuard:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to your branch
5. Open a Pull Request

---

# ⭐ Support

If you found this project helpful, please consider giving it a **⭐ Star** on GitHub. It helps others discover the project and supports future development.

---

# 📄 License

This project is licensed under the **MIT License**.

See the **LICENSE** file for more information.
