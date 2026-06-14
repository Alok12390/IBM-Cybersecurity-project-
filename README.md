# Mail-Guard — Phishing & Vulnerability Detector

A local Python web application for detecting phishing emails and scanning websites for security vulnerabilities.

## Features

### Email Analyzer
- Phishing keyword detection (50+ patterns)
- URL analysis (suspicious TLDs, brand spoofing, URL shorteners, raw IPs)
- Email header analysis (SPF, DKIM, DMARC validation)
- Sender domain spoofing detection
- Subject line urgency/pressure analysis
- Risk score (0–100) with Low / Medium / High / Critical levels

### Vulnerability Scanner
- SSL/TLS certificate validation (expiry, weak ciphers)
- Security header audit (CSP, HSTS, X-Frame-Options, etc.)
- Sensitive path exposure detection (.env, .git, wp-config, admin panels)
- Open port scan (MySQL, Redis, MongoDB, RDP, Telnet, etc.)
- Risk score with detailed remediation guidance

## Requirements

- Python 3.8 or higher
- pip

## Installation & Running

### Windows

```batch
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

### macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Then open **http://localhost:5000** in your browser.

## Logo

Mail-Guard uses a ✉️🔒 envelope-lock icon representing secure email analysis.

## Legal Notice

Only scan websites you own or have explicit written permission to test.
Unauthorized vulnerability scanning may be illegal in your jurisdiction.

## Stack

- Backend: Python 3 + Flask
- Frontend: Vanilla HTML / CSS / JavaScript (no build step required)
- All detection logic is built-in — no external API keys needed
