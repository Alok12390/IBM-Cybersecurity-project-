import re
import email
from email import policy
from email.parser import BytesParser, Parser
from urllib.parse import urlparse
import html


PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "suspended account",
    "unusual activity", "click here immediately", "act now", "urgent action required",
    "your account will be closed", "update your payment", "validate your account",
    "login attempt", "security alert", "verify now", "limited time offer",
    "congratulations you won", "claim your prize", "free gift", "password expired",
    "account suspended", "click to unsubscribe", "confirm your email",
    "dear customer", "dear user", "dear account holder", "bank account",
    "social security", "wire transfer", "western union", "money transfer",
    "nigerian prince", "inheritance", "lottery winner", "you have been selected",
    "risk-free", "100% free", "no cost", "winner!", "you are a winner",
    "click below", "follow the link", "verify here", "reset password immediately",
    "unauthorized access", "account breach", "data breach alert",
]

SUSPICIOUS_TLD = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".pw",
    ".cc", ".su", ".biz", ".info", ".ru", ".cn", ".work", ".click",
    ".link", ".download", ".zip", ".review", ".country",
]

SUSPICIOUS_URL_PATTERNS = [
    r"bit\.ly", r"tinyurl\.com", r"goo\.gl", r"t\.co", r"ow\.ly",
    r"is\.gd", r"buff\.ly", r"adf\.ly", r"short\.link",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # Raw IP address
    r"@",  # URL with @ sign (redirects)
    r"paypa1", r"payp4l", r"g00gle", r"micros0ft", r"amaz0n",
    r"app1e", r"faceb00k", r"secure.*login", r"login.*secure",
    r"account.*verify", r"verify.*account", r"signin.*secure",
]

SPOOFED_DOMAINS = [
    "paypal", "google", "microsoft", "amazon", "apple", "facebook",
    "netflix", "bank", "chase", "wellsfargo", "citibank", "irs",
    "instagram", "twitter", "linkedin", "dropbox", "adobe",
]


def extract_urls(text):
    url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    return re.findall(url_pattern, text, re.IGNORECASE)


def analyze_url(url):
    findings = []
    risk = 0
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        for pattern in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                findings.append(f"Suspicious URL pattern detected: matches '{pattern}'")
                risk += 20

        for tld in SUSPICIOUS_TLD:
            if domain.endswith(tld):
                findings.append(f"Suspicious TLD: domain ends with '{tld}'")
                risk += 25
                break

        for brand in SPOOFED_DOMAINS:
            if brand in domain and not domain.endswith(f".{brand}.com"):
                if not (domain == f"{brand}.com" or domain.endswith(f".{brand}.com")):
                    findings.append(f"Possible brand spoofing: '{brand}' found in domain '{domain}'")
                    risk += 30

        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            findings.append("URL uses raw IP address instead of domain name")
            risk += 35

        if len(url) > 100:
            findings.append(f"Unusually long URL ({len(url)} chars) — may be obfuscating destination")
            risk += 10

        if url.count('.') > 5:
            findings.append("Excessive subdomains in URL — common phishing technique")
            risk += 15

    except Exception:
        pass
    return findings, min(risk, 100)


def analyze_headers(headers_text):
    findings = []
    risk = 0
    headers_lower = headers_text.lower()

    if "received-spf: fail" in headers_lower:
        findings.append("SPF check FAILED — sender is not authorized by the domain")
        risk += 40
    elif "received-spf: softfail" in headers_lower:
        findings.append("SPF SOFTFAIL — sender may not be authorized by the domain")
        risk += 20
    elif "received-spf: pass" in headers_lower:
        findings.append("SPF check passed ✓")

    if "dkim=fail" in headers_lower:
        findings.append("DKIM signature FAILED — email may have been tampered with")
        risk += 40
    elif "dkim=pass" in headers_lower:
        findings.append("DKIM signature verified ✓")
    else:
        findings.append("No DKIM signature found — sender authenticity unverified")
        risk += 15

    if "dmarc=fail" in headers_lower:
        findings.append("DMARC policy FAILED — domain alignment mismatch")
        risk += 35
    elif "dmarc=pass" in headers_lower:
        findings.append("DMARC policy passed ✓")
    else:
        findings.append("No DMARC record — domain lacks anti-spoofing policy")
        risk += 10

    from_match = re.search(r'from:\s*(.+)', headers_text, re.IGNORECASE)
    reply_match = re.search(r'reply-to:\s*(.+)', headers_text, re.IGNORECASE)
    if from_match and reply_match:
        from_domain = re.search(r'@([\w.-]+)', from_match.group(1))
        reply_domain = re.search(r'@([\w.-]+)', reply_match.group(1))
        if from_domain and reply_domain:
            if from_domain.group(1).lower() != reply_domain.group(1).lower():
                findings.append(
                    f"Reply-To domain '{reply_domain.group(1)}' differs from From domain '{from_domain.group(1)}' — classic phishing trick"
                )
                risk += 35

    received_lines = re.findall(r'received:.*', headers_text, re.IGNORECASE)
    if len(received_lines) > 8:
        findings.append(f"Unusually high number of mail servers ({len(received_lines)}) — possible relay abuse")
        risk += 15

    return findings, min(risk, 100)


def analyze_email(raw_email_text="", headers_text="", subject="", body="", sender=""):
    result = {
        "score": 0,
        "risk_level": "Low",
        "findings": [],
        "url_analysis": [],
        "header_analysis": [],
        "keyword_hits": [],
        "summary": "",
    }

    total_risk = 0
    weight_count = 0

    # --- Parse raw email if provided ---
    if raw_email_text.strip():
        try:
            msg = Parser(policy=policy.default).parsestr(raw_email_text)
            if not subject:
                subject = msg.get("Subject", "")
            if not sender:
                sender = msg.get("From", "")
            if not body:
                if msg.is_multipart():
                    for part in msg.walk():
                        ct = part.get_content_type()
                        if ct in ("text/plain", "text/html"):
                            try:
                                body += part.get_payload(decode=True).decode(errors="replace")
                            except Exception:
                                pass
                else:
                    try:
                        body = msg.get_payload(decode=True).decode(errors="replace")
                    except Exception:
                        body = str(msg.get_payload())
            if not headers_text:
                headers_text = str(msg)
        except Exception:
            pass

    full_text = f"{subject} {body}".lower()

    # --- Keyword analysis ---
    for kw in PHISHING_KEYWORDS:
        if kw in full_text:
            result["keyword_hits"].append(kw)

    if result["keyword_hits"]:
        kw_risk = min(len(result["keyword_hits"]) * 12, 80)
        result["findings"].append(
            f"Found {len(result['keyword_hits'])} phishing keyword(s): {', '.join(repr(k) for k in result['keyword_hits'][:5])}"
            + (" ..." if len(result["keyword_hits"]) > 5 else "")
        )
        total_risk += kw_risk
        weight_count += 1

    # --- URL analysis ---
    urls = extract_urls(body) + extract_urls(subject)
    if urls:
        all_url_findings = []
        url_risk_total = 0
        for url in urls[:20]:
            findings, url_risk = analyze_url(url)
            if findings:
                all_url_findings.append({"url": url, "issues": findings, "risk": url_risk})
                url_risk_total += url_risk
        result["url_analysis"] = all_url_findings
        if all_url_findings:
            avg_url_risk = url_risk_total // len(all_url_findings)
            total_risk += avg_url_risk
            weight_count += 1
            result["findings"].append(f"Analyzed {len(urls)} URL(s), {len(all_url_findings)} flagged as suspicious")
    else:
        result["findings"].append("No URLs found in email body")

    # --- Header analysis ---
    if headers_text.strip():
        hdr_findings, hdr_risk = analyze_headers(headers_text)
        result["header_analysis"] = hdr_findings
        total_risk += hdr_risk
        weight_count += 1

    # --- Subject analysis ---
    if subject:
        subject_lower = subject.lower()
        if re.search(r'urgent|immediate|action required|alert|warning|important|critical', subject_lower):
            result["findings"].append("Subject uses urgency/alarm language — common phishing tactic")
            total_risk += 20
            weight_count += 1
        if re.search(r'[A-Z]{4,}', subject):
            result["findings"].append("Subject contains excessive ALL-CAPS — pressure/alarm tactic")
            total_risk += 10
        if subject.count('!') > 2:
            result["findings"].append(f"Subject has {subject.count('!')} exclamation marks — high-pressure language")
            total_risk += 10

    # --- Sender analysis ---
    if sender:
        for brand in SPOOFED_DOMAINS:
            if brand in sender.lower():
                domain_match = re.search(r'@([\w.-]+)', sender)
                if domain_match:
                    domain = domain_match.group(1).lower()
                    if not (domain == f"{brand}.com" or domain.endswith(f".{brand}.com")):
                        result["findings"].append(
                            f"Sender claims to be '{brand}' but uses domain '{domain}' — possible spoofing"
                        )
                        total_risk += 40
                        weight_count += 1

    # --- Compute final score ---
    if weight_count > 0:
        final_score = min(int(total_risk / max(weight_count, 1)), 100)
    else:
        final_score = 0

    if not raw_email_text.strip() and not body.strip() and not headers_text.strip() and not subject.strip():
        result["findings"].append("No email content provided for analysis.")
        final_score = 0

    result["score"] = final_score

    if final_score >= 70:
        result["risk_level"] = "Critical"
        result["summary"] = "High probability phishing email. Do NOT click any links or provide information."
    elif final_score >= 45:
        result["risk_level"] = "High"
        result["summary"] = "Suspicious email with multiple red flags. Treat with extreme caution."
    elif final_score >= 20:
        result["risk_level"] = "Medium"
        result["summary"] = "Some suspicious indicators found. Verify sender before acting."
    else:
        result["risk_level"] = "Low"
        result["summary"] = "No significant phishing indicators detected. Email appears legitimate."

    return result
