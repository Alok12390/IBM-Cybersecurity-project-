from flask import Flask, render_template, request, jsonify
from detectors.email_analyzer import analyze_email
from detectors.vulnerability_scanner import scan_url

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze-email", methods=["POST"])
def api_analyze_email():
    data = request.get_json(force=True)
    raw = data.get("raw_email", "")
    headers = data.get("headers", "")
    subject = data.get("subject", "")
    body = data.get("body", "")
    sender = data.get("sender", "")

    result = analyze_email(
        raw_email_text=raw,
        headers_text=headers,
        subject=subject,
        body=body,
        sender=sender,
    )
    return jsonify(result)


@app.route("/api/scan-url", methods=["POST"])
def api_scan_url():
    data = request.get_json(force=True)
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    result = scan_url(url)
    return jsonify(result)


if __name__ == "__main__":
    print("=" * 60)
    print("  Mail-Guard — Phishing & Vulnerability Detector")
    print("  Open http://localhost:5000 in your browser")
    print("=" * 60)
    app.run(debug=False, host="0.0.0.0", port=5000)
