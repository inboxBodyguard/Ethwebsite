import os
import base64
import time
import logging
from typing import Optional
from threading import Thread
from requests import RequestException
import requests
import validators
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

# ——— LOGGING SETUP ———
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ——— APP SETUP ———
app = Flask(__name__, static_folder='.', template_folder='.')
CORS(app)

# ——— DATABASE SETUP ———
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite:///demo_requests.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ——— ENV VARIABLES / CONFIG ———
VT_API = os.getenv("VIRUSTOTAL_API_KEY")
HEADERS = {"x-apikey": VT_API} if VT_API else {}
VT_BASE = "https://www.virustotal.com/api/v3"

URLSCAN_API = os.getenv("URLSCAN_API_KEY")
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
RECAPTCHA_SECRET = os.getenv("RECAPTCHA_SECRET_KEY")
HF_API_KEY = os.getenv("HF_API_KEY")
WHOIS_API_KEY = os.getenv("WHOISXML_API_KEY")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

MAX_CONTENT_LEN = 1800
RETRIES = 3
BACKOFF = 0.5
TIMEOUT = 8

# ——— DATABASE MODELS ———
class DemoRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    email = db.Column(db.String(254), index=True)
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.now())

# ——— HELPERS ———
def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def url_id_from_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

def do_vt_check(url):
    if not VT_API:
        raise Exception("VirusTotal API key not found. Set the VIRUSTOTAL_API_KEY environment variable.")
    url = normalize_url(url)
    url_id = url_id_from_url(url)

    response = requests.get(f"{VT_BASE}/urls/{url_id}", headers=HEADERS, timeout=15)
    if response.status_code == 200:
        return response.json().get("data", {}).get("attributes", {})

    response = requests.post(f"{VT_BASE}/urls", headers=HEADERS, data={"url": url}, timeout=15)
    if response.status_code in (200, 201):
        analysis_id = response.json()["data"]["id"]
        for _ in range(6):
            time.sleep(1)
            analysis_response = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=HEADERS, timeout=15)
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                if analysis_data.get("data", {}).get("attributes", {}).get("status") == "completed":
                    url_report = requests.get(f"{VT_BASE}/urls/{url_id}", headers=HEADERS, timeout=15)
                    if url_report.status_code == 200:
                        return url_report.json().get("data", {}).get("attributes", {})
                    stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
                    return {"last_analysis_stats": stats}
        return {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0}}
    elif response.status_code == 429:
        raise Exception("VirusTotal rate limit exceeded. Please try again later.")
    else:
        raise Exception(f"VirusTotal API error: {response.status_code}")

def send_welcome_email(to_email):
    SENDER_EMAIL = os.getenv("SENDER_EMAIL")
    SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        logger.warning("Email credentials missing!")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Welcome to EZM Cyber!"
    msg["From"] = SENDER_EMAIL
    msg["To"] = to_email
    msg.attach(MIMEText("<strong>Thanks for signing up! You are now protected by EZM Cyber.</strong>", "html"))

    try:
        with smtplib.SMTP("smtp.hostinger.com", 587, timeout=10) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        logger.info(f"Welcome email sent to {to_email}")
        return True
    except Exception as e:
        logger.error("Email send failed: %s", e)
        return False

def _safe_text(s: Optional[str], max_len: int = 400) -> str:
    if not s:
        return ""
    s = s.strip()
    return s if len(s) <= max_len else s[: max_len - 3] + "..."

def send_webhook_alert(req: DemoRequest) -> bool:
    url = DISCORD_WEBHOOK_URL or SLACK_WEBHOOK_URL
    if not url:
        logger.warning("No webhook URL configured")
        return False

    name = _safe_text(req.name, 60) or "—"
    email = _safe_text(req.email, 120) or "—"
    message = _safe_text(req.message, 800) or "—"

    content = f"**New Demo Request**\n**Name:** {name}\n**Email:** {email}\n**Message:** {message}"
    if len(content) > MAX_CONTENT_LEN:
        content = content[:MAX_CONTENT_LEN - 3] + "..."
    payload = {"content": content}
    headers = {"Content-Type": "application/json"}

    for attempt in range(1, RETRIES + 1):
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=TIMEOUT)
            if 200 <= r.status_code < 300:
                return True
            if r.status_code == 429:
                wait = BACKOFF * attempt
                logger.warning("Rate limited; sleeping %s seconds", wait)
                time.sleep(wait)
                continue
            logger.warning("Webhook returned %s: %s", r.status_code, r.text[:1000])
        except RequestException:
            logger.exception("Webhook request failed (attempt %s)", attempt)
        time.sleep(BACKOFF * attempt)

    logger.error("Webhook alert failed after %s attempts for demo request id=%s email=%s", RETRIES, getattr(req, "id", None), email)
    return False

# ——— ROUTES ———
@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/verify-link')
def verify_link():
    return send_from_directory('.', 'verify_link.html')

@app.route('/api/urlscan', methods=['POST'])
def urlscan_check():
    try:
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({"error": "Missing URL parameter"}), 400
        if not URLSCAN_API:
            return jsonify({"error": "URLScan API key not configured"}), 500

        headers = {"API-Key": URLSCAN_API, "Content-Type": "application/json"}
        payload = {"url": normalize_url(url), "visibility": "private"}
        response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=payload, timeout=20)

        if response.status_code not in (200, 201):
            logger.error(f"URLScan API error: {response.status_code} - {response.text}")
            return jsonify({"error": f"URLScan API error {response.status_code}", "details": response.text}), response.status_code

        data = response.json()
        return jsonify({
            "scan_id": data.get("uuid"),
            "result_url": data.get("result"),
            "message": "Scan started successfully. Use 'result_url' to view full analysis."
        })
    except Exception as e:
        logger.error(f"URLScan endpoint error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/virustotal', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        url = data.get('url')
        email = data.get('email')
        if not url:
            return jsonify({"error": "Missing URL parameter"}), 400
        result = do_vt_check(url)
        if email:
            send_welcome_email(email)
        return jsonify(result)
    except Exception as e:
        error_msg = str(e)
        return jsonify({"error": error_msg}), 500

@app.route('/api/whois', methods=['POST'])
def whois_lookup():
    try:
        data = request.get_json()
        domain = data.get('domain')
        if not domain:
            return jsonify({'error': 'Domain missing'}), 400
        endpoint = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=JSON"
        r = requests.get(endpoint, timeout=10)
        r.raise_for_status()
        return jsonify(r.json())
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

@app.route('/chat', methods=['POST'])
def chat_with_model():
    logger.info("=== CHAT ENDPOINT HIT ===")
    try:
        data = request.get_json(force=True)
        user_input = data.get("prompt") or data.get("message")
        if not user_input:
            return jsonify({"error": "Prompt or message is required"}), 400
        if not HF_API_KEY:
            return jsonify({"response": "🤖 AI is currently offline."}), 200

        context = """You are a cybersecurity expert assistant for EZM Cyber security platform.
Key features: URL scanning with VirusTotal (90+ security vendors), URLScan.io integration,
malware/phishing detection, breach monitoring. Answer security questions clearly and concisely."""

        payload = {
            "inputs": f"{context}\n\nUser: {user_input}\nAssistant:",
            "parameters": {"max_new_tokens": 250, "temperature": 0.7, "return_full_text": False, "do_sample": True}
        }
        headers = {"Authorization": f"Bearer {HF_API_KEY}", "Content-Type": "application/json"}
        response = requests.post(
            "https://api-inference.huggingface.co/models/fdtn-ai/Foundation-Sec-8B",
            headers=headers, json=payload, timeout=30
        )

        if response.status_code != 200:
            return jsonify({"response": "⚡ AI model temporarily unavailable."}), 200

        result = response.json()
        text = result[0].get("generated_text", "") if isinstance(result, list) else result.get("generated_text", "")
        text = text.replace(context, "").replace(f"User: {user_input}", "").replace("Assistant:", "").strip()
        return jsonify({"response": text}), 200
    except Exception as e:
        logger.error(f"Chat endpoint error: {str(e)}", exc_info=True)
        return jsonify({"response": "Error handling request."}), 200

@app.route('/api/demo-request', methods=['POST'])
def demo_request_route():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    message = (data.get("message") or "").strip()

    if not email or not validators.email(email):
        return jsonify({"ok": False, "error": "Invalid email"}), 400

    req = DemoRequest(name=name, email=email, message=message)
    db.session.add(req)
    db.session.commit()

    # ✅ Background webhook alert (safe inside app context)
    def _bg_send(rid):
        with app.app_context():
            try:
                r = db.session.get(DemoRequest, rid)
                if r:
                    send_webhook_alert(r)
                    logger.info(f"✅ Webhook sent for id={rid}")
            except Exception as e:
                logger.exception(f"❌ Webhook failed for id={rid}: {e}")

    Thread(target=_bg_send, args=(req.id,), daemon=True).start()

    # ✅ Include redirect info (frontend will handle it)
    return jsonify({"ok": True, "id": req.id, "redirect": "/demo_thank_you.html"}), 200
    
    @app.route('/demo_thank_you.html')
def demo_thank_you():
    return send_from_directory('.', 'demo_thank_you.html')
    
# ——— RUN APP ———
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting Flask app on port {port}")

    # ✅ Create database tables safely
    with app.app_context():
        db.create_all()

    app.run(host='0.0.0.0', port=port, debug=False)