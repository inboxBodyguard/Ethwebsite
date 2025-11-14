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
from flask_bcrypt import Bcrypt
from flask import Flask, send_from_directory

# ——— LOGGING SETUP ———
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ——— APP SETUP ———
app = Flask(__name__, static_folder='.', template_folder='templates')  # UPDATED: template_folder='templates'
CORS(app)
bcrypt = Bcrypt(app)

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
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")

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

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

# ——— HELPERS ———
def hash_password(password: str) -> str:
    return bcrypt.generate_password_hash(password).decode('utf-8')

def check_password_verified(hashed_password: str, password: str) -> bool:
    return bcrypt.check_password_hash(hashed_password, password)

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
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        logger.warning("Email credentials missing (SENDER_EMAIL/SENDER_PASSWORD). Cannot send welcome email.")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Welcome to EZM Cyber!"
    msg["From"] = SENDER_EMAIL
    msg["To"] = to_email
    html_content = f"""
    <html>
      <body>
        <p>Hello,</p>
        <p><strong>Thanks for signing up to EZM Cyber!</strong> Your account is now active under the email: <strong>{to_email}</strong>. You are now protected by EZM Cyber.</p>
        <p>Start scanning links and securing your online presence today.</p>
        <br>
        <p>Best regards,<br>The EZM Cyber Team</p>
      </body>
    </html>
    """
    msg.attach(MIMEText(html_content, "html"))

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

# ADDED: Routes for all HTML files in templates folder
@app.route('/about')
def about():
    return send_from_directory('templates', 'about.html')

@app.route('/services')
def services():
    return send_from_directory('templates', 'services.html')

@app.route('/contact')
def contact():
    return send_from_directory('templates', 'contact.html')

@app.route('/signup')
def signup_page():
    return send_from_directory('templates', 'signup.html')

@app.route('/hash-generator')
def hash_generator():
    return send_from_directory('templates', 'hash-generator.html')

@app.route('/password-tools')
def password_tools():
    return send_from_directory('templates', 'password-tools.html')

@app.route('/file-scanner')
def file_scanner():
    return send_from_directory('templates', 'file-scanner.html')

@app.route('/network-tools')
def network_tools():
    return send_from_directory('templates', 'network-tools.html')

@app.route('/checker')
def checker():
    return send_from_directory('templates', 'checker.html')

@app.route('/checker-thankyou')
def checker_thankyou():
    return send_from_directory('templates', 'checker-thankyou.html')

@app.route('/demo_thank_you')
def demo_thank_you():
    return send_from_directory('templates', 'demo_thank_you.html')

@app.route('/home')
def home_page():
    return send_from_directory('templates', 'home.html')

@app.route('/incident-playbook')
def incident_playbook():
    return send_from_directory('templates', 'incident-playbook.html')

@app.route('/login')
def login_page():
    return send_from_directory('templates', 'login.html')

@app.route('/newsletter')
def newsletter():
    return send_from_directory('templates', 'newsletter.html')

@app.route('/next_steps')
def next_steps():
    return send_from_directory('templates', 'next_steps.html')

@app.route('/playbook')
def playbook():
    return send_from_directory('templates', 'playbook.html')

@app.route('/privacy')
def privacy():
    return send_from_directory('templates', 'privacy.html')

@app.route('/subscribe-thankyou')
def subscribe_thankyou():
    return send_from_directory('templates', 'subscribe-thankyou.html')

@app.route('/thank-you')
def thank_you():
    return send_from_directory('templates', 'thank-you.html')

@app.route('/verify_link')
def verify_link():
    return send_from_directory('templates', 'verify_link.html')

@app.route('/whoisxmlapi')
def whoisxmlapi():
    return send_from_directory('templates', 'whoisxmlapi.html')

@app.route('/404')
def not_found_page():
    return send_from_directory('templates', '404.html')

# API Routes
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
            Thread(target=send_welcome_email, args=(email,), daemon=True).start()
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

        if OPENAI_API_KEY:
            response = chat_with_openai(user_input)
            if response:
                return response

        if GROQ_API_KEY:
            response = chat_with_groq(user_input)
            if response:
                return response

        return jsonify({"response": "🤖 AI is currently offline. Please try again later or use our URL scanning features."}), 200

    except Exception as e:
        logger.error(f"Chat endpoint error: {str(e)}", exc_info=True)
        return jsonify({"response": "AI service temporarily unavailable. Please try again shortly."}), 200

def chat_with_openai(user_input):
    try:
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert assistant for EZM Cyber security platform. Key features: URL scanning with VirusTotal (90+ security vendors), URLScan.io integration, malware/phishing detection, breach monitoring. Answer security questions clearly and concisely."
                },
                {
                    "role": "user",
                    "content": user_input
                }
            ],
            "max_tokens": 250,
            "temperature": 0.7
        }

        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            text = result["choices"][0]["message"]["content"].strip()
            return jsonify({"response": text}), 200
        else:
            logger.error(f"OpenAI API error: {response.status_code}")
            return None

    except Exception as e:
        logger.error(f"OpenAI connection error: {str(e)}")
        return None

def chat_with_groq(user_input):
    try:
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert assistant for EZM Cyber security platform. Key features: URL scanning with VirusTotal, URLScan.io integration, malware/phishing detection. Answer security questions clearly and concisely."
                },
                {
                    "role": "user",
                    "content": user_input
                }
            ],
            "model": "mixtral-8x7b-32768",
            "temperature": 0.7,
            "max_tokens": 250
        }

        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            text = result["choices"][0]["message"]["content"].strip()
            return jsonify({"response": text}), 200
        else:
            logger.error(f"Groq API error: {response.status_code}")
            return None

    except Exception as e:
        logger.error(f"Groq connection error: {str(e)}")
        return None

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

    return jsonify({"ok": True, "id": req.id, "redirect": "/demo_thank_you"}), 200

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password")

    if not email or not validators.email(email):
        return jsonify({"ok": False, "error": "Invalid email format"}), 400

    if not password or len(password) < 8:
        return jsonify({"ok": False, "error": "Password must be at least 8 characters"}), 400

    if db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none():
        return jsonify({"ok": False, "error": "Email already registered"}), 409

    try:
        hashed_password = hash_password(password)
        new_user = User(email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        Thread(target=send_welcome_email, args=(email,), daemon=True).start()

        return jsonify({"ok": True, "message": "Account created successfully. Welcome email is being sent."}), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Signup failed for {email}: {e}")
        return jsonify({"ok": False, "error": "An internal error occurred during registration."}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password")

    user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()

    if user and check_password_verified(user.password_hash, password):
        return jsonify({"ok": True, "message": f"Login successful for user: {email}"}), 200
    else:
        return jsonify({"ok": False, "error": "Invalid email or password"}), 401

# Maintenance mode toggle
MAINTENANCE_MODE = False  # Set to False to allow access to all pages

@app.before_request pages

@app.before_request
def maintenance_redirect():
    if MAINTENANCE_MODE:
        return send_from_directory('.', 'index.html')
# —index.html')

# ——— RUN—— RUN APP ———
if APP ———
if __name__ == '__main__':
    port = __name__ == '__main__':
    port = int(os int(os.environ.get("PORT", 5000))
.environ.get("PORT", 5000))
    logger    logger.info(f"Starting Flask app.info(f"Starting Flask app on on port {port}")

 port {port}")

    with app.app_context():
        db.create_all    with app.app_context():
        db.create_all()

    app()

    app.run(host.run(host='0.0.0.0', port=='0.0.0.0', port=port, debug=False)
port, debug=False)