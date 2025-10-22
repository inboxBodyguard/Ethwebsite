from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import logging
import requests
import base64
import time

# -------------------- SETUP --------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.', template_folder='.')
CORS(app, resources={
    r"/*": {
        "origins": [
            "https://www.ezmcyber.xyz",
            "https://ezmcyber.xyz",
            "http://localhost:5000",
            "http://127.0.0.1:5000"
        ],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

# -------------------- ENVIRONMENT VARIABLES --------------------
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
NOTIFY_EMAIL = os.getenv("NOTIFY_EMAIL")
HF_API_KEY = os.getenv("HF_API_KEY")
HF_MODEL = "mistralai/Mistral-7B-Instruct-v0.2"
VT_API = os.getenv("VIRUSTOTAL_API_KEY")
URLSCAN_API = os.getenv("URLSCAN_API_KEY")
WHOIS_API_KEY = os.getenv("WHOISXML_API_KEY")
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
RECAPTCHA_SECRET = os.getenv("RECAPTCHA_SECRET_KEY")

HEADERS_VT = {"x-apikey": VT_API} if VT_API else {}
VT_BASE = "https://www.virustotal.com/api/v3"

logger.info(f"Starting app with SENDER_EMAIL: {SENDER_EMAIL}")
logger.info(f"NOTIFY_EMAIL: {NOTIFY_EMAIL}")
if not HF_API_KEY:
    logger.warning("⚠️ Hugging Face API key not found in environment!")

# -------------------- EMAIL FUNCTION --------------------
def send_email(to_email, subject, html_content):
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        logger.error("Email credentials not configured!")
        return False, "Email credentials missing"
    
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = to_email
    msg.attach(MIMEText(html_content, "html"))

    try:
        logger.info(f"Attempting to send email to {to_email}")
        with smtplib.SMTP("smtp.hostinger.com", 587, timeout=10) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        logger.info(f"Email sent successfully to {to_email}")
        return True, None
    except Exception as e:
        logger.error(f"Email send failed: {str(e)}")
        return False, str(e)

def send_welcome_email(to_email):
    subject = "Welcome to EZM Cyber!"
    html_content = f"""
    <html>
        <body>
            <h2>Welcome to EZM Cyber! 👋</h2>
            <p>Thank you for signing up at <strong>EZM Cyber</strong>!</p>
            <p>We'll keep you updated on our threat intelligence platform.</p>
            <br>
            <p>Best regards,<br>The EZM Cyber Team</p>
        </body>
    </html>
    """
    return send_email(to_email, subject, html_content)

# -------------------- HELPERS --------------------
def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def url_id_from_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

def do_vt_check(url):
    if not VT_API:
        raise Exception("VirusTotal API key not found.")
    
    url = normalize_url(url)
    url_id = url_id_from_url(url)

    # Try getting existing report
    response = requests.get(f"{VT_BASE}/urls/{url_id}", headers=HEADERS_VT, timeout=15)
    if response.status_code == 200:
        return response.json().get("data", {}).get("attributes", {})

    # Submit URL for analysis
    response = requests.post(f"{VT_BASE}/urls", headers=HEADERS_VT, data={"url": url}, timeout=15)
    if response.status_code in (200, 201):
        analysis_id = response.json()["data"]["id"]
        for _ in range(6):
            time.sleep(1)
            analysis_response = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=HEADERS_VT, timeout=15)
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                status = analysis_data.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    url_report = requests.get(f"{VT_BASE}/urls/{url_id}", headers=HEADERS_VT, timeout=15)
                    if url_report.status_code == 200:
                        return url_report.json().get("data", {}).get("attributes", {})
                    stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
                    return {"last_analysis_stats": stats}
        return {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0}}
    elif response.status_code == 429:
        raise Exception("VirusTotal rate limit exceeded.")
    else:
        raise Exception(f"VirusTotal API error: {response.status_code}")

# -------------------- ROUTES --------------------
@app.route("/", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "EZM Cyber Combined Service",
        "version": "1.0"
    }), 200

@app.route('/home')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/verify-link')
def verify_link():
    return send_from_directory('.', 'verify_link.html')

# -------------------- SIGNUP / WELCOME EMAIL --------------------
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get('email')
        recaptcha_token = data.get('recaptchaToken')

        if not email:
            return jsonify({"error": "Email required"}), 400

        # Verify reCAPTCHA
        if RECAPTCHA_SECRET:
            recaptcha_resp = requests.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={"secret": RECAPTCHA_SECRET, "response": recaptcha_token}
            ).json()
            if not recaptcha_resp.get("success"):
                return jsonify({"error": f"reCAPTCHA failed: {recaptcha_resp.get('error-codes', ['Unknown error'])}"}), 400

        # Send welcome email
        sent, error = send_welcome_email(email)
        return jsonify({"status": "success" if sent else "error", "message": "Welcome email sent" if sent else f"Failed to send email: {error}"}), 200 if sent else 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -------------------- SEND REPORT / ADMIN NOTIFY --------------------
@app.route("/send-report", methods=["POST", "OPTIONS"])
def send_report():
    if request.method == "OPTIONS":
        return "", 200

    try:
        data = request.get_json()
        email = data.get("email")
        link_status = data.get("link_status", "Welcome!")

        if not email:
            return jsonify({"status": "error", "message": "Email is required"}), 400

        # User email
        user_subject = "Welcome to EZM Cyber!"
        user_html = f"""
        <html>
            <body>
                <h2>Welcome to EZM Cyber! 👋</h2>
                <p>Status: {link_status}</p>
                <p>We'll keep you updated on our threat intelligence platform.</p>
            </body>
        </html>
        """
        sent, error = send_email(email, user_subject, user_html)
        if not sent:
            return jsonify({"status": "error", "message": f"Failed to send welcome email: {error}"}), 500

        # Notify admin
        if NOTIFY_EMAIL:
            admin_subject = "🚨 New Signup Alert!"
            admin_html = f"""
            <html>
                <body>
                    <h2>New User Signup</h2>
                    <ul>
                        <li><strong>Email:</strong> {email}</li>
                        <li><strong>Status:</strong> {link_status}</li>
                        <li><strong>Time:</strong> {request.headers.get('Date', 'Unknown')}</li>
                    </ul>
                </body>
            </html>
            """
            send_email(NOTIFY_EMAIL, admin_subject, admin_html)

        return jsonify({"status": "sent", "message": "Welcome email sent successfully!"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# -------------------- VIRUSTOTAL --------------------
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
        if "rate limit" in error_msg.lower():
            return jsonify({"error": error_msg}), 429
        return jsonify({"error": error_msg}), 500

# -------------------- URLSCAN --------------------
@app.route('/api/urlscan', methods=['POST'])
def urlscan_check():
    try:
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({"error": "Missing URL parameter"}), 400

        headers = {"API-Key": URLSCAN_API, "Content-Type": "application/json"}
        payload = {"url": url, "visibility": "private"}
        response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=payload, timeout=20)

        if response.status_code not in (200, 201):
            return jsonify({"error": f"URLScan API error {response.status_code}", "details": response.text}), response.status_code

        data = response.json()
        return jsonify({
            "scan_id": data.get("uuid"),
            "result_url": data.get("result"),
            "message": "Scan started successfully. Use 'result_url' to view full analysis."
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -------------------- WHOIS --------------------
@app.route('/whois')
def whois_page():
    return send_from_directory('.', 'whois.html')

@app.route('/api/whois', methods=['POST'])
def whois_lookup():
    try:
        data = request.get_json()
        domain = data.get('domain')
        if not domain:
            return jsonify({'error': 'Domain missing'}), 400

        endpoint = (
            f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
            f"?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=JSON"
        )
        r = requests.get(endpoint, timeout=10)
        r.raise_for_status()
        return jsonify(r.json())
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

# -------------------- HUGGING FACE CHAT --------------------
@app.route("/chat", methods=["POST"])
def chat_with_model():
    try:
        data = request.get_json(force=True)
        user_input = data.get("prompt") or data.get("message")  # Support both
        if not user_input:
            return jsonify({"error": "Prompt or message is required"}), 400

        if not HF_API_KEY:
            logger.error("Hugging Face API key missing")
            return jsonify({"error": "AI service unavailable: API key missing"}), 500

        # Context about EZM Cyber
        context = """
        You are a cybersecurity AI assistant for EZM Cyber, a premier cybersecurity firm.
        EZM Cyber protects users from digital threats with services like:
        - Suspicious Link Checker (VirusTotal, URLScan.io) for malware and phishing detection.
        - Real-time threat monitoring and detailed reports.
        - Tutorials on online safety and password management.
        - 24/7 rapid response and custom consultations.
        The platform uses 90+ security vendors via VirusTotal, URLScan.io for deep scans, and supports breach detection.
        Answer as a friendly, expert assistant using a cyberpunk tone with emojis (😎, 🚨, 🛡️).
        """
        payload = {
            "inputs": f"{context}\n\nUser Question: {user_input}",
            "parameters": {"max_new_tokens": 500, "temperature": 0.7}
        }

        headers = {
            "Authorization": f"Bearer {HF_API_KEY}",
            "Content-Type": "application/json"
        }
        response = requests.post(
            f"https://api-inference.huggingface.co/models/{HF_MODEL}",
            headers=headers,
            json=payload,
            timeout=20
        )

        if response.status_code != 200:
            logger.error(f"Hugging Face API error: {response.status_code} - {response.text}")
            return jsonify({"error": f"AI service error: {response.status_code}"}), response.status_code

        result = response.json()
        text = result[0].get("generated_text", "").strip() if isinstance(result, list) else result.get("generated_text", "").strip()
        if not text:
            return jsonify({"error": "Empty response from AI model"}), 500

        # Clean response (remove context/user question)
        response_text = text.replace(context, "").replace(f"User Question: {user_input}", "").strip()
        return jsonify({"response": response_text}), 200
    except Exception as e:
        logger.error(f"Chat endpoint error: {str(e)}")
        return jsonify({"error": f"AI service failed: {str(e)}"}), 500

# -------------------- ERROR HANDLERS --------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"status": "error", "message": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"status": "error", "message": "Internal server error"}), 500

# -------------------- RUN APP --------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)