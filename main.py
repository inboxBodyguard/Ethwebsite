import os
import base64
import time
import requests
import logging
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# –––––––––– LOGGING SETUP ––––––––––

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(**name**)

# –––––––––– SETUP ––––––––––

app = Flask(**name**, static_folder=’.’, template_folder=’.’)
CORS(app)

# –––––––––– VIRUSTOTAL CONFIG ––––––––––

VT_API = os.getenv(“VIRUSTOTAL_API_KEY”)
HEADERS = {“x-apikey”: VT_API} if VT_API else {}
VT_BASE = “https://www.virustotal.com/api/v3”

# –––––––––– URLSCAN CONFIG ––––––––––

URLSCAN_API = os.getenv(“URLSCAN_API_KEY”)

# –––––––––– SENDGRID CONFIG ––––––––––

SENDGRID_API_KEY = os.getenv(“SENDGRID_API_KEY”)

# –––––––––– RECAPTCHA CONFIG ––––––––––

RECAPTCHA_SECRET = os.getenv(“RECAPTCHA_SECRET_KEY”)

# –––––––––– HUGGINGFACE CONFIG ––––––––––

HF_API_KEY = os.getenv(“HF_API_KEY”)

# –––––––––– HELPERS ––––––––––

def normalize_url(url):
url = url.strip()
if not url.startswith((“http://”, “https://”)):
url = “http://” + url
return url

def url_id_from_url(url):
return base64.urlsafe_b64encode(url.encode()).decode().rstrip(”=”)

def do_vt_check(url):
if not VT_API:
raise Exception(“VirusTotal API key not found. Set the VIRUSTOTAL_API_KEY environment variable.”)

```
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
            status = analysis_data.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os


SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")

if not SENDER_EMAIL or not SENDER_PASSWORD:
    print("Email credentials missing!")
    return False

msg = MIMEMultipart("alternative")
msg["Subject"] = "Welcome to EZM Cyber!"
msg["From"] = SENDER_EMAIL
msg["To"] = to_email
msg.attach(MIMEText(
    "<strong>Thanks for signing up! You are now protected by EZM Cyber.</strong>", 
    "html"
))

try:
    with smtplib.SMTP("smtp.hostinger.com", 587, timeout=10) as server:
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
    print(f"Welcome email sent to {to_email}")
    return True
except Exception as e:
    print("Email send failed:", e)
    return False


# –––––––––– ROUTES ––––––––––

@app.route(’/’)
def home():
return send_from_directory(’.’, ‘index.html’)

@app.route(’/verify-link’)
def verify_link():
return send_from_directory(’.’, ‘verify_link.html’)

@app.route(’/api/urlscan’, methods=[‘POST’])
def urlscan_check():
try:
data = request.get_json()
url = data.get(‘url’)
if not url:
return jsonify({“error”: “Missing URL parameter”}), 400


    if not URLSCAN_API:
        return jsonify({"error": "URLScan API key not configured"}), 500

    headers = {"API-Key": URLSCAN_API, "Content-Type": "application/json"}
    payload = {"url": normalize_url(url), "visibility": "private"}
    response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=payload, timeout=20)

    if response.status_code not in (200, 201):
        logger.error(f"URLScan API error: {response.status_code} - {response.text}")
        if response.status_code == 429:
            return jsonify({"error": "URLScan rate limit exceeded", "details": response.text}), 429
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


@app.route(’/api/virustotal’, methods=[‘POST’])
def check_url():
try:
data = request.get_json()
url = data.get(‘url’)
email = data.get(‘email’)
if not url:
return jsonify({“error”: “Missing URL parameter”}), 400


    result = do_vt_check(url)

    if email:
        send_welcome_email(email)

    return jsonify(result)
except Exception as e:
    error_msg = str(e)
    if "rate limit" in error_msg.lower():
        return jsonify({"error": error_msg}), 429
    return jsonify({"error": error_msg}), 500

# –––––––––– WHOIS ––––––––––

WHOIS_API_KEY = os.getenv(“WHOISXML_API_KEY”)

@app.route(’/whois’)
def whois_page():
return send_from_directory(’.’, ‘whois.html’)

@app.route(’/api/whois’, methods=[‘POST’])
def whois_lookup():
try:
data = request.get_json()
domain = data.get(‘domain’)
if not domain:
return jsonify({‘error’: ‘Domain missing’}), 400


    endpoint = (
        f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
        f"?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=JSON"
    )
    r = requests.get(endpoint, timeout=10)
    r.raise_for_status()
    return jsonify(r.json())
except requests.exceptions.RequestException as e:
    return jsonify({'error': str(e)}), 500


# –––––––––– REGISTER ––––––––––

@app.route(’/register’, methods=[‘POST’])
def register():
try:
data = request.get_json()
email = data.get(‘email’)
password = data.get(‘password’)
recaptcha_token = data.get(‘recaptchaToken’)


    if not email:
        return jsonify({"error": "Email required"}), 400
    
    if RECAPTCHA_SECRET:
        recaptcha_resp = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": RECAPTCHA_SECRET, "response": recaptcha_token}
        ).json()
        if not recaptcha_resp.get("success"):
            return jsonify({"error": f"reCAPTCHA failed: {recaptcha_resp.get('error-codes', ['Unknown error'])}"}), 400
    
    sent = send_welcome_email(email)
    return jsonify({"status": "success" if sent else "error", "message": "Welcome email sent" if sent else "Failed to send welcome email"}), 200 if sent else 500
except Exception as e:
    return jsonify({"error": str(e)}), 500


# –––––––––– HUGGING FACE CHAT (FIXED) ––––––––––

@app.route(”/chat”, methods=[“POST”])
def chat_with_model():
logger.info(”=== CHAT ENDPOINT HIT ===”)


try:
    data = request.get_json(force=True)
    user_input = data.get("prompt") or data.get("message")
    
    logger.info(f"User input received: {user_input}")
    
    if not user_input:
        return jsonify({"error": "Prompt or message is required"}), 400

    # Check API key
    if not HF_API_KEY:
        logger.error("HF_API_KEY environment variable is missing!")
        return jsonify({
            "response": "🤖 AI is currently offline. Our security scanner uses VirusTotal (90+ vendors) and URLScan.io to detect malware, phishing, and breaches. What would you like to know about these features?"
        }), 200

    logger.info(f"HF_API_KEY found: {HF_API_KEY[:10]}...")

    # Simplified, focused context
    context = """You are a cybersecurity expert assistant for EZM Cyber security platform.


Key features: URL scanning with VirusTotal (90+ security vendors), URLScan.io integration,
malware/phishing detection, breach monitoring. Answer security questions clearly and concisely.”””


    payload = {
        "inputs": f"{context}\n\nUser: {user_input}\nAssistant:",
        "parameters": {
            "max_new_tokens": 250,
            "temperature": 0.7,
            "return_full_text": False,
            "do_sample": True
        }
    }

    headers = {
        "Authorization": f"Bearer {HF_API_KEY}",
        "Content-Type": "application/json"
    }
    
    logger.info("Sending request to Hugging Face API...")
    
    response = requests.post(
        "https://api-inference.huggingface.co/models/fdtn-ai/Foundation-Sec-8B",
        headers=headers,
        json=payload,
        timeout=30
    )

    logger.info(f"HF API Response Status: {response.status_code}")
    logger.info(f"HF API Response: {response.text[:500]}")

    if response.status_code == 503:
        # Model is loading
        logger.warning("Model is loading, using fallback response")
        return jsonify({
            "response": "🔍 I'm here to help with security questions! Our platform scans URLs using VirusTotal's 90+ security engines and URLScan.io to detect malware, phishing, and data breaches. We analyze links in real-time to keep you safe. What specific security topic would you like to explore?"
        }), 200

    if response.status_code != 200:
        logger.error(f"HF API error: {response.status_code} - {response.text}")
        return jsonify({
            "response": "🛡️ Security tip: Our scanner checks every link against 90+ security vendors to catch malware, phishing sites, and compromised domains. We also monitor for data breaches. What security question can I help with?"
        }), 200

    result = response.json()
    logger.info(f"Parsed result type: {type(result)}")
    
    # Extract text from response
    text = ""
    if isinstance(result, list) and len(result) > 0:
        text = result[0].get("generated_text", "")
    elif isinstance(result, dict):
        text = result.get("generated_text", result.get("response", ""))
    
    logger.info(f"Extracted text length: {len(text)}")
    
    # Clean up the response
    text = text.replace(context, "").replace(f"User: {user_input}", "").replace("Assistant:", "").strip()
    
    # Remove any remaining context artifacts
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    if lines:
        text = lines[0]  # Take first meaningful line
    
    if not text or len(text) < 10:
        logger.warning("Empty or too short response, using fallback")
        return jsonify({
            "response": "🔐 Great question! Our security platform combines VirusTotal (90+ engines) and URLScan.io to analyze links for threats. We detect malware, phishing, suspicious behavior, and monitor for data breaches. Each scan gives you detailed vendor analysis and threat scores. What would you like to know more about?"
        }), 200

    logger.info(f"Sending cleaned response: {text}")
    return jsonify({"response": text}), 200
    
except requests.exceptions.Timeout:
    logger.error("HF API timeout")
    return jsonify({
        "response": "⚡ Quick security tip: We scan links using VirusTotal's network of 90+ security vendors plus URLScan.io for comprehensive threat detection. This catches malware, phishing, and breaches before they reach you. What aspect of security scanning interests you?"
    }), 200
except Exception as e:
    logger.error(f"Chat endpoint error: {str(e)}", exc_info=True)
    return jsonify({
        "response": "🛡️ I'm your security assistant! Our platform uses industry-leading tools (VirusTotal, URLScan.io) to scan links for malware, phishing, and data breaches. We analyze URLs against 90+ security engines in real-time. How can I help you stay secure?"
    }), 200

# –––––––––– RUN APP ––––––––––

if **name** == ‘**main**’:
port = int(os.environ.get(“PORT”, 5000))
logger.info(f”Starting Flask app on port {port}”)
logger.info(f”HF_API_KEY configured: {bool(HF_API_KEY)}”)
app.run(host=‘0.0.0.0’, port=port, debug=False)