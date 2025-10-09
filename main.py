import os
import base64
import time
import requests
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

app = Flask(__name__, static_folder='.')  # Static files in same folder
CORS(app)

# --- VirusTotal Configuration ---
VT_API = os.getenv("VIRUSTOTAL_API_KEY")
HEADERS = {"x-apikey": VT_API} if VT_API else {}
VT_BASE = "https://www.virustotal.com/api/v3"

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

# --- SendGrid Welcome Email ---
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")

def send_welcome_email(to_email):
    if not SENDGRID_API_KEY:
        print("SendGrid API key not found.")
        return
    message = Mail(
        from_email='you@yourdomain.com',  # Replace with your verified sender
        to_emails=to_email,
        subject='Welcome to EZM Cyber!',
        html_content='<strong>Thanks for signing up! You are now protected by EZM Cyber.</strong>'
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print("Email sent:", response.status_code)
    except Exception as e:
        print("SendGrid error:", e)

# --- Routes ---
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/verify-link')
def verify_link():
    return send_from_directory('.', 'verify_link.html')

@app.route('/api/virustotal', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        url = data.get('url')
        email = data.get('email')  # Optional: pass email to send welcome
        if not url:
            return jsonify({"error": "Missing URL parameter"}), 400
        
        result = do_vt_check(url)

        # Send welcome email if email provided
        if email:
            send_welcome_email(email)

        return jsonify(result)
    except Exception as e:
        error_msg = str(e)
        if "rate limit" in error_msg.lower():
            return jsonify({"error": error_msg}), 429
        return jsonify({"error": error_msg}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)