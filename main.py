import os
import base64
import time
import requests
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# -------------------- SETUP --------------------
app = Flask(__name__, static_folder='.', template_folder='.')
CORS(app)

# -------------------- VIRUSTOTAL CONFIG --------------------
VT_API = os.getenv("VIRUSTOTAL_API_KEY")
HEADERS = {"x-apikey": VT_API} if VT_API else {}
VT_BASE = "https://www.virustotal.com/api/v3"

# -------------------- URLSCAN CONFIG --------------------
URLSCAN_API = os.getenv("URLSCAN_API_KEY")

# -------------------- SENDGRID CONFIG --------------------
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

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
        raise Exception("VirusTotal API key not found. Set the VIRUSTOTAL_API_KEY environment variable.")

    url = normalize_url(url)
    url_id = url_id_from_url(url)

    # Try getting existing report
    response = requests.get(f"{VT_BASE}/urls/{url_id}", headers=HEADERS, timeout=15)
    if response.status_code == 200:
        return response.json().get("data", {}).get("attributes", {})

    # Submit URL for analysis
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

# -------------------- ROUTES --------------------
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

@app.route('/api/virustotal', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        url = data.get('url')
        email = data.get('email')  # optional
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

# -------------------- WHOIS --------------------
WHOIS_API_KEY = os.getenv("WHOISXML_API_KEY")

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

# -------------------- RUN APP --------------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)