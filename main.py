import os
import base64
import time
import requests
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='.')
CORS(app)

# VirusTotal API key from environment variable
VT_API = os.getenv("VIRUSTOTAL_API_KEY")
if not VT_API:
    raise RuntimeError("⚠️ VIRUSTOTAL_API_KEY environment variable is not set")

HEADERS = {"x-apikey": VT_API}
VT_BASE = "https://www.virustotal.com/api/v3"

def normalize_url(url):
    """Normalize URL to ensure it has a protocol"""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def url_id_from_url(url):
    """Convert URL to VirusTotal URL ID format (base64 urlsafe without padding)"""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

def do_vt_check(url):
    """Check URL against VirusTotal API"""
    url = normalize_url(url)
    url_id = url_id_from_url(url)

    # Try to get cached report first
    response = requests.get(f"{VT_BASE}/urls/{url_id}", headers=HEADERS, timeout=15)
    
    if response.status_code == 200:
        data = response.json()
        return data.get("data", {}).get("attributes", {})
    
    # Submit URL for analysis if not cached
    response = requests.post(f"{VT_BASE}/urls", headers=HEADERS, data={"url": url}, timeout=15)
    
    if response.status_code in (200, 201):
        analysis_id = response.json()["data"]["id"]
        
        # Poll for analysis completion (up to 6 seconds)
        for _ in range(6):
            time.sleep(1)
            analysis_response = requests.get(
                f"{VT_BASE}/analyses/{analysis_id}", 
                headers=HEADERS, 
                timeout=15
            )
            
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                status = analysis_data.get("data", {}).get("attributes", {}).get("status")
                
                if status == "completed":
                    # Fetch the full URL report for detailed stats
                    url_report = requests.get(f"{VT_BASE}/urls/{url_id}", headers=HEADERS, timeout=15)
                    if url_report.status_code == 200:
                        return url_report.json().get("data", {}).get("attributes", {})
                    # Fallback: use analysis stats
                    stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
                    return {"last_analysis_stats": stats}
        
        # If analysis not completed in time, return pending status
        return {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0}}
    
    elif response.status_code == 429:
        raise Exception("VirusTotal rate limit exceeded. Please try again in a few minutes.")
    else:
        raise Exception(f"VirusTotal API error: {response.status_code}")

@app.route('/')
def index():
    """Serve the main HTML page"""
    return send_from_directory('.', 'index.html')

@app.route('/api/virustotal', methods=['POST'])
def check_url():
    """API endpoint to check a URL with VirusTotal"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({"error": "Missing URL parameter"}), 400
        
        # Perform VirusTotal check
        result = do_vt_check(url)
        return jsonify(result)
    
    except Exception as e:
        error_msg = str(e)
        # Return appropriate status code for rate limits
        if "rate limit" in error_msg.lower():
            return jsonify({"error": error_msg}), 429
        return jsonify({"error": error_msg}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)