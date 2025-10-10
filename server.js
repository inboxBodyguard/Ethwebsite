from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
import base64
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# Single VirusTotal API key
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY_1")

@app.route("/api/check-link", methods=["POST"])
def check_link():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "Missing URL"}), 400

    try:
        encoded_url = base64.b64encode(url.encode()).decode()
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded_url}",
            headers=headers,
            timeout=20
        )
        return jsonify({"status": "success", "data": response.json()})
    except Exception as e:
        return jsonify({"error": "Backend timeout or VirusTotal API error", "message": str(e)}), 500

@app.route("/")
def root():
    return "✅ EZM Cyber Link Checker Backend is running fine."

if __name__ == "__main__":
    port = int(os.getenv("PORT", 3000))
    app.run(host="0.0.0.0", port=port)