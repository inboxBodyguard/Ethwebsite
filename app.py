from flask import Flask, request, jsonify
from flask_cors import CORS
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

app = Flask(__name__)
CORS(app)  # allow cross-origin requests

# --- Environment Variables ---
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "contact@ezmcyber.xyz")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "YOUR_EMAIL_PASSWORD")
NOTIFY_EMAIL = os.getenv("NOTIFY_EMAIL", "yourownnotifyemail@example.com")

def send_email(to_email, subject, html_content):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = to_email
    msg.attach(MIMEText(html_content, "html"))

    try:
        with smtplib.SMTP("smtp.office365.com", 587) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        return True, None
    except Exception as e:
        return False, str(e)

@app.route("/send-report", methods=["POST"])
def send_report():
    data = request.get_json()
    if not data or "email" not in data:
        return jsonify({"status":"error", "message":"Email is required"}), 400

    email = data["email"]
    link_status = data.get("link_status", "Welcome!")

    # Send welcome email
    sent, error = send_email(
        email,
        "Welcome to EZM Cyber!",
        f"<h2>Welcome 👋</h2><p>Thank you for signing up at <b>EZM Cyber</b>! Status: {link_status}</p>"
    )
    if not sent:
        return jsonify({"status":"error","message":f"Failed to send user email: {error}"}), 500

    # Send admin notification
    sent, error = send_email(
        NOTIFY_EMAIL,
        "New Signup Alert!",
        f"<p>New user signed up:</p><ul><li>Email: {email}</li><li>Status: {link_status}</li></ul>"
    )
    if not sent:
        return jsonify({"status":"error","message":f"Failed to notify admin: {error}"}), 500

    return jsonify({"status":"sent","message":"Emails sent successfully!"})

if __name__ == "__main__":
    app.run(debug=True)