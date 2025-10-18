# save this as app.py
from flask import Flask, request, jsonify
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

app = Flask(__name__)

# --- Environment Variables ---
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "EzmcyberHQ@hotmail.com")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "YOUR_OUTLOOK_PASSWORD")
NOTIFY_EMAIL = os.getenv("NOTIFY_EMAIL", "yourownnotifyemail@example.com")  # admin notify email

# --- Email sending function ---
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
        print(f"✅ Email sent to {to_email}")
        return True
    except Exception as e:
        print(f"❌ Error sending email: {e}")
        return False

# --- Signup route ---
@app.route("/send-report", methods=["POST"])
def signup():
    try:
        data = request.get_json()  # <-- read JSON
        email = data.get("email")
        link_status = data.get("link_status", "Welcome!")

        if not email:
            return jsonify({"error": "Email is required."}), 400

        # --- 1. Send welcome email to user ---
        welcome_subject = "Welcome to EZM Cyber!"
        welcome_content = f"""
            <h2>Welcome 👋</h2>
            <p>Thank you for signing up at <b>EZM Cyber</b>! Your status: {link_status}</p>
        """
        send_email(email, welcome_subject, welcome_content)

        # --- 2. Send notification to admin ---
        notify_subject = "New Signup Alert!"
        notify_content = f"""
            <p>New user signed up:</p>
            <ul>
                <li>Email: {email}</li>
                <li>Status: {link_status}</li>
            </ul>
        """
        send_email(NOTIFY_EMAIL, notify_subject, notify_content)

        return jsonify({"status": "sent", "message": "Emails sent successfully!"})

    except Exception as e:
        print("Error:", e)
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)