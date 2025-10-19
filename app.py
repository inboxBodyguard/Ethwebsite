from flask import Flask, request, jsonify
from flask_cors import CORS
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# CORS - Allow your website specifically
CORS(app, resources={
    r"/*": {
        "origins": [
            "https://www.ezmcyber.xyz",
            "https://ezmcyber.xyz",
            "http://localhost:5000",  # for testing
            "http://127.0.0.1:5000"   # for testing
        ],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

# --- Environment Variables ---
SENDER_EMAIL = os.getenv("contact@ezmcyber.xyz")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
NOTIFY_EMAIL = os.getenv("contact@ezmcyber.xyz")

# Log startup config (without passwords)
logger.info(f"Starting app with SENDER_EMAIL: {SENDER_EMAIL}")
logger.info(f"NOTIFY_EMAIL: {NOTIFY_EMAIL}")

def send_email(to_email, subject, html_content):
    """Send email via Office365 SMTP"""
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
        with smtplib.SMTP("smtp.office365.com", 587, timeout=10) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        logger.info(f"Email sent successfully to {to_email}")
        return True, None
    except Exception as e:
        logger.error(f"Email send failed: {str(e)}")
        return False, str(e)

@app.route("/", methods=["GET"])
def health_check():
    """Health check endpoint for Render"""
    return jsonify({
        "status": "healthy",
        "service": "EZM Cyber Signup Service",
        "version": "1.0"
    }), 200

@app.route("/send-report", methods=["POST", "OPTIONS"])
def send_report():
    """Handle signup form submissions"""
    
    # Handle preflight OPTIONS request
    if request.method == "OPTIONS":
        return "", 200
    
    # Log incoming request
    logger.info(f"Received request: {request.method} from {request.remote_addr}")
    logger.info(f"Headers: {dict(request.headers)}")
    
    try:
        data = request.get_json()
        logger.info(f"Request data: {data}")
    except Exception as e:
        logger.error(f"Failed to parse JSON: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Invalid JSON data"
        }), 400
    
    # Validate data
    if not data:
        logger.warning("No data received")
        return jsonify({
            "status": "error",
            "message": "No data provided"
        }), 400
    
    if "email" not in data:
        logger.warning("Email missing from request")
        return jsonify({
            "status": "error",
            "message": "Email is required"
        }), 400

    email = data["email"]
    link_status = data.get("link_status", "Welcome!")
    
    logger.info(f"Processing signup for: {email}")

    # Send welcome email to user
    user_subject = "Welcome to EZM Cyber!"
    user_html = f"""
    <html>
        <body>
            <h2>Welcome to EZM Cyber! 👋</h2>
            <p>Thank you for signing up at <strong>EZM Cyber</strong>!</p>
            <p>Status: {link_status}</p>
            <p>We'll keep you updated on our threat intelligence platform.</p>
            <br>
            <p>Best regards,<br>The EZM Cyber Team</p>
        </body>
    </html>
    """
    
    sent, error = send_email(email, user_subject, user_html)
    if not sent:
        logger.error(f"Failed to send user email: {error}")
        return jsonify({
            "status": "error",
            "message": f"Failed to send welcome email: {error}"
        }), 500

    # Send notification to admin
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
        
        sent, error = send_email(NOTIFY_EMAIL, admin_subject, admin_html)
        if not sent:
            logger.warning(f"Failed to notify admin: {error}")
            # Don't fail the whole request if admin notification fails

    return jsonify({
        "status": "sent",
        "message": "Welcome email sent successfully!"
    }), 200

@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "status": "error",
        "message": "Endpoint not found"
    }), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Internal server error: {str(e)}")
    return jsonify({
        "status": "error",
        "message": "Internal server error"
    }), 500

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)