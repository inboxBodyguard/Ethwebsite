# save this as app.py
from flask import Flask, request, jsonify
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

app = Flask(__name__)

# Set your SendGrid API key as an environment variable: SENDGRID_API_KEY
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
NOTIFY_EMAIL = 'your-notify-email@example.com'  # email you want notifications sent to
FROM_EMAIL = 'no-reply@yourdomain.com'  # verified sender in SendGrid

def send_email(to_email, subject, content):
    message = Mail(
        from_email=FROM_EMAIL,
        to_emails=to_email,
        subject=subject,
        html_content=content
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        return response.status_code
    except Exception as e:
        print(f"Send email error: {e}")
        return None

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.form  # works with FormData from your HTML
    email = data.get('email')
    password = data.get('password')  # handle securely if storing
    if not email or not password:
        return jsonify({'error': 'Email and password are required.'}), 400

    # --- 1. Send welcome email to user ---
    welcome_subject = "Welcome to EZM Cyber!"
    welcome_content = f"""
        <h2>Welcome,</h2>
        <p>Thank you for signing up at EZM Cyber. Your digital security journey starts here!</p>
    """
    send_email(email, welcome_subject, welcome_content)

    # --- 2. Send notification email to yourself ---
    notify_subject = "New Signup Alert!"
    notify_content = f"""
        <p>New user signed up:</p>
        <ul>
            <li>Email: {email}</li>
            <li>Password: {password}</li> <!-- remove if storing securely -->
        </ul>
    """
    send_email(NOTIFY_EMAIL, notify_subject, notify_content)

    return jsonify({'success': True, 'message': 'Signup successful, emails sent!'})

if __name__ == '__main__':
    app.run(debug=True)