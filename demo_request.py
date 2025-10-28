import requests
import smtplib
from email.message import EmailMessage
import os
from demo_request import DemoRequest  # your existing model

def send_alert_email(req: DemoRequest):
    # --- Email Alert ---
    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")
    ALERT_TO = os.getenv("ALERT_TO")  # your team email

    if SMTP_HOST and SMTP_USER and SMTP_PASS and ALERT_TO:
        try:
            msg = EmailMessage()
            msg["Subject"] = f"Demo request from {req.email}"
            msg["From"] = SMTP_USER
            msg["To"] = ALERT_TO
            body = f"Name: {req.name}\nEmail: {req.email}\nMessage: {req.message}\nTime: {req.created_at}"
            msg.set_content(body)

            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.starttls()
                s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        except Exception as e:
            print("Email alert failed:", e)

    # --- Discord/Slack Webhook Alert ---
    WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")  # or SLACK_WEBHOOK_URL
    if WEBHOOK_URL:
        try:
            requests.post(WEBHOOK_URL, json={
                "content": f"🧠 New Demo Request!\n👤 Name: {req.name}\n📧 Email: {req.email}\n💬 Message: {req.message}"
            })
        except Exception as e:
            print("Webhook alert failed:", e)