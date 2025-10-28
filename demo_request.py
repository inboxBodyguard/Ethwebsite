from flask import Blueprint, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import smtplib
from email.message import EmailMessage
import os
import validators

bp = Blueprint("demo_request", __name__)
db = SQLAlchemy()

class DemoRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    email = db.Column(db.String(254), index=True)
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@bp.route("/api/demo-request", methods=["POST"])
def demo_request():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    message = (data.get("message") or "").strip()

    if not email or not validators.email(email):
        return jsonify({"ok": False, "error": "Invalid email"}), 400

    req = DemoRequest(name=name, email=email, message=message)
    db.session.add(req)
    db.session.commit()

    # Send immediate alert (email via SMTP)
    send_alert_email(req)

    return jsonify({"ok": True, "id": req.id})

def send_alert_email(req: DemoRequest):
    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")
    ALERT_TO = os.getenv("ALERT_TO")  # e.g., your team address

    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and ALERT_TO):
        return

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
