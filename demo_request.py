import os
import time
import requests
import logging
from typing import Optional
from demo_request import DemoRequest
from requests import RequestException

LOG = logging.getLogger(__name__)
MAX_CONTENT_LEN = 1800
RETRIES = 3
BACKOFF = 0.5
TIMEOUT = 8

def _safe_text(s: Optional[str], max_len: int = 400) -> str:
    if not s:
        return ""
    s = s.strip()
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s

def send_webhook_alert(req: DemoRequest) -> bool:
    url = os.getenv("DISCORD_WEBHOOK_URL") or os.getenv("SLACK_WEBHOOK_URL")
    if not url:
        LOG.warning("No webhook URL configured")
        return False

    name = _safe_text(req.name, 60) or "—"
    email = _safe_text(req.email, 120) or "—"
    message = _safe_text(req.message, 800) or "—"

    content = f"**New Demo Request**\n**Name:** {name}\n**Email:** {email}\n**Message:** {message}"
    if len(content) > MAX_CONTENT_LEN:
        content = content[:MAX_CONTENT_LEN - 3] + "..."

    payload = {"content": content}
    headers = {"Content-Type": "application/json"}

    for attempt in range(1, RETRIES + 1):
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=TIMEOUT)
            if 200 <= r.status_code < 300:
                return True
            if r.status_code == 429:
                retry_after = r.headers.get("Retry-After")
                wait = float(retry_after) if retry_after and retry_after.isdigit() else BACKOFF * attempt
                LOG.warning("Rate limited; sleeping %s seconds", wait)
                time.sleep(wait)
                continue
            LOG.warning("Webhook returned %s: %s", r.status_code, r.text[:1000])
        except RequestException:
            LOG.exception("Webhook request failed (attempt %s)", attempt)

        time.sleep(BACKOFF * attempt)

    LOG.error("Webhook alert failed after %s attempts for demo request id=%s email=%s", RETRIES, getattr(req, "id", None), email)
    return False
