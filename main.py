# main.py
import os
import base64
import asyncio
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

VT_API = os.getenv("VIRUSTOTAL_API_KEY")
if not VT_API:
    raise RuntimeError("Set VIRUSTOTAL_API_KEY environment variable")

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change to your domain in production
    allow_methods=["*"],
    allow_headers=["*"],
)

HEADERS = {"x-apikey": VT_API}
VT_BASE = "https://www.virustotal.com/api/v3"

def normalize_url(u: str) -> str:
    u = u.strip()
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    return u

def url_id_from_url(u: str) -> str:
    # unpadded urlsafe base64 per VT docs
    return base64.urlsafe_b64encode(u.encode()).decode().strip("=")

async def do_vt_check(url: str) -> dict:
    url = normalize_url(url)
    url_id = url_id_from_url(url)

    async with httpx.AsyncClient(timeout=15.0) as client:
        # 1) try cached report -> GET /urls/{id}
        r = await client.get(f"{VT_BASE}/urls/{url_id}", headers=HEADERS)
        if r.status_code == 200:
            return {"source": "cached_url_report", "vt": r.json()}

        # 2) submit for analysis -> POST /urls (returns analysis id)
        r = await client.post(f"{VT_BASE}/urls", headers=HEADERS, data={"url": url})
        if r.status_code in (200, 201):
            analysis_id = r.json()["data"]["id"]
            # poll analyses endpoint for completion (GET /analyses/{id})
            for _ in range(6):  # ~6s total (adjust if you want)
                await asyncio.sleep(1)
                a = await client.get(f"{VT_BASE}/analyses/{analysis_id}", headers=HEADERS)
                if a.status_code == 200:
                    j = a.json()
                    status = j.get("data", {}).get("attributes", {}).get("status")
                    if status == "completed":
                        return {"source": "analysis_complete", "analysis": j}
            # not finished yet
            return {"source": "analysis_pending", "analysis_id": analysis_id}
        elif r.status_code == 429:
            raise HTTPException(status_code=429, detail="VirusTotal rate limit")
        else:
            raise HTTPException(status_code=502, detail=f"VirusTotal error {r.status_code}")

@app.post("/check")
async def check_post(req: Request):
    body = await req.json()
    url = body.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="Missing 'url' in JSON body")
    return await do_vt_check(url)

@app.get("/check")
async def check_get(url: Optional[str] = None):
    if not url:
        raise HTTPException(status_code=400, detail="Missing 'url' query param")
    return await do_vt_check(url)