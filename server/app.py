#!/usr/bin/env python3
import os
import hmac
import json
import base64
import hashlib
import sqlite3
import smtplib
import secrets
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone

from flask import Flask, request, jsonify, redirect

# ----------------------------
# Config (set these as env vars)
# ----------------------------
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://127.0.0.1:5000")  # where /verify lives
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me")               # used to sign tokens + IDs
ADMIN_KEY = os.environ.get("ADMIN_KEY", "dev-admin-key")                # simple admin auth

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "requests.db"))

app = Flask(__name__)

# ----------------------------
# DB
# ----------------------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
      CREATE TABLE IF NOT EXISTS requests (
        id TEXT PRIMARY KEY,
        email_hash TEXT UNIQUE NOT NULL,
        lang TEXT,
        country TEXT,
        heritage TEXT,
        created_utc TEXT NOT NULL,
        status TEXT NOT NULL, -- pending|ready
        audio_url TEXT
      );
    """)
    cur.execute("""
      CREATE TABLE IF NOT EXISTS verify_tokens (
        token TEXT PRIMARY KEY,
        email_hash TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        expires_utc TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
      );
    """)
    conn.commit()
    conn.close()

init_db()

# ----------------------------
# Helpers
# ----------------------------
def now_utc():
    return datetime.now(timezone.utc)

def iso(dt: datetime):
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def email_hash(email: str) -> str:
    # Never store raw email. Hash normalized email.
    return sha256_hex(email.strip().lower())

def hmac_short_id(email_hash_hex: str) -> str:
    # Deterministic, not reversible, looks like A7F3-19C2
    digest = hmac.new(SECRET_KEY.encode("utf-8"), email_hash_hex.encode("utf-8"), hashlib.sha256).digest()
    # Take first 4 bytes -> 8 hex chars; format XXXX-XXXX
    hx = digest[:4].hex().upper()
    return f"{hx[:4]}-{hx[4:]}"

def sign_token(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), raw, hashlib.sha256).digest()
    blob = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=") + "." + base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
    return blob

def verify_token(token: str) -> dict | None:
    try:
        raw_b64, sig_b64 = token.split(".", 1)
        # restore padding
        raw = base64.urlsafe_b64decode(raw_b64 + "==")
        sig = base64.urlsafe_b64decode(sig_b64 + "==")
        expected = hmac.new(SECRET_KEY.encode("utf-8"), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None

def send_verification_email(to_email: str, verify_url: str):
    if not SMTP_HOST:
        # Email not configured: raise to tell caller.
        raise RuntimeError("SMTP not configured")

    msg = EmailMessage()
    msg["Subject"] = "Project 67 — verify your request"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(
        "Confirm your request by opening this link:\n\n"
        f"{verify_url}\n\n"
        "If you did not request this, ignore this email.\n"
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls()
        if SMTP_USER:
            s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)

# ----------------------------
# API
# ----------------------------
@app.post("/api/request")
def api_request():
    data = request.get_json(force=True, silent=True) or {}

    email = (data.get("email") or "").strip()
    lang = (data.get("lang") or "").strip()
    country = (data.get("country") or "").strip()
    heritage = (data.get("heritage") or "").strip()

    if not email or "@" not in email:
        return jsonify({"ok": False, "error": "Please enter a valid email."}), 400

    ehash = email_hash(email)

    # Enforce no repeats: if request already exists, do not allow another
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, status FROM requests WHERE email_hash = ?", (ehash,))
    row = cur.fetchone()
    if row:
        conn.close()
        return jsonify({
            "ok": False,
            "error": "A request already exists for this email. Please use your existing ID on the page."
        }), 409

    # Create a one-time verification token entry (expires in 24h)
    payload = {
        "email_hash": ehash,
        "lang": lang[:64],
        "country": country[:64],
        "heritage": heritage[:500],
        "exp": int((now_utc() + timedelta(hours=24)).timestamp()),
        "nonce": secrets.token_urlsafe(12),
    }
    token = sign_token(payload)
    expires = iso(now_utc() + timedelta(hours=24))

    cur.execute(
        "INSERT OR REPLACE INTO verify_tokens(token, email_hash, payload_json, expires_utc, used) VALUES (?,?,?,?,0)",
        (token, ehash, json.dumps(payload, separators=(",", ":")), expires)
    )
    conn.commit()
    conn.close()

    verify_url = f"{APP_BASE_URL}/verify?token={token}"

    try:
        send_verification_email(email, verify_url)
    except Exception as ex:
        # If you haven't configured SMTP yet, this tells you.
        return jsonify({
            "ok": False,
            "error": "Email verification is not available yet (SMTP not configured).",
            "detail": str(ex),
            "verify_url_for_testing": verify_url
        }), 503

    return jsonify({"ok": True, "message": "Verification email sent. Please check your inbox."})

@app.get("/verify")
def verify():
    token = request.args.get("token", "")
    payload = verify_token(token)
    if not payload:
        return "Invalid verification link.", 400

    # Check token record + expiry + unused
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT token, expires_utc, used, payload_json FROM verify_tokens WHERE token = ?", (token,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return "Verification link not found.", 400
    if int(row["used"]) == 1:
        conn.close()
        return "This verification link has already been used.", 400

    expires_dt = datetime.fromisoformat(row["expires_utc"])
    if now_utc() > expires_dt:
        conn.close()
        return "Verification link expired. Please submit again.", 400

    # Create request entry (unique by email_hash)
    ehash = payload["email_hash"]
    req_id = hmac_short_id(ehash)

    # Double-check no existing request (race condition safe)
    cur.execute("SELECT id FROM requests WHERE email_hash = ?", (ehash,))
    if cur.fetchone():
        # mark token used anyway
        cur.execute("UPDATE verify_tokens SET used = 1 WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        return redirect("/whoareyou.html#already")

    cur.execute("""
      INSERT INTO requests(id, email_hash, lang, country, heritage, created_utc, status, audio_url)
      VALUES (?,?,?,?,?,?,?,?)
    """, (
        req_id,
        ehash,
        payload.get("lang", ""),
        payload.get("country", ""),
        payload.get("heritage", ""),
        iso(now_utc()),
        "pending",
        None
    ))

    cur.execute("UPDATE verify_tokens SET used = 1 WHERE token = ?", (token,))
    conn.commit()
    conn.close()

    # Redirect user back to the page. You can change this path as needed.
    return redirect("/whoareyou.html#verified")

@app.get("/api/requests")
def api_requests():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
      SELECT id, lang, country, status, audio_url, created_utc
      FROM requests
      ORDER BY created_utc DESC
      LIMIT 200
    """)
    items = []
    for r in cur.fetchall():
        items.append({
            "id": r["id"],
            "lang": r["lang"] or "",
            "country": r["country"] or "",
            "status": r["status"],
            "audio_url": r["audio_url"],
            "created_utc": r["created_utc"],
        })
    conn.close()
    return jsonify({"ok": True, "items": items})

@app.post("/api/admin/attach_audio")
def admin_attach_audio():
    # Simple admin key header. Replace later with real auth when funded.
    key = request.headers.get("x-admin-key", "")
    if not key or not hmac.compare_digest(key, ADMIN_KEY):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(force=True, silent=True) or {}
    req_id = (data.get("id") or "").strip().upper()
    audio_url = (data.get("audio_url") or "").strip()

    if not req_id or not audio_url.startswith("http"):
        return jsonify({"ok": False, "error": "Provide id and a valid audio_url"}), 400

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM requests WHERE id = ?", (req_id,))
    if not cur.fetchone():
        conn.close()
        return jsonify({"ok": False, "error": "ID not found"}), 404

    cur.execute("UPDATE requests SET status = 'ready', audio_url = ? WHERE id = ?", (audio_url, req_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

if __name__ == "__main__":
    # Run: python app.py
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
