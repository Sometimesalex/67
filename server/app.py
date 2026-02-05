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

from flask import Flask, request, jsonify, redirect, send_from_directory

# -------------------------------------------------
# Configuration (override with environment variables)
# -------------------------------------------------

APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://127.0.0.1:5000")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "dev-admin-key")

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(HERE, ".."))
DB_PATH = os.environ.get("DB_PATH", os.path.join(HERE, "requests.db"))

app = Flask(__name__)

# -------------------------------------------------
# Database
# -------------------------------------------------

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
        status TEXT NOT NULL,
        audio_url TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS verify_tokens (
        token TEXT PRIMARY KEY,
        email_hash TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        expires_utc TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
    )
    """)

    conn.commit()
    conn.close()

init_db()

# -------------------------------------------------
# Helpers
# -------------------------------------------------

def now_utc():
    return datetime.now(timezone.utc)

def iso(dt):
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()

def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()

def email_hash(email):
    return sha256_hex(email.strip().lower())

def anon_id_from_hash(ehash):
    digest = hmac.new(SECRET_KEY.encode(), ehash.encode(), hashlib.sha256).digest()
    hx = digest[:4].hex().upper()
    return f"{hx[:4]}-{hx[4:]}"

def sign_token(payload):
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(SECRET_KEY.encode(), raw, hashlib.sha256).digest()
    return (
        base64.urlsafe_b64encode(raw).decode().rstrip("=")
        + "."
        + base64.urlsafe_b64encode(sig).decode().rstrip("=")
    )

def verify_token(token):
    try:
        raw_b64, sig_b64 = token.split(".", 1)
        raw = base64.urlsafe_b64decode(raw_b64 + "==")
        sig = base64.urlsafe_b64decode(sig_b64 + "==")
        exp = hmac.new(SECRET_KEY.encode(), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, exp):
            return None
        return json.loads(raw.decode())
    except Exception:
        return None

def send_verification_email(to_email, verify_url):
    if not SMTP_HOST:
        raise RuntimeError("SMTP not configured")

    msg = EmailMessage()
    msg["Subject"] = "Project 67 — verify your request"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(
        "Please confirm your Project 67 request by opening this link:\n\n"
        f"{verify_url}\n\n"
        "If you did not request this, you may ignore this email.\n"
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls()
        if SMTP_USER:
            s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)

# -------------------------------------------------
# Static file serving (project root)
# -------------------------------------------------

@app.route("/")
def root():
    return send_from_directory(PROJECT_ROOT, "index.html")

@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(PROJECT_ROOT, filename)

# -------------------------------------------------
# API
# -------------------------------------------------

@app.post("/api/request")
def api_request():
    data = request.get_json(force=True, silent=True) or {}

    email = (data.get("email") or "").strip()
    lang = (data.get("lang") or "").strip()
    country = (data.get("country") or "").strip()
    heritage = (data.get("heritage") or "").strip()

    if not email or "@" not in email:
        return jsonify(ok=False, error="Valid email required"), 400

    ehash = email_hash(email)

    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM requests WHERE email_hash=?", (ehash,))
    if cur.fetchone():
        conn.close()
        return jsonify(ok=False, error="Request already exists for this email"), 409

    payload = {
        "email_hash": ehash,
        "lang": lang[:64],
        "country": country[:64],
        "heritage": heritage[:500],
        "exp": int((now_utc() + timedelta(hours=24)).timestamp()),
        "nonce": secrets.token_urlsafe(8)
    }

    token = sign_token(payload)
    expires = iso(now_utc() + timedelta(hours=24))

    cur.execute(
        "INSERT OR REPLACE INTO verify_tokens(token,email_hash,payload_json,expires_utc,used) VALUES(?,?,?,?,0)",
        (token, ehash, json.dumps(payload), expires)
    )

    conn.commit()
    conn.close()

    verify_url = f"{APP_BASE_URL}/verify?token={token}"

    try:
        send_verification_email(email, verify_url)
        return jsonify(ok=True, message="Verification email sent")
    except Exception as e:
        return jsonify(ok=False, error=str(e), verify_url_for_testing=verify_url), 503

@app.get("/verify")
def verify():
    token = request.args.get("token", "")
    payload = verify_token(token)
    if not payload:
        return "Invalid link", 400

    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT used,expires_utc FROM verify_tokens WHERE token=?", (token,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return "Token not found", 400

    if row["used"]:
        conn.close()
        return redirect("/whoareyou.html#already")

    if now_utc() > datetime.fromisoformat(row["expires_utc"]):
        conn.close()
        return "Token expired", 400

    ehash = payload["email_hash"]
    anon = anon_id_from_hash(ehash)

    cur.execute("SELECT id FROM requests WHERE email_hash=?", (ehash,))
    if not cur.fetchone():
        cur.execute("""
        INSERT INTO requests(id,email_hash,lang,country,heritage,created_utc,status,audio_url)
        VALUES(?,?,?,?,?,?,?,?)
        """, (
            anon,
            ehash,
            payload.get("lang",""),
            payload.get("country",""),
            payload.get("heritage",""),
            iso(now_utc()),
            "pending",
            None
        ))

    cur.execute("UPDATE verify_tokens SET used=1 WHERE token=?", (token,))
    conn.commit()
    conn.close()

    return redirect("/whoareyou.html#verified")

@app.get("/api/requests")
def api_requests():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
      SELECT id,lang,country,status,audio_url,created_utc
      FROM requests
      ORDER BY created_utc DESC
      LIMIT 200
    """)
    rows = [
        dict(r) for r in cur.fetchall()
    ]
    conn.close()
    return jsonify(ok=True, items=rows)

@app.post("/api/admin/attach_audio")
def attach_audio():
    if request.headers.get("x-admin-key") != ADMIN_KEY:
        return jsonify(ok=False, error="Unauthorized"), 401

    data = request.get_json(force=True, silent=True) or {}
    rid = (data.get("id") or "").upper()
    url = (data.get("audio_url") or "")

    if not rid or not url.startswith("http"):
        return jsonify(ok=False, error="id + audio_url required"), 400

    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE requests SET status='ready', audio_url=? WHERE id=?", (url, rid))
    conn.commit()
    conn.close()

    return jsonify(ok=True)

# -------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
