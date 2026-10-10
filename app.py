# app.py
import os
import re
import base64
import sqlite3
import logging
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
DB_NAME = "security.db"

logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

# Create a 32-byte key once and store it securely as an
# environment variable. Never upload the key to GitHub.
key_text = os.environ.get("AES_SECRET_KEY")

if not key_text:
    raise RuntimeError("Set the AES_SECRET_KEY environment variable.")

try:
    AES_KEY = base64.b64decode(key_text, validate=True)
except Exception as exc:
    raise RuntimeError("AES_SECRET_KEY must be valid Base64.") from exc

if len(AES_KEY) != 32:
    raise RuntimeError("AES_SECRET_KEY must decode to 32 bytes.")

cipher = AESGCM(AES_KEY)

# Detection is only a warning signal, not proof of an attack.
SQL_PATTERNS = [
    r"\bUNION\s+SELECT\b",
    r"\bOR\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
    r"--",
    r"/\*",
    r"\bSLEEP\s*\(",
    r"\bDROP\s+TABLE\b",
    r"\bINSERT\s+INTO\b",
    r"\bUPDATE\s+\w+\s+SET\b"
]


def detect_sql_injection(value):
    """Return True if input resembles a known SQL attack pattern."""
    if not isinstance(value, str):
        return False

    return any(
        re.search(pattern, value, re.IGNORECASE)
        for pattern in SQL_PATTERNS
    )


def log_event(event, username, suspicious=False):
    # Avoid logging passwords or complete user-submitted payloads.
    safe_user = re.sub(r"[^a-zA-Z0-9_.@-]", "_", str(username))[:80]
    logging.info(
        "event=%s user=%s suspicious=%s",
        event, safe_user, suspicious
    )


def get_db():
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                secret_data TEXT NOT NULL
            )
        """)


def encrypt_data(plain_text):
    nonce = os.urandom(12)
    encrypted = cipher.encrypt(nonce, plain_text.encode("utf-8"), None)
    return base64.b64encode(nonce + encrypted).decode("utf-8")


def decrypt_data(encrypted_text):
    raw = base64.b64decode(encrypted_text, validate=True)
    nonce, encrypted = raw[:12], raw[12:]
    return cipher.decrypt(nonce, encrypted, None).decode("utf-8")


@app.route("/")
def home():
    return jsonify({
        "project": "SQL Injection Leak Detection System",
        "status": "running",
        "endpoints": {
            "register": "POST /register",
            "login": "POST /login",
            "health": "GET /health"
        }
    })


@app.route("/health")
def health():
    return jsonify({"status": "healthy"})


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    secret = data.get("secret_data", "")

    if not all(isinstance(x, str) for x in [username, password, secret]):
        return jsonify({"error": "All fields must be text."}), 400

    if not username.strip() or len(username) > 80:
        return jsonify({"error": "Username is required (max 80 characters)."}), 400

    if len(password) < 8 or len(password) > 128:
        return jsonify({"error": "Password must be 8-128 characters."}), 400

    if len(secret) > 2000:
        return jsonify({"error": "Secret data is too long."}), 400

    suspicious = detect_sql_injection(username) or detect_sql_injection(secret)
    if suspicious:
        log_event("suspicious_registration_input", username, True)

    try:
        with get_db() as db:
            # Parameterized query prevents input being treated as SQL.
            db.execute(
                """INSERT INTO users (username, password_hash, secret_data)
                   VALUES (?, ?, ?)""",
                (
                    username.strip(),
                    generate_password_hash(password),
                    encrypt_data(secret)
                )
            )
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists."}), 409

    log_event("registration", username, suspicious)
    return jsonify({
        "message": "User registered securely.",
        "suspicious_input_detected": suspicious
    }), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "Username and password must be text."}), 400

    suspicious = detect_sql_injection(username)
    if suspicious:
        log_event("possible_sql_injection_login", username, True)

    with get_db() as db:
        # Do not build SQL queries by concatenating user input.
        user = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if user and check_password_hash(user["password_hash"], password):
        log_event("login_success", username, suspicious)
        return jsonify({
            "message": "Login successful.",
            "suspicious_input_detected": suspicious
        })

    log_event("login_failed", username, suspicious)
    return jsonify({
        "error": "Invalid username or password.",
        "suspicious_input_detected": suspicious
    }), 401


@app.route("/my-secret/<username>", methods=["GET"])
def get_secret(username):
    # Demo endpoint: a real application must enforce authentication
    # and authorization before returning private data.
    with get_db() as db:
        user = db.execute(
            "SELECT secret_data FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if not user:
        return jsonify({"error": "User not found."}), 404

    try:
        secret = decrypt_data(user["secret_data"])
    except Exception:
        return jsonify({"error": "Unable to decrypt data."}), 500

    return jsonify({"secret_data": secret})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
