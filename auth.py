"""
GREEN GRID - Authentication Module
Provides password policy enforcement, JWT token generation/validation,
@login_required route decorator, input validation, and in-memory rate limiting.
"""

import os
import re
import time
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify, g
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    JWT_SECRET = secrets.token_hex(32)
    print("[AUTH NOTE] JWT_SECRET environment variable is missing. Generated a temporary in-memory key for this session.")

JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", 2))

# In-memory rate limiting for login attempts
# Tracks failed attempts: { email_lower: [timestamp1, timestamp2, ...] }
FAILED_LOGIN_ATTEMPTS = {}
RATE_LIMIT_WINDOW_SECONDS = 300  # 5 minutes
MAX_FAILED_ATTEMPTS = 5

# Common password blocklist (case-insensitive)
COMMON_PASSWORDS = {
    "password123",
    "password@123",
    "12345678",
    "qwerty123",
    "admin@123",
    "password",
    "admin123",
    "123456789",
    "welcome123",
    "pass@123",
    "p@ssword",
    "iloveyou",
}


def password_problems(password: str) -> list[str]:
    """
    Evaluates password against the strict GREEN GRID password policy.
    Returns a list of human-readable problem descriptions.
    A valid password returns an empty list.

    Policy:
    - 8 to 64 characters
    - At least one UPPERCASE letter (A-Z)
    - At least one lowercase letter (a-z)
    - At least one number (0-9)
    - At least one special character (! @ # $ % ^ & * etc.)
    - No spaces
    - Not a common password
    """
    problems = []

    if not isinstance(password, str):
        return ["Password must be a text string."]

    # Rule 1: Length between 8 and 64 characters
    if len(password) < 8:
        problems.append("Must be at least 8 characters long.")
    elif len(password) > 64:
        problems.append("Must be no more than 64 characters long.")

    # Rule 2: At least one uppercase letter (A-Z)
    if not re.search(r"[A-Z]", password):
        problems.append("Must contain at least one uppercase letter (A-Z).")

    # Rule 3: At least one lowercase letter (a-z)
    if not re.search(r"[a-z]", password):
        problems.append("Must contain at least one lowercase letter (a-z).")

    # Rule 4: At least one number (0-9)
    if not re.search(r"\d", password):
        problems.append("Must contain at least one number (0-9).")

    # Rule 5: At least one special character
    if not re.search(r"""[!@#$%^&*(),.?":{}|<>_~`+=\-\[\]\\/']""", password):
        problems.append("Must contain at least one special character (!@#$%^&* etc.).")

    # Rule 6: No spaces
    if re.search(r"\s", password):
        problems.append("Must not contain spaces.")

    # Rule 7: Not a common password (case-insensitive check)
    if password.strip().lower() in COMMON_PASSWORDS:
        problems.append("Must not be a common or easily guessable password.")

    return problems


def check_rate_limit(email: str) -> bool:
    """
    Returns True if the email is within allowed limits, False if rate limited.
    Allows up to 5 failed attempts per 5 minutes; 6th attempt is blocked.
    """
    key = email.strip().lower()
    now = time.time()

    if key in FAILED_LOGIN_ATTEMPTS:
        FAILED_LOGIN_ATTEMPTS[key] = [
            ts for ts in FAILED_LOGIN_ATTEMPTS[key]
            if now - ts < RATE_LIMIT_WINDOW_SECONDS
        ]
        if len(FAILED_LOGIN_ATTEMPTS[key]) >= MAX_FAILED_ATTEMPTS:
            return False
    return True


def record_failed_attempt(email: str):
    """
    Records a failed login attempt for the given email.
    """
    key = email.strip().lower()
    now = time.time()
    if key not in FAILED_LOGIN_ATTEMPTS:
        FAILED_LOGIN_ATTEMPTS[key] = []
    FAILED_LOGIN_ATTEMPTS[key].append(now)


def clear_failed_attempts(email: str):
    """
    Clears failed login attempts upon successful login.
    """
    key = email.strip().lower()
    FAILED_LOGIN_ATTEMPTS.pop(key, None)


def validate_email_format(email: str) -> bool:
    """
    Validates standard email regex syntax.
    """
    if not email or not isinstance(email, str):
        return False
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(email_regex, email.strip()))


def create_jwt_token(user_id: int, email: str, name: str, role: str) -> str:
    """
    Encodes a signed HS256 JWT token with standard claims and 2-hour expiration.
    """
    payload = {
        "user_id": user_id,
        "email": email.strip().lower(),
        "name": name,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_jwt_token(token: str) -> dict:
    """
    Decodes and verifies a JWT token.
    Raises jwt.ExpiredSignatureError or jwt.InvalidTokenError on failure.
    """
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])


def login_required(f):
    """
    Decorator to protect routes requiring authentication.
    Reads 'Authorization: Bearer <token>' header.
    Returns 401 status code with descriptive message on failure.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({
                "status": "error",
                "message": "Authorization header is missing. Please log in."
            }), 401

        parts = auth_header.split(" ")
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({
                "status": "error",
                "message": "Authorization format must be 'Bearer <token>'."
            }), 401

        token = parts[1]
        try:
            payload = decode_jwt_token(token)
            g.current_user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": "error",
                "message": "Session expired. Please log in again."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "status": "error",
                "message": "Invalid authentication token. Please log in."
            }), 401

        return f(*args, **kwargs)

    return decorated_function
