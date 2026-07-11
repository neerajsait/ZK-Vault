import os
import re
import secrets
import base64
import json
import logging
import ipaddress
from datetime import datetime, timedelta
import hmac
import hashlib

from flask import (
    Flask, render_template, request, session, redirect, url_for,
    flash, abort, g, jsonify
)
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_talisman import Talisman
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from sqlalchemy import (
    create_engine, Column, String, Integer, DateTime, Text,
    Boolean, ForeignKey, func, text
)
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy.orm import sessionmaker, scoped_session, relationship, DeclarativeBase
import uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
import requests
import redis
from redis.exceptions import RedisError

load_dotenv()

# ----------------------------------------------------------------------
# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('app.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Flask app setup
app = Flask(__name__)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

if not os.getenv('SECRET_KEY'):
    raise RuntimeError("SECRET_KEY environment variable must be set")
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Server-side HMAC key used to key the verifier hash (adds server secret to
# the Argon2id hash so a stolen DB alone can't run offline verifier attacks).
# Optional but recommended. If not set, plain Argon2id is used.
_VERIFIER_HMAC_KEY_B64 = os.getenv('VERIFIER_HMAC_KEY')
VERIFIER_HMAC_KEY: bytes | None = (
    base64.b64decode(_VERIFIER_HMAC_KEY_B64) if _VERIFIER_HMAC_KEY_B64 else None
)

app.config['WTF_CSRF_SECRET_KEY'] = os.getenv('WTF_CSRF_SECRET_KEY', secrets.token_hex(32))
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.config['SESSION_SERIALIZATION_FORMAT'] = 'json'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['TEMPLATES_AUTO_RELOAD'] = app.debug

app.config['MAX_RECORDS_PER_USER'] = int(os.getenv('MAX_RECORDS_PER_USER', 1000))
app.config['MAX_STORAGE_PER_USER_MB'] = int(os.getenv('MAX_STORAGE_PER_USER_MB', 100))

# The password-change endpoint requires submitting all user records at once.
# To prevent HTTP 413 Payload Too Large when a user is near their storage quota,
# MAX_CONTENT_LENGTH must be larger than MAX_STORAGE_PER_USER_MB with some headroom
# (e.g., to accommodate JSON structure overhead and extra fields).
app.config['MAX_CONTENT_LENGTH'] = (app.config['MAX_STORAGE_PER_USER_MB'] + 50) * 1024 * 1024

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.from_url(
    os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
    decode_responses=True,
    protocol=2
)
app.config['SESSION_KEY_PREFIX'] = 'session:'
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True if not app.debug else False
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
_force_https = os.getenv('FORCE_HTTPS', 'false').lower() in ('true', '1', 'yes')
if _force_https:
    app.config['SESSION_COOKIE_NAME'] = '__Host-zkv_sess'
else:
    app.config['SESSION_COOKIE_NAME'] = 'zkv_sess'
app.config['SESSION_COOKIE_PATH'] = '/'

Session(app)

csrf = CSRFProtect(app)

@app.context_processor
def inject_nonce():
    return {'csp_nonce': g.get('csp_nonce', '')}

@app.before_request
def set_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)

# NOTE: wasm-unsafe-eval is required for Argon2 WASM (hash-wasm / argon2-browser).
# This only permits WebAssembly instantiation, not JS eval.
# CSP is applied dynamically via add_csp_headers() to include per-request nonces.
# Talisman's content_security_policy is set to False so it doesn't emit its own
# (nonce-less) CSP header that would conflict.
_force_https = os.getenv('FORCE_HTTPS', 'false').lower() in ('true', '1', 'yes')
Talisman(
    app,
    content_security_policy=False,
    force_https=_force_https,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    frame_options='DENY',
    x_content_type_options='nosniff',
    referrer_policy='strict-origin-when-cross-origin',
    permissions_policy={'geolocation': "'self'"}
)

@app.after_request
def add_csp_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Server'] = 'SecurePersonalVault'

    # If redirect or JSON, apply minimal strict CSP.
    # We must explicitly define form-action, base-uri, object-src, and frame-ancestors
    # to avoid ZAP's 'Failure to Define Directive with No Fallback' warning.
    if (300 <= response.status_code < 400) or (response.mimetype == 'application/json'):
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "object-src 'none'"
        )
        return response

    nonce = g.get('csp_nonce', '')

    # Only include 'wasm-unsafe-eval' on routes that actually derive keys via Argon2 WASM
    needs_wasm = False
    if request.path in ('/set_password', '/vault', '/change_password'):
        needs_wasm = True
    elif request.path == '/login' and request.args.get('step') == 'password':
        needs_wasm = True

    script_sources = ["'self'", f"'nonce-{nonce}'"]
    if needs_wasm:
        script_sources.append("'wasm-unsafe-eval'")

    policy = {
        'default-src': "'self'",
        'script-src': script_sources,
        'style-src': ["'self'", f"'nonce-{nonce}'"],
        'font-src': "'self'",
        'img-src': "'self' data:",
        'form-action': "'self'",
        'base-uri': "'self'",
        'object-src': "'none'",
        'frame-ancestors': "'none'",
    }
    parts = []
    for key, value in policy.items():
        parts.append(f"{key} {' '.join(value) if isinstance(value, list) else value}")
    response.headers['Content-Security-Policy'] = '; '.join(parts)
    return response

# Mail
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
mail = Mail(app)

_redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10000 per day", "1000 per hour"],
    storage_uri=_redis_url,
    storage_options={"protocol": 2},
)

redis_client = app.config['SESSION_REDIS']

# ----------------------------------------------------------------------
# Database
engine = create_engine(
    f"mysql+pymysql://{os.getenv('MYSQL_USER')}:{os.getenv('MYSQL_PASSWORD')}"
    f"@{os.getenv('MYSQL_HOST')}/{os.getenv('MYSQL_DB')}",
    pool_recycle=3600,
    pool_pre_ping=True
)
class Base(DeclarativeBase):
    pass
db_session = scoped_session(sessionmaker(bind=engine))

# ----------------------------------------------------------------------
# Email encryption (server-side; email is not user-controlled plaintext,
# so server-side encryption here is fine and unrelated to the ZK vault)
EMAIL_ENC_KEY = base64.b64decode(os.getenv('EMAIL_ENCRYPTION_KEY', ''))
EMAIL_INDEX_KEY = base64.b64decode(os.getenv('EMAIL_INDEX_KEY', ''))
if not EMAIL_ENC_KEY or not EMAIL_INDEX_KEY:
    raise RuntimeError("EMAIL_ENCRYPTION_KEY and EMAIL_INDEX_KEY must be set")

def encrypt_email(plain_email: str) -> str:
    iv = secrets.token_bytes(12)
    ct = AESGCM(EMAIL_ENC_KEY).encrypt(iv, plain_email.encode(), None)
    return base64.b64encode(iv + ct).decode('ascii')

def decrypt_email(enc_b64: str) -> str:
    try:
        raw = base64.b64decode(enc_b64)
        return AESGCM(EMAIL_ENC_KEY).decrypt(raw[:12], raw[12:], None).decode()
    except Exception as e:
        raise ValueError("Invalid encrypted email") from e

def make_email_index(email: str) -> str:
    return hmac.HMAC(EMAIL_INDEX_KEY, email.strip().lower().encode(), hashlib.sha256).hexdigest()

# ----------------------------------------------------------------------
# Argon2id parameters
#
# SERVER-SIDE (verifier hashing): cheap because the client already did the
# expensive KDF. We just need to protect the verifier at rest.
ARGON2_VERIFIER_TIME = 2
ARGON2_VERIFIER_MEMORY = 64 * 1024   # 64 MB
ARGON2_VERIFIER_PARALLEL = 2
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

# ----------------------------------------------------------------------
# SQLAlchemy Models
#
# Key changes from the old schema:
#   - encrypted_canary        -> verifier_hash        (Argon2id hash of client verifier)
#   - encrypted_secret_canary -> secret_verifier_hash (same, for secret vault)
#   - record_count / storage_bytes added for O(1) quota checks
#   - NormalRecord / SecretRecord: encrypted_payload is now the *only* source
#     of truth -- filename/mime are inside the ciphertext (full ZK choice).
#     A cleartext `size` column is kept so the server can enforce quotas
#     without decrypting.

class User(Base):
    __tablename__ = 'users'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email_index = Column(String(64), unique=True, nullable=False, index=True)
    encrypted_email = Column(Text, nullable=False)
    name = Column(String(100), nullable=False)

    # ZK auth fields
    salt = Column(String(64), nullable=False)           # base64 of 16-byte Argon2 salt
    verifier_hash = Column(Text, nullable=False)        # Argon2id(verifier_b64)

    secret_salt = Column(String(64), nullable=True)
    secret_verifier_hash = Column(Text, nullable=True)  # Argon2id(secret_verifier_b64)

    # Quota counters -- updated atomically, no decryption needed
    record_count = Column(Integer, default=0, nullable=False)
    storage_bytes = Column(Integer, default=0, nullable=False)

    # Lockout / session management
    failed_attempts = Column(Integer, default=0)
    lock_until = Column(DateTime, nullable=True)
    secret_failed_attempts = Column(Integer, default=0)
    secret_lock_until = Column(DateTime, nullable=True)
    secret_reauthentication_required = Column(Boolean, default=False)
    logout_cooldown_until = Column(DateTime, nullable=True)
    last_remote_logout = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    normal_records = relationship("NormalRecord", back_populates="user", cascade="all, delete-orphan")
    secret_records = relationship("SecretRecord", back_populates="user", cascade="all, delete-orphan")


class NormalRecord(Base):
    __tablename__ = 'normal_records'
    id = Column(String(12), primary_key=True)
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False)
    encrypted_payload = Column(LONGTEXT, nullable=False)   # AES-GCM, client-encrypted
    size = Column(Integer, nullable=False, default=0)  # ciphertext byte length, for quota
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    user = relationship("User", back_populates="normal_records")


class SecretRecord(Base):
    __tablename__ = 'secret_records'
    id = Column(String(12), primary_key=True)
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False)
    encrypted_payload = Column(LONGTEXT, nullable=False)
    size = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    user = relationship("User", back_populates="secret_records")


Base.metadata.create_all(engine)

# Migration: alter columns to LONGTEXT if they exist with an older TEXT type
with engine.connect() as connection:
    try:
        connection.execute(text("ALTER TABLE normal_records MODIFY encrypted_payload LONGTEXT"))
        connection.execute(text("ALTER TABLE secret_records MODIFY encrypted_payload LONGTEXT"))
        connection.commit()
        logger.info("Database migration: Altered record payload columns to LONGTEXT successfully.")
    except Exception as e:
        logger.warning(f"Database migration note: Alter to LONGTEXT skipped or already done: {e}")

# ----------------------------------------------------------------------
# Verifier hashing
#
# The client sends verifier_b64 = HKDF(key1, info="login-verifier").
# We hash it server-side with Argon2id so that a stolen DB can't be used
# to run offline attacks against the verifier directly.
# Argon2id parameters here are deliberately cheap (client did the real work).

def _verifier_input(verifier_b64: str) -> bytes:
    """
    Optionally HMAC the verifier with a server secret before hashing.
    This ties the hash to the server, so a stolen DB without the key is useless.
    """
    raw = base64.b64decode(verifier_b64)
    if VERIFIER_HMAC_KEY:
        return hmac.HMAC(VERIFIER_HMAC_KEY, raw, hashlib.sha256).digest()
    return raw

def hash_verifier(verifier_b64: str) -> str:
    """Return an Argon2id hash of the (optionally keyed) verifier."""
    salt = secrets.token_bytes(ARGON2_SALT_LEN)
    digest = hash_secret_raw(
        secret=_verifier_input(verifier_b64),
        salt=salt,
        time_cost=ARGON2_VERIFIER_TIME,
        memory_cost=ARGON2_VERIFIER_MEMORY,
        parallelism=ARGON2_VERIFIER_PARALLEL,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )
    # Store salt:hash, both base64-encoded, colon-separated
    return base64.b64encode(salt).decode() + ':' + base64.b64encode(digest).decode()

def check_verifier(verifier_b64: str, stored: str) -> bool:
    """Constant-time verification."""
    try:
        salt_b64, hash_b64 = stored.split(':', 1)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        actual = hash_secret_raw(
            secret=_verifier_input(verifier_b64),
            salt=salt,
            time_cost=ARGON2_VERIFIER_TIME,
            memory_cost=ARGON2_VERIFIER_MEMORY,
            parallelism=ARGON2_VERIFIER_PARALLEL,
            hash_len=ARGON2_HASH_LEN,
            type=Type.ID,
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def validate_verifier_b64(value: str, field_name: str = 'verifier') -> str:
    """
    Validate that a verifier field is plausibly a base64-encoded 32-byte value.
    Rejects obviously wrong inputs early before they hit Argon2id, preventing
    DoS via huge inputs and catching client bugs fast.
    Max length: ceil(32/3)*4 = 44 base64 chars (+ possible padding).
    We allow up to 64 to be safe with different padding/encoding variants.
    """
    if not value or not isinstance(value, str):
        raise ValueError(f"Missing {field_name}")
    if len(value) > 64:
        raise ValueError(f"{field_name} too long")
    try:
        padded_value = value + ('=' * (-len(value) % 4))
        decoded = base64.b64decode(padded_value)
        if len(decoded) < 16:
            raise ValueError(f"{field_name} too short")
    except Exception:
        raise ValueError(f"{field_name} is not valid base64")
    return value

def validate_salt_b64(value: str, field_name: str = 'salt') -> str:
    """Validate that a salt field is a base64-encoded 16-byte value."""
    if not value or not isinstance(value, str):
        raise ValueError(f"Missing {field_name}")
    if len(value) > 64:
        raise ValueError(f"{field_name} too long")
    try:
        padded_value = value + ('=' * (-len(value) % 4))
        decoded = base64.b64decode(padded_value)
        if len(decoded) != 16:
            raise ValueError(f"{field_name} must decode to exactly 16 bytes")
    except Exception:
        raise ValueError(f"{field_name} is not valid base64")
    return value

# Maximum ciphertext size for a single record (10 MB raw x base64 inflation x
# 5 files + JSON envelope). Enforced per-record to prevent a single record from
# consuming the entire quota in one request.
MAX_SINGLE_RECORD_BYTES = 70 * 1024 * 1024  # 70 MB

# ----------------------------------------------------------------------
# Helpers

def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
            logger.info(f"Email sent to {msg.recipients[0]}: {msg.subject}")
        except Exception as e:
            logger.error(f"Failed to send email to {msg.recipients[0]} -- subject: {msg.subject} -- error: {e}", exc_info=True)

def send_email(to, subject, body, sync=False) -> bool:
    try:
        msg = Message(subject, recipients=[to])
        msg.body = body
        if sync or app.testing:
            mail.send(msg)
            logger.info(f"Email sent synchronously to {to}: {subject}")
            return True
        else:
            from threading import Thread
            from flask import current_app
            ctx_app = current_app._get_current_object()
            t = Thread(target=send_async_email, args=(ctx_app, msg))
            t.daemon = True
            t.start()
            return True
    except Exception as e:
        logger.error(f"Failed to send email to {to} -- subject: {subject} -- error: {e}", exc_info=True)
        return False

def generate_record_id():
    return secrets.token_urlsafe(8)

def safe_decrypt_email(enc_b64, fallback="[redacted]"):
    try:
        return decrypt_email(enc_b64)
    except ValueError:
        return fallback

def _is_private_or_local(ip_str: str) -> bool:
    """Check if an IP address is private, loopback, or otherwise non-routable."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        return True  # unparseable → treat as local

def _validate_ip(ip_str: str) -> str | None:
    """Return the IP string only if it is a valid IP address, else None."""
    try:
        ipaddress.ip_address(ip_str)
        return ip_str
    except ValueError:
        return None

def get_ip_location(ip: str | None) -> str:
    """
    Fetches geographical location for an IP address using ip-api.com (HTTPS).
    For local development (127.0.0.1 / private IP), resolves public WAN IP
    so real location is shown during local testing.
    """
    if not ip or ip == 'localhost' or _is_private_or_local(ip):
        try:
            pub_resp = requests.get('https://api.ipify.org?format=json', timeout=2)
            if pub_resp.status_code == 200:
                ip = pub_resp.json().get('ip')
        except Exception:
            return 'Local Network / Localhost'

    # Final validation: only proceed with a legitimate IP
    ip = _validate_ip(ip) if ip else None
    if not ip:
        return 'Unknown Location'

    try:
        # ip-api.com free tier only supports HTTP; validate ip is clean before interpolating
        resp = requests.get(
            f'http://ip-api.com/json/{ip}',
            params={'fields': 'status,country,regionName,city'},
            timeout=2,
            allow_redirects=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                city = data.get('city', '')
                region = data.get('regionName', '')
                country = data.get('country', '')
                parts = [p for p in [city, region, country] if p]
                if parts:
                    return ', '.join(parts)
    except Exception as e:
        logger.warning(f"Failed to fetch IP location for {ip}: {e}")

    return 'Unknown Location'

# ----------------------------------------------------------------------
# Input validation

def is_garbage_local_part(local):
    """
    Rejects obviously fake/bot local parts only.
    Deliberately permissive -- real users have short names, digits, etc.
    We only block patterns that are statistically never real humans.
    """
    local = local.lower()
    # Hard length bounds
    if len(local) < 1 or len(local) > 64:
        return True
    # Pure repeated character: aaaaaa, 111111
    if re.match(r'^(.)\1+$', local):
        return True
    # Clearly programmatic: qwerty, asdfgh, zxcvbn
    if re.match(r'^(qwerty|asdfgh|zxcvbn|abcdef|123456|password)$', local):
        return True
    return False

def is_disposable_email(email):
    """
    SSRF hardening:
    - Only calls a fixed, hardcoded URL -- the email is passed as a query
      parameter, never used to construct the host or path.
    - email is already validated by regex before this is called, so it
      cannot contain path-traversal or injection characters.
    - Short timeout + no redirects to prevent slow-loris / SSRF via redirect.
    """
    try:
        # email is already regex-validated at this point; encode it safely
        safe_email = requests.utils.quote(email, safe='')
        resp = requests.get(
            f"https://disposable.debounce.io/?email={safe_email}",
            timeout=5,
            allow_redirects=False,   # never follow redirects -- SSRF via 301
        )
        if resp.status_code == 200 and resp.json().get('disposable') == 'true':
            return True
    except Exception as e:
        logger.warning(f"Disposable email check failed: {e}")
    return False

def validate_email(email, check_disposable=True):
    email = email.strip().lower()
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        raise ValueError("Invalid email format.")
    local, domain = email.split('@', 1)
    if is_garbage_local_part(local):
        raise ValueError("Invalid email format.")
    BLOCKED = {'10minutemail.com','yopmail.com','tempmail.org','mailinator.com',
               'guerrillamail.com','mail.tm','getnada.com','moakt.com','trashmail.com'}
    if domain in BLOCKED:
        raise ValueError("Invalid email format.")
    if check_disposable and is_disposable_email(email):
        raise ValueError("Invalid email format.")
    return email

def validate_name(name):
    if not name or len(name) < 2 or len(name) > 100:
        raise ValueError("Invalid name.")
    if not re.match(r"^[a-zA-Z\s\-\.'éèêëàâäôöûüç]+$", name):
        raise ValueError("Invalid name.")

# ----------------------------------------------------------------------
# Redis OTP

class RedisOTP:
    SIGNUP_PREFIX = "signup_otp:"
    LOGIN_PREFIX = "login_otp:"
    OTP_TTL = 600
    ATTEMPTS_TTL = 600

    def _get_key(self, prefix, email):
        return f"{prefix}{email}"

    def _get_attempts_key(self, prefix, email):
        return f"{prefix}{email}:attempts"

    def set_otp(self, email, code, prefix=SIGNUP_PREFIX):
        try:
            key = self._get_key(prefix, email)
            redis_client.setex(key, self.OTP_TTL, json.dumps({'code': str(code), 'used': False}))
            redis_client.setex(self._get_attempts_key(prefix, email), self.ATTEMPTS_TTL, 0)
        except RedisError as e:
            logger.error(f"Redis set_otp failed: {e}")
            raise RuntimeError("OTP service temporarily unavailable") from e

    def get_otp_data(self, email, prefix=SIGNUP_PREFIX):
        try:
            val = redis_client.get(self._get_key(prefix, email))
            return json.loads(val) if val else None
        except RedisError as e:
            logger.error(f"Redis get_otp_data failed: {e}")
        return None

    def delete_otp(self, email, prefix=SIGNUP_PREFIX):
        try:
            redis_client.delete(self._get_key(prefix, email))
            redis_client.delete(self._get_attempts_key(prefix, email))
        except RedisError as e:
            logger.error(f"Redis delete_otp failed: {e}")

    def verify_otp(self, email, code, prefix=SIGNUP_PREFIX):
        data = self.get_otp_data(email, prefix)
        if not data:
            return False, "OTP expired or not found."
        if data['used']:
            return False, "OTP already used."
        attempts_key = self._get_attempts_key(prefix, email)
        try:
            attempts = redis_client.incr(attempts_key)
            if attempts > 5:
                self.delete_otp(email, prefix)
                return False, "Too many attempts. Please request a new OTP."
            if data['code'] != str(code):
                return False, f"Invalid OTP. {5 - attempts} attempts remaining."
            data['used'] = True
            redis_client.setex(self._get_key(prefix, email), self.OTP_TTL, json.dumps(data))
            redis_client.delete(attempts_key)
            return True, "OTP verified."
        except RedisError as e:
            logger.error(f"Redis verify_otp failed: {e}")
            return False, "OTP verification temporarily unavailable"

signup_otp = RedisOTP()
login_otp = RedisOTP()

# ----------------------------------------------------------------------
# Session / logout helpers

USER_SESSIONS_PREFIX = "user_sessions:"
LOGOUT_TOKEN_PREFIX = "logout_token:"
LOGOUT_TOKEN_TTL = 7200

def add_user_session(user_id, session_id):
    try:
        redis_client.sadd(f"{USER_SESSIONS_PREFIX}{user_id}", session_id)
    except RedisError as e:
        logger.error(f"Redis add_user_session failed: {e}")

def remove_user_session(user_id, session_id):
    try:
        redis_client.srem(f"{USER_SESSIONS_PREFIX}{user_id}", session_id)
    except RedisError as e:
        logger.error(f"Redis remove_user_session failed: {e}")

def get_user_sessions(user_id):
    try:
        return redis_client.smembers(f"{USER_SESSIONS_PREFIX}{user_id}")
    except RedisError as e:
        logger.error(f"Redis get_user_sessions failed: {e}")
        return set()

def clear_user_sessions(user_id):
    try:
        for sid in get_user_sessions(user_id):
            redis_client.delete(f"{app.config['SESSION_KEY_PREFIX']}{sid}")
        redis_client.delete(f"{USER_SESSIONS_PREFIX}{user_id}")
        return True
    except RedisError as e:
        logger.error(f"Redis clear_user_sessions failed: {e}")
        return False

def generate_logout_token(user_id):
    token = secrets.token_hex(32)
    try:
        redis_client.setex(f"{LOGOUT_TOKEN_PREFIX}{token}", LOGOUT_TOKEN_TTL, user_id)
    except RedisError as e:
        raise RuntimeError("Could not generate token") from e
    return token

def get_user_id_from_logout_token(token):
    try:
        return redis_client.get(f"{LOGOUT_TOKEN_PREFIX}{token}")
    except RedisError:
        return None

def consume_logout_token(token):
    try:
        uid = redis_client.get(f"{LOGOUT_TOKEN_PREFIX}{token}")
        if uid:
            redis_client.delete(f"{LOGOUT_TOKEN_PREFIX}{token}")
            return uid
    except RedisError:
        pass
    return None

# ----------------------------------------------------------------------
# Email alert helpers

def send_login_alert(user, logout_link):
    email = safe_decrypt_email(user.encrypted_email)
    ip = request.remote_addr
    loc = get_ip_location(ip)
    body = (
        "Hi,\n\n"
        "A new session was initiated on your ZK Vault account.\n\n"
        "Request Details:\n"
        "- Event: Account Login\n"
        f"- Location: {loc} (IP: {ip})\n"
        f"- Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        "If this wasn't you, terminate all sessions immediately:\n"
        f"{logout_link}\n\n"
        "— ZK Vault Team"
    )
    send_email(email, "[ZK Vault] Login Alert", body)

def send_unified_logout_email(user, session_id, ip_address):
    email = safe_decrypt_email(user.encrypted_email)
    loc = get_ip_location(ip_address)
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    log_entries = get_activity_log(session_id) if session_id else []

    body = (
        f"Hi {user.name},\n\n"
        "Your ZK Vault session has ended.\n\n"
        "Session Details:\n"
        f"- Location: {loc} (IP: {ip_address})\n"
        f"- Time: {now_str}\n"
    )

    if log_entries:
        body += "\nActivity Summary:\n"
        for entry in log_entries:
            if isinstance(entry, bytes):
                entry = entry.decode()
            body += f"- {entry}\n"
    else:
        body += "\nActivity Summary:\n- No vault modifications recorded during this session.\n"

    body += "\n— ZK Vault Team"

    send_email(email, "[ZK Vault] Session Ended & Activity Summary", body)
    if session_id:
        clear_activity_log(session_id)

def send_session_terminated_alert(user, cooldown_minutes):
    email = safe_decrypt_email(user.encrypted_email)
    ip = request.remote_addr
    loc = get_ip_location(ip)
    body = (
        "Hi,\n\n"
        f"All active sessions for your ZK Vault account have been terminated. Account temporarily locked ({cooldown_minutes} mins).\n\n"
        "Request Details:\n"
        "- Event: Session Termination\n"
        f"- Location: {loc} (IP: {ip})\n"
        f"- Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        "— ZK Vault Team"
    )
    send_email(email, "[ZK Vault] Security Alert: Sessions Terminated", body)

def send_account_deletion_alert(email):
    ip = request.remote_addr
    loc = get_ip_location(ip)
    body = (
        "Hi,\n\n"
        "Your ZK Vault account and all associated data have been permanently deleted.\n\n"
        "Request Details:\n"
        "- Event: Account Deletion\n"
        f"- Location: {loc} (IP: {ip})\n"
        f"- Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        "— ZK Vault Team"
    )
    send_email(email, "[ZK Vault] Account Deletion Confirmation", body)

def send_password_changed_alert(user):
    email = safe_decrypt_email(user.encrypted_email)
    ip = request.remote_addr
    loc = get_ip_location(ip)
    body = (
        "Hi,\n\n"
        "Your ZK Vault master password was updated successfully.\n\n"
        "Request Details:\n"
        "- Event: Password Update\n"
        f"- Location: {loc} (IP: {ip})\n"
        f"- Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        "Didn't make this change? Please contact security immediately.\n\n"
        "— ZK Vault Team"
    )
    send_email(email, "[ZK Vault] Password Changed", body)

def send_vault_lockout_alert(user, permanent=False):
    email = safe_decrypt_email(user.encrypted_email)
    ip = request.remote_addr
    loc = get_ip_location(ip)
    subject = '[ZK Vault] Permanent Lockout Alert' if permanent else '[ZK Vault] Temporary Lockout Alert'
    unlock_msg = 'Please contact support.' if permanent else f'Unlocks at {user.lock_until}.'
    body = (
        "Hi,\n\n"
        f"Your ZK Vault account has been locked due to multiple failed unlock attempts.\n"
        f"Status: {unlock_msg}\n\n"
        "Request Details:\n"
        f"- Location: {loc} (IP: {ip})\n\n"
        "— ZK Vault Team"
    )
    send_email(email, subject, body)

# ----------------------------------------------------------------------
# Lockout logic
#
# IMPORTANT: callers MUST fetch `user` with `.with_for_update()` before
# calling these, so concurrent failed attempts can't read a stale
# failed_attempts value and under-count. Both functions commit internally,
# which releases the row lock.

def apply_vault_lockout(user):
    if user.lock_until and user.lock_until <= datetime.now():
        user.failed_attempts = 0
        user.lock_until = None

    user.failed_attempts += 1
    if user.failed_attempts == 2:
        user.lock_until = datetime.now() + timedelta(minutes=30)
        send_vault_lockout_alert(user)
    elif user.failed_attempts == 3:
        user.lock_until = datetime.now() + timedelta(hours=24)
        send_vault_lockout_alert(user)
    elif user.failed_attempts == 4:
        user.lock_until = datetime.now() + timedelta(days=7)
        send_vault_lockout_alert(user)
    elif user.failed_attempts >= 5:
        user.lock_until = datetime.now() + timedelta(days=365)
        send_vault_lockout_alert(user, permanent=True)
        db_session.commit()
        session.clear()
        flash('Too many vault unlock failures. Please log in again.', 'danger')
        return False
    db_session.commit()
    flash('Incorrect vault password.', 'danger')
    return True

def apply_secret_lockout(user):
    if user.secret_lock_until and user.secret_lock_until <= datetime.now():
        user.secret_failed_attempts = 0
        user.secret_lock_until = None

    user.secret_failed_attempts += 1
    if user.secret_failed_attempts == 2:
        user.secret_lock_until = datetime.now() + timedelta(minutes=30)
    elif user.secret_failed_attempts == 3:
        user.secret_lock_until = datetime.now() + timedelta(hours=24)
    elif user.secret_failed_attempts == 4:
        user.secret_lock_until = datetime.now() + timedelta(days=7)
    elif user.secret_failed_attempts >= 5:
        user.secret_reauthentication_required = True
        user.secret_lock_until = None
        db_session.commit()
        flash('Too many secret code failures. Re-authentication required.', 'danger')
        return False
    db_session.commit()
    flash('Incorrect secret code.', 'danger')
    return True

# ----------------------------------------------------------------------
# Activity logging

ACTIVITY_LOG_PREFIX = "vault_activity:"
ACTIVITY_LOG_TTL = 28800

def log_activity(session_id, action, details=""):
    try:
        if not session_id:
            return
        key = f"{ACTIVITY_LOG_PREFIX}{session_id}"
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] {action}" + (f" -- {details}" if details else "")
        redis_client.rpush(key, entry)
        redis_client.expire(key, ACTIVITY_LOG_TTL)
    except RedisError as e:
        logger.error(f"Failed to log activity: {e}")

def get_activity_log(session_id):
    try:
        return redis_client.lrange(f"{ACTIVITY_LOG_PREFIX}{session_id}", 0, -1)
    except RedisError:
        return []

def clear_activity_log(session_id):
    try:
        redis_client.delete(f"{ACTIVITY_LOG_PREFIX}{session_id}")
    except RedisError:
        pass



# ----------------------------------------------------------------------
# Middleware

@app.before_request
def before_request():
    public_endpoints = [
        'login', 'send_login_otp', 'verify_login',
        'signup', 'request_signup_otp', 'verify_signup_otp',
        'set_password', 'get_signup_salt', 'create_account',
        'static', 'terminate_sessions', 'request_logout_link', 'terms',
        'robots_txt', 'sitemap_xml',
    ]
    if request.endpoint in public_endpoints:
        return

    if 'user_id' not in session:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))

    user = db_session.query(User).filter_by(id=session['user_id']).first()
    if not user:
        session.clear()
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    if user.logout_cooldown_until and user.logout_cooldown_until > datetime.now():
        if request.endpoint not in ['logout', 'terminate_sessions', 'request_logout_link']:
            flash('Account temporarily locked for security.', 'warning')
            return redirect(url_for('login'))

    unlocked_endpoints = [
        'vault', 'unlock_vault', 'secret_setup', 'secret_unlock', 'logout',
        'secret_reauth', 'secret_reauth_verify', 'home', 'secret_home',
        'api_list_records', 'api_create_record', 'api_update_record',
        'api_delete_record', 'api_list_secret_records', 'api_create_secret_record',
        'api_delete_secret_record',
        'api_change_password',
        'api_download_file',
        'api_get_secret_salt',
        'api_user_quota',
    ]
    if request.endpoint not in unlocked_endpoints:
        if not session.get('vault_unlocked'):
            flash('Vault is locked. Please unlock first.', 'warning')
            return redirect(url_for('unlock_vault'))

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

# ----------------------------------------------------------------------
# Error handlers
#
# All HTML error handlers render error.html.
# API routes (/api/*) get JSON error responses instead of HTML pages --
# the _wants_json() helper detects this by inspecting the request path.

def _wants_json() -> bool:
    """True if the request is to an API endpoint (expects JSON, not HTML)."""
    return request.path.startswith('/api/')

def _error_response(code: int, title: str, message: str):
    if _wants_json():
        return jsonify(error=message), code
    return render_template('error.html', title=title, code=code, message=message), code

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if _wants_json():
        return jsonify(error='CSRF token missing or invalid. Refresh and retry.'), 403
    flash('Your session expired. Please try again.', 'warning')
    return redirect(url_for('login'))

@app.errorhandler(400)
def bad_request(e):
    return _error_response(400, 'Bad Request', 'The request was malformed. Please check your input.')

@app.errorhandler(401)
def unauthorized(e):
    return _error_response(401, 'Unauthorized', 'Authentication required. Please log in.')

@app.errorhandler(403)
def forbidden(e):
    return _error_response(403, 'Access Denied',
                           'You do not have permission to access this resource.')

@app.errorhandler(404)
def page_not_found(e):
    return _error_response(404, 'Page Not Found',
                           'The page you are looking for does not exist or has been moved.')

@app.errorhandler(405)
def method_not_allowed(e):
    return _error_response(405, 'Method Not Allowed',
                           'The HTTP method used is not allowed for this endpoint.')

@app.errorhandler(408)
def request_timeout(e):
    return _error_response(408, 'Request Timeout',
                           'The request took too long. Please try again.')

@app.errorhandler(413)
def request_entity_too_large(e):
    mb = app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
    return _error_response(413, 'Payload Too Large',
                           f'Upload exceeds the {mb} MB limit.')

@app.errorhandler(429)
def ratelimit_handler(e):
    return _error_response(429, 'Too Many Requests',
                           'You have made too many requests. Please wait and try again.')

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500: {e}", exc_info=True)
    return _error_response(500, 'Something Went Wrong',
                           'An unexpected server error occurred.')

@app.errorhandler(503)
def service_unavailable(e):
    return _error_response(503, 'Service Unavailable',
                           'The service is temporarily unavailable. Please try again shortly.')

@app.errorhandler(Exception)
def handle_all_exceptions(e):
    # Don't double-handle HTTPExceptions -- Flask already routes those above
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return _error_response(e.code, e.name, e.description)
    logger.error(f"Unhandled exception: {e}", exc_info=True)
    return _error_response(500, 'Something Went Wrong',
                           'An unexpected error occurred. Please try again.')

# ----------------------------------------------------------------------
# Routes -- Login / Signup

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET'])
def login():
    step = request.args.get('step', 'email')
    email = session.get('login_email', '')
    salt = ''
    if step in ('otp', 'password') and email:
        user = db_session.query(User).filter_by(email_index=make_email_index(email)).first()
        if user:
            salt = user.salt
    after_signup = session.get('after_signup', False)
    return render_template('login.html', step=step, email=email, salt=salt, after_signup=after_signup)

@app.route('/send_login_otp', methods=['POST'])
@limiter.limit("5 per minute")
def send_login_otp():
    raw_email = request.form.get('email')
    try:
        validate_email(raw_email, check_disposable=False)
    except ValueError:
        flash('Invalid email or OTP.', 'warning')
        return redirect(url_for('login', step='email'))

    email = raw_email.strip().lower()
    user = db_session.query(User).filter_by(email_index=make_email_index(email)).first()

    if user and not (user.logout_cooldown_until and user.logout_cooldown_until > datetime.now()):
        code_str = f"{secrets.randbelow(1000000):06d}"
        login_otp.set_otp(email, code_str, prefix=RedisOTP.LOGIN_PREFIX)
        ip = request.remote_addr
        loc = get_ip_location(ip)
        body = (
            "Hi,\n\n"
            f"Your ZK Vault login verification code is: {code_str} (Expires in 10 mins).\n\n"
            "Request Details:\n"
            "- Event: Account Authentication\n"
            f"- Location: {loc} (IP: {ip})\n"
            f"- Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            "Didn't request this code? Please secure your account immediately.\n\n"
            "— ZK Vault Team"
        )
        sent = send_email(email, '[ZK Vault] Login Verification Code', body)
        if not sent:
            flash('Failed to send login verification code email. Please try again.', 'danger')
            return redirect(url_for('login', step='email'))
    else:
        # Non-existing user: do equivalent-shaped work to reduce timing asymmetry.
        dummy_code_str = f"{secrets.randbelow(1000000):06d}"
        dummy_prefix = "dummy_login_otp:"
        try:
            redis_client.setex(f"{dummy_prefix}{email}", 600, json.dumps({'code': dummy_code_str, 'used': False}))
        except RedisError:
            pass

    flash('If the email is registered, an OTP will be sent.', 'info')
    session['login_email'] = email
    return redirect(url_for('login', step='otp'))

@app.route('/verify_login', methods=['POST'])
@limiter.limit("10 per minute")
def verify_login():
    email = (request.form.get('email') or '').strip().lower()
    otp = request.form.get('otp')
    if not email or not otp:
        flash('Invalid email or OTP.', 'danger')
        return redirect(url_for('login', step='otp'))

    user = db_session.query(User).filter_by(email_index=make_email_index(email)).first()
    if not user or (user.logout_cooldown_until and user.logout_cooldown_until > datetime.now()):
        flash('Invalid email or OTP.', 'danger')
        return redirect(url_for('login', step='otp'))

    ok, msg = login_otp.verify_otp(email, otp, prefix=RedisOTP.LOGIN_PREFIX)
    if not ok:
        flash('Invalid email or OTP.', 'danger')
        return redirect(url_for('login', step='otp'))

    after_signup = session.get('after_signup', False)
    # Session fixation protection
    old_sid = session.sid if hasattr(session, 'sid') else None
    if old_sid:
        redis_client.delete(f"{app.config['SESSION_KEY_PREFIX']}{old_sid}")
    session.clear()
    session.modified = True
    session.permanent = True
    session['user_id'] = user.id
    session['vault_unlocked'] = False
    session['vault_session_id'] = str(uuid.uuid4())
    session['login_email'] = email
    if after_signup:
        session['after_signup'] = True

    new_sid = session.sid if hasattr(session, 'sid') else None
    if new_sid:
        add_user_session(user.id, new_sid)

    log_activity(session['vault_session_id'],
                 f"LOGIN OTP SUCCESS from IP {request.remote_addr}")
    try:
        token = generate_logout_token(user.id)
        logout_link = url_for('terminate_sessions', token=token, _external=True)
        send_login_alert(user, logout_link)
    except Exception as e:
        logger.error(f"Login alert failed: {e}")

    flash('OTP verified! Please enter your master password.', 'success')
    return redirect(url_for('login', step='password'))

# ---- Static crawlers / bot files ----

@app.route('/robots.txt')
def robots_txt():
    return "User-agent: *\nDisallow: /", 200, {'Content-Type': 'text/plain'}

@app.route('/sitemap.xml')
def sitemap_xml():
    return '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>', 200, {'Content-Type': 'application/xml'}

# ---- Signup ----

@app.route('/terms', methods=['GET'])
def terms():
    return render_template('terms.html')

@app.route('/signup', methods=['GET'])
def signup():
    return render_template('signup.html')

@app.route('/request_signup_otp', methods=['POST'])
@limiter.limit("5 per minute")
def request_signup_otp():
    raw_email = request.form.get('email', '').strip().lower()
    name = request.form.get('name', '').strip()
    try:
        validate_email(raw_email)
        validate_name(name)
    except ValueError:
        flash("Invalid email or name.", 'warning')
        return render_template('signup.html')

    user_exists = bool(db_session.query(User).filter_by(email_index=make_email_index(raw_email)).first())

    if user_exists:
        code_str = f"{secrets.randbelow(1000000):06d}"
        login_otp.set_otp(raw_email, code_str, prefix=RedisOTP.LOGIN_PREFIX)
        ip = request.remote_addr
        loc = get_ip_location(ip)
        body = (
            "Hi,\n\n"
            f"Your ZK Vault login verification code is: {code_str} (Expires in 10 mins).\n\n"
            "Request Details:\n"
            "- Event: Account Authentication (via Signup)\n"
            f"- Location: {loc} (IP: {ip})\n"
            f"- Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            "— ZK Vault Team"
        )
        send_email(raw_email, '[ZK Vault] Login Verification Code', body, sync=True)
        session['login_email'] = raw_email
        flash('An account with this email already exists. A login verification code has been sent to your email.', 'info')
        return redirect(url_for('login', step='otp'))

    code_str = f"{secrets.randbelow(1000000):06d}"
    signup_otp.set_otp(raw_email, code_str)
    ip = request.remote_addr
    loc = get_ip_location(ip)
    body = (
        "Hi,\n\n"
        f"Your ZK Vault registration verification code is: {code_str} (Expires in 10 mins).\n\n"
        "Request Details:\n"
        "- Event: Registration Verification\n"
        f"- Location: {loc} (IP: {ip})\n"
        f"- Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        "Didn't request this code? You can safely ignore this email.\n\n"
        "— ZK Vault Team"
    )
    sent = send_email(raw_email, '[ZK Vault] Your Verification Code', body)
    if not sent:
        flash('Failed to send verification code email. Please try again.', 'danger')
        return render_template('signup.html')

    session['signup_email'] = raw_email
    session['signup_name'] = name
    flash('If the email is eligible, a verification code has been sent.', 'success')
    return render_template('verify_signup.html', email=raw_email)

@app.route('/verify_signup_otp', methods=['POST'])
@limiter.limit("10 per minute")
def verify_signup_otp():
    email = request.form.get('email')
    otp = request.form.get('otp')
    if not email or not otp:
        flash('Email and OTP are required.', 'danger')
        return render_template('verify_signup.html', email=email)

    ok, msg = signup_otp.verify_otp(email, otp)
    if ok:
        session['signup_verified_email'] = email
        session['signup_verified_at'] = datetime.now().isoformat()
        flash('Email verified! Now set your vault password.', 'success')
        return redirect(url_for('set_password'))
    flash(msg, 'danger')
    return render_template('verify_signup.html', email=email)

@app.route('/set_password', methods=['GET'])
def set_password():
    if 'signup_verified_email' not in session:
        flash('Please verify your email first.', 'warning')
        return redirect(url_for('signup'))
    return render_template('set_password.html', email=session['signup_verified_email'])

# ----------------------------------------------------------------------
# ZK account creation
#
# Flow:
#   1. GET  /set_password/get_salt  -> server generates & session-stores a salt,
#                                     returns it to the JS so it can derive key1
#                                     and then derive the verifier client-side.
#   2. POST /create_account         -> JS sends only verifier_b64 (never the password).
#
# Password complexity MUST be enforced in JS before derivation; the server
# cannot see the password and therefore cannot validate it here.

@app.route('/set_password/get_salt', methods=['GET'])
def get_signup_salt():
    if 'signup_verified_email' not in session:
        return jsonify(error='Email verification required'), 403
    salt = secrets.token_bytes(ARGON2_SALT_LEN)
    session['pending_salt'] = base64.b64encode(salt).decode()
    return jsonify(salt=session['pending_salt'])

@app.route('/create_account', methods=['POST'])
@limiter.limit("5 per minute")
def create_account():
    if 'signup_verified_email' not in session:
        flash('Email verification required.', 'warning')
        return redirect(url_for('signup'))

    verifier_b64 = request.form.get('verifier', '').strip()
    try:
        validate_verifier_b64(verifier_b64, 'verifier')
    except ValueError as e:
        flash(str(e), 'danger')
        return render_template('set_password.html', email=session['signup_verified_email'])

    salt_b64 = session.pop('pending_salt', None)
    if not salt_b64:
        flash('Session expired. Please start again.', 'warning')
        return redirect(url_for('set_password'))

    email = session['signup_verified_email']
    name = session.get('signup_name', '')
    email_index = make_email_index(email)

    if db_session.query(User).filter_by(email_index=email_index).first():
        flash('Email already registered.', 'danger')
        session.pop('signup_verified_email', None)
        return redirect(url_for('login'))

    try:
        user = User(
            id=str(uuid.uuid4()),
            email_index=email_index,
            encrypted_email=encrypt_email(email),
            name=name,
            salt=salt_b64,
            verifier_hash=hash_verifier(verifier_b64),
        )
        db_session.add(user)
        db_session.commit()
        logger.info(f"New user created: email_index={email_index}")
    except Exception as e:
        db_session.rollback()
        logger.error(f"create_account: DB commit failed for email_index={email_index}: {e}", exc_info=True)
        flash('Account creation failed due to a server error. Please try again.', 'danger')
        return render_template('set_password.html', email=email)

    session.pop('signup_verified_email', None)
    session.pop('signup_email', None)
    session.pop('signup_name', None)

    # Session fixation protection: clear pending signup session keys, and recreate session
    old_sid = session.sid if hasattr(session, 'sid') else None
    if old_sid:
        redis_client.delete(f"{app.config['SESSION_KEY_PREFIX']}{old_sid}")
    session.clear()
    session.modified = True
    session.permanent = True
    session['user_id'] = user.id
    session['vault_unlocked'] = True
    session['vault_session_id'] = str(uuid.uuid4())
    session['login_email'] = email

    new_sid = session.sid if hasattr(session, 'sid') else None
    if new_sid:
        add_user_session(user.id, new_sid)

    log_activity(session['vault_session_id'],
                 f"ACCOUNT CREATED & AUTO-LOGGED IN from IP {request.remote_addr}")

    # Send login alert email (since they are logged in now)
    try:
        token = generate_logout_token(user.id)
        logout_link = url_for('terminate_sessions', token=token, _external=True)
        send_login_alert(user, logout_link)
    except Exception as e:
        logger.error(f"Login alert failed: {e}")

    flash('Account created successfully!', 'success')
    return redirect(url_for('vault'))

# ----------------------------------------------------------------------
# Request links

@app.route('/request_logout_link', methods=['POST'])
@limiter.limit("5 per hour")
def request_logout_link():
    if 'user_id' not in session:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = db_session.query(User).filter_by(id=session['user_id']).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    if user.logout_cooldown_until and user.logout_cooldown_until > datetime.now():
        flash('Account temporarily locked.', 'warning')
        return redirect(url_for('login'))
    try:
        token = generate_logout_token(user.id)
        link = url_for('terminate_sessions', token=token, _external=True)
        ip = request.remote_addr
        loc = get_ip_location(ip)
        body = (
            "Hi,\n\n"
            "Request received to terminate all active sessions for your ZK Vault account.\n\n"
            "Authorize termination link (Valid for 2 hours):\n"
            f"{link}\n\n"
            "Request Details:\n"
            "- Event: Session Termination Request\n"
            f"- Location: {loc} (IP: {ip})\n"
            f"- Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            "— ZK Vault Team"
        )
        send_email(safe_decrypt_email(user.encrypted_email),
                   '[ZK Vault] Session Termination Authorization',
                   body)
        flash('Termination link sent to your email.', 'success')
    except Exception as e:
        logger.error(f"Failed to send termination link: {e}")
        flash('Could not send link. Please try again.', 'danger')
    return redirect(url_for('home'))

@app.route('/terminate_sessions/<token>', methods=['GET', 'POST'])
def terminate_sessions(token):
    if request.method == 'POST':
        user_id = consume_logout_token(token)
        if not user_id:
            flash('Invalid or expired session termination link.', 'danger')
            return redirect(url_for('login'))
        user = db_session.query(User).filter_by(id=user_id).first()
        if user:
            clear_user_sessions(user_id)
            user.logout_cooldown_until = datetime.now() + timedelta(minutes=15)
            db_session.commit()
            send_session_terminated_alert(user, 15)
        session.clear()
        flash('All active sessions have been terminated.', 'info')
        return redirect(url_for('login'))
    else:
        user_id = get_user_id_from_logout_token(token)
        if not user_id:
            flash('Invalid or expired session termination link.', 'danger')
            return redirect(url_for('login'))
        user = db_session.query(User).filter_by(id=user_id).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('login'))
        email = safe_decrypt_email(user.encrypted_email)
        return render_template('confirm_terminate.html', token=token, email=email)




# ----------------------------------------------------------------------
# Vault unlock
#
# The client submits verifier_b64 (derived in-browser from the password).
# The server checks it against the stored Argon2id hash.
# No key is cached server-side. session['vault_unlocked'] is a UI hint only.
#
# On a WRONG password: the user is redirected to /home (in a locked state), the real
# escalating lockout (apply_vault_lockout) applies, and a lockout alert
# email fires per the existing thresholds. There is no decoy/fake vault --
# per spec, a wrong password must never produce a "success" outcome or
# any populated data; the only thing it produces is a locked state.

@app.route('/vault', methods=['GET'])
@limiter.limit("1000 per day")
def vault():
    if 'user_id' not in session:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = db_session.query(User).filter_by(id=session['user_id']).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    user_email = safe_decrypt_email(user.encrypted_email)
    return render_template('vault.html',
                           user=user,
                           user_email=user_email,
                           salt=user.salt,
                           secret_salt=user.secret_salt,
                           has_secret=bool(user.secret_salt))

@app.route('/unlock', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def unlock_vault():
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error='Please log in.'), 401
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))

    user = db_session.query(User).filter_by(id=session['user_id']).first()
    if not user:
        session.clear()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error='User not found.'), 401
        return redirect(url_for('login'))

    if user.logout_cooldown_until and user.logout_cooldown_until > datetime.now():
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error='Account temporarily locked.'), 403
        flash('Account temporarily locked.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'GET':
        return redirect(url_for('vault'))

    # POST: client sends verifier only -- never the password
    verifier_b64 = request.form.get('verifier', '').strip()
    try:
        validate_verifier_b64(verifier_b64, 'verifier')
    except ValueError as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error=str(e)), 400
        flash(str(e), 'danger')
        return redirect(url_for('vault'))

    if user.lock_until and user.lock_until > datetime.now():
        remaining = int((user.lock_until - datetime.now()).total_seconds() // 60)
        msg = f'Vault locked. Try again in {remaining} minutes.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error=msg), 403
        flash(msg, 'danger')
        return redirect(url_for('vault'))

    if check_verifier(verifier_b64, user.verifier_hash):
        user = db_session.query(User).filter_by(id=session['user_id']).with_for_update().first()
        user.failed_attempts = 0
        user.lock_until = None
        db_session.commit()
        session['vault_unlocked'] = True
        session.pop('after_signup', None)
        log_activity(session.get('vault_session_id'), "VAULT UNLOCKED")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json or request.accept_mimetypes.accept_json:
            return jsonify(success=True)
        flash('Vault unlocked!', 'success')
        return redirect(url_for('vault'))

    user = db_session.query(User).filter_by(id=session['user_id']).with_for_update().first()
    if not apply_vault_lockout(user):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error='Too many vault unlock failures. Please log in again.', relogin=True), 403
        return redirect(url_for('login'))

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
        return jsonify(error='Incorrect vault password.'), 400
    return redirect(url_for('vault'))

@app.route('/home', methods=['GET'])
@limiter.limit("1000 per day")
def home():
    return redirect(url_for('vault'))

# ----------------------------------------------------------------------
# Records API -- all crypto happens client-side
#
# The server stores and retrieves opaque ciphertext blobs.
# Quota enforcement uses the pre-computed counters on the User row,
# updated atomically under SELECT ... FOR UPDATE.
#
# Full ZK choice: filename/mime_type are inside the ciphertext.
# The server serves downloads as application/octet-stream with a generic
# name; the browser decrypts and re-presents the real name/type.

def _require_logged_in_user():
    """Return (user, None) or (None, error_response) for any authenticated user."""
    if 'user_id' not in session:
        return None, (jsonify(error='Please log in.'), 401)
    user = db_session.query(User).filter_by(id=session['user_id']).first()
    if not user:
        return None, (jsonify(error='User not found.'), 403)
    return user, None

def _require_vault_unlocked():
    """Return (user, None) or (None, error_response)."""
    if not session.get('vault_unlocked'):
        return None, (jsonify(error='Vault locked'), 403)
    user = db_session.query(User).filter_by(id=session['user_id']).first()
    if not user:
        return None, (jsonify(error='User not found'), 403)
    return user, None

@app.route('/api/records', methods=['GET'])
@limiter.limit("1000 per day")
def api_list_records():
    user, err = _require_logged_in_user()
    if err:
        return err
    records = (db_session.query(NormalRecord)
               .filter_by(user_id=user.id)
               .order_by(NormalRecord.created_at.desc())
               .all())
    return jsonify([{'id': r.id, 'ciphertext': r.encrypted_payload,
                     'created_at': r.created_at.isoformat() if r.created_at else None}
                    for r in records])

@app.route('/api/records', methods=['POST'])
@limiter.limit("1000 per hour")
def api_create_record():
    """
    Expects JSON: { "ciphertext": "<base64 AES-GCM blob>" }
    The blob contains title, notes, and file data, all encrypted client-side.

    CSRF note: CSRFProtect checks the X-CSRFToken request header for JSON
    requests (not the body). Your JS fetch() calls MUST include:
      headers: { 'X-CSRFToken': getCookie('csrf_token') }
    SameSite=Strict is a strong second layer but is not a substitute.
    """
    user, err = _require_vault_unlocked()
    if err:
        return err

    data = request.get_json(silent=True)
    if not data or 'ciphertext' not in data:
        return jsonify(error='Missing ciphertext'), 400

    ciphertext = data['ciphertext']
    if not isinstance(ciphertext, str):
        return jsonify(error='ciphertext must be a string'), 400
    size = len(ciphertext.encode('utf-8'))

    # Business logic: reject individual records that exceed the per-record cap.
    # Prevents a single request from consuming the entire user quota at once.
    if size > MAX_SINGLE_RECORD_BYTES:
        return jsonify(error='Single record exceeds maximum allowed size'), 400

    # Atomic quota check and update
    user = (db_session.query(User)
            .filter_by(id=session['user_id'])
            .with_for_update()
            .first())

    if user.record_count >= app.config['MAX_RECORDS_PER_USER']:
        return jsonify(error=f"Record limit reached ({app.config['MAX_RECORDS_PER_USER']})"), 400

    max_bytes = app.config['MAX_STORAGE_PER_USER_MB'] * 1024 * 1024
    if user.storage_bytes + size > max_bytes:
        return jsonify(error=f"Storage quota exceeded ({app.config['MAX_STORAGE_PER_USER_MB']} MB)"), 400

    rec = NormalRecord(id=generate_record_id(), user_id=user.id,
                       encrypted_payload=ciphertext, size=size)
    user.record_count += 1
    user.storage_bytes += size
    db_session.add(rec)
    db_session.commit()

    log_activity(session.get('vault_session_id'), "RECORD CREATED", f"ID: {rec.id}")
    return jsonify(id=rec.id), 201

@app.route('/api/records/<record_id>', methods=['PUT'])
@limiter.limit("200 per hour")
def api_update_record(record_id):
    """
    Expects JSON: { "ciphertext": "<new base64 AES-GCM blob>" }
    Storage delta is applied atomically.
    """
    user, err = _require_vault_unlocked()
    if err:
        return err

    data = request.get_json(silent=True)
    if not data or 'ciphertext' not in data:
        return jsonify(error='Missing ciphertext'), 400

    rec = (db_session.query(NormalRecord)
           .filter_by(id=record_id, user_id=user.id)
           .first())
    if not rec:
        return jsonify(error='Record not found'), 404

    new_ciphertext = data['ciphertext']
    if not isinstance(new_ciphertext, str):
        return jsonify(error='ciphertext must be a string'), 400
    new_size = len(new_ciphertext.encode('utf-8'))
    if new_size > MAX_SINGLE_RECORD_BYTES:
        return jsonify(error='Single record exceeds maximum allowed size'), 400
    size_delta = new_size - rec.size

    user = (db_session.query(User)
            .filter_by(id=session['user_id'])
            .with_for_update()
            .first())

    max_bytes = app.config['MAX_STORAGE_PER_USER_MB'] * 1024 * 1024
    if user.storage_bytes + size_delta > max_bytes:
        return jsonify(error='Storage quota exceeded'), 400

    rec.encrypted_payload = new_ciphertext
    rec.size = new_size
    user.storage_bytes += size_delta
    db_session.commit()

    log_activity(session.get('vault_session_id'), "RECORD UPDATED", f"ID: {record_id}")
    return jsonify(ok=True)

@app.route('/api/records/<record_id>', methods=['DELETE'])
@limiter.limit("200 per hour")
def api_delete_record(record_id):
    user, err = _require_vault_unlocked()
    if err:
        return err

    user = (db_session.query(User)
            .filter_by(id=session['user_id'])
            .with_for_update()
            .first())
    rec = (db_session.query(NormalRecord)
           .filter_by(id=record_id, user_id=user.id)
           .first())
    if not rec:
        return jsonify(error='Record not found'), 404

    user.record_count = max(0, user.record_count - 1)
    user.storage_bytes = max(0, user.storage_bytes - rec.size)
    db_session.delete(rec)
    db_session.commit()

    log_activity(session.get('vault_session_id'), "RECORD DELETED", f"ID: {record_id}")
    return jsonify(ok=True)

# File download -- serves raw ciphertext; client decrypts and presents the file.
# We can't set the real Content-Type or filename because those are inside
# the ciphertext (full ZK choice). The JS fetch handler should trigger a
# download using the decrypted filename after decryption.
@app.route('/api/records/<record_id>/file/<int:file_index>', methods=['GET'])
@limiter.limit("200 per hour")
def api_download_file(record_id, file_index):
    user, err = _require_vault_unlocked()
    if err:
        return err

    rec = (db_session.query(NormalRecord)
           .filter_by(id=record_id, user_id=user.id)
           .first())
    if not rec:
        abort(404)

    # The ciphertext for the full record is returned; the client picks the
    # right file blob out after decrypting the JSON envelope.
    # Alternatively, if you store per-file ciphertext separately, adjust here.
    log_activity(session.get('vault_session_id'),
                 "FILE DOWNLOAD (ciphertext)", f"Record: {record_id}, file index: {file_index}")

    return jsonify(ciphertext=rec.encrypted_payload, file_index=file_index)

# ----------------------------------------------------------------------
# Password / verifier change
#
# The client must:
#   1. Fetch all ciphertext blobs.
#   2. Decrypt with old key1 (re-derived from old password + old salt).
#   3. Re-encrypt with new key1 (new password + new salt).
#   4. POST to this endpoint with new_salt, new_verifier, and the full
#      array of re-encrypted ciphertexts.  Everything is applied in one
#      transaction; counters are recalculated from the new sizes.
#
# The server never sees old or new passwords.

@app.route('/api/change_password', methods=['POST'])
@limiter.limit("5 per hour")
def api_change_password():
    """
    Expects JSON:
    {
      "old_verifier": "<base64>",        REQUIRED: proof of current password
      "new_salt":     "<base64>",
      "new_verifier": "<base64>",
      "records": [
        { "id": "...", "ciphertext": "..." },
        ...
      ],
      // Required only if a secret vault exists:
      "old_secret_verifier": "<base64>",
      "new_secret_salt":     "<base64>",
      "new_secret_verifier": "<base64>",
      "secret_records": [
        { "id": "...", "ciphertext": "..." },
        ...
      ]
    }

    Security: the row lock is taken FIRST, before any verifier check, and
    held continuously through validation and the swap. This closes the
    TOCTOU window where two concurrent requests could both read the same
    stale verifier_hash and both pass the check before either commits.
    """
    if 'user_id' not in session or not session.get('vault_unlocked'):
        return jsonify(error='Vault locked'), 403

    data = request.get_json(silent=True)
    if not data:
        return jsonify(error='Invalid request body'), 400

    required = ['old_verifier', 'new_salt', 'new_verifier', 'records']
    if not all(k in data for k in required):
        return jsonify(error=f'Missing required fields: {required}'), 400

    try:
        validate_verifier_b64(data.get('old_verifier'), 'old_verifier')
        validate_verifier_b64(data.get('new_verifier'), 'new_verifier')
        validate_salt_b64(data.get('new_salt'), 'new_salt')
        if not isinstance(data.get('records'), list):
            raise ValueError("Field 'records' must be a list")
        for r in data['records']:
            if not isinstance(r, dict) or 'id' not in r or 'ciphertext' not in r:
                raise ValueError("Each item in 'records' must be a dictionary containing 'id' and 'ciphertext'")
            if not isinstance(r['id'], str) or not isinstance(r['ciphertext'], str):
                raise ValueError("Record 'id' and 'ciphertext' must be strings")

        if 'secret_records' in data:
            if not isinstance(data.get('secret_records'), list):
                raise ValueError("Field 'secret_records' must be a list")
            for r in data['secret_records']:
                if not isinstance(r, dict) or 'id' not in r or 'ciphertext' not in r:
                    raise ValueError("Each item in 'secret_records' must be a dictionary containing 'id' and 'ciphertext'")
                if not isinstance(r['id'], str) or not isinstance(r['ciphertext'], str):
                    raise ValueError("Secret record 'id' and 'ciphertext' must be strings")
    except ValueError as e:
        return jsonify(error=str(e)), 400

    # Lock acquired ONCE, held through verification AND the swap.
    user = (db_session.query(User)
            .filter_by(id=session['user_id'])
            .with_for_update()
            .first())
    if not user:
        db_session.rollback()
        return jsonify(error='User not found'), 404

    if user.lock_until and user.lock_until > datetime.now():
        remaining = int((user.lock_until - datetime.now()).total_seconds() // 60)
        db_session.rollback()
        return jsonify(error=f'Vault locked for {remaining} more minutes'), 423

    if not check_verifier(data['old_verifier'], user.verifier_hash):
        if not apply_vault_lockout(user):
            session.clear()
            return jsonify(error='Too many failures. Logged out.'), 401
        return jsonify(error='Incorrect current password'), 401

    has_secret = bool(user.secret_salt)
    if has_secret:
        secret_required = ['old_secret_verifier', 'new_secret_salt',
                           'new_secret_verifier', 'secret_records']
        if not all(k in data for k in secret_required):
            db_session.rollback()
            return jsonify(error=f'Secret vault fields required: {secret_required}'), 400

        try:
            validate_verifier_b64(data.get('old_secret_verifier'), 'old_secret_verifier')
            validate_verifier_b64(data.get('new_secret_verifier'), 'new_secret_verifier')
            validate_salt_b64(data.get('new_secret_salt'), 'new_secret_salt')
        except ValueError as e:
            db_session.rollback()
            return jsonify(error=str(e)), 400

        if user.secret_lock_until and user.secret_lock_until > datetime.now():
            remaining = int((user.secret_lock_until - datetime.now()).total_seconds() // 60)
            db_session.rollback()
            return jsonify(error=f'Secret vault locked for {remaining} more minutes'), 423

        if not check_verifier(data['old_secret_verifier'], user.secret_verifier_hash):
            if not apply_secret_lockout(user):
                return jsonify(error='Too many secret vault failures. Re-auth required.'), 401
            return jsonify(error='Incorrect current secret code'), 401

    # Validate all record IDs belong to this user before touching anything
    incoming_ids = {r['id'] for r in data['records']}
    existing = {r.id for r in db_session.query(NormalRecord).filter_by(user_id=user.id).all()}
    if incoming_ids != existing:
        db_session.rollback()
        return jsonify(error='Record set mismatch -- re-fetch and retry'), 409

    if has_secret:
        secret_incoming = {r['id'] for r in data['secret_records']}
        secret_existing = {r.id for r in db_session.query(SecretRecord).filter_by(user_id=user.id).all()}
        if secret_incoming != secret_existing:
            db_session.rollback()
            return jsonify(error='Secret record set mismatch -- re-fetch and retry'), 409

    try:
        new_storage = 0
        for item in data['records']:
            rec = db_session.query(NormalRecord).filter_by(
                id=item['id'], user_id=user.id).first()
            if not rec:
                raise ValueError(f"Record {item['id']} not found")
            new_ct = item['ciphertext']
            new_size = len(new_ct.encode('utf-8'))
            rec.encrypted_payload = new_ct
            rec.size = new_size
            new_storage += new_size

        if has_secret:
            for item in data['secret_records']:
                rec = db_session.query(SecretRecord).filter_by(
                    id=item['id'], user_id=user.id).first()
                if not rec:
                    raise ValueError(f"Secret record {item['id']} not found")
                new_ct = item['ciphertext']
                new_size = len(new_ct.encode('utf-8'))
                rec.encrypted_payload = new_ct
                rec.size = new_size
                new_storage += new_size

        user.salt = data['new_salt']
        user.verifier_hash = hash_verifier(data['new_verifier'])
        user.storage_bytes = new_storage
        # Reset lockout counters on successful credential change
        user.failed_attempts = 0
        user.lock_until = None

        if has_secret:
            user.secret_salt = data['new_secret_salt']
            user.secret_verifier_hash = hash_verifier(data['new_secret_verifier'])
            user.secret_failed_attempts = 0
            user.secret_lock_until = None
            user.secret_reauthentication_required = False

        db_session.commit()
    except Exception as e:
        db_session.rollback()
        logger.error(f"Password change transaction failed: {e}")
        return jsonify(error='Password change failed. No data was modified.'), 500

    clear_user_sessions(user.id)
    session.clear()
    send_password_changed_alert(user)
    return jsonify(ok=True, message='Password changed. Please log in again.')

# ----------------------------------------------------------------------
# Secret vault
#
# Setup: client derives key2 from secret_code + secret_salt (provided by
# server), then computes the verifier for the secret vault and POSTs it.
# Unlock: client sends secret_verifier; server checks it.
# The combined final_key = HKDF(key1 + key2) is never sent to the server.

@app.route('/api/secret/get_salt', methods=['GET'])
def api_get_secret_salt():
    """Return the secret vault salt so the client can derive key2."""
    if 'user_id' not in session:
        return jsonify(error='Please log in'), 401
    user = db_session.query(User).filter_by(id=session['user_id']).first()
    if not user or not user.secret_salt:
        return jsonify(error='Secret vault not set up'), 404
    return jsonify(secret_salt=user.secret_salt)

@app.route('/secret/setup', methods=['GET', 'POST'])
def secret_setup():
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error='Please log in.'), 401
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = db_session.query(User).filter_by(id=session['user_id']).first()
    if not user:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error='User not found.'), 401
        return redirect(url_for('login'))
    if user.secret_salt:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error='Secret vault already set up.'), 400
        flash('Secret vault already set up.', 'info')
        return redirect(url_for('secret_unlock'))

    if request.method == 'GET':
        # Generate and session-store a salt for client-side key2 derivation
        salt = secrets.token_bytes(ARGON2_SALT_LEN)
        session['pending_secret_salt'] = base64.b64encode(salt).decode()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(salt=session['pending_secret_salt'])
        return render_template('secret_setup.html',
                               pending_salt=session['pending_secret_salt'])

    # POST: client sends secret_verifier derived from key2
    verifier_b64 = request.form.get('secret_verifier', '').strip()
    try:
        validate_verifier_b64(verifier_b64, 'secret_verifier')
    except ValueError as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error=str(e)), 400
        flash(str(e), 'danger')
        return redirect(url_for('secret_setup'))

    salt_b64 = session.pop('pending_secret_salt', None)
    if not salt_b64:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error='Session expired. Please try setup again.'), 400
        flash('Setup failed. Please try again.', 'danger')
        return redirect(url_for('secret_setup'))

    user.secret_salt = salt_b64
    user.secret_verifier_hash = hash_verifier(verifier_b64)
    db_session.commit()
    session['secret_unlocked'] = True
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
        return jsonify(success=True, salt=salt_b64)
    flash('Secret vault set up.', 'success')
    return redirect(url_for('secret_unlock'))

@app.route('/secret/unlock', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def secret_unlock():
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error='Please log in.'), 401
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = db_session.query(User).filter_by(id=session['user_id']).first()
    if not user:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error='User not found.'), 401
        return redirect(url_for('login'))
    if not user.secret_salt:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error='Secret vault not set up.'), 400
        flash('Secret vault not set up. Please set it up first.', 'info')
        return redirect(url_for('secret_setup'))
    if user.secret_reauthentication_required:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error='Re-authentication required.'), 403
        flash('Too many failures. Please re-authenticate.', 'warning')
        return redirect(url_for('secret_reauth'))
    if user.secret_lock_until and user.secret_lock_until > datetime.now():
        remaining = int((user.secret_lock_until - datetime.now()).total_seconds() // 60)
        msg = f'Secret vault locked. Try again in {remaining} minutes.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error=msg), 403
        flash(msg, 'danger')
        return redirect(url_for('secret_home'))

    if request.method == 'GET':
        return render_template('secret_unlock.html', secret_salt=user.secret_salt)

    # Client sends the secret_verifier (HKDF-derived from final_key = HKDF(key1+key2))
    verifier_b64 = request.form.get('secret_verifier', '').strip()
    try:
        validate_verifier_b64(verifier_b64, 'secret_verifier')
    except ValueError as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error=str(e)), 400
        flash(str(e), 'danger')
        return render_template('secret_unlock.html', secret_salt=user.secret_salt)

    if check_verifier(verifier_b64, user.secret_verifier_hash):
        # Re-fetch with row lock to securely reset secret counters
        user = db_session.query(User).filter_by(id=session['user_id']).with_for_update().first()
        user.secret_failed_attempts = 0
        user.secret_lock_until = None
        user.secret_reauthentication_required = False
        db_session.commit()
        session['secret_unlocked'] = True
        log_activity(session.get('vault_session_id'), "SECRET VAULT UNLOCKED")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(success=True)
        flash('Secret vault unlocked.', 'success')
        return redirect(url_for('secret_home'))

    # Re-fetch with row lock before applying the secret lockout counter increment
    user = db_session.query(User).filter_by(id=session['user_id']).with_for_update().first()
    if not apply_secret_lockout(user):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify(error='Too many failures. Re-auth required.'), 401
        return redirect(url_for('secret_reauth'))
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
        return jsonify(error='Incorrect secret code.'), 400
    return render_template('secret_unlock.html', secret_salt=user.secret_salt)

@app.route('/secret/home', methods=['GET'])
@limiter.limit("1000 per day")
def secret_home():
    return redirect(url_for('vault'))

@app.route('/change_password', methods=['GET'])
def change_password():
    return redirect(url_for('vault'))

@app.route('/api/user_quota', methods=['GET'])
def api_user_quota():
    if 'user_id' not in session:
        return jsonify(error='Unauthorized'), 401
    user = db_session.query(User).filter_by(id=session['user_id']).first()
    if not user:
        return jsonify(error='User not found'), 403
    return jsonify({
        'storage_bytes': user.storage_bytes or 0,
        'record_count': user.record_count or 0,
        'max_storage_mb': app.config['MAX_STORAGE_PER_USER_MB'],
        'max_records': app.config['MAX_RECORDS_PER_USER'],
        'name': user.name,
        'has_secret': bool(user.secret_salt)
    })

# Secret records API (mirror of normal records API)

def _require_secret_unlocked():
    if 'user_id' not in session:
        return None, (jsonify(error='Please log in.'), 401)
    if not session.get('secret_unlocked'):
        return None, (jsonify(error='Secret vault locked'), 403)
    user = db_session.query(User).filter_by(id=session['user_id']).first()
    if not user:
        return None, (jsonify(error='User not found'), 403)
    if not user.secret_salt:
        return None, (jsonify(error='Secret vault not set up'), 404)
    return user, None

@app.route('/api/secret/records', methods=['GET'])
@limiter.limit("1000 per day")
def api_list_secret_records():
    user, err = _require_secret_unlocked()
    if err:
        return err
    records = (db_session.query(SecretRecord)
               .filter_by(user_id=user.id)
               .order_by(SecretRecord.created_at.desc())
               .all())
    return jsonify([{'id': r.id, 'ciphertext': r.encrypted_payload,
                     'created_at': r.created_at.isoformat() if r.created_at else None}
                    for r in records])

@app.route('/api/secret/records', methods=['POST'])
@limiter.limit("1000 per hour")
def api_create_secret_record():
    user, err = _require_secret_unlocked()
    if err:
        return err

    data = request.get_json(silent=True)
    if not data or 'ciphertext' not in data:
        return jsonify(error='Missing ciphertext'), 400

    ciphertext = data['ciphertext']
    if not isinstance(ciphertext, str):
        return jsonify(error='ciphertext must be a string'), 400
    size = len(ciphertext.encode('utf-8'))
    if size > MAX_SINGLE_RECORD_BYTES:
        return jsonify(error='Single record exceeds maximum allowed size'), 400

    user = (db_session.query(User)
            .filter_by(id=session['user_id'])
            .with_for_update()
            .first())

    if user.record_count >= app.config['MAX_RECORDS_PER_USER']:
        return jsonify(error='Record limit reached'), 400

    max_bytes = app.config['MAX_STORAGE_PER_USER_MB'] * 1024 * 1024
    if user.storage_bytes + size > max_bytes:
        return jsonify(error='Storage quota exceeded'), 400

    rec = SecretRecord(id=generate_record_id(), user_id=user.id,
                       encrypted_payload=ciphertext, size=size)
    user.record_count += 1
    user.storage_bytes += size
    db_session.add(rec)
    db_session.commit()

    log_activity(session.get('vault_session_id'), "SECRET RECORD CREATED", f"ID: {rec.id}")
    return jsonify(id=rec.id), 201

@app.route('/api/secret/records/<record_id>', methods=['DELETE'])
@limiter.limit("200 per hour")
def api_delete_secret_record(record_id):
    user, err = _require_secret_unlocked()
    if err:
        return err

    user = (db_session.query(User)
            .filter_by(id=session['user_id'])
            .with_for_update()
            .first())
    rec = db_session.query(SecretRecord).filter_by(id=record_id, user_id=user.id).first()
    if not rec:
        return jsonify(error='Record not found'), 404

    user.record_count = max(0, user.record_count - 1)
    user.storage_bytes = max(0, user.storage_bytes - rec.size)
    db_session.delete(rec)
    db_session.commit()

    log_activity(session.get('vault_session_id'), "SECRET RECORD DELETED", f"ID: {record_id}")
    return jsonify(ok=True)

# ----------------------------------------------------------------------
# Secret vault re-authentication

SECRET_REAUTH_ATTEMPTS_PREFIX = "secret_reauth_attempts:"
SECRET_REAUTH_OTP_PREFIX = "secret_reauth_otp:"
SECRET_REAUTH_ATTEMPTS_TTL = 600
SECRET_REAUTH_OTP_TTL = 600

@app.route('/secret/reauth', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def secret_reauth():
    uid = session.get('user_id')
    if not uid:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = db_session.query(User).filter_by(id=uid).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    if not user.secret_reauthentication_required:
        flash('Re-authentication not required.', 'info')
        return redirect(url_for('secret_unlock'))

    if request.method == 'POST':
        code_str = f"{secrets.randbelow(1000000):06d}"
        redis_client.setex(f"{SECRET_REAUTH_ATTEMPTS_PREFIX}{uid}",
                           SECRET_REAUTH_ATTEMPTS_TTL, 0)
        # Store OTP in Redis (not session) to avoid Redis-access exfiltration
        redis_client.setex(
            f"{SECRET_REAUTH_OTP_PREFIX}{uid}",
            SECRET_REAUTH_OTP_TTL,
            json.dumps({'code': code_str, 'used': False})
        )
        ip = request.remote_addr
        loc = get_ip_location(ip)
        body = (
            "Hi,\n\n"
            f"Your Secret Vault re-authentication code is: {code_str} (Expires in 10 mins).\n\n"
            "Request Details:\n"
            "- Event: Secret Vault Re-authentication\n"
            f"- Location: {loc} (IP: {ip})\n"
            f"- Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            "— ZK Vault Team"
        )
        sent = send_email(safe_decrypt_email(user.encrypted_email),
                   '[ZK Vault] Secret Vault Re-authentication Code',
                   body, sync=True)
        if not sent:
            flash('Failed to send re-authentication code. Please try again.', 'danger')
            return render_template('secret_reauth.html')
        flash('OTP sent.', 'success')
        return render_template('secret_reauth_verify.html')

    return render_template('secret_reauth.html')

@app.route('/secret/reauth/verify', methods=['POST'])
@limiter.limit("5 per minute")
def secret_reauth_verify():
    uid = session.get('user_id')
    if not uid:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    user = db_session.query(User).filter_by(id=uid).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))

    otp = request.form.get('otp')
    otp_key = f"{SECRET_REAUTH_OTP_PREFIX}{uid}"
    try:
        otp_raw = redis_client.get(otp_key)
    except RedisError as e:
        logger.error(f"Redis secret reauth verify read: {e}")
        flash('Verification temporarily unavailable.', 'danger')
        return redirect(url_for('secret_reauth'))

    if not otp_raw:
        flash('OTP expired or not found. Request a new one.', 'danger')
        return redirect(url_for('secret_reauth'))

    otp_data = json.loads(otp_raw)
    stored_otp = otp_data.get('code')

    attempts_key = f"{SECRET_REAUTH_ATTEMPTS_PREFIX}{uid}"
    try:
        attempts = redis_client.incr(attempts_key)
        if attempts > 5:
            redis_client.delete(attempts_key)
            redis_client.delete(otp_key)
            flash('Too many attempts.', 'danger')
            return redirect(url_for('secret_reauth'))
        if not hmac.compare_digest(str(otp), str(stored_otp)):
            flash(f'Invalid OTP. {5 - attempts} attempts remaining.', 'danger')
            return redirect(url_for('secret_reauth'))
    except RedisError as e:
        logger.error(f"Redis secret reauth verify: {e}")
        flash('Verification temporarily unavailable.', 'danger')
        return redirect(url_for('secret_reauth'))

    user.secret_reauthentication_required = False
    db_session.commit()
    redis_client.delete(otp_key)
    redis_client.delete(attempts_key)
    flash('Re-authentication successful.', 'success')
    return redirect(url_for('secret_unlock'))

# ----------------------------------------------------------------------
# Account deletion (in-session)
#
# Security: requires the vault to be unlocked AND re-verifies the user's
# password (verifier) before proceeding, preventing CSRF / session-hijack
# from destroying data without knowing the password.

@app.route('/delete_account', methods=['POST'])
@limiter.limit("3 per hour")
def delete_account():
    uid = session.get('user_id')
    if not uid:
        flash('Please log in.', 'warning')
        return redirect(url_for('login'))
    if not session.get('vault_unlocked'):
        flash('Please unlock your vault first.', 'warning')
        return redirect(url_for('unlock_vault'))

    user = db_session.query(User).filter_by(id=uid).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))

    # Re-verify vault password before irreversible deletion
    verifier_b64 = request.form.get('verifier', '').strip()
    try:
        validate_verifier_b64(verifier_b64, 'verifier')
    except ValueError:
        flash('Password verification required to delete account.', 'danger')
        return redirect(url_for('home'))

    if not check_verifier(verifier_b64, user.verifier_hash):
        flash('Incorrect password. Account deletion cancelled.', 'danger')
        return redirect(url_for('home'))

    user_email = safe_decrypt_email(user.encrypted_email)
    clear_user_sessions(uid)
    db_session.query(NormalRecord).filter_by(user_id=uid).delete()
    db_session.query(SecretRecord).filter_by(user_id=uid).delete()
    db_session.delete(user)
    db_session.commit()
    send_account_deletion_alert(user_email)
    session.clear()
    flash('Account deleted.', 'info')
    return redirect(url_for('login'))

# ----------------------------------------------------------------------
# Logout

@app.route('/logout')
def logout():
    uid = session.pop('user_id', None)
    vsid = session.pop('vault_session_id', None)
    if uid:
        user = db_session.query(User).filter_by(id=uid).first()
        if user:
            try:
                send_unified_logout_email(user, vsid, request.remote_addr)
            except Exception as e:
                logger.error(f"Logout notification failed: {e}")
            if hasattr(session, 'sid'):
                remove_user_session(uid, session.sid)
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

# Monkeypatch Werkzeug to obfuscate the Server header version information
try:
    import werkzeug.serving
    werkzeug.serving.WSGIRequestHandler.version_string = lambda self: "SecurePersonalVault"
except Exception:
    pass

if __name__ == '__main__':
   # app.run(host='127.0.0.1', port=5000, debug=False)
   app.run(host='0.0.0.0', port=5000, debug=False)