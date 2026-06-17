"""
StudyPlan Backend - Flask + SQLite
LD4: Full backend with CRUD, auth, input validation, security
LD5: Email notifications, university management, timezone-aware scheduling
"""
 
import os
import re
import json
import time
import hmac
import base64
import hashlib
import secrets
import sqlite3
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g

try:
    import pytz
    HAS_PYTZ = True
except ImportError:
    HAS_PYTZ = False

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    HAS_SCHEDULER = True
except ImportError:
    HAS_SCHEDULER = False

# ─── App Setup ───────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder='public', static_url_path='')

SECRET_KEY       = os.environ.get('SECRET_KEY', secrets.token_hex(32))
DB_PATH          = os.path.join(os.path.dirname(__file__), 'studyplan.db')
TOKEN_TTL        = 60 * 60 * 24 * 7   # 7 days in seconds
VERIFY_TOKEN_TTL = 60 * 60 * 24       # 24 hours for email verification

# Email configuration (set via environment variables)
SMTP_HOST     = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT     = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER     = os.environ.get('SMTP_USER', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
SMTP_FROM     = os.environ.get('SMTP_FROM', SMTP_USER)
APP_URL       = os.environ.get('APP_URL', 'http://localhost:5000')

# Google Maps API key (set via environment variable)
MAPS_API_KEY  = os.environ.get('MAPS_API_KEY', '')

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
 
# ─── Database helpers ─────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db
 
@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db:
        db.close()
 
def init_db():
    """Create all tables if they don't exist and run lightweight migrations."""
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name           TEXT    NOT NULL,
            email               TEXT    NOT NULL UNIQUE,
            password            TEXT    NOT NULL,
            university          TEXT    NOT NULL DEFAULT 'Not specified',
            timezone            TEXT    NOT NULL DEFAULT 'EET',
            role                TEXT    NOT NULL DEFAULT 'student',
            email_verified      INTEGER NOT NULL DEFAULT 0,
            email_verify_token  TEXT    NOT NULL DEFAULT '',
            created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS universities (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL UNIQUE,
            location   TEXT    NOT NULL DEFAULT '',
            latitude   REAL,
            longitude  REAL,
            timezone   TEXT    NOT NULL DEFAULT 'UTC',
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title         TEXT    NOT NULL,
            course        TEXT    NOT NULL DEFAULT '',
            task_type     TEXT    NOT NULL DEFAULT 'Assignment',
            description   TEXT    NOT NULL DEFAULT '',
            deadline      TEXT    NOT NULL,
            notify_at     TEXT    NOT NULL DEFAULT '',
            notify_email  TEXT    NOT NULL DEFAULT '',
            priority      TEXT    NOT NULL DEFAULT 'medium',
            completed     INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS notification_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id    INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            email_to   TEXT    NOT NULL,
            status     TEXT    NOT NULL DEFAULT 'sent',
            sent_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_tasks_user ON tasks(user_id);
        CREATE INDEX IF NOT EXISTS idx_tasks_deadline ON tasks(deadline);
        CREATE INDEX IF NOT EXISTS idx_notif_task ON notification_log(task_id);
        CREATE INDEX IF NOT EXISTS idx_notif_user ON notification_log(user_id);
    """)
    # Lightweight migrations: add new columns to existing tables if missing
    existing = {row[1] for row in db.execute("PRAGMA table_info(users)")}
    if 'email_verified' not in existing:
        db.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")
    if 'email_verify_token' not in existing:
        db.execute("ALTER TABLE users ADD COLUMN email_verify_token TEXT NOT NULL DEFAULT ''")
    db.commit()
    db.close()
 
# ─── Password helpers ─────────────────────────────────────────────────────────
def hash_password(plain: str) -> str:
    """PBKDF2-HMAC-SHA256 with a random 32-byte salt, 260k iterations."""
    salt = secrets.token_hex(16)
    dk   = hashlib.pbkdf2_hmac('sha256', plain.encode(), salt.encode(), 260_000)
    return f"pbkdf2$260000${salt}${dk.hex()}"
 
def check_password(plain: str, hashed: str) -> bool:
    try:
        _, iters, salt, stored = hashed.split('$')
        dk = hashlib.pbkdf2_hmac('sha256', plain.encode(), salt.encode(), int(iters))
        return hmac.compare_digest(dk.hex(), stored)
    except Exception:
        return False
 
# ─── JWT-style token helpers ──────────────────────────────────────────────────
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def create_token(user_id: int, role: str) -> str:
    payload = json.dumps({'uid': user_id, 'role': role, 'exp': int(time.time()) + TOKEN_TTL})
    header  = _b64(b'{"alg":"HS256"}')
    body    = _b64(payload.encode())
    sig     = _b64(hmac.new(SECRET_KEY.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"

def decode_token(token: str) -> dict | None:
    try:
        header, body, sig = token.split('.')
        expected = _b64(hmac.new(SECRET_KEY.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(base64.urlsafe_b64decode(body + '=='))
        if data.get('exp', 0) < time.time():
            return None
        return data
    except Exception:
        return None

# ─── Email verification token helpers ────────────────────────────────────────
def create_verify_token(user_id: int, email: str) -> str:
    """Create a time-limited HMAC token for email verification."""
    payload = json.dumps({'uid': user_id, 'email': email, 'exp': int(time.time()) + VERIFY_TOKEN_TTL, 'purpose': 'verify'})
    body    = _b64(payload.encode())
    sig     = _b64(hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"

def decode_verify_token(token: str) -> dict | None:
    """Decode and validate an email verification token."""
    try:
        body, sig = token.split('.')
        expected  = _b64(hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(base64.urlsafe_b64decode(body + '=='))
        if data.get('exp', 0) < time.time():
            return None
        if data.get('purpose') != 'verify':
            return None
        return data
    except Exception:
        return None

# ─── Email sending helpers ────────────────────────────────────────────────────
def _send_email(to_addr: str, subject: str, html_body: str, text_body: str = '') -> bool:
    """Send an email via SMTP. Returns True on success, False on failure."""
    if not SMTP_USER or not SMTP_PASSWORD:
        logging.warning("SMTP credentials not configured – skipping email to %s", to_addr)
        return False
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = SMTP_FROM or SMTP_USER
        msg['To']      = to_addr
        if text_body:
            msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(msg['From'], [to_addr], msg.as_string())
        logging.info("Email sent to %s: %s", to_addr, subject)
        return True
    except Exception as exc:
        logging.error("Failed to send email to %s: %s", to_addr, exc)
        return False

def send_verification_email(email: str, full_name: str, token: str) -> bool:
    """Send a registration confirmation / email-verification email."""
    verify_url = f"{APP_URL}/api/auth/verify-email/{token}"
    html = f"""
    <html><body style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
      <h2 style="color:#4f46e5">Welcome to StudyPlan, {full_name}!</h2>
      <p>Thank you for registering. Please verify your email address to activate your account.</p>
      <p style="text-align:center">
        <a href="{verify_url}"
           style="background:#4f46e5;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;display:inline-block">
          Verify Email Address
        </a>
      </p>
      <p style="color:#666;font-size:12px">This link expires in 24 hours.<br>
      If you did not register, please ignore this email.</p>
    </body></html>"""
    text = f"Welcome to StudyPlan, {full_name}!\n\nVerify your email: {verify_url}\n\nLink expires in 24 hours."
    return _send_email(email, "Verify your StudyPlan email address", html, text)

def send_task_reminder_email(email: str, full_name: str, task: dict) -> bool:
    """Send a task deadline reminder email."""
    html = f"""
    <html><body style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
      <h2 style="color:#4f46e5">Task Reminder: {task['title']}</h2>
      <p>Hi {full_name}, this is a reminder about your upcoming task.</p>
      <table style="width:100%;border-collapse:collapse">
        <tr><td style="padding:8px;font-weight:bold">Task</td><td style="padding:8px">{task['title']}</td></tr>
        <tr style="background:#f3f4f6"><td style="padding:8px;font-weight:bold">Course</td><td style="padding:8px">{task.get('course','—')}</td></tr>
        <tr><td style="padding:8px;font-weight:bold">Type</td><td style="padding:8px">{task.get('task_type','—')}</td></tr>
        <tr style="background:#f3f4f6"><td style="padding:8px;font-weight:bold">Deadline</td><td style="padding:8px">{task['deadline']}</td></tr>
        <tr><td style="padding:8px;font-weight:bold">Priority</td><td style="padding:8px">{task.get('priority','medium').upper()}</td></tr>
      </table>
      <p style="color:#666;font-size:12px">Log in to StudyPlan to view or complete this task.</p>
    </body></html>"""
    text = f"Task Reminder: {task['title']}\nDeadline: {task['deadline']}\nCourse: {task.get('course','—')}"
    return _send_email(email, f"📚 Reminder: {task['title']} is due soon", html, text)

# ─── Google Maps / university timezone helpers ────────────────────────────────
def geocode_university(name: str) -> dict | None:
    """
    Use Google Maps Geocoding API to find coordinates and address of a university.
    Returns dict with keys: latitude, longitude, location; or None on failure.
    """
    if not HAS_REQUESTS or not MAPS_API_KEY:
        logging.warning("Google Maps API key not configured or requests library missing")
        return None
    try:
        url    = "https://maps.googleapis.com/maps/api/geocode/json"
        params = {'address': name, 'key': MAPS_API_KEY}
        resp   = _requests.get(url, params=params, timeout=10)
        data   = resp.json()
        if data.get('status') != 'OK' or not data.get('results'):
            return None
        result = data['results'][0]
        loc    = result['geometry']['location']
        return {
            'latitude':  loc['lat'],
            'longitude': loc['lng'],
            'location':  result.get('formatted_address', ''),
        }
    except Exception as exc:
        logging.error("Geocoding failed for %r: %s", name, exc)
        return None

def get_timezone_from_coords(lat: float, lng: float) -> str:
    """
    Use Google Maps Timezone API to determine timezone for coordinates.
    Returns IANA timezone string (e.g. 'Europe/Vilnius') or 'UTC' on failure.
    """
    if not HAS_REQUESTS or not MAPS_API_KEY:
        return 'UTC'
    try:
        url    = "https://maps.googleapis.com/maps/api/timezone/json"
        params = {
            'location': f"{lat},{lng}",
            'timestamp': int(time.time()),
            'key': MAPS_API_KEY,
        }
        resp = _requests.get(url, params=params, timeout=10)
        data = resp.json()
        if data.get('status') == 'OK':
            return data.get('timeZoneId', 'UTC')
    except Exception as exc:
        logging.error("Timezone lookup failed for (%s,%s): %s", lat, lng, exc)
    return 'UTC'

def lookup_or_create_university(name: str, db) -> str:
    """
    Return the timezone for a university name.
    If the university is not in the DB, geocode it via Google Maps and persist it.
    Returns timezone string.
    """
    row = db.execute('SELECT timezone FROM universities WHERE name=?', (name,)).fetchone()
    if row:
        return row['timezone']

    # University not found — geocode it
    geo = geocode_university(name)
    if geo:
        tz = get_timezone_from_coords(geo['latitude'], geo['longitude'])
        try:
            db.execute(
                'INSERT OR IGNORE INTO universities (name, location, latitude, longitude, timezone) VALUES (?,?,?,?,?)',
                (name, geo['location'], geo['latitude'], geo['longitude'], tz)
            )
            db.commit()
            logging.info("Added new university %r with timezone %s", name, tz)
        except Exception as exc:
            logging.error("Could not save university %r: %s", name, exc)
        return tz
    return 'UTC'
 
# ─── Auth decorator ───────────────────────────────────────────────────────────
def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = None
        auth  = request.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            token = auth[7:]
        if not token:
            token = request.cookies.get('sp_token')
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        data = decode_token(token)
        if not data:
            return jsonify({'error': 'Invalid or expired token'}), 401
        g.current_user_id   = data['uid']
        g.current_user_role = data['role']
        return f(*args, **kwargs)
    return wrapper
 
def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if getattr(g, 'current_user_role', None) != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return require_auth(wrapper)
 
# ─── Input validation helpers ─────────────────────────────────────────────────
ALLOWED_TASK_TYPES = {'Assignment', 'Exam', 'Project', 'Reading', 'Lab', 'Presentation', 'Other'}
ALLOWED_PRIORITIES = {'high', 'medium', 'low'}
 
def sanitize_str(s: str, max_len: int = 255) -> str:
    """Strip leading/trailing whitespace and truncate."""
    return str(s).strip()[:max_len]
 
def validate_email(email: str) -> bool:
    return bool(re.fullmatch(r'[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-]+', email))
 
def validate_datetime(dt: str) -> bool:
    """Accept ISO-8601 style strings or HTML datetime-local format."""
    for fmt in ('%Y-%m-%dT%H:%M', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S'):
        try:
            datetime.strptime(dt, fmt)
            return True
        except ValueError:
            continue
    return False
 
def no_sql_injection(s: str) -> bool:
    """Reject strings containing common SQL injection patterns."""
    bad = re.compile(r"(--|;|/\*|\*/|xp_|\bOR\b|\bAND\b|\bDROP\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bEXEC\b|\bUNION\b|\bSELECT\b)",
                     re.IGNORECASE)
    return not bad.search(s)
 
def validate_task_input(data: dict) -> list[str]:
    """Returns list of error messages (empty = valid)."""
    errors = []
    title = data.get('title', '').strip()
    if not title:
        errors.append('Task title is required.')
    elif len(title) > 200:
        errors.append('Task title must be 200 characters or fewer.')
    elif not no_sql_injection(title):
        errors.append('Task title contains invalid characters.')
 
    course = data.get('course', '').strip()
    if len(course) > 100:
        errors.append('Course name must be 100 characters or fewer.')
 
    task_type = data.get('task_type', 'Assignment')
    if task_type not in ALLOWED_TASK_TYPES:
        errors.append(f"Task type must be one of: {', '.join(sorted(ALLOWED_TASK_TYPES))}.")
 
    priority = data.get('priority', 'medium')
    if priority not in ALLOWED_PRIORITIES:
        errors.append('Priority must be high, medium, or low.')
 
    deadline = data.get('deadline', '').strip()
    if not deadline:
        errors.append('Deadline is required.')
    elif not validate_datetime(deadline):
        errors.append('Deadline must be a valid date/time (YYYY-MM-DDTHH:MM).')
 
    notify_email = data.get('notify_email', '').strip()
    if notify_email and not validate_email(notify_email):
        errors.append('Notification email is not a valid email address.')
 
    return errors
 
def validate_registration_input(data: dict) -> list[str]:
    errors = []
    name = data.get('full_name', '').strip()
    if not name:
        errors.append('Full name is required.')
    elif len(name) > 100:
        errors.append('Full name must be 100 characters or fewer.')
    elif re.search(r'[<>"\';&]', name):
        errors.append('Full name contains invalid characters.')
 
    email = data.get('email', '').strip()
    if not email:
        errors.append('Email is required.')
    elif not validate_email(email):
        errors.append('Email address is not valid.')
 
    password = data.get('password', '')
    if len(password) < 8:
        errors.append('Password must be at least 8 characters.')
    elif not re.search(r'[A-Za-z]', password):
        errors.append('Password must contain at least one letter.')
    elif not re.search(r'[0-9]', password):
        errors.append('Password must contain at least one digit.')
 
    return errors
 
# ─── Static pages ─────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('public', 'index.html')
 
@app.route('/login')
def login_page():
    return send_from_directory('public', 'login.html')
 
@app.route('/register')
def register_page():
    return send_from_directory('public', 'register.html')
 
@app.route('/dashboard-app')
def dashboard_app_page():
    return send_from_directory('public', 'dashboard-app.html')
 
# ─── Auth routes ──────────────────────────────────────────────────────────────
@app.route('/api/auth/register', methods=['POST'])
def api_register():
    data   = request.get_json(silent=True) or {}
    errors = validate_registration_input(data)
    if errors:
        return jsonify({'errors': errors}), 400

    email      = sanitize_str(data['email']).lower()
    full_name  = sanitize_str(data['full_name'])
    university = sanitize_str(data.get('university', 'Not specified'), 200)
    timezone_  = sanitize_str(data.get('timezone', 'EET'), 50)
    password   = data['password']

    db = get_db()
    if db.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
        return jsonify({'errors': ['An account with that email already exists.']}), 409

    # Auto-detect university timezone via Google Maps if a real university name given
    if university and university != 'Not specified' and MAPS_API_KEY:
        detected_tz = lookup_or_create_university(university, db)
        if detected_tz and detected_tz != 'UTC':
            timezone_ = detected_tz

    verify_token = create_verify_token(0, email)  # placeholder uid=0 before insert
    pw_hash      = hash_password(password)
    cur = db.execute(
        'INSERT INTO users (full_name, email, password, university, timezone, email_verified, email_verify_token) VALUES (?,?,?,?,?,0,?)',
        (full_name, email, pw_hash, university, timezone_, verify_token)
    )
    db.commit()
    user_id      = cur.lastrowid
    # Re-create verify token with the real user_id
    verify_token = create_verify_token(user_id, email)
    db.execute('UPDATE users SET email_verify_token=? WHERE id=?', (verify_token, user_id))
    db.commit()

    # Send verification email (non-blocking; failure does not abort registration)
    send_verification_email(email, full_name, verify_token)

    token = create_token(user_id, 'student')
    return jsonify({
        'token': token,
        'user': {
            'id': user_id, 'full_name': full_name, 'email': email,
            'university': university, 'timezone': timezone_,
            'role': 'student', 'email_verified': False,
        },
        'message': 'Registration successful. Please check your email to verify your account.',
    }), 201

@app.route('/api/auth/verify-email/<token>', methods=['GET'])
def api_verify_email(token):
    data = decode_verify_token(token)
    if not data:
        return jsonify({'error': 'Invalid or expired verification link.'}), 400
    db   = get_db()
    user = db.execute('SELECT id, email_verify_token, email_verified FROM users WHERE id=?', (data['uid'],)).fetchone()
    if not user:
        return jsonify({'error': 'User not found.'}), 404
    if user['email_verified']:
        return jsonify({'message': 'Email is already verified.'})
    if not hmac.compare_digest(user['email_verify_token'], token):
        return jsonify({'error': 'Invalid verification token.'}), 400
    db.execute("UPDATE users SET email_verified=1, email_verify_token='' WHERE id=?", (data['uid'],))
    db.commit()
    return jsonify({'message': 'Email verified successfully. You can now log in.'})

@app.route('/api/auth/resend-verification', methods=['POST'])
def api_resend_verification():
    data  = request.get_json(silent=True) or {}
    email = sanitize_str(data.get('email', '')).lower()
    if not email:
        return jsonify({'errors': ['Email is required.']}), 400
    db   = get_db()
    user = db.execute('SELECT id, full_name, email, email_verified FROM users WHERE email=?', (email,)).fetchone()
    if not user:
        # Return success to prevent user enumeration
        return jsonify({'message': 'If this email is registered, a verification link has been sent.'})
    if user['email_verified']:
        return jsonify({'message': 'Email is already verified.'})
    new_token = create_verify_token(user['id'], user['email'])
    db.execute('UPDATE users SET email_verify_token=? WHERE id=?', (new_token, user['id']))
    db.commit()
    send_verification_email(user['email'], user['full_name'], new_token)
    return jsonify({'message': 'If this email is registered, a verification link has been sent.'})

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data  = request.get_json(silent=True) or {}
    email = sanitize_str(data.get('email', '')).lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'errors': ['Email and password are required.']}), 400

    db   = get_db()
    user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()

    if not user or not check_password(password, user['password']):
        return jsonify({'errors': ['Invalid email or password.']}), 401

    if not user['email_verified']:
        return jsonify({'errors': ['Please verify your email address before logging in. Check your inbox for a verification link.']}), 403

    token = create_token(user['id'], user['role'])
    return jsonify({'token': token, 'user': {
        'id': user['id'], 'full_name': user['full_name'], 'email': user['email'],
        'university': user['university'], 'timezone': user['timezone'], 'role': user['role'],
        'email_verified': bool(user['email_verified']),
    }})
 
@app.route('/api/auth/me', methods=['GET'])
@require_auth
def api_me():
    db   = get_db()
    user = db.execute('SELECT id, full_name, email, university, timezone, role, created_at FROM users WHERE id=?',
                      (g.current_user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(dict(user))
 
@app.route('/api/auth/profile', methods=['PUT'])
@require_auth
def api_update_profile():
    data = request.get_json(silent=True) or {}
    errors = []
 
    updates = {}
    if 'full_name' in data:
        name = sanitize_str(data['full_name'])
        if not name:
            errors.append('Full name cannot be empty.')
        elif len(name) > 100:
            errors.append('Full name must be 100 characters or fewer.')
        elif re.search(r'[<>"\';&]', name):
            errors.append('Full name contains invalid characters.')
        else:
            updates['full_name'] = name
 
    if 'university' in data:
        updates['university'] = sanitize_str(data['university'], 200)
 
    if 'timezone' in data:
        updates['timezone'] = sanitize_str(data['timezone'], 50)
 
    if 'new_password' in data:
        new_pw = data['new_password']
        if len(new_pw) < 8:
            errors.append('New password must be at least 8 characters.')
        else:
            old_pw = data.get('current_password', '')
            db   = get_db()
            user = db.execute('SELECT password FROM users WHERE id=?', (g.current_user_id,)).fetchone()
            if not check_password(old_pw, user['password']):
                errors.append('Current password is incorrect.')
            else:
                updates['password'] = hash_password(new_pw)
 
    if errors:
        return jsonify({'errors': errors}), 400
 
    if not updates:
        return jsonify({'message': 'No changes provided.'})
 
    db  = get_db()
    set_clause = ', '.join(f"{k}=?" for k in updates)
    db.execute(f"UPDATE users SET {set_clause} WHERE id=?", (*updates.values(), g.current_user_id))
    db.commit()
    return jsonify({'message': 'Profile updated successfully.'})
 
# ─── Task CRUD ────────────────────────────────────────────────────────────────
@app.route('/api/tasks', methods=['GET'])
@require_auth
def api_get_tasks():
    db = get_db()
    # Search & filter
    search   = request.args.get('q', '').strip()
    priority = request.args.get('priority', '').strip()
    task_type = request.args.get('type', '').strip()
    completed = request.args.get('completed', '').strip()
 
    query  = 'SELECT * FROM tasks WHERE user_id=?'
    params = [g.current_user_id]
 
    if search:
        query  += ' AND (title LIKE ? OR course LIKE ? OR description LIKE ?)'
        like    = f'%{search}%'
        params += [like, like, like]
 
    if priority and priority in ALLOWED_PRIORITIES:
        query  += ' AND priority=?'
        params += [priority]
 
    if task_type and task_type in ALLOWED_TASK_TYPES:
        query  += ' AND task_type=?'
        params += [task_type]
 
    if completed in ('0', '1'):
        query  += ' AND completed=?'
        params += [int(completed)]
 
    query += ' ORDER BY deadline ASC'
 
    rows  = db.execute(query, params).fetchall()
    tasks = [dict(r) for r in rows]
 
    if not tasks and search:
        return jsonify({'tasks': [], 'message': f'No tasks found matching "{search}".'})
 
    return jsonify({'tasks': tasks})
 
@app.route('/api/tasks', methods=['POST'])
@require_auth
def api_create_task():
    data   = request.get_json(silent=True) or {}
    errors = validate_task_input(data)
    if errors:
        return jsonify({'errors': errors}), 400
 
    title        = sanitize_str(data['title'], 200)
    course       = sanitize_str(data.get('course', ''), 100)
    task_type    = data.get('task_type', 'Assignment')
    description  = sanitize_str(data.get('description', ''), 1000)
    deadline     = sanitize_str(data['deadline'], 50)
    notify_at    = sanitize_str(data.get('notify_at', ''), 50)
    notify_email = sanitize_str(data.get('notify_email', ''), 254)
    priority     = data.get('priority', 'medium')
 
    db  = get_db()
    cur = db.execute(
        '''INSERT INTO tasks (user_id, title, course, task_type, description, deadline,
           notify_at, notify_email, priority)
           VALUES (?,?,?,?,?,?,?,?,?)''',
        (g.current_user_id, title, course, task_type, description, deadline,
         notify_at, notify_email, priority)
    )
    db.commit()
    task = dict(db.execute('SELECT * FROM tasks WHERE id=?', (cur.lastrowid,)).fetchone())
    return jsonify({'task': task, 'message': f'Task "{title}" created successfully.'}), 201
 
@app.route('/api/tasks/<int:task_id>', methods=['GET'])
@require_auth
def api_get_task(task_id):
    db   = get_db()
    task = db.execute('SELECT * FROM tasks WHERE id=? AND user_id=?',
                      (task_id, g.current_user_id)).fetchone()
    if not task:
        return jsonify({'error': 'Task not found or access denied.'}), 404
    return jsonify(dict(task))
 
@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
@require_auth
def api_update_task(task_id):
    db   = get_db()
    task = db.execute('SELECT * FROM tasks WHERE id=? AND user_id=?',
                      (task_id, g.current_user_id)).fetchone()
    if not task:
        return jsonify({'error': 'Task not found or access denied.'}), 404
 
    data   = request.get_json(silent=True) or {}
    errors = validate_task_input(data)
    if errors:
        return jsonify({'errors': errors}), 400
 
    title        = sanitize_str(data['title'], 200)
    course       = sanitize_str(data.get('course', ''), 100)
    task_type    = data.get('task_type', 'Assignment')
    description  = sanitize_str(data.get('description', ''), 1000)
    deadline     = sanitize_str(data['deadline'], 50)
    notify_at    = sanitize_str(data.get('notify_at', ''), 50)
    notify_email = sanitize_str(data.get('notify_email', ''), 254)
    priority     = data.get('priority', 'medium')
    completed    = 1 if data.get('completed') else 0
 
    db.execute(
        '''UPDATE tasks SET title=?, course=?, task_type=?, description=?, deadline=?,
           notify_at=?, notify_email=?, priority=?, completed=?,
           updated_at=datetime('now')
           WHERE id=? AND user_id=?''',
        (title, course, task_type, description, deadline, notify_at, notify_email,
         priority, completed, task_id, g.current_user_id)
    )
    db.commit()
    updated = dict(db.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone())
    return jsonify({'task': updated, 'message': 'Task updated successfully.'})
 
@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@require_auth
def api_delete_task(task_id):
    db   = get_db()
    task = db.execute('SELECT * FROM tasks WHERE id=? AND user_id=?',
                      (task_id, g.current_user_id)).fetchone()
    if not task:
        return jsonify({'error': 'Task not found or access denied.'}), 404
 
    db.execute('DELETE FROM tasks WHERE id=? AND user_id=?', (task_id, g.current_user_id))
    db.commit()
    return jsonify({'message': f'Task "{task["title"]}" deleted successfully.'})
 
@app.route('/api/tasks/<int:task_id>/complete', methods=['PATCH'])
@require_auth
def api_toggle_complete(task_id):
    db   = get_db()
    task = db.execute('SELECT * FROM tasks WHERE id=? AND user_id=?',
                      (task_id, g.current_user_id)).fetchone()
    if not task:
        return jsonify({'error': 'Task not found or access denied.'}), 404
 
    new_state = 0 if task['completed'] else 1
    db.execute("UPDATE tasks SET completed=?, updated_at=datetime('now') WHERE id=?",
               (new_state, task_id))
    db.commit()
    status = 'completed' if new_state else 'pending'
    return jsonify({'message': f'Task marked as {status}.', 'completed': new_state})
 
# ─── Stats endpoint ───────────────────────────────────────────────────────────
@app.route('/api/tasks/stats', methods=['GET'])
@require_auth
def api_task_stats():
    db  = get_db()
    uid = g.current_user_id
    total     = db.execute('SELECT COUNT(*) FROM tasks WHERE user_id=?', (uid,)).fetchone()[0]
    completed = db.execute('SELECT COUNT(*) FROM tasks WHERE user_id=? AND completed=1', (uid,)).fetchone()[0]
    pending   = total - completed
    upcoming  = db.execute(
        "SELECT * FROM tasks WHERE user_id=? AND completed=0 ORDER BY deadline ASC LIMIT 5", (uid,)
    ).fetchall()
    return jsonify({
        'total': total, 'completed': completed, 'pending': pending,
        'upcoming': [dict(r) for r in upcoming]
    })
 
# ─── University endpoints ─────────────────────────────────────────────────────
@app.route('/api/universities', methods=['GET'])
def api_list_universities():
    """List all universities in the database (public endpoint)."""
    db   = get_db()
    rows = db.execute('SELECT id, name, location, timezone FROM universities ORDER BY name ASC').fetchall()
    return jsonify({'universities': [dict(r) for r in rows]})

@app.route('/api/universities', methods=['POST'])
@require_auth
def api_add_university():
    """
    Add a new university. If a Google Maps API key is configured, the server
    auto-geocodes the university name to fill location and timezone.
    """
    data = request.get_json(silent=True) or {}
    name = sanitize_str(data.get('name', ''), 200).strip()
    if not name:
        return jsonify({'errors': ['University name is required.']}), 400

    db = get_db()
    existing = db.execute('SELECT id, name, location, timezone FROM universities WHERE name=?', (name,)).fetchone()
    if existing:
        return jsonify({'university': dict(existing), 'message': 'University already exists.'}), 200

    geo      = geocode_university(name)
    location = geo['location'] if geo else sanitize_str(data.get('location', ''), 300)
    lat      = geo['latitude']  if geo else data.get('latitude')
    lng      = geo['longitude'] if geo else data.get('longitude')
    tz       = get_timezone_from_coords(lat, lng) if (geo and lat and lng) else sanitize_str(data.get('timezone', 'UTC'), 50)

    cur = db.execute(
        'INSERT INTO universities (name, location, latitude, longitude, timezone) VALUES (?,?,?,?,?)',
        (name, location, lat, lng, tz)
    )
    db.commit()
    univ = dict(db.execute('SELECT * FROM universities WHERE id=?', (cur.lastrowid,)).fetchone())
    return jsonify({'university': univ, 'message': f'University "{name}" added with timezone {tz}.'}), 201

# ─── Notification log endpoints ───────────────────────────────────────────────
@app.route('/api/notifications', methods=['GET'])
@require_auth
def api_list_notifications():
    """
    Students see their own notifications.
    Admins can see all notifications (optionally filtered by user_id query param).
    """
    db  = get_db()
    uid = g.current_user_id

    if g.current_user_role == 'admin':
        filter_uid = request.args.get('user_id', '').strip()
        if filter_uid and filter_uid.isdigit():
            rows = db.execute(
                '''SELECT n.*, t.title as task_title, u.email as user_email
                   FROM notification_log n
                   JOIN tasks t ON t.id=n.task_id
                   JOIN users u ON u.id=n.user_id
                   WHERE n.user_id=? ORDER BY n.sent_at DESC LIMIT 200''',
                (int(filter_uid),)
            ).fetchall()
        else:
            rows = db.execute(
                '''SELECT n.*, t.title as task_title, u.email as user_email
                   FROM notification_log n
                   JOIN tasks t ON t.id=n.task_id
                   JOIN users u ON u.id=n.user_id
                   ORDER BY n.sent_at DESC LIMIT 200'''
            ).fetchall()
    else:
        rows = db.execute(
            '''SELECT n.*, t.title as task_title
               FROM notification_log n
               JOIN tasks t ON t.id=n.task_id
               WHERE n.user_id=? ORDER BY n.sent_at DESC LIMIT 100''',
            (uid,)
        ).fetchall()

    return jsonify({'notifications': [dict(r) for r in rows]})

# ─── Background scheduler: task deadline reminders ───────────────────────────
def _send_due_notifications():
    """
    Cron job: find tasks whose notify_at time has passed (in user's timezone),
    have not yet been notified, and have a notify_email set.  Send reminders.
    """
    now_utc = datetime.now(timezone.utc)
    try:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")

        # Fetch tasks that have a notify_at set, are not completed, and have
        # not already been logged as notified.
        tasks = db.execute(
            """SELECT t.*, u.full_name, u.email as user_email, u.timezone as user_tz
               FROM tasks t
               JOIN users u ON u.id = t.user_id
               WHERE t.notify_at != ''
                 AND t.completed = 0
                 AND t.notify_email != ''
                 AND t.id NOT IN (SELECT DISTINCT task_id FROM notification_log)
            """
        ).fetchall()

        for task in tasks:
            task = dict(task)
            notify_at_str = task.get('notify_at', '')
            if not notify_at_str:
                continue

            # Parse the notify_at datetime string
            notify_dt = None
            for fmt in ('%Y-%m-%dT%H:%M', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M'):
                try:
                    notify_dt = datetime.strptime(notify_at_str, fmt)
                    break
                except ValueError:
                    continue
            if notify_dt is None:
                continue

            # Interpret notify_at as being in the user's local timezone
            user_tz_name = task.get('user_tz', 'UTC')
            if HAS_PYTZ:
                try:
                    user_tz = pytz.timezone(user_tz_name)
                    notify_dt_aware = user_tz.localize(notify_dt)
                except Exception:
                    notify_dt_aware = notify_dt.replace(tzinfo=timezone.utc)
            else:
                notify_dt_aware = notify_dt.replace(tzinfo=timezone.utc)

            if now_utc >= notify_dt_aware.astimezone(timezone.utc):
                # Time to send the reminder
                email_to  = task['notify_email']
                full_name = task.get('full_name', 'Student')
                sent      = send_task_reminder_email(email_to, full_name, task)
                status    = 'sent' if sent else 'failed'
                db.execute(
                    'INSERT INTO notification_log (task_id, user_id, email_to, status) VALUES (?,?,?,?)',
                    (task['id'], task['user_id'], email_to, status)
                )
                db.commit()
                logging.info("Notification %s for task %d to %s", status, task['id'], email_to)
    except Exception as exc:
        logging.error("Notification scheduler error: %s", exc)
    finally:
        try:
            db.close()
        except Exception:
            pass

def start_scheduler():
    """Start the APScheduler background job if the library is available."""
    if not HAS_SCHEDULER:
        logging.warning("APScheduler not installed – background notifications disabled.")
        return
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(_send_due_notifications, 'interval', minutes=1, id='notify_job',
                      max_instances=1, coalesce=True)
    scheduler.start()
    logging.info("Background notification scheduler started (runs every minute).")

# ─── Error handlers ───────────────────────────────────────────────────────────
@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': 'Bad request', 'details': str(e)}), 400
 
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404
 
@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'error': 'Method not allowed'}), 405
 
@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500
 
# ─── Run ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    start_scheduler()
    print("✅ StudyPlan backend started on http://localhost:5000")
    app.run(debug=True, port=5000)
 