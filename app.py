"""
StudyPlan Backend - Flask + SQLite
LD4: Full backend with CRUD, auth, input validation, security
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
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g
 
# ─── App Setup ───────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder='public', static_url_path='')
 
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
DB_PATH    = os.path.join(os.path.dirname(__file__), 'studyplan.db')
TOKEN_TTL  = 60 * 60 * 24 * 7   # 7 days in seconds
 
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
    """Create all tables if they don't exist."""
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name   TEXT    NOT NULL,
            email       TEXT    NOT NULL UNIQUE,
            password    TEXT    NOT NULL,
            university  TEXT    NOT NULL DEFAULT 'Not specified',
            timezone    TEXT    NOT NULL DEFAULT 'EET',
            role        TEXT    NOT NULL DEFAULT 'student',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
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
 
        CREATE INDEX IF NOT EXISTS idx_tasks_user ON tasks(user_id);
        CREATE INDEX IF NOT EXISTS idx_tasks_deadline ON tasks(deadline);
    """)
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
 
    pw_hash = hash_password(password)
    cur = db.execute(
        'INSERT INTO users (full_name, email, password, university, timezone) VALUES (?,?,?,?,?)',
        (full_name, email, pw_hash, university, timezone_)
    )
    db.commit()
    user_id = cur.lastrowid
    token   = create_token(user_id, 'student')
    return jsonify({'token': token, 'user': {'id': user_id, 'full_name': full_name, 'email': email,
                                              'university': university, 'timezone': timezone_,
                                              'role': 'student'}}), 201
 
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
 
    token = create_token(user['id'], user['role'])
    return jsonify({'token': token, 'user': {
        'id': user['id'], 'full_name': user['full_name'], 'email': user['email'],
        'university': user['university'], 'timezone': user['timezone'], 'role': user['role']
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
    print("✅ StudyPlan backend started on http://localhost:5000")
    app.run(debug=True, port=5000)
 