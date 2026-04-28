# StudyPlan — LD4 Back-End Documentation
**Dattatreya Sangabattula (IF2400108) · INF3002_EN · Vytautas Magnus University · 2026**

---

## 1. Overview

The LD4 back-end transforms the static LD3 frontend into a fully functional web application. The server is built with **Python Flask** serving a **SQLite** database, with all endpoints exposed as a RESTful JSON API consumed by both the original landing page and a new authenticated dashboard (`/dashboard-app`).

**Technology choices (matching LD2/LD3 tech stack table):**

| Layer | Technology | Reason |
|-------|-----------|--------|
| Backend | Python 3 + Flask | Lightweight, no external setup required; REST API |
| Database | SQLite (via `sqlite3` stdlib) | Zero-config, file-based, full SQL support; easy to migrate to PostgreSQL |
| Auth | PBKDF2-HMAC-SHA256 + custom JWT-style tokens | Industry-standard password hashing; stateless tokens |
| Security | Input validation, parameterised queries, HMAC signatures | Prevents injection, XSS, and forgery |

---

## 2. Database Schema

```sql
CREATE TABLE users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name   TEXT    NOT NULL,
    email       TEXT    NOT NULL UNIQUE,      -- validated: RFC 5322 pattern
    password    TEXT    NOT NULL,             -- PBKDF2 hash, never plaintext
    university  TEXT    NOT NULL DEFAULT 'Not specified',
    timezone    TEXT    NOT NULL DEFAULT 'EET',
    role        TEXT    NOT NULL DEFAULT 'student',  -- 'student' | 'admin'
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE tasks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title         TEXT    NOT NULL,           -- max 200 chars, validated
    course        TEXT    NOT NULL DEFAULT '',
    task_type     TEXT    NOT NULL DEFAULT 'Assignment',
    description   TEXT    NOT NULL DEFAULT '',
    deadline      TEXT    NOT NULL,           -- ISO-8601 datetime string
    notify_at     TEXT    NOT NULL DEFAULT '',
    notify_email  TEXT    NOT NULL DEFAULT '',
    priority      TEXT    NOT NULL DEFAULT 'medium',  -- 'high'|'medium'|'low'
    completed     INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
```

---

## 3. API Endpoints

### Authentication

| Method | Endpoint | Description | Auth required |
|--------|----------|-------------|---------------|
| POST | `/api/auth/register` | Create new user account | No |
| POST | `/api/auth/login` | Log in, receive token | No |
| GET | `/api/auth/me` | Get current user profile | Yes |
| PUT | `/api/auth/profile` | Update name/university/password | Yes |

### Tasks (CRUD)

| Method | Endpoint | Description | Auth required |
|--------|----------|-------------|---------------|
| GET | `/api/tasks` | List own tasks (with search & filter) | Yes |
| POST | `/api/tasks` | Create new task | Yes |
| GET | `/api/tasks/{id}` | Get single task | Yes (own tasks only) |
| PUT | `/api/tasks/{id}` | Update task | Yes (own tasks only) |
| DELETE | `/api/tasks/{id}` | Delete task | Yes (own tasks only) |
| PATCH | `/api/tasks/{id}/complete` | Toggle completed status | Yes (own tasks only) |
| GET | `/api/tasks/stats` | Dashboard statistics | Yes |

### Search & Filter Parameters (GET `/api/tasks`)

| Parameter | Description | Example |
|-----------|-------------|---------|
| `q` | Full-text search in title/course/description | `?q=research` |
| `priority` | Filter by priority | `?priority=high` |
| `type` | Filter by task type | `?type=Exam` |
| `completed` | Filter by completion | `?completed=0` |

---

## 4. Security Implementation

### 4.1 Password Hashing
Passwords are never stored in plaintext. The `hash_password()` function uses **PBKDF2-HMAC-SHA256** with 260,000 iterations and a 32-byte random salt — well above NIST SP 800-132 recommendations. Comparison uses `hmac.compare_digest()` to prevent timing attacks.

```
Format: pbkdf2$260000$<hex_salt>$<hex_derived_key>
```

### 4.2 Token Authentication
Tokens use a custom **HMAC-SHA256** signed structure (similar to JWT):
```
base64(header) . base64(payload) . base64(signature)
```
- Payload includes `user_id`, `role`, and `exp` (expiry timestamp, 7 days)
- Signature is verified with `hmac.compare_digest()` on every request
- Tokens are sent as `Authorization: Bearer <token>` header or read from `localStorage`

### 4.3 Input Validation & SQL Injection Prevention
All user input is validated before reaching the database:

- **Parameterised queries** — every database call uses `?` placeholders; no string interpolation
- **SQL injection regex check** — `no_sql_injection()` rejects strings containing `--`, `;`, `UNION`, `DROP`, etc.
- **Field-level rules** — email regex, datetime format check, whitelist for `priority` and `task_type`
- **Length limits** — all string fields are truncated at safe maximums (200 chars for title, 254 for email, etc.)
- **XSS prevention** — all values rendered in HTML templates are HTML-escaped with `esc()` in JavaScript

### 4.4 Access Control
- Unauthenticated users can only access the public landing page, login, and register pages
- Authenticated users can only read, update, or delete **their own** tasks (`WHERE id=? AND user_id=?`)
- Attempting to access another user's task returns `404` (not `403`) to prevent enumeration

### 4.5 Error Reporting
The API returns structured error responses that are displayed to the user:
```json
{ "errors": ["Task title is required.", "Deadline must be a valid date/time."] }
```
Frontend renders these as user-friendly messages — never raw stack traces.

---

## 5. User Roles

| Role | Can do |
|------|--------|
| **Unauthenticated** | View landing page; access `/login` and `/register` |
| **student** (default) | Full CRUD on own tasks; update own profile |
| **admin** | (Reserved for future: view all users; manage university list) |

---

## 6. File Structure

```
studyplan/
├── app.py               ← Flask backend (all routes, auth, validation)
├── studyplan.db         ← SQLite database (auto-created on first run)
├── start.sh             ← One-command startup script
├── MIGRATION.md         ← This document
└── public/              ← Static frontend files (served by Flask)
    ├── index.html       ← LD3 landing page (updated with auth links)
    ├── styles.css       ← Shared CSS (unchanged from LD3)
    ├── script.js        ← LD3 JS (unchanged from LD3)
    ├── login.html       ← New: login page
    ├── register.html    ← New: registration page
    └── dashboard-app.html ← New: authenticated task dashboard
```

---

## 7. Migration Plan (Server-to-Server)

### 7.1 Files to Transfer

| Item | Path | Notes |
|------|------|-------|
| Application code | `app.py` | Main Flask server |
| Frontend files | `public/` directory | All HTML, CSS, JS |
| Database | `studyplan.db` | Contains all user and task data |
| Startup script | `start.sh` | One-command launch |

### 7.2 Step-by-Step Deployment on a New Server

**Step 1 — Server preparation**
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Python 3 and pip
sudo apt install -y python3 python3-pip

# Install Flask
pip3 install flask
```

**Step 2 — Transfer files**
```bash
# From old server, create an archive
tar -czf studyplan_backup.tar.gz studyplan/

# Copy to new server (replace USER and SERVER with real values)
scp studyplan_backup.tar.gz USER@NEW_SERVER:/home/USER/

# On new server, extract
tar -xzf studyplan_backup.tar.gz
```

**Step 3 — Set environment variables**
```bash
# Generate a new strong secret key for the new server
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# To persist across reboots, add to ~/.bashrc or /etc/environment:
echo 'export SECRET_KEY="your_generated_key_here"' >> ~/.bashrc
```

**Step 4 — Run the application**
```bash
cd studyplan
bash start.sh
# Server is now running on http://localhost:5000
```

**Step 5 — Production setup (optional, for public deployment)**
```bash
# Install Gunicorn WSGI server
pip3 install gunicorn

# Run with Gunicorn (4 workers)
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Install Nginx as reverse proxy
sudo apt install -y nginx

# Nginx config at /etc/nginx/sites-available/studyplan:
# server {
#     listen 80;
#     server_name yourdomain.com;
#     location / {
#         proxy_pass http://127.0.0.1:5000;
#         proxy_set_header Host $host;
#         proxy_set_header X-Real-IP $remote_addr;
#     }
# }

sudo nginx -t && sudo systemctl reload nginx
```

**Step 6 — Configure domain/URL**
- Point DNS A record for `yourdomain.com` to the new server's IP
- Update Nginx `server_name` to match domain
- For HTTPS: `sudo certbot --nginx -d yourdomain.com`

### 7.3 Database Migration (SQLite → PostgreSQL)

For production scale, migrate from SQLite to PostgreSQL:

```bash
# Install PostgreSQL adapter
pip3 install psycopg2-binary

# Export SQLite data
sqlite3 studyplan.db .dump > studyplan_dump.sql

# Create PostgreSQL database
psql -U postgres -c "CREATE DATABASE studyplan;"

# Adapt schema (INTEGER AUTOINCREMENT → SERIAL, datetime → TIMESTAMP)
# Then import via psql
psql -U postgres -d studyplan < studyplan_schema_pg.sql
```

Modify `app.py` — replace `sqlite3.connect()` with `psycopg2.connect()` and `?` placeholders with `%s`.

### 7.4 Post-Migration Verification Tests

Run these checks after deploying to the new server:

| # | Test | Expected result |
|---|------|-----------------|
| 1 | `GET /` | Landing page loads, all CSS/JS files present |
| 2 | `GET /register` | Registration form renders |
| 3 | Register new user | 201 response, token returned, user in DB |
| 4 | `POST /api/auth/login` with valid credentials | 200, token returned |
| 5 | `POST /api/auth/login` with wrong password | 401, error message |
| 6 | Create task via dashboard | Task appears in task list and stats |
| 7 | Edit task | Changes saved correctly |
| 8 | Delete task | Task removed from DB |
| 9 | Search tasks | Only matching tasks returned |
| 10 | Access task of another user | 404 returned |
| 11 | Expired/invalid token | 401 returned |
| 12 | SQL injection attempt in title | Rejected with validation error |
| 13 | `GET /dashboard-app` without token | Redirected to `/login` |
| 14 | Theme toggle (dark/light) | Persists across page refreshes |

---

## 8. Known Limitations & Future Work (Practical Work No. 5)

- **Email notifications are not actually dispatched** — the `notify_at` and `notify_email` fields are stored and confirmed to the user, but a real email job queue (e.g., Celery + SMTP) requires the full backend deployment and an email API key (Mailgun/SendGrid). This is the backend infrastructure described in the tech stack.
- **University timezone auto-detection** — displays the saved timezone from registration; Google Maps API integration requires an API key and would be activated in production.
- **No admin panel UI** — the `admin` role is defined in the schema and enforced by `require_admin`, but no admin interface is built in this iteration.
