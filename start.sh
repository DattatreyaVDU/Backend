#!/bin/bash
# StudyPlan Backend Startup Script
# Run: bash start.sh
# Access: http://localhost:5000

cd "$(dirname "$0")"

echo "=================================================="
echo "  📚 StudyPlan Backend — LD5"
echo "=================================================="

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "❌ Python 3 is required. Install it and try again."
  exit 1
fi

# Check / install required packages
for pkg in flask apscheduler pytz requests; do
  if ! python3 -c "import ${pkg}" 2>/dev/null; then
    echo "⚠  ${pkg} not found. Installing..."
    pip3 install "${pkg}" --break-system-packages 2>/dev/null || pip3 install "${pkg}"
  fi
done

# Set secret key if not set
export SECRET_KEY="${SECRET_KEY:-$(python3 -c 'import secrets; print(secrets.token_hex(32))')}"

echo "✅ Starting server on http://localhost:5000"
echo "   - Home:       http://localhost:5000/"
echo "   - Register:   http://localhost:5000/register"
echo "   - Login:      http://localhost:5000/login"
echo "   - Dashboard:  http://localhost:5000/dashboard-app"
echo ""
echo "   Configure email/Google Maps via environment variables (see .env.example)"
echo ""

python3 app.py
