#!/usr/bin/env bash
# One-shot setup for macOS / Linux
set -e
cd "$(dirname "$0")"
[ -f backend/.env ] || cp backend/.env.example backend/.env
[ -f frontend/.env ] || cp frontend/.env.example frontend/.env
python3 -m venv backend/.venv
backend/.venv/bin/pip install -r backend/requirements.txt
(cd frontend && npm install)
echo ""
echo "Done. Now edit backend/.env (GEMINI_API_KEY, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)."
echo "Run backend : cd backend && .venv/bin/uvicorn app.main:app --reload --port 8000"
echo "Run frontend: cd frontend && npm run dev   (opens http://localhost:5173)"
