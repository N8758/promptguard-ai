@echo off
REM One-shot setup for Windows
cd /d %~dp0
if not exist backend\.env copy backend\.env.example backend\.env
if not exist frontend\.env copy frontend\.env.example frontend\.env
python -m venv backend\.venv
backend\.venv\Scripts\pip install -r backend\requirements.txt
cd frontend && call npm install && cd ..
echo.
echo Done. Now edit backend\.env (GEMINI_API_KEY, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY).
echo Run backend : cd backend ^&^& .venv\Scripts\uvicorn app.main:app --reload --port 8000
echo Run frontend: cd frontend ^&^& npm run dev
