# Lightweight SAST Web App

Backend for the SASTRA platform. It serves the new frontend pages directly and exposes scanning/auth/report APIs.

## Features
- Static vulnerability scanning for Python, Java, and C/C++.
- File upload, ZIP upload, and pasted-code scanning.
- ML-enriched severity classification.
- CWE/OWASP mapping and PDF report export.
- Auth + role-based user management.

## Run (Windows PowerShell)
```powershell
cd backend
py -m venv .venv-win
.\.venv-win\Scripts\Activate.ps1
pip install -r requirements.txt
$env:NVIDIA_API_KEY="your-api-key"   # optional, only for /api/llm/codefix
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Run (Linux/macOS)
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export NVIDIA_API_KEY="your-api-key" # optional
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open `http://127.0.0.1:8000`.

## Data + generated files
- SQLite DB: `backend/app/data/sast.db`
- Generated rules: `backend/app/data/generated_rules.json`
- ML model: `backend/app/data/ml_engine.pkl.gz`
- Logs: `backend/app/data/logs/sast.log`

## Notes
- First startup can take longer due to rule/model initialization.
- LLM code-fix endpoint: `POST /api/llm/codefix` (requires API key).
