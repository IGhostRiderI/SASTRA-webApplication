# SASTRA — Static Application Security Testing and Remediation Assistant

Lightweight SAST web application. FastAPI backend serves static HTML pages. Scans Python, Java, and C/C++ source for vulnerabilities with ML-based severity prediction and optional LLM-powered remediation.

## Repository Structure

- `SASTRA/backend/` - FastAPI app, auth, scanning APIs, DB, reports
- `SASTRA/frontend/` - HTML pages served by backend routes
- `datasets/` - Training and test datasets

## Prerequisites

- Python 3.10+ (3.12 recommended)
- pip
- Git

## 1. Install

```bash
cd SASTRA/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2. Configure environment

Create a `.env` or export the following. Never commit real values.

```bash
export NVIDIA_API_KEY="nvidia-api-key"            # optional, for LLM code fix
export NVIDIA_CHAT_API_KEY="nvidia-chat-api-key"  # optional, for chatbot
export SUPERADMIN_USERNAME="admin"
export SUPERADMIN_PASSWORD="change-me"
export JWT_SECRET="secret"
```

## 3. Run

```bash
cd SASTRA/backend
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`.

On the first run (or if `ml_engine.pkl.gz` is deleted), the ML model trains on startup. The app is ready once `Application startup complete` appears in the terminal.

## Run on GitHub Codespaces

```bash
cd /workspaces/SASTRA-webApplication/SASTRA/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# export environment variables as above
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open the Codespaces `Ports` tab, forward port `8000`, and open the forwarded URL.

## Common Issues

### Virtualenv symlink error

If `Unable to symlink ... python3` appears:

```bash
python3 -m venv --copies .venv
```

### Stale UI after frontend changes

Hard refresh: `Ctrl + Shift + R`.

## Notes

- SQLite DB file is created at `SASTRA/backend/app/data/sast.db`.
- Frontend pages are served by backend routes such as `/dashboard.html`, `/new-scan.html`, `/scan-history.html`, `/settings.html`.
