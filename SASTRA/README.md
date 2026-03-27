# SASTRA — Static Application Security Testing and Remediation Assistant

Lightweight SAST web application with a FastAPI backend and static frontend pages. Supports Python, Java, and C/C++ code scanning with ML-based severity prediction and optional LLM-powered remediation.

## Repository Structure

- `backend/` FastAPI app, auth, scanning APIs, DB, reports
- `frontend/` HTML pages (served by backend routes)
- `datasets/` training/test datasets and helper scripts

## Prerequisites

- Python `3.10+` (recommended `3.12`)
- `pip`
- Git

## 1) Install dependencies

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2) Run app (local)

```bash
cd backend
source .venv/bin/activate
export NVIDIA_API_KEY="your-nvidia-api-key"   # optional — only needed for LLM code fixes
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open: `http://127.0.0.1:8000`

> **Note:** On first run (or if `ml_engine.pkl.gz` is deleted), the ML model will train automatically on startup. This may take a few minutes. The app is ready once `Application startup complete` appears in the terminal.

## 3) Run on GitHub Codespaces

```bash
cd /workspaces/SASTRA/SASTRA/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export NVIDIA_API_KEY="your-nvidia-api-key"   # optional
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Then open the Codespaces `Ports` tab, forward port `8000`, and open the forwarded URL.

## Common Issues

### Virtualenv symlink error

If you see an error like:

`Unable to symlink ... python3`

Use:

```bash
python3 -m venv --copies .venv
```

### Stale UI after frontend changes

Hard refresh the browser:

- `Ctrl + Shift + R`

## Notes

- SQLite DB file is created at `backend/app/data/sast.db`
- Frontend pages are served by backend routes like `/dashboard.html`, `/new-scan.html`, `/scan-history.html`, `/settings.html`
