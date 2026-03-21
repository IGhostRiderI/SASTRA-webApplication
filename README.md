# Applied-project-testing-new-frontend-

Lightweight SAST web application with a FastAPI backend and static frontend pages served by the backend.

## Repository Structure

- `backend/` FastAPI app, auth, scanning APIs, DB, reports
- `frontend/` HTML pages (served by backend routes)
- `datasets/` training/test datasets and helper scripts

## Prerequisites

- Python `3.10+` (recommended `3.12`)
- `pip`
- Git

## 1) Clone the repository

```bash
git clone https://github.com/IGhostRiderI/Applied-project-testing-new-frontend-.git
cd Applied-project-testing-new-frontend-
```

## 2) Create and activate virtual environment

### Linux/macOS

```bash
cd backend
python3 -m venv --copies .venv
source .venv/bin/activate
```

### Windows PowerShell

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

## 3) Install dependencies

```bash
pip install -r requirements.txt
```

## 4) (Optional) Set NVIDIA key for LLM code-fix endpoint

Only needed for `POST /api/llm/codefix`.

### Linux/macOS

```bash
export NVIDIA_API_KEY="your-api-key"
```

### Windows PowerShell

```powershell
$env:NVIDIA_API_KEY="your-api-key"
```

## 5) Run the application

From `backend/` with virtualenv activated:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open in browser:

- `http://127.0.0.1:8000`

## 6) Stop the server

Press `Ctrl + C` in terminal.

## Quick Start (copy/paste)

### Linux/macOS

```bash
cd backend
python3 -m venv --copies .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Windows PowerShell

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

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