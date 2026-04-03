# Lightweight SAST Web App

Local web app for static vulnerability detection on uploaded/pasted Python, Java, and C/C++ code with:
- Dataset-driven rules built from:
  - `datasets/13870382` (CSV vulnerability corpus)
  - `datasets/C/testcases` (Juliet C/C++)
- Upload support for single files and `.zip` archives
- Paste-code scan mode (no file required)
- Active local ML remediation model (no external LLM required)
- CWE + OWASP category mapping
- Severity scoring (`Critical/High/Medium/Low`)
- Dashboard with charts, preview highlighting, and finding detail pages
- PDF report export per scan
- User accounts with per-user scan history and role-based admin controls

## Auth and roles
- ADMIN
  - Username: `Nadinak`
  - Password: `Nadina`
- Regular users can sign up/sign in and view only their own scan history.
- Superadmin can view all users and histories, create/delete users, and assign admin role.
- Admin users can create/delete standard users.

## 1) Install dependencies

```bash
cd /Users/nadinak/Projects/SASTRA-WEBAPPLICATION/SASTRA/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2) Run app (local)

```bash
cd /Users/nadinak/Projects/SASTRA-WEBAPPLICATION/SASTRA/backend
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000

```

Open: `http://127.0.0.1:8000`

> **Note:** On first run (or if `ml_engine.pkl.gz` is deleted), the ML model will train automatically on startup. This may take a few minutes. The app will be ready once you see `Application startup complete` in the terminal. Subsequent startups load the saved model instantly.


```

Then open the Codespaces `Ports` tab, forward port `8000`, and open the forwarded URL.

## Notes
- First startup generates rules and stores them in `backend/app/data/generated_rules.json`.
- First startup also trains/loads the ML engine at `backend/app/data/ml_engine.pkl.gz`.
- If you do not commit raw datasets, keep `generated_rules.json` and `ml_engine.pkl.gz` in the repo so scans still work fully.
- Scan history and users are stored in SQLite: `backend/app/data/sast.db`.
- Upload size limit is 2MB per single file.
- ZIP upload limit is 25MB, with up to 250 supported files scanned from the archive.

## ML endpoints
- `GET /api/ml/status`: model readiness + metadata
- `POST /api/ml/retrain`: retrain remediation model from datasets (admin/superadmin)

## LLM code‑fix helper (optional)
A lightweight button on each finding now lets users request a **code‑specific fix** from an
external LLM. This requires an API key from one of: NVIDIA, DeepSeek, or Hugging Face.
Set `NVIDIA_API_KEY` for NVIDIA (preferred), `DEEPSEEK_API_KEY` for DeepSeek, or `HF_API_TOKEN` for Hugging Face fallback.
`HF_MODEL` may be used to choose a different HF model (defaults to `microsoft/DialoGPT-small`).

The new endpoint is:

- `POST /api/llm/codefix` – body contains `snippet`, `cwe_id`, `language` (and
  optionally `recommendation`). Returns a short patched code example.

If no API key is configured the button will simply surface an error message.

> **Troubleshooting errors:** Ensure your API key is valid and has access to the model. For NVIDIA, use the provided key; for others, check their docs.

