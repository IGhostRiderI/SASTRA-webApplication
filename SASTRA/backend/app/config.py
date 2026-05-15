import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASETS_ROOT = PROJECT_ROOT / "datasets"
CSV_DATASET_DIR = DATASETS_ROOT / "13870382"
JULIET_TESTCASES_DIR = DATASETS_ROOT / "C" / "testcases"

APP_DIR = Path(__file__).resolve().parent
APP_DATA_DIR = APP_DIR / "data"
DB_PATH = APP_DATA_DIR / "sast.db"
ML_ENGINE_PATH = APP_DATA_DIR / "ml_engine.pkl.gz"

APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR = APP_DATA_DIR / "backups"
LOG_DIR    = APP_DATA_DIR / "logs"

SUPPORTED_LANGUAGES = {"python", "java", "cpp"}
EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".java": "java",
    ".c": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "cpp",
    ".hpp": "cpp",
}

LANGUAGE_TO_CSV = {
    "python": CSV_DATASET_DIR / "data_Python.csv",
    "java": CSV_DATASET_DIR / "data_Java.csv",
    "cpp": CSV_DATASET_DIR / "data_C++.csv",
}

MAX_FINDINGS_PER_SCAN = 999_999  # no effective cap
MAX_UPLOAD_SIZE_BYTES = 2 * 1024 * 1024
MAX_ZIP_UPLOAD_SIZE_BYTES = 25 * 1024 * 1024
MAX_ZIP_FILES = 250
MAX_ZIP_MEMBER_SIZE_BYTES = 1 * 1024 * 1024

ML_MAX_SAMPLES_PER_LANGUAGE = 999_999  # no effective cap - use all available data
ML_MAX_VOCAB = 40000   
ML_MIN_DF = 2

# NVIDIA API key for LLM-powered code fixes
NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "")
# NVIDIA API key for the SASTRA AI chatbot (separate key / model)
NVIDIA_CHAT_API_KEY = os.environ.get("NVIDIA_CHAT_API_KEY", "")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes", "on"}

#  Observability / alerting configuration 
ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "").strip()
ERROR_RATE_WINDOW_SECONDS = int(os.environ.get("ERROR_RATE_WINDOW_SECONDS", "300"))
ERROR_RATE_MIN_REQUESTS = int(os.environ.get("ERROR_RATE_MIN_REQUESTS", "50"))
ERROR_RATE_MIN_ERRORS = int(os.environ.get("ERROR_RATE_MIN_ERRORS", "10"))
ERROR_RATE_THRESHOLD = float(os.environ.get("ERROR_RATE_THRESHOLD", "0.2"))
ALERT_COOLDOWN_SECONDS = int(os.environ.get("ALERT_COOLDOWN_SECONDS", "300"))

#  JWT configuration 
# JWT_SECRET MUST be set as an environment variable in any real deployment.
# Changing this secret invalidates all existing tokens - all users will
# need to sign in again.
JWT_SECRET = os.environ.get("JWT_SECRET", "")
if not JWT_SECRET:
    raise RuntimeError(
        "JWT_SECRET environment variable is not set. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\" "
        "and set it before starting the server."
    )
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_DAYS = 7

#  Google OAuth 
GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI  = os.environ.get("GOOGLE_REDIRECT_URI", "https://www.sastra.website/auth/google/callback")
