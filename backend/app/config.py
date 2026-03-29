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

ML_MAX_SAMPLES_PER_LANGUAGE = 999_999  # no effective cap — use all available data
ML_MAX_VOCAB = 40000   # increased from 20k to match expanded dataset (~72k rows)
ML_MIN_DF = 2

# NVIDIA API key for LLM-powered code fixes
NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "")
# NVIDIA API key for the SASTRA AI chatbot. If unset, reuse NVIDIA_API_KEY.
NVIDIA_CHAT_API_KEY = os.environ.get("NVIDIA_CHAT_API_KEY", NVIDIA_API_KEY)
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes", "on"}

# ── JWT configuration ──────────────────────────────────────────────────────────
# JWT_SECRET MUST be set as an environment variable in any real deployment.
# The default value below is for local development convenience only.
# Changing this secret invalidates all existing tokens — all users will
# need to sign in again.
JWT_SECRET = os.environ.get(
    "JWT_SECRET",
    "dev-secret-change-in-production-set-JWT_SECRET-env-var",
)
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_DAYS = 7
