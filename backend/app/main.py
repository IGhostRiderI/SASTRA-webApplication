import io
import logging
import logging.handlers
import posixpath
import sys
import zipfile
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
import requests
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .config import (
    BACKUP_DIR,
    DB_PATH,
    EXTENSION_TO_LANGUAGE,
    JWT_EXPIRY_DAYS,
    COOKIE_SECURE,
    LOG_DIR,
    MAX_UPLOAD_SIZE_BYTES,
    MAX_ZIP_FILES,
    MAX_ZIP_MEMBER_SIZE_BYTES,
    MAX_ZIP_UPLOAD_SIZE_BYTES,
    SUPPORTED_LANGUAGES,
)
from .backup import backup_database
from .rules import build_rules_catalog
from .mappings import severity_score
from .db import (
    ROLE_ADMIN,
    ROLE_SUPERADMIN,
    ROLE_USER,
    SCAN_RETENTION_DAYS,
    authenticate_user,
    create_access_token,
    create_user,
    decode_access_token,
    delete_user_and_data,
    get_finding,
    save_finding_fix,
    get_scan,
    get_user_by_id,
    init_db,
    list_scans,
    list_users,
    purge_old_scans,
    save_scan,
    update_user_credentials,
    update_user_role,
)
from .pdf_report import build_pdf_report
from .ml_engine import load_or_train
from .scanner import ScannerEngine

# ── Centralised logging (NFR-8) ────────────────────────────────────────────────
# Logs are written to both the console and a rotating file so that
# crashes and high error rates can be monitored after the fact.
#
# Rotation policy: 10 MB per file, 5 backup files retained.
# Log directory:   app/data/logs/sast.log

LOG_DIR.mkdir(parents=True, exist_ok=True)
_LOG_FORMAT  = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"

_root_logger = logging.getLogger()
_root_logger.setLevel(logging.INFO)

# Console handler — always present
_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))
_root_logger.addHandler(_console_handler)

# Rotating file handler — persists logs for post-incident review
_file_handler = logging.handlers.RotatingFileHandler(
    filename=str(LOG_DIR / "sast.log"),
    maxBytes=10 * 1024 * 1024,  # 10 MB
    backupCount=5,
    encoding="utf-8",
)
_file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))
_root_logger.addHandler(_file_handler)

logger = logging.getLogger("sast")

# ── Error rate tracker (NFR-8) ─────────────────────────────────────────────────
# Counts 5xx errors and logs a warning when the rate looks elevated.
_error_counter: dict = {"count": 0}
_ERROR_ALERT_THRESHOLD = 10  # warn after this many 5xx errors per session


def _record_error(endpoint: str = "") -> None:
    """Increment the server-error counter and emit an alert if needed."""
    _error_counter["count"] += 1
    count = _error_counter["count"]
    if count == _ERROR_ALERT_THRESHOLD:
        logger.warning(
            "ALERT: %d server errors recorded this session — check logs for root cause. "
            "Last endpoint: %s",
            count, endpoint,
        )
    elif count > _ERROR_ALERT_THRESHOLD and count % _ERROR_ALERT_THRESHOLD == 0:
        logger.warning("ALERT: server error count now %d", count)


# ── Unhandled exception hook ───────────────────────────────────────────────────
def _log_unhandled_exception(exc_type, exc_value, exc_tb):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return
    logger.critical("Unhandled exception", exc_info=(exc_type, exc_value, exc_tb))


sys.excepthook = _log_unhandled_exception

SESSION_COOKIE = "sast_session"
SESSION_COOKIE_MAX_AGE = 60 * 60 * 24 * JWT_EXPIRY_DAYS  # matches JWT expiry

app_state: dict = {
    "scanner":   None,
    "catalog":   None,
    "ml_engine": None,
    "ml_meta":   None,
}

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}


class AuthPayload(BaseModel):
    username: str
    password: str


class CreateUserPayload(BaseModel):
    username: str
    password: str
    role: str = ROLE_USER


class UpdateRolePayload(BaseModel):
    role: str


class UpdateSelfPayload(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None


class LLMFixRequest(BaseModel):
    snippet: str
    cwe_id: str
    language: str
    recommendation: Optional[str] = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("SAST application starting up")

    init_db()
    logger.info("Database initialised")

    # NFR-4: create a daily backup on every startup
    try:
        backup_path = backup_database(DB_PATH, BACKUP_DIR)
        logger.info("Startup backup created: %s", backup_path.name)
    except Exception:
        logger.exception("Startup database backup failed — continuing without backup")

    # NFR-5: purge scans older than retention period on every startup
    try:
        removed = purge_old_scans()
        if removed:
            logger.info(
                "Startup purge: removed %d scan(s) older than %d days",
                removed, SCAN_RETENTION_DAYS,
            )
        else:
            logger.info(
                "Startup purge: no scans older than %d days found",
                SCAN_RETENTION_DAYS,
            )
    except Exception:
        logger.exception("Startup purge failed — continuing without purging")

    catalog = build_rules_catalog()
    app_state["catalog"] = catalog
    app_state["scanner"] = ScannerEngine(catalog)
    logger.info(
        "Rule catalog loaded — %d rules, %d CWEs",
        catalog.get("rule_count", 0),
        len(catalog.get("cwe_catalog", {})),
    )

    try:
        ml_engine = load_or_train(force_retrain=False)
        app_state["ml_engine"] = ml_engine
        app_state["ml_meta"]   = ml_engine.metadata
        logger.info(
            "ML engine ready — samples: %d  vocab: %d  severity classes: %s",
            ml_engine.metadata.get("sample_count", 0),
            ml_engine.metadata.get("vocab_size", 0),
            ml_engine.metadata.get("severity_classes", []),
        )
    except Exception:
        app_state["ml_engine"] = None
        app_state["ml_meta"]   = {"status": "unavailable"}
        logger.exception("Failed to load ML engine — continuing without ML enrichment")

    logger.info("SAST application ready")
    yield
    logger.info("SAST application shutting down")


app = FastAPI(title="Lightweight SAST Dashboard", lifespan=lifespan)

BASE_DIR     = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent.parent / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ── helpers ────────────────────────────────────────────────────────────────────

def _user_public(user: dict) -> dict:
    return {
        "id":         user["id"],
        "username":   user["username"],
        "role":       user["role"],
        "created_at": user.get("created_at"),
    }


def _set_session_cookie(response: JSONResponse, token: str) -> None:
    """Store the JWT in an HttpOnly cookie so it is inaccessible to JavaScript."""
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_COOKIE_MAX_AGE,
        path="/",
    )


def _clear_session_cookie(response: JSONResponse) -> None:
    response.delete_cookie(key=SESSION_COOKIE, path="/")


def _require_user(request: Request) -> dict:
    """
    FastAPI dependency — reads the JWT from the HttpOnly cookie, verifies
    it, and returns the user dict.  Raises 401 on any failure.

    Because JWT is stateless, no database lookup is needed for token
    verification.  A single DB call retrieves the user record to confirm
    the account still exists and to surface the current role.
    """
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Please sign in first.")

    user_id = decode_access_token(token)
    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="Session expired or invalid. Please sign in again.",
        )

    user = get_user_by_id(user_id)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="User account not found. Please sign in again.",
        )
    return user


def _require_admin(current_user: dict = Depends(_require_user)) -> dict:
    if current_user.get("role") not in {ROLE_ADMIN, ROLE_SUPERADMIN}:
        raise HTTPException(status_code=403, detail="Admin access required.")
    return current_user


def infer_language(filename: str, language: Optional[str]) -> str:
    if language:
        normalized = language.strip().lower()
        if normalized in SUPPORTED_LANGUAGES:
            return normalized
    ext = Path(filename).suffix.lower()
    detected = EXTENSION_TO_LANGUAGE.get(ext)
    if detected:
        return detected
    raise HTTPException(
        status_code=400,
        detail="Unsupported file type. Use .py, .java, .cpp/.c/.h files, or upload a .zip archive.",
    )


def _zip_sources(data: bytes) -> list[dict[str, str]]:
    sources: list[dict[str, str]] = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400, detail="Invalid ZIP archive.") from exc

    for info in archive.infolist():
        if info.is_dir():
            continue
        if len(sources) >= MAX_ZIP_FILES:
            break
        if info.file_size > MAX_ZIP_MEMBER_SIZE_BYTES:
            continue
        normalized = posixpath.normpath(info.filename).lstrip("/")
        if normalized.startswith(".."):
            continue
        ext = Path(normalized).suffix.lower()
        if ext not in EXTENSION_TO_LANGUAGE:
            continue
        language = EXTENSION_TO_LANGUAGE[ext]
        with archive.open(info) as fh:
            content = fh.read().decode("utf-8", errors="ignore")
        if not content.strip():
            continue
        sources.append({"source_path": normalized, "language": language, "content": content})

    return sources


def _rebuild_summary_from_findings(scan_output: dict) -> dict:
    findings = scan_output.get("findings", [])
    summary = scan_output.get("summary", {})

    severity_counts: Counter = Counter()
    cwe_counts: Counter = Counter()
    owasp_counts: Counter = Counter()
    weighted = 0

    for finding in findings:
        sev = str(finding.get("severity", ""))
        if sev in VALID_SEVERITIES:
            severity_counts[sev] += 1
        cwe = str(finding.get("cwe_id", ""))
        if cwe:
            cwe_counts[cwe] += 1
        owasp = str(finding.get("owasp_category", ""))
        if owasp:
            owasp_counts[owasp] += 1
        weighted += int(finding.get("severity_score", 0) or 0)

    total = len(findings)
    risk_score = round(weighted / total, 2) if total else 0

    summary.update(
        {
            "total_findings": total,
            "risk_score": risk_score,
            "severity": {
                "Critical": severity_counts.get("Critical", 0),
                "High": severity_counts.get("High", 0),
                "Medium": severity_counts.get("Medium", 0),
                "Low": severity_counts.get("Low", 0),
            },
            "top_cwe": sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:8],
            "top_owasp": sorted(owasp_counts.items(), key=lambda x: x[1], reverse=True)[:8],
        }
    )
    scan_output["summary"] = summary
    return scan_output


def _promote_ml_severity(scan_output: dict) -> dict:
    """
    Use ML severity as the primary severity for all findings.
    Summary and risk score are recalculated from ML-based severities.
    """
    findings = scan_output.get("findings", [])
    for finding in findings:
        ml_sev = str(finding.get("ml_severity", "")).strip()
        if ml_sev in VALID_SEVERITIES:
            finding["severity"] = ml_sev
            finding["severity_score"] = severity_score(ml_sev)
    return _rebuild_summary_from_findings(scan_output)


def _filter_false_positives(scan_output: dict) -> dict:
    """
    Separate FP-flagged findings from confirmed findings.

    - scan_output["findings"]        → real findings only (used for risk score / summary)
    - scan_output["false_positives"] → FP-flagged findings shown separately in the UI
    - scan_output["summary"]["fp_count"] → count of filtered FP findings
    """
    all_findings = scan_output.get("findings", [])
    real_findings = [f for f in all_findings if not f.get("fp_flag")]
    fp_findings   = [f for f in all_findings if f.get("fp_flag")]

    scan_output["findings"]        = real_findings
    scan_output["false_positives"] = fp_findings
    scan_output.setdefault("summary", {})["fp_count"] = len(fp_findings)

    return _rebuild_summary_from_findings(scan_output)


# ── page routes ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return RedirectResponse(url="/sastra-landing.html", status_code=307)


def _serve_frontend_page(page_name: str) -> FileResponse:
    path = FRONTEND_DIR / page_name
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Frontend page '{page_name}' not found")
    return FileResponse(
        path,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.get("/sastra-landing.html", response_class=HTMLResponse)
async def landing_page() -> FileResponse:
    return _serve_frontend_page("sastra-landing.html")


@app.get("/signin.html", response_class=HTMLResponse)
async def signin_page() -> FileResponse:
    return _serve_frontend_page("signin.html")


@app.get("/signup.html", response_class=HTMLResponse)
async def signup_page() -> FileResponse:
    return _serve_frontend_page("signup.html")


@app.get("/dashboard.html", response_class=HTMLResponse)
async def dashboard_page() -> FileResponse:
    return _serve_frontend_page("dashboard.html")


@app.get("/new-scan.html", response_class=HTMLResponse)
async def new_scan_page() -> FileResponse:
    return _serve_frontend_page("new-scan.html")


@app.get("/scan-results.html", response_class=HTMLResponse)
async def scan_results_page() -> FileResponse:
    return _serve_frontend_page("scan-results.html")


@app.get("/scan-history.html", response_class=HTMLResponse)
async def scan_history_page() -> FileResponse:
    return _serve_frontend_page("scan-history.html")


@app.get("/settings.html", response_class=HTMLResponse)
async def settings_page() -> FileResponse:
    return _serve_frontend_page("settings.html")


# ── system endpoints ───────────────────────────────────────────────────────────

@app.get("/api/health")
async def health() -> JSONResponse:
    return JSONResponse({"ok": app_state.get("scanner") is not None})


@app.get("/api/catalog")
async def catalog_summary() -> JSONResponse:
    catalog = app_state.get("catalog") or {}
    return JSONResponse({
        "rule_count":   catalog.get("rule_count", 0),
        "cwe_count":    len(catalog.get("cwe_catalog", {})),
        "generated_at": catalog.get("generated_at"),
    })


# ── auth endpoints ─────────────────────────────────────────────────────────────

def _signup_response(payload: AuthPayload) -> JSONResponse:
    try:
        user = create_user(payload.username, payload.password, role=ROLE_USER)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    token = create_access_token(int(user["id"]))
    logger.info("New user registered — username: %s", user["username"])
    response = JSONResponse({"ok": True, "user": _user_public(user)})
    _set_session_cookie(response, token)
    return response


def _login_response(payload: AuthPayload) -> JSONResponse:
    user = authenticate_user(payload.username, payload.password)
    if user is None:
        logger.warning("Failed login attempt — username: %s", payload.username)
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = create_access_token(int(user["id"]))
    logger.info("User signed in — username: %s  role: %s", user["username"], user["role"])
    response = JSONResponse({"ok": True, "user": _user_public(user)})
    _set_session_cookie(response, token)
    return response


@app.post("/api/auth/signup")
async def signup(payload: AuthPayload) -> JSONResponse:
    return _signup_response(payload)


@app.post("/api/signup")
async def signup_compat(payload: AuthPayload) -> JSONResponse:
    return _signup_response(payload)


@app.post("/api/auth/login")
async def login(payload: AuthPayload) -> JSONResponse:
    return _login_response(payload)


@app.post("/api/login")
async def login_compat(payload: AuthPayload) -> JSONResponse:
    return _login_response(payload)


@app.post("/api/auth/logout")
async def logout() -> JSONResponse:
    # JWT is stateless — no server-side record to delete.
    # Simply clear the HttpOnly cookie on the client.
    logger.info("User signed out")
    response = JSONResponse({"ok": True})
    _clear_session_cookie(response)
    return response


@app.post("/api/logout")
async def logout_compat() -> JSONResponse:
    return await logout()


@app.get("/api/auth/me")
async def auth_me(current_user: dict = Depends(_require_user)) -> JSONResponse:
    return JSONResponse({"ok": True, "user": _user_public(current_user)})


@app.get("/api/me")
async def auth_me_compat(current_user: dict = Depends(_require_user)) -> JSONResponse:
    return JSONResponse({"ok": True, "user": _user_public(current_user)})


@app.patch("/api/auth/me")
async def auth_me_update(
    payload: UpdateSelfPayload,
    current_user: dict = Depends(_require_user),
) -> JSONResponse:
    try:
        updated = update_user_credentials(
            int(current_user["id"]),
            username=payload.username,
            password=payload.password,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if updated is None:
        raise HTTPException(status_code=404, detail="User not found.")

    logger.info("User updated account settings — username: %s", updated["username"])
    return JSONResponse({"ok": True, "user": _user_public(updated)})


@app.patch("/api/me")
async def auth_me_update_compat(
    payload: UpdateSelfPayload,
    current_user: dict = Depends(_require_user),
) -> JSONResponse:
    return await auth_me_update(payload, current_user)


@app.delete("/api/auth/me")
async def auth_me_delete(current_user: dict = Depends(_require_user)) -> JSONResponse:
    if current_user.get("role") == ROLE_SUPERADMIN:
        raise HTTPException(status_code=403, detail="Superadmin account cannot be deleted.")

    try:
        delete_user_and_data(int(current_user["id"]))
    except Exception:
        logger.exception("Account deletion failed for user id=%s", current_user["id"])
        raise HTTPException(status_code=500, detail="Unable to delete account data.")
    logger.info("User deleted their account — id: %s", current_user["id"])
    response = JSONResponse({"ok": True})
    _clear_session_cookie(response)
    return response


@app.post("/api/auth/delete")
async def auth_me_delete_post(current_user: dict = Depends(_require_user)) -> JSONResponse:
    # Fallback for clients/proxies that restrict DELETE requests.
    return await auth_me_delete(current_user)


@app.delete("/api/me")
async def auth_me_delete_compat(current_user: dict = Depends(_require_user)) -> JSONResponse:
    return await auth_me_delete(current_user)


@app.post("/api/delete")
async def auth_me_delete_compat_post(current_user: dict = Depends(_require_user)) -> JSONResponse:
    return await auth_me_delete(current_user)


# ── admin — user management ────────────────────────────────────────────────────

@app.get("/api/admin/users")
async def admin_users(current_user: dict = Depends(_require_admin)) -> JSONResponse:
    users = list_users()
    if current_user["role"] == ROLE_ADMIN:
        users = [u for u in users if u["role"] == ROLE_USER or u["id"] == current_user["id"]]
    return JSONResponse({"items": users})


@app.post("/api/admin/users")
async def admin_create_user(
    payload: CreateUserPayload,
    current_user: dict = Depends(_require_admin),
) -> JSONResponse:
    requested_role = (payload.role or ROLE_USER).strip().lower()
    if current_user["role"] == ROLE_ADMIN and requested_role != ROLE_USER:
        raise HTTPException(status_code=403, detail="Admins can only create standard users.")
    if requested_role == ROLE_SUPERADMIN:
        raise HTTPException(status_code=403, detail="Cannot create additional superadmin accounts.")
    try:
        user = create_user(payload.username, payload.password, role=requested_role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info(
        "Admin '%s' created user '%s' with role '%s'",
        current_user["username"], user["username"], user["role"],
    )
    return JSONResponse({"ok": True, "user": user})


@app.patch("/api/admin/users/{user_id}/role")
async def admin_update_role(
    user_id: int,
    payload: UpdateRolePayload,
    current_user: dict = Depends(_require_admin),
) -> JSONResponse:
    if current_user["role"] != ROLE_SUPERADMIN:
        raise HTTPException(status_code=403, detail="Only superadmin can change user privileges.")
    target = get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")
    if target["role"] == ROLE_SUPERADMIN:
        raise HTTPException(status_code=403, detail="Cannot modify superadmin role.")
    if target["id"] == current_user["id"]:
        raise HTTPException(status_code=403, detail="Superadmin role cannot be changed here.")
    next_role = (payload.role or ROLE_USER).strip().lower()
    if next_role not in {ROLE_USER, ROLE_ADMIN}:
        raise HTTPException(status_code=400, detail="Role must be 'user' or 'admin'.")
    updated = update_user_role(user_id=user_id, role=next_role)
    if updated is None:
        raise HTTPException(status_code=404, detail="User not found.")
    logger.info(
        "Superadmin '%s' changed role of '%s' to '%s'",
        current_user["username"], target["username"], next_role,
    )
    return JSONResponse({"ok": True, "user": updated})


@app.delete("/api/admin/users/{user_id}")
async def admin_delete_user(
    user_id: int,
    current_user: dict = Depends(_require_admin),
) -> JSONResponse:
    target = get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")
    if target["role"] == ROLE_SUPERADMIN:
        raise HTTPException(status_code=403, detail="Cannot remove the superadmin account.")
    if target["id"] == current_user["id"]:
        raise HTTPException(status_code=403, detail="You cannot remove your own account.")
    if current_user["role"] == ROLE_ADMIN and target["role"] != ROLE_USER:
        raise HTTPException(status_code=403, detail="Admins can only remove standard users.")
    delete_user_and_data(user_id)
    logger.info(
        "Admin '%s' deleted user '%s' (id=%d)",
        current_user["username"], target["username"], user_id,
    )
    return JSONResponse({"ok": True})


# ── NFR-5: manual purge endpoint ───────────────────────────────────────────────

@app.post("/api/admin/purge")
async def admin_purge(current_user: dict = Depends(_require_admin)) -> JSONResponse:
    try:
        removed = purge_old_scans()
    except Exception:
        logger.exception("Manual purge failed — triggered by '%s'", current_user["username"])
        raise HTTPException(status_code=500, detail="Purge operation failed.")
    logger.info(
        "Manual purge by '%s' — removed %d scan(s) older than %d days",
        current_user["username"], removed, SCAN_RETENTION_DAYS,
    )
    return JSONResponse({"ok": True, "removed": removed, "retention_days": SCAN_RETENTION_DAYS})


# ── ML remediation model ───────────────────────────────────────────────────────

@app.get("/api/ml/status")
async def ml_status() -> JSONResponse:
    return JSONResponse({
        "ready":    app_state.get("ml_engine") is not None,
        "metadata": app_state.get("ml_meta", {}),
    })


@app.post("/api/ml/retrain")
async def ml_retrain(current_user: dict = Depends(_require_admin)) -> JSONResponse:
    logger.info("ML engine retrain requested by '%s'", current_user["username"])
    try:
        ml_engine = load_or_train(force_retrain=True)
    except Exception:
        logger.exception("ML engine retrain failed")
        _record_error("/api/ml/retrain")
        raise HTTPException(status_code=500, detail="ML retrain failed.")
    app_state["ml_engine"] = ml_engine
    app_state["ml_meta"]   = ml_engine.metadata
    logger.info(
        "ML retrain complete — samples: %d  severity classes: %s",
        ml_engine.metadata.get("sample_count", 0),
        ml_engine.metadata.get("severity_classes", []),
    )
    return JSONResponse({"ok": True, "metadata": ml_engine.metadata})


# ── LLM code-fix helper ────────────────────────────────────────────────────────

import re as _re

_EXPLANATION_MARKERS = _re.compile(
    r'(?i)^(becomes|fixed(\s+code)?|secure(\s+version)?|result|output|here\s+is|fix\:?)\s*:?\s*$'
)
_CODE_FENCE = _re.compile(r'^```[^\n]*\n?|^```$', _re.MULTILINE)
_IMPORT_LINE = _re.compile(r'^\s*(import\s+\w+|from\s+\w+\s+import\b)')

def _extract_code_only(text: str) -> str:
    """Strip explanation prose, 'becomes' markers, code fences, and stray imports."""
    # Remove code fences
    text = _CODE_FENCE.sub('', text).strip()
    lines = text.splitlines()
    # If there's a "becomes" style split, take everything after the last marker
    last_marker = -1
    for i, line in enumerate(lines):
        if _EXPLANATION_MARKERS.match(line.strip()):
            last_marker = i
    if last_marker >= 0:
        lines = lines[last_marker + 1:]
    # Strip stray import lines — we only want the fixed code, not added imports
    lines = [l for l in lines if not _IMPORT_LINE.match(l)]
    return '\n'.join(lines).strip()


@app.post("/api/llm/codefix")
async def llm_codefix(
    payload: LLMFixRequest,
    current_user: dict = Depends(_require_user),
) -> JSONResponse:
    from . import config
    if not config.NVIDIA_API_KEY:
        raise HTTPException(status_code=503, detail="NVIDIA_API_KEY not configured.")

    snippet_lines = payload.snippet.strip().splitlines()
    line_count = len(snippet_lines)
    rec_hint = f"\nFix guidance: {payload.recommendation}" if payload.recommendation else ""
    prompt = (
        f"Security vulnerability: {payload.cwe_id} in {payload.language}.{rec_hint}\n\n"
        f"VULNERABLE ({line_count} line{'s' if line_count != 1 else ''}):\n{payload.snippet}\n\n"
        f"FIXED (output EXACTLY {line_count} line{'s' if line_count != 1 else ''} — "
        f"the same code with only the vulnerability fixed, nothing added or removed):"
    )

    logger.info(
        "LLM code-fix requested by '%s' — CWE: %s  language: %s",
        current_user["username"], payload.cwe_id, payload.language,
    )

    try:
        response = requests.post(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {config.NVIDIA_API_KEY}",
                "Accept": "application/json",
            },
            json={
                "model": "meta/llama-3.1-405b-instruct",
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a code security tool. "
                            "You receive vulnerable code and output ONLY that exact code with the vulnerability fixed. "
                            "STRICT RULES: same number of lines as input, no new functions, no imports, "
                            "no explanations, no comments, no markdown, no code fences. "
                            "Only change what is necessary to fix the vulnerability. Nothing else."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": 300,
                "temperature": 0.1,
                "top_p": 0.9,
                "stream": False,
            },
        )
        response.raise_for_status()
        raw = response.json()["choices"][0]["message"]["content"].strip()
        text = _extract_code_only(raw)
        logger.info("LLM code-fix returned for CWE: %s", payload.cwe_id)
    except Exception:
        logger.exception("NVIDIA API call failed — CWE: %s", payload.cwe_id)
        _record_error("/api/llm/codefix")
        raise HTTPException(status_code=502, detail="NVIDIA API error.")

    return JSONResponse({"ok": True, "text": text})


class LLMFixSaveRequest(BaseModel):
    fix_text: str


@app.post("/api/findings/{finding_id}/fix")
async def save_llm_fix(
    finding_id: int,
    payload: LLMFixSaveRequest,
    current_user: dict = Depends(_require_user),
) -> JSONResponse:
    ok = save_finding_fix(
        finding_id,
        payload.fix_text,
        requester_user_id=current_user["id"],
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return JSONResponse({"ok": True})


# ── scan endpoints ─────────────────────────────────────────────────────────────

@app.post("/api/scan")
async def scan_file(
    file: UploadFile | None = File(default=None),
    language: Optional[str] = Form(default=None),
    code: Optional[str] = Form(default=None),
    code_filename: Optional[str] = Form(default=None),
    current_user: dict = Depends(_require_user),
) -> JSONResponse:
    if app_state.get("scanner") is None:
        raise HTTPException(status_code=503, detail="Scanner is still initializing.")

    scanner: ScannerEngine = app_state["scanner"]

    if file is not None:
        data     = await file.read()
        filename = file.filename or "uploaded_file"

        if Path(filename).suffix.lower() == ".zip":
            if len(data) > MAX_ZIP_UPLOAD_SIZE_BYTES:
                raise HTTPException(status_code=413, detail="ZIP too large. Upload archives up to 25MB.")
            sources = _zip_sources(data)
            if not sources:
                raise HTTPException(status_code=400, detail="ZIP has no supported source files.")
            logger.info("ZIP scan by '%s' — %s  files: %d", current_user["username"], filename, len(sources))
            scan_output   = scanner.scan_many(sources=sources, archive_name=filename)
            scan_language = scan_output["summary"]["language"]
        else:
            if len(data) > MAX_UPLOAD_SIZE_BYTES:
                raise HTTPException(status_code=413, detail="File too large. Upload files up to 2MB.")
            content = data.decode("utf-8", errors="ignore")
            if not content.strip():
                raise HTTPException(status_code=400, detail="Uploaded file is empty.")
            detected_language = infer_language(filename, language)
            logger.info("File scan by '%s' — %s  lang: %s", current_user["username"], filename, detected_language)
            scan_output   = scanner.scan(content=content, language=detected_language, filename=filename, source_path=filename)
            scan_language = detected_language
    else:
        snippet = (code or "").strip()
        if not snippet:
            raise HTTPException(status_code=400, detail="Upload a file/zip or paste code to scan.")
        synthetic_name = (code_filename or "snippet.py").strip() or "snippet.py"
        try:
            scan_language = infer_language(synthetic_name, language)
        except HTTPException:
            if not language:
                raise HTTPException(status_code=400, detail="Select language for pasted code.")
            raise
        logger.info("Paste scan by '%s' — %s  lang: %s", current_user["username"], synthetic_name, scan_language)
        scan_output = scanner.scan(content=snippet, language=scan_language, filename=synthetic_name, source_path=synthetic_name)
        filename    = synthetic_name

    ml_engine = app_state.get("ml_engine")
    if ml_engine is None:
        raise HTTPException(status_code=503, detail="ML severity engine is unavailable.")
    scan_output = ml_engine.enrich_scan_output(scan_output)
    scan_output = _promote_ml_severity(scan_output)
    scan_output = _filter_false_positives(scan_output)

    scan_id = save_scan(int(current_user["id"]), filename, scan_language, scan_output)

    logger.info(
        "Scan #%d complete — user: '%s'  findings: %d  risk: %s",
        scan_id, current_user["username"],
        scan_output["summary"]["total_findings"],
        scan_output["summary"]["risk_score"],
    )

    result = get_scan(
        scan_id,
        requester_user_id=int(current_user["id"]),
        include_all=current_user["role"] == ROLE_SUPERADMIN,
    )
    if result is None:
        logger.error("Scan #%d saved but could not be retrieved", scan_id)
        _record_error("/api/scan")
        raise HTTPException(status_code=500, detail="Unable to load scan output.")
    return JSONResponse(result)


@app.get("/api/scans")
async def scans(
    user_id: Optional[int] = None,
    current_user: dict = Depends(_require_user),
) -> JSONResponse:
    include_all    = current_user["role"] == ROLE_SUPERADMIN
    target_user_id = user_id if include_all else None
    items = list_scans(
        requester_user_id=int(current_user["id"]),
        limit=60,
        include_all=include_all,
        target_user_id=target_user_id,
    )
    return JSONResponse({"items": items})


@app.get("/api/scans/{scan_id}")
async def scan_details(
    scan_id: int, current_user: dict = Depends(_require_user)
) -> JSONResponse:
    result = get_scan(
        scan_id,
        requester_user_id=int(current_user["id"]),
        include_all=current_user["role"] == ROLE_SUPERADMIN,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(result)


@app.get("/api/scans/{scan_id}/findings/{finding_id}")
async def finding_details(
    scan_id: int, finding_id: int, current_user: dict = Depends(_require_user)
) -> JSONResponse:
    result = get_finding(
        scan_id, finding_id,
        requester_user_id=int(current_user["id"]),
        include_all=current_user["role"] == ROLE_SUPERADMIN,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Finding not found")
    return JSONResponse(result)


@app.get("/api/scans/{scan_id}/report.pdf")
async def scan_pdf(
    scan_id: int, current_user: dict = Depends(_require_user)
) -> Response:
    result = get_scan(
        scan_id,
        requester_user_id=int(current_user["id"]),
        include_all=current_user["role"] == ROLE_SUPERADMIN,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        pdf_data = build_pdf_report(result)
    except Exception:
        logger.exception("PDF generation failed for scan #%d", scan_id)
        _record_error("/api/scans/{scan_id}/report.pdf")
        raise HTTPException(status_code=500, detail="PDF generation failed.")

    logger.info("PDF report generated for scan #%d by '%s'", scan_id, current_user["username"])
    return Response(
        content=pdf_data,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}_report.pdf"},
    )
