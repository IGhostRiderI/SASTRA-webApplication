import asyncio
import io
import logging
import logging.handlers
import posixpath
import random
import secrets
import sys
import threading
import time
import zipfile
from urllib.parse import urlencode
from collections import Counter
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
import requests
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

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
    ALERT_WEBHOOK_URL,
    ALERT_COOLDOWN_SECONDS,
    ERROR_RATE_MIN_ERRORS,
    ERROR_RATE_MIN_REQUESTS,
    ERROR_RATE_THRESHOLD,
    ERROR_RATE_WINDOW_SECONDS,
    SUPPORTED_LANGUAGES,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
)
from .backup import backup_database
from .rules import build_rules_catalog
from .mappings import severity_score
from .db import (
    LLM_RPM_LIMIT,
    ROLE_ADMIN,
    ROLE_SUPERADMIN,
    ROLE_USER,
    SCAN_HOURLY_LIMIT,
    SCAN_RETENTION_DAYS,
    authenticate_user,
    create_access_token,
    create_user,
    decode_access_token,
    delete_user_and_data,
    get_finding,
    get_llm_rpm_quota,
    get_or_create_google_user,
    save_finding_fix,
    get_scan,
    get_hourly_scan_quota,
    get_user_by_id,
    init_db,
    list_scans,
    list_users,
    purge_old_scans,
    record_llm_request,
    save_scan,
    update_user_credentials,
    update_user_role,
)
from .pdf_report import build_pdf_report
from .ml_engine import load_or_train
from .scanner import ScannerEngine
from .ast_scanner import JAVALANG_AVAILABLE, CLANG_AVAILABLE, probe_clang_runtime

#  Centralised logging (NFR-8) 
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

# Console handler - always present
if not any(isinstance(handler, logging.StreamHandler) for handler in _root_logger.handlers):
    _console_handler = logging.StreamHandler(sys.stdout)
    _console_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))
    _root_logger.addHandler(_console_handler)

# Rotating file handler - persists logs for post-incident review
_log_file_path = str(LOG_DIR / "sast.log")
_has_rotating_log = any(
    isinstance(handler, logging.handlers.RotatingFileHandler)
    and getattr(handler, "baseFilename", "") == _log_file_path
    for handler in _root_logger.handlers
)
if not _has_rotating_log:
    _file_handler = logging.handlers.RotatingFileHandler(
        filename=_log_file_path,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    _file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))
    _root_logger.addHandler(_file_handler)

logger = logging.getLogger("sast")

#  Error rate tracker (NFR-8) 
# Counts 5xx errors and logs a warning when the rate looks elevated.
_error_counter: dict = {"count": 0}
_ERROR_ALERT_THRESHOLD = 10  # warn after this many 5xx errors per session
_alert_state: dict = {"last_sent_at": 0.0}
_requests_window: deque[float] = deque()
_errors_window: deque[float] = deque()
_window_lock = threading.Lock()


def _send_alert(event: str, message: str, extra: Optional[dict] = None) -> None:
    """Send alerts to logs and optionally to a webhook for external monitoring."""
    payload = {
        "service": "sastra-backend",
        "event": event,
        "message": message,
        "timestamp": int(time.time()),
    }
    if extra:
        payload["extra"] = extra

    if not ALERT_WEBHOOK_URL:
        return

    try:
        requests.post(ALERT_WEBHOOK_URL, json=payload, timeout=3)
    except Exception:
        logger.exception("Failed to deliver alert webhook")


def _prune_window(now: float) -> None:
    cutoff = now - max(1, ERROR_RATE_WINDOW_SECONDS)
    while _requests_window and _requests_window[0] < cutoff:
        _requests_window.popleft()
    while _errors_window and _errors_window[0] < cutoff:
        _errors_window.popleft()


def _evaluate_error_rate_alert(endpoint: str = "") -> None:
    now = time.time()
    with _window_lock:
        _prune_window(now)
        request_count = len(_requests_window)
        error_count = len(_errors_window)
        if request_count <= 0:
            return

        error_rate = error_count / request_count
        threshold_hit = (
            request_count >= ERROR_RATE_MIN_REQUESTS
            and error_count >= ERROR_RATE_MIN_ERRORS
            and error_rate >= ERROR_RATE_THRESHOLD
        )
        cooldown_ok = (now - _alert_state["last_sent_at"]) >= max(1, ALERT_COOLDOWN_SECONDS)
        if not (threshold_hit and cooldown_ok):
            return

        _alert_state["last_sent_at"] = now

    message = (
        "ALERT: high 5xx error rate detected "
        f"({error_count}/{request_count} = {error_rate:.1%} in last {ERROR_RATE_WINDOW_SECONDS}s)"
    )
    logger.error("%s. Last endpoint: %s", message, endpoint)
    _send_alert(
        event="high_error_rate",
        message=message,
        extra={
            "endpoint": endpoint,
            "error_count": error_count,
            "request_count": request_count,
            "error_rate": round(error_rate, 4),
            "window_seconds": ERROR_RATE_WINDOW_SECONDS,
        },
    )


def _record_request(status_code: int, endpoint: str = "") -> None:
    now = time.time()
    with _window_lock:
        _requests_window.append(now)
        if status_code >= 500:
            _errors_window.append(now)
        _prune_window(now)

    if status_code >= 500:
        _record_error(endpoint)
        _evaluate_error_rate_alert(endpoint)


def _record_error(endpoint: str = "") -> None:
    """Increment the server-error counter and emit an alert if needed."""
    _error_counter["count"] += 1
    count = _error_counter["count"]
    if count == _ERROR_ALERT_THRESHOLD:
        logger.warning(
            "ALERT: %d server errors recorded this session - check logs for root cause. "
            "Last endpoint: %s",
            count, endpoint,
        )
    elif count > _ERROR_ALERT_THRESHOLD and count % _ERROR_ALERT_THRESHOLD == 0:
        logger.warning("ALERT: server error count now %d", count)


#  Unhandled exception hook 
def _log_unhandled_exception(exc_type, exc_value, exc_tb):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return
    logger.critical("Unhandled exception", exc_info=(exc_type, exc_value, exc_tb))
    _send_alert("unhandled_exception", "Unhandled process-level exception captured")


sys.excepthook = _log_unhandled_exception

_limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

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

    def validate_fields(self) -> None:
        import re as _re
        if not _re.fullmatch(r"CWE-\d{1,5}", self.cwe_id.strip()):
            raise ValueError(f"Invalid cwe_id format: {self.cwe_id!r}")
        if self.language.strip().lower() not in {"python", "java", "cpp"}:
            raise ValueError(f"Unsupported language: {self.language!r}")
        if len(self.snippet) > 8000:
            raise ValueError("snippet too large")
        if self.recommendation and len(self.recommendation) > 2000:
            raise ValueError("recommendation too large")


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
        logger.exception("Startup database backup failed - continuing without backup")

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
        logger.exception("Startup purge failed - continuing without purging")

    catalog = build_rules_catalog()
    app_state["catalog"] = catalog
    app_state["scanner"] = ScannerEngine(catalog)
    logger.info(
        "Rule catalog loaded - %d rules, %d CWEs",
        catalog.get("rule_count", 0),
        len(catalog.get("cwe_catalog", {})),
    )

    logger.info("Java AST availability (javalang): %s", "ready" if JAVALANG_AVAILABLE else "unavailable")
    if not CLANG_AVAILABLE:
        logger.warning("C/C++ AST availability (libclang): unavailable (clang.cindex import failed)")
    else:
        clang_ready, clang_reason = probe_clang_runtime()
        if clang_ready:
            logger.info("C/C++ AST availability (libclang): ready")
        else:
            logger.warning("C/C++ AST availability (libclang): unavailable (%s)", clang_reason)

    try:
        ml_engine = load_or_train(force_retrain=False)
        app_state["ml_engine"] = ml_engine
        app_state["ml_meta"]   = ml_engine.metadata
        logger.info(
            "ML engine ready - samples: %d  vocab: %d  severity classes: %s",
            ml_engine.metadata.get("sample_count", 0),
            ml_engine.metadata.get("vocab_size", 0),
            ml_engine.metadata.get("severity_classes", []),
        )
    except Exception:
        app_state["ml_engine"] = None
        app_state["ml_meta"]   = {"status": "unavailable"}
        logger.exception("Failed to load ML engine - continuing without ML enrichment")

    logger.info("SAST application ready")
    yield
    logger.info("SAST application shutting down")


app = FastAPI(title="Lightweight SAST Dashboard", lifespan=lifespan)
app.state.limiter = _limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


async def _not_found_handler(request: Request, exc: HTTPException) -> JSONResponse:
    # Random delay 100–400ms — slows directory enumeration tools significantly
    await asyncio.sleep(random.uniform(0.1, 0.4))
    return JSONResponse({"detail": "Not found"}, status_code=404)


app.add_exception_handler(404, _not_found_handler)

BASE_DIR     = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent.parent / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.middleware("http")
async def observability_middleware(request: Request, call_next):
    start = time.perf_counter()
    endpoint = request.url.path
    method = request.method
    try:
        response = await call_next(request)
    except Exception:
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        _record_request(500, endpoint)
        logger.exception("Unhandled request failure - %s %s (%sms)", method, endpoint, duration_ms)
        raise

    status_code = response.status_code
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    _record_request(status_code, endpoint)

    if status_code >= 500:
        logger.error("Request failed - %s %s status=%d duration_ms=%s", method, endpoint, status_code, duration_ms)
    else:
        logger.info("Request served - %s %s status=%d duration_ms=%s", method, endpoint, status_code, duration_ms)
    return response


#  helpers 

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
        samesite="strict",
        max_age=SESSION_COOKIE_MAX_AGE,
        path="/",
    )


def _clear_session_cookie(response: JSONResponse) -> None:
    response.delete_cookie(key=SESSION_COOKIE, path="/")


def _require_user(request: Request) -> dict:
    """
    FastAPI dependency - reads the JWT from the HttpOnly cookie, verifies
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
    import tempfile, os as _os
    sources: list[dict[str, str]] = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400, detail="Invalid ZIP archive.") from exc

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir).resolve()
        for info in archive.infolist():
            if info.is_dir():
                continue
            if len(sources) >= MAX_ZIP_FILES:
                break
            if info.file_size > MAX_ZIP_MEMBER_SIZE_BYTES:
                continue
            # Resolve the target path and verify it stays inside the temp dir
            # This prevents path traversal via "..", absolute paths, or symlinks.
            normalized = posixpath.normpath(info.filename).lstrip("/")
            target = (tmp_root / normalized).resolve()
            if not str(target).startswith(str(tmp_root) + _os.sep):
                logger.warning("ZIP path traversal blocked: %s", info.filename)
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
    Use ML severity as the primary severity only when the model is
    confident enough (>= 0.70).  Otherwise keep the rule-based severity
    which is derived from well-known CWE→severity mappings.

    Summary and risk score are recalculated afterwards.
    """
    ML_SEV_CONFIDENCE_THRESHOLD = 0.70
    findings = scan_output.get("findings", [])
    for finding in findings:
        ml_sev  = str(finding.get("ml_severity", "")).strip()
        ml_conf = float(finding.get("ml_severity_confidence", 0.0))
        if ml_sev in VALID_SEVERITIES and ml_conf >= ML_SEV_CONFIDENCE_THRESHOLD:
            finding["severity"] = ml_sev
            finding["severity_score"] = severity_score(ml_sev)
    return _rebuild_summary_from_findings(scan_output)


def _filter_false_positives(scan_output: dict) -> dict:
    """
    Keep ALL findings in scan_output["findings"] so they are visible in the UI.
    FP-flagged findings retain fp_flag=True so the frontend can mark them visually.

    - scan_output["findings"]            → all findings (FP ones have fp_flag=True)
    - scan_output["false_positives"]     → same FP subset, kept for backwards compat
    - scan_output["summary"]["fp_count"] → count of FP-flagged findings
    """
    all_findings = scan_output.get("findings", [])
    fp_findings  = [f for f in all_findings if f.get("fp_flag")]

    scan_output["false_positives"] = fp_findings
    scan_output.setdefault("summary", {})["fp_count"] = len(fp_findings)

    return _rebuild_summary_from_findings(scan_output)


#  page routes 

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


@app.get("/privacy-policy.html", response_class=HTMLResponse)
async def privacy_policy_page() -> FileResponse:
    return _serve_frontend_page("privacy-policy.html")


@app.get("/learn-more.html", response_class=HTMLResponse)
async def learn_more_page() -> FileResponse:
    return _serve_frontend_page("learn-more.html")


#  system endpoints 

@app.get("/api/health")
async def health() -> JSONResponse:
    return JSONResponse({"ok": app_state.get("scanner") is not None})


@app.get("/api/catalog")
async def catalog_summary(current_user: dict = Depends(_require_user)) -> JSONResponse:
    catalog = app_state.get("catalog") or {}
    return JSONResponse({
        "rule_count":   catalog.get("rule_count", 0),
        "cwe_count":    len(catalog.get("cwe_catalog", {})),
        "generated_at": catalog.get("generated_at"),
    })


#  auth endpoints 

def _signup_response(payload: AuthPayload) -> JSONResponse:
    try:
        user = create_user(payload.username, payload.password, role=ROLE_USER)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    token = create_access_token(int(user["id"]))
    logger.info("New user registered - username: %s", user["username"])
    response = JSONResponse({"ok": True, "user": _user_public(user)})
    _set_session_cookie(response, token)
    return response


def _login_response(payload: AuthPayload) -> JSONResponse:
    user = authenticate_user(payload.username, payload.password)
    if user is None:
        logger.warning("Failed login attempt - username: %s", payload.username)
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = create_access_token(int(user["id"]))
    logger.info("User signed in - username: %s  role: %s", user["username"], user["role"])
    response = JSONResponse({"ok": True, "user": _user_public(user)})
    _set_session_cookie(response, token)
    return response


@app.post("/api/auth/signup")
@_limiter.limit("10/minute")
async def signup(request: Request, payload: AuthPayload) -> JSONResponse:
    return _signup_response(payload)


@app.post("/api/signup")
@_limiter.limit("10/minute")
async def signup_compat(request: Request, payload: AuthPayload) -> JSONResponse:
    return _signup_response(payload)


@app.post("/api/auth/login")
@_limiter.limit("10/minute")
async def login(request: Request, payload: AuthPayload) -> JSONResponse:
    return _login_response(payload)


@app.post("/api/login")
@_limiter.limit("10/minute")
async def login_compat(request: Request, payload: AuthPayload) -> JSONResponse:
    return _login_response(payload)


@app.post("/api/auth/logout")
async def logout() -> JSONResponse:
    # JWT is stateless - no server-side record to delete.
    # Simply clear the HttpOnly cookie on the client.
    logger.info("User signed out")
    response = JSONResponse({"ok": True})
    _clear_session_cookie(response)
    return response


@app.post("/api/logout")
async def logout_compat() -> JSONResponse:
    return await logout()


@app.get("/auth/google")
async def google_login() -> RedirectResponse:
    state = secrets.token_urlsafe(32)
    params = urlencode({
        "client_id":     GOOGLE_CLIENT_ID,
        "redirect_uri":  GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope":         "openid email profile",
        "state":         state,
    })
    response = RedirectResponse(f"https://accounts.google.com/o/oauth2/v2/auth?{params}")
    response.set_cookie("oauth_state", state, httponly=True, max_age=300, samesite="lax", secure=COOKIE_SECURE)
    return response


@app.get("/auth/google/callback")
async def google_callback(request: Request, code: str = "", state: str = "", error: str = "") -> RedirectResponse:
    if error or not code:
        return RedirectResponse("/signin.html?error=google_denied")

    # Validate the state parameter against the cookie set in /auth/google
    # to prevent OAuth CSRF attacks.
    stored_state = request.cookies.get("oauth_state", "")
    if not stored_state or not secrets.compare_digest(stored_state, state):
        logger.warning("OAuth state mismatch - possible CSRF attempt")
        return RedirectResponse("/signin.html?error=google_denied")

    token_resp = requests.post("https://oauth2.googleapis.com/token", data={
        "code":          code,
        "client_id":     GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri":  GOOGLE_REDIRECT_URI,
        "grant_type":    "authorization_code",
    })
    if not token_resp.ok:
        logger.warning("Google token exchange failed: %s", token_resp.text)
        return RedirectResponse("/signin.html?error=google_failed")

    access_token = token_resp.json().get("access_token")
    userinfo_resp = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if not userinfo_resp.ok:
        return RedirectResponse("/signin.html?error=google_failed")

    userinfo  = userinfo_resp.json()
    google_id = userinfo.get("id", "")
    email     = userinfo.get("email", "")

    if not google_id or not email:
        return RedirectResponse("/signin.html?error=google_failed")

    user  = get_or_create_google_user(google_id, email)
    token = create_access_token(int(user["id"]))
    logger.info("Google sign-in - username: %s", user["username"])

    response = RedirectResponse("/dashboard.html")
    _set_session_cookie(response, token)
    response.delete_cookie("oauth_state")
    return response


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

    logger.info("User updated account settings - username: %s", updated["username"])
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
    logger.info("User deleted their account - id: %s", current_user["id"])
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


#  admin - user management 

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


#  NFR-5: manual purge endpoint 

@app.post("/api/admin/purge")
async def admin_purge(current_user: dict = Depends(_require_admin)) -> JSONResponse:
    try:
        removed = purge_old_scans()
    except Exception:
        logger.exception("Manual purge failed - triggered by '%s'", current_user["username"])
        raise HTTPException(status_code=500, detail="Purge operation failed.")
    logger.info(
        "Manual purge by '%s' - removed %d scan(s) older than %d days",
        current_user["username"], removed, SCAN_RETENTION_DAYS,
    )
    return JSONResponse({"ok": True, "removed": removed, "retention_days": SCAN_RETENTION_DAYS})


#  ML remediation model 

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
        "ML retrain complete - samples: %d  severity classes: %s",
        ml_engine.metadata.get("sample_count", 0),
        ml_engine.metadata.get("severity_classes", []),
    )
    return JSONResponse({"ok": True, "metadata": ml_engine.metadata})


#  LLM code-fix helper 

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
    # Strip stray import lines - we only want the fixed code, not added imports
    lines = [l for l in lines if not _IMPORT_LINE.match(l)]
    return '\n'.join(lines).strip()


@app.post("/api/llm/codefix")
async def llm_codefix(
    payload: LLMFixRequest,
    current_user: dict = Depends(_require_user),
) -> JSONResponse:
    try:
        payload.validate_fields()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    quota = get_llm_rpm_quota(int(current_user["id"]))
    if quota["remaining"] <= 0:
        retry_after = max(1, quota["retry_after_seconds"])
        raise HTTPException(
            status_code=429,
            detail={
                "code": "LLM_RATE_LIMIT_REACHED",
                "message": f"AI request limit reached. You can send up to {LLM_RPM_LIMIT} requests per minute.",
                "limit": quota["limit"],
                "retry_after_seconds": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )
    record_llm_request(int(current_user["id"]), "/api/llm/codefix")

    from . import config
    if not config.NVIDIA_API_KEY:
        raise HTTPException(status_code=503, detail="NVIDIA_API_KEY not configured.")

    snippet_lines = payload.snippet.strip().splitlines()
    line_count = len(snippet_lines)
    rec_hint = f"\nFix guidance: {payload.recommendation}" if payload.recommendation else ""
    prompt = (
        f"Security vulnerability: {payload.cwe_id} in {payload.language}.{rec_hint}\n\n"
        f"VULNERABLE ({line_count} line{'s' if line_count != 1 else ''}):\n{payload.snippet}\n\n"
        f"FIXED (output EXACTLY {line_count} line{'s' if line_count != 1 else ''} - "
        f"the same code with only the vulnerability fixed, nothing added or removed):"
    )

    logger.info(
        "LLM code-fix requested by '%s' - CWE: %s  language: %s",
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
        logger.exception("NVIDIA API call failed - CWE: %s", payload.cwe_id)
        _record_error("/api/llm/codefix")
        raise HTTPException(status_code=502, detail="NVIDIA API error.")

    return JSONResponse({"ok": True, "text": text})


#  SASTRA AI Chatbot 

class ChatRequest(BaseModel):
    message: str
    history: list[dict] = []


@app.post("/api/chat")
async def chat_with_ai(
    payload: ChatRequest,
    current_user: dict = Depends(_require_user),
):
    """Stream a security-focused chat response using NVIDIA Llama 3.3 70B."""
    quota = get_llm_rpm_quota(int(current_user["id"]))
    if quota["remaining"] <= 0:
        retry_after = max(1, quota["retry_after_seconds"])
        raise HTTPException(
            status_code=429,
            detail={
                "code": "LLM_RATE_LIMIT_REACHED",
                "message": f"AI request limit reached. You can send up to {LLM_RPM_LIMIT} requests per minute.",
                "limit": quota["limit"],
                "retry_after_seconds": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )
    record_llm_request(int(current_user["id"]), "/api/chat")

    from . import config
    try:
        from openai import OpenAI
    except ImportError:
        raise HTTPException(status_code=503, detail="openai package not installed. Run: pip install openai")

    if not config.NVIDIA_CHAT_API_KEY:
        raise HTTPException(status_code=503, detail="NVIDIA_CHAT_API_KEY not configured.")

    user_role = current_user.get("role", "user")
    system_prompt = (
        "You are SASTRA AI, the built-in assistant for the SASTRA web application - "
        "a Static Application Security Testing (SAST) tool.\n\n"

        "## About SASTRA\n"
        "SASTRA scans source code for security vulnerabilities using 5,800+ regex rules, "
        "AST-based analysis, and an ML-based severity prediction model (Random Forest). "
        "It supports Python, Java, and C/C++ source files or ZIP archives.\n\n"

        "## How to Use the App\n"
        "- **New Scan**: Go to 'New Scan', upload a .py/.java/.c/.cpp/.zip file or paste code directly, "
        "select the language, and click Scan. Results appear in seconds.\n"
        "- **Scan Results**: Shows all findings grouped by severity (Critical / High / Medium / Low / Info). "
        "Each finding shows the CWE ID, OWASP category, affected line, and a code snippet.\n"
        "- **LLM Code Fix**: Click the fix icon on any finding to get an AI-generated remediation "
        "for that specific code snippet (requires the NVIDIA API key to be configured).\n"
        "- **PDF Report**: On the Scan Results page, click 'Download PDF' to export the full report.\n"
        "- **Scan History**: Browse all past scans, view findings from any previous scan.\n"
        "- **Dashboard**: Overview of total scans, finding trends, and severity breakdown charts.\n"
        "- **Settings**: Change your password and manage account preferences.\n"
        + (
            "- **Admin Panel**: Create and manage users, view all scans across all users, "
            "retrain the ML model, and monitor system health.\n"
            if user_role in ("admin", "superadmin") else ""
        ) +

        "\n## Severity Levels\n"
        "Critical > High > Medium > Low > Info. Always prioritize Critical and High findings first.\n\n"

        "## ML Model\n"
        "SASTRA uses a trained Random Forest model to predict severity and flag likely false positives. "
        "A finding marked as a likely false positive has a confidence score below 0.55.\n\n"

        "## Your Role\n"
        "Help users with: how to use SASTRA features, interpreting scan results, "
        "understanding CWE/OWASP categories, and secure coding in Python, Java, and C/C++.\n"
        "IMPORTANT: Match response length to question complexity. "
        "For simple questions give 1-3 sentences. For multi-step tasks give a clear numbered list. "
        "Never add preamble or filler. Be direct."
    )

    messages: list[dict] = [{"role": "system", "content": system_prompt}]
    for msg in payload.history[-10:]:
        if msg.get("role") in ("user", "assistant") and msg.get("content"):
            messages.append({"role": msg["role"], "content": str(msg["content"])[:2000]})
    messages.append({"role": "user", "content": str(payload.message)[:4000]})

    logger.info("Chat request from '%s'", current_user["username"])

    def _stream():
        import json as _json
        try:
            client = OpenAI(
                base_url="https://integrate.api.nvidia.com/v1",
                api_key=config.NVIDIA_CHAT_API_KEY,
            )
            completion = client.chat.completions.create(
                model="meta/llama-3.3-70b-instruct",
                messages=messages,
                temperature=0.2,
                top_p=0.7,
                max_tokens=1024,
                stream=True,
            )
            for chunk in completion:
                if chunk.choices and chunk.choices[0].delta.content is not None:
                    yield f"data: {_json.dumps({'token': chunk.choices[0].delta.content})}\n\n"
        except Exception:
            logger.exception("Chat API failed for user: %s", current_user["username"])
            yield f"data: {_json.dumps({'token': 'AI service unavailable. Please try again.'})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream")


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


#  scan endpoints 

@app.post("/api/scan")
@_limiter.limit("10/minute")
async def scan_file(
    request: Request,
    file: UploadFile | None = File(default=None),
    language: Optional[str] = Form(default=None),
    code: Optional[str] = Form(default=None),
    code_filename: Optional[str] = Form(default=None),
    current_user: dict = Depends(_require_user),
) -> JSONResponse:
    if app_state.get("scanner") is None:
        raise HTTPException(status_code=503, detail="Scanner is still initializing.")

    quota = get_hourly_scan_quota(int(current_user["id"]))
    if quota["remaining"] <= 0:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "SCAN_HOURLY_LIMIT_REACHED",
                "message": f"Hourly quota has been reached. You can run up to {SCAN_HOURLY_LIMIT} scans per hour.",
                "limit": quota["limit"],
                "retry_after_seconds": quota["retry_after_seconds"],
            },
        )

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
            logger.info("ZIP scan by '%s' - %s  files: %d", current_user["username"], filename, len(sources))
            scan_output   = scanner.scan_many(sources=sources, archive_name=filename)
            scan_language = scan_output["summary"]["language"]
        else:
            if len(data) > MAX_UPLOAD_SIZE_BYTES:
                raise HTTPException(status_code=413, detail="File too large. Upload files up to 2MB.")
            content = data.decode("utf-8", errors="ignore")
            if not content.strip():
                raise HTTPException(status_code=400, detail="Uploaded file is empty.")
            detected_language = infer_language(filename, language)
            logger.info("File scan by '%s' - %s  lang: %s", current_user["username"], filename, detected_language)
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
        logger.info("Paste scan by '%s' - %s  lang: %s", current_user["username"], synthetic_name, scan_language)
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
        "Scan #%d complete - user: '%s'  findings: %d  risk: %s",
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
