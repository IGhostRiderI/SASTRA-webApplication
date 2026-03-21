"""
Database access layer.

Authentication
--------------
Session tokens stored in SQLite are replaced by stateless JWT tokens.
- ``create_access_token(user_id)``  — issues a signed JWT valid for 7 days.
- ``decode_access_token(token)``    — verifies and returns the user_id, or
                                      None if the token is expired/invalid.
No sessions table is created or used.

ORM
---
All database access goes through SQLAlchemy ORM sessions (see database.py).
Raw sqlite3 is no longer used anywhere in this module.
"""

import hashlib
import hmac
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from passlib.hash import pbkdf2_sha256 as _passlib_pbkdf2

import jwt
from sqlalchemy import func, text

from .config import (
    DB_PATH,
    JWT_ALGORITHM,
    JWT_EXPIRY_DAYS,
    JWT_SECRET,
)
from .database import Base, _get_session, engine
from .models import Finding, Scan, User

# ── roles ──────────────────────────────────────────────────────────────────────
ROLE_USER       = "user"
ROLE_ADMIN      = "admin"
ROLE_SUPERADMIN = "superadmin"
VALID_ROLES     = {ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN}

# ── superadmin credentials ─────────────────────────────────────────────────────
# Loaded from environment variables at startup.
# Falls back to the defaults below ONLY for local development convenience.
# In any real deployment set SUPERADMIN_USERNAME and SUPERADMIN_PASSWORD
# as environment variables — never commit credentials to the repository.
SUPERADMIN_USERNAME = os.environ.get("SUPERADMIN_USERNAME", "Nadinak")
SUPERADMIN_PASSWORD = os.environ.get("SUPERADMIN_PASSWORD", "Nadina")

# ── password hashing (passlib PBKDF2-SHA256) ───────────────────────────────────
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

# ── scan retention ─────────────────────────────────────────────────────────────
# NFR-5: scan records older than this are automatically purged on startup
# and on demand via POST /api/admin/purge.
SCAN_RETENTION_DAYS = 90


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _hash_password(password: str) -> str:
    """Hash *password* using passlib's PBKDF2-SHA256 scheme (NFR-3)."""
    return _passlib_pbkdf2.hash(password)


def _verify_password(password: str, hashed_value: str) -> bool:
    """
    Verify *password* against *hashed_value*.

    Supports two formats:
      - New format: passlib PBKDF2-SHA256 ($pbkdf2-sha256$...)
      - Legacy format: raw hashlib encoding (pbkdf2_sha256$iters$salt$digest)
    """
    if hashed_value.startswith("$pbkdf2"):
        # New passlib format
        try:
            return _passlib_pbkdf2.verify(password, hashed_value)
        except Exception:
            return False

    # Legacy hashlib format — backward compatibility for existing accounts
    try:
        algo, iterations_raw, salt_hex, digest_hex = hashed_value.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iterations_raw)
        salt       = bytes.fromhex(salt_hex)
        expected   = bytes.fromhex(digest_hex)
        candidate  = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(candidate, expected)
    except (ValueError, TypeError):
        return False


def _clean_username(username: str) -> str:
    cleaned = (username or "").strip()
    if not USERNAME_REGEX.fullmatch(cleaned):
        raise ValueError("Username must be 3-32 chars and use letters, numbers, _, -, or .")
    return cleaned


def _validate_password(password: str) -> str:
    cleaned = (password or "").strip()
    if len(cleaned) < 4:
        raise ValueError("Password must be at least 4 characters.")
    return cleaned


def _normalize_role(role: str) -> str:
    normalized = (role or ROLE_USER).strip().lower()
    if normalized not in VALID_ROLES:
        raise ValueError("Invalid role.")
    return normalized


# ══════════════════════════════════════════════════════════════════════════════
# JWT AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════════════

def create_access_token(user_id: int) -> str:
    """
    Issue a signed JWT containing the user ID.

    The token is valid for JWT_EXPIRY_DAYS days (default 7).
    It is stored in an HttpOnly cookie by the caller (main.py) — the
    client never sees it in JavaScript.
    """
    now = _utc_now()
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(days=JWT_EXPIRY_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[int]:
    """
    Verify *token* and return the encoded user_id, or None if:
      - the token is malformed
      - the signature is invalid
      - the token has expired
    """
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )
        return int(payload["sub"])
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE INITIALISATION
# ══════════════════════════════════════════════════════════════════════════════

def _ensure_superadmin() -> int:
    """
    Create the superadmin account if it does not exist, or update its
    password_hash and role if it does.  Returns the superadmin user id.
    """
    with _get_session() as session:
        user = (
            session.query(User)
            .filter(User.username == SUPERADMIN_USERNAME)
            .first()
        )
        hashed = _hash_password(SUPERADMIN_PASSWORD)
        if user is None:
            user = User(
                username=SUPERADMIN_USERNAME,
                password_hash=hashed,
                role=ROLE_SUPERADMIN,
                created_at=_utc_now_iso(),
            )
            session.add(user)
            session.flush()
        else:
            user.role          = ROLE_SUPERADMIN
            user.password_hash = hashed
            session.flush()
        return user.id


def init_db() -> None:
    """
    Create all tables that do not yet exist and apply column migrations
    needed for databases created by earlier versions of the application.

    ``Base.metadata.create_all`` is idempotent — it skips tables that
    already exist, so this is safe to call on every startup.
    """
    # Create tables defined in models.py that do not exist yet
    Base.metadata.create_all(bind=engine)

    # ── column migrations for existing databases ────────────────────────────
    # These ALTER TABLE statements add columns introduced after the initial
    # release.  Each is wrapped in a try/except so it is silently skipped
    # if the column already exists (SQLite raises OperationalError on
    # duplicate column addition).
    migration_statements = [
        "ALTER TABLE scans    ADD COLUMN files_scanned           INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE findings ADD COLUMN source_path             TEXT    NOT NULL DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN language                TEXT    NOT NULL DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN ml_confidence           REAL    NOT NULL DEFAULT 0",
        "ALTER TABLE findings ADD COLUMN ml_severity             TEXT    NOT NULL DEFAULT ''",
        "ALTER TABLE findings ADD COLUMN ml_severity_confidence  REAL    NOT NULL DEFAULT 0",
        "ALTER TABLE findings ADD COLUMN fp_flag                 INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE findings ADD COLUMN fp_label                TEXT    NOT NULL DEFAULT ''",
    ]

    with engine.connect() as conn:
        for stmt in migration_statements:
            try:
                conn.execute(text(stmt))
                conn.commit()
            except Exception:
                # Column already exists — skip silently
                conn.rollback()

    superadmin_id = _ensure_superadmin()

    # Reassign any scan whose user_id is NULL / 0 / orphaned
    with _get_session() as session:
        valid_user_ids = [row.id for row in session.query(User.id).all()]
        if valid_user_ids:
            (
                session.query(Scan)
                .filter(
                    (Scan.user_id == None) |
                    (Scan.user_id == 0) |
                    (~Scan.user_id.in_(valid_user_ids))
                )
                .update({"user_id": superadmin_id}, synchronize_session=False)
            )


# ══════════════════════════════════════════════════════════════════════════════
# USER MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def create_user(
    username: str, password: str, role: str = ROLE_USER
) -> Dict[str, object]:
    clean_username = _clean_username(username)
    clean_password = _validate_password(password)
    normalized_role = _normalize_role(role)

    with _get_session() as session:
        existing = (
            session.query(User)
            .filter(func.lower(User.username) == func.lower(clean_username))
            .first()
        )
        if existing is not None:
            raise ValueError("Username already exists.")

        user = User(
            username=clean_username,
            password_hash=_hash_password(clean_password),
            role=normalized_role,
            created_at=_utc_now_iso(),
        )
        session.add(user)
        session.flush()
        return user.to_dict()


def get_user_by_id(user_id: int) -> Optional[Dict[str, object]]:
    with _get_session() as session:
        user = session.get(User, user_id)
        if user is None:
            return None
        return user.to_dict()


def authenticate_user(
    username: str, password: str
) -> Optional[Dict[str, object]]:
    clean_username = (username or "").strip()
    if not clean_username:
        return None

    with _get_session() as session:
        user = (
            session.query(User)
            .filter(User.username == clean_username)
            .first()
        )
        if user is None:
            return None
        if not _verify_password(password or "", user.password_hash):
            return None
        return user.to_dict()


def list_users() -> List[Dict[str, object]]:
    with _get_session() as session:
        rows = (
            session.query(User, func.count(Scan.id).label("scan_count"))
            .outerjoin(Scan, Scan.user_id == User.id)
            .group_by(User.id)
            .order_by(User.username)
            .all()
        )
        result = []
        for user, scan_count in rows:
            d = user.to_dict()
            d["scan_count"] = scan_count or 0
            result.append(d)
        return result


def update_user_role(user_id: int, role: str) -> Optional[Dict[str, object]]:
    normalized_role = _normalize_role(role)
    with _get_session() as session:
        user = session.get(User, user_id)
        if user is None:
            return None
        user.role = normalized_role
        session.flush()
        return user.to_dict()


def update_user_credentials(
    user_id: int,
    *,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> Optional[Dict[str, object]]:
    clean_username: Optional[str] = None
    clean_password: Optional[str] = None

    if username is not None:
        clean_username = _clean_username(username)
    if password is not None:
        clean_password = _validate_password(password)

    if clean_username is None and clean_password is None:
        raise ValueError("Provide username and/or password to update.")

    with _get_session() as session:
        user = session.get(User, user_id)
        if user is None:
            return None

        if clean_username is not None:
            existing = (
                session.query(User)
                .filter(func.lower(User.username) == func.lower(clean_username), User.id != user_id)
                .first()
            )
            if existing is not None:
                raise ValueError("Username already exists.")
            user.username = clean_username

        if clean_password is not None:
            user.password_hash = _hash_password(clean_password)

        session.flush()
        return user.to_dict()


def delete_user_and_data(user_id: int) -> None:
    """
    Delete a user and all their associated scans and findings.
    Child rows are removed explicitly in dependency order so this works even
    when older SQLite tables were created without ON DELETE CASCADE.
    """
    with _get_session() as session:
        scan_ids = [
            row[0]
            for row in session.query(Scan.id).filter(Scan.user_id == user_id).all()
        ]

        if scan_ids:
            session.query(Finding).filter(Finding.scan_id.in_(scan_ids)).delete(
                synchronize_session=False
            )
            session.query(Scan).filter(Scan.id.in_(scan_ids)).delete(
                synchronize_session=False
            )

        session.query(User).filter(User.id == user_id).delete(synchronize_session=False)


# ══════════════════════════════════════════════════════════════════════════════
# SCAN HISTORY — NFR-5: 90-DAY RETENTION
# ══════════════════════════════════════════════════════════════════════════════

def purge_old_scans(retention_days: int = SCAN_RETENTION_DAYS) -> int:
    """
    Delete all scans (and their findings) whose ``scanned_at`` timestamp
    is older than *retention_days* days from the current UTC time.

    SQLAlchemy cascade handles finding deletion automatically.

    Returns the number of scan records deleted.
    """
    cutoff = (_utc_now() - timedelta(days=retention_days)).isoformat()

    with _get_session() as session:
        old_scans = (
            session.query(Scan)
            .filter(Scan.scanned_at < cutoff)
            .all()
        )
        count = len(old_scans)
        for scan in old_scans:
            session.delete(scan)
        return count


# ══════════════════════════════════════════════════════════════════════════════
# SCAN STORAGE AND RETRIEVAL
# ══════════════════════════════════════════════════════════════════════════════

def save_scan(
    user_id: int, filename: str, language: str, scan_output: Dict[str, object]
) -> int:
    summary  = scan_output["summary"]
    severity = summary["severity"]

    with _get_session() as session:
        scan = Scan(
            user_id        = user_id,
            filename       = filename,
            language       = language,
            scanned_at     = _utc_now_iso(),
            risk_score     = summary["risk_score"],
            total_findings = summary["total_findings"],
            critical_count = severity.get("Critical", 0),
            high_count     = severity.get("High", 0),
            medium_count   = severity.get("Medium", 0),
            low_count      = severity.get("Low", 0) + severity.get("Info", 0),
            info_count     = 0,
            files_scanned  = int(summary.get("files_scanned", 1)),
        )
        session.add(scan)
        session.flush()   # populate scan.id before creating findings

        finding_objects = [
            Finding(
                scan_id          = scan.id,
                rule_id          = item["rule_id"],
                title            = item["title"],
                cwe_id           = item["cwe_id"],
                cwe_name         = item["cwe_name"],
                owasp_category   = item["owasp_category"],
                severity         = item["severity"],
                severity_score   = item["severity_score"],
                language         = item.get("language", language),
                line_number      = item["line_number"],
                column_number    = item["column_number"],
                snippet          = item["snippet"],
                source_path      = item.get("source_path", filename),
                recommendation   = item["recommendation"],
                ml_severity            = item.get("ml_severity", ""),
                ml_severity_confidence = item.get("ml_severity_confidence", 0.0),
                ml_confidence          = item.get("ml_confidence", 0.0),
                source           = item["source"],
                confidence       = item["confidence"],
                fp_flag          = 1 if item.get("fp_flag", False) else 0,
                fp_label         = item.get("fp_label", ""),
            )
            for item in scan_output.get("findings", [])
        ]
        session.add_all(finding_objects)
        return scan.id


def list_scans(
    requester_user_id: int,
    *,
    limit: int = 30,
    include_all: bool = False,
    target_user_id: Optional[int] = None,
) -> List[Dict[str, object]]:
    with _get_session() as session:
        query = (
            session.query(Scan, User.username.label("owner_username"))
            .join(User, User.id == Scan.user_id)
        )

        if include_all:
            if target_user_id is not None:
                query = query.filter(Scan.user_id == target_user_id)
        else:
            query = query.filter(Scan.user_id == requester_user_id)

        rows = query.order_by(Scan.id.desc()).limit(limit).all()

        return [
            {
                "id":             scan.id,
                "user_id":        scan.user_id,
                "owner_username": owner_username,
                "filename":       scan.filename,
                "language":       scan.language,
                "scanned_at":     scan.scanned_at,
                "risk_score":     scan.risk_score,
                "total_findings": scan.total_findings,
                "critical_count": scan.critical_count,
                "high_count":     scan.high_count,
                "medium_count":   scan.medium_count,
                "low_count":      scan.low_count,
                "files_scanned":  scan.files_scanned,
            }
            for scan, owner_username in rows
        ]


def get_scan(
    scan_id: int,
    *,
    requester_user_id: int,
    include_all: bool = False,
) -> Optional[Dict[str, object]]:
    with _get_session() as session:
        query = (
            session.query(Scan, User.username.label("owner_username"))
            .join(User, User.id == Scan.user_id)
            .filter(Scan.id == scan_id)
        )
        if not include_all:
            query = query.filter(Scan.user_id == requester_user_id)

        row = query.first()
        if row is None:
            return None

        scan, owner_username = row

        finding_rows = (
            session.query(Finding)
            .filter(Finding.scan_id == scan_id)
            .order_by(Finding.severity_score.desc(), Finding.line_number.asc())
            .all()
        )

    summary = {
        "total_findings": scan.total_findings,
        "risk_score":     scan.risk_score,
        "severity": {
            "Critical": scan.critical_count,
            "High":     scan.high_count,
            "Medium":   scan.medium_count,
            "Low":      scan.low_count,
        },
        "files_scanned": scan.files_scanned,
        "filename":      scan.filename,
        "language":      scan.language,
    }

    cwe_counter:   Dict[str, int] = {}
    owasp_counter: Dict[str, int] = {}
    findings = []
    for f in finding_rows:
        d = f.to_dict()
        findings.append(d)
        cwe_counter[d["cwe_id"]]        = cwe_counter.get(d["cwe_id"], 0) + 1
        owasp_counter[d["owasp_category"]] = owasp_counter.get(d["owasp_category"], 0) + 1

    summary["top_cwe"]   = sorted(cwe_counter.items(),   key=lambda x: x[1], reverse=True)[:8]
    summary["top_owasp"] = sorted(owasp_counter.items(), key=lambda x: x[1], reverse=True)[:8]

    return {
        "scan_id":        scan.id,
        "owner_id":       scan.user_id,
        "owner_username": owner_username,
        "filename":       scan.filename,
        "language":       scan.language,
        "scanned_at":     scan.scanned_at,
        "summary":        summary,
        "findings":       findings,
    }


def get_finding(
    scan_id: int,
    finding_id: int,
    *,
    requester_user_id: int,
    include_all: bool = False,
) -> Optional[Dict[str, object]]:
    with _get_session() as session:
        scan_query = (
            session.query(Scan, User.username.label("owner_username"))
            .join(User, User.id == Scan.user_id)
            .filter(Scan.id == scan_id)
        )
        if not include_all:
            scan_query = scan_query.filter(Scan.user_id == requester_user_id)

        scan_row = scan_query.first()
        if scan_row is None:
            return None

        scan, owner_username = scan_row

        finding = (
            session.query(Finding)
            .filter(Finding.scan_id == scan_id, Finding.id == finding_id)
            .first()
        )
        if finding is None:
            return None

        return {
            "scan": {
                "scan_id":        scan.id,
                "owner_id":       scan.user_id,
                "owner_username": owner_username,
                "filename":       scan.filename,
                "language":       scan.language,
                "scanned_at":     scan.scanned_at,
            },
            "finding": finding.to_dict(),
        }
