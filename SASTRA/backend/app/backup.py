"""
Database backup utility — NFR-4.

Creates atomic SQLite backups using the sqlite3.backup() API, which
produces a consistent snapshot even while the database is in use.

Backup policy:
  - Backups are stored in BACKUP_DIR (app/data/backups/)..
  - File names follow the pattern: sast_<YYYYMMDDTHHMMSSZ>.db
  - A maximum of MAX_BACKUPS recent backups are retained; older ones
    are automatically pruned after each successful backup.

Recovery targets (NFR-4):
  - RPO 24 h — a daily backup (triggered on application startup) means
    at most one day of data can be lost.
  - RTO 4 h  — restoring is a single file copy: cp backup.db sast.db
"""

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("sast.backup")

MAX_BACKUPS = 7  # keep the seven most-recent backups (daily = one week)


def backup_database(db_path: Path, backup_dir: Path) -> Path:
    """
    Create an atomic backup of the SQLite database at *db_path*.

    The backup is written to *backup_dir* / ``sast_<timestamp>.db``.
    Afterwards, backups older than MAX_BACKUPS are pruned.

    Returns the ``Path`` of the newly created backup file.

    Raises ``FileNotFoundError`` if *db_path* does not exist.
    """
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found at {db_path}")

    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp   = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"sast_{timestamp}.db"

    src_conn = sqlite3.connect(str(db_path))
    dst_conn = sqlite3.connect(str(backup_path))
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()

    logger.info("Database backed up → %s", backup_path.name)
    _prune_old_backups(backup_dir)
    return backup_path


def _prune_old_backups(backup_dir: Path) -> None:
    """Remove the oldest backups, keeping only MAX_BACKUPS files."""
    backups = sorted(
        backup_dir.glob("sast_*.db"),
        key=lambda p: p.stat().st_mtime,
    )
    for old in backups[:-MAX_BACKUPS]:
        try:
            old.unlink()
            logger.info("Pruned old backup: %s", old.name)
        except OSError as exc:
            logger.warning("Could not prune backup %s: %s", old.name, exc)
