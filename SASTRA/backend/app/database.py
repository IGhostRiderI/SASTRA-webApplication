"""SQLAlchemy engine, session factory, declarative base, and a _get_session
context manager that commits on exit and rolls back on exception."""

from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import DB_PATH

#  engine 
# check_same_thread=False is required for SQLite when used with FastAPI because
# FastAPI may access the same connection from different threads during testing
# or background tasks.  The session-per-request pattern below keeps this safe.
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,         # set True to log every SQL statement during debugging
)


# Enforce foreign key constraints for every connection opened by the engine.
# SQLite disables FK enforcement by default; this re-enables it.
@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


#  session factory 
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,   # keep ORM objects usable after commit
)


#  declarative base 
class Base(DeclarativeBase):
    pass


#  session context manager 
@contextmanager
def _get_session() -> Session:
    """
    Open a SQLAlchemy session, commit on clean exit, roll back on exception.

    Example::

        with _get_session() as session:
            user = session.get(User, user_id)
            user.role = "admin"
            # commit happens automatically on exit
    """
    session: Session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
