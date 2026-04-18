"""ORM models: users, scans, findings. Auth uses JWTs, so no sessions table."""

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    username      = Column(String(32), nullable=False, unique=True)
    password_hash = Column(Text, nullable=False)
    role          = Column(String(16), nullable=False, default="user")
    created_at    = Column(String(40), nullable=False)
    google_id     = Column(String(128), nullable=True, unique=True)

    # One user → many scans.
    # cascade="all, delete-orphan" means deleting a User automatically
    # deletes their Scans, which in turn deletes their Findings.
    scans = relationship(
        "Scan",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    llm_requests = relationship(
        "LLMRequest",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def to_dict(self, *, include_scan_count: bool = False) -> dict:
        payload = {
            "id":         self.id,
            "username":   self.username,
            "role":       self.role,
            "created_at": self.created_at,
        }
        if include_scan_count:
            payload["scan_count"] = len(self.scans) if self.scans is not None else 0
        return payload


class Scan(Base):
    __tablename__ = "scans"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    user_id        = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    filename       = Column(Text, nullable=False)
    language       = Column(String(16), nullable=False)
    scanned_at     = Column(String(40), nullable=False)
    risk_score     = Column(Float, nullable=False)
    total_findings = Column(Integer, nullable=False)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count     = Column(Integer, nullable=False, default=0)
    medium_count   = Column(Integer, nullable=False, default=0)
    low_count      = Column(Integer, nullable=False, default=0)
    info_count     = Column(Integer, nullable=False, default=0)
    files_scanned  = Column(Integer, nullable=False, default=1)

    user = relationship("User", back_populates="scans")
    findings = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Finding(Base):
    __tablename__ = "findings"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    scan_id         = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    rule_id         = Column(String(120), nullable=False)
    title           = Column(Text, nullable=False)
    cwe_id          = Column(String(20), nullable=False)
    cwe_name        = Column(Text, nullable=False)
    owasp_category  = Column(Text, nullable=False)
    severity        = Column(String(16), nullable=False)
    severity_score  = Column(Integer, nullable=False)
    language        = Column(String(16), nullable=False, default="")
    line_number     = Column(Integer, nullable=False)
    column_number   = Column(Integer, nullable=False)
    snippet         = Column(Text, nullable=False)
    source_path     = Column(Text, nullable=False, default="")
    recommendation  = Column(Text, nullable=False)
    ml_severity             = Column(String(16), nullable=False, default="")
    ml_severity_confidence  = Column(Float,      nullable=False, default=0.0)
    ml_confidence           = Column(Float,      nullable=False, default=0.0)
    source          = Column(String(40), nullable=False)
    confidence      = Column(Float, nullable=False)
    fp_flag         = Column(Integer, nullable=False, default=0)
    fp_label        = Column(Text, nullable=False, default="")
    llm_fix         = Column(Text, nullable=False, default="")

    scan = relationship("Scan", back_populates="findings")

    def to_dict(self) -> dict:
        return {
            "finding_id":       self.id,
            "rule_id":          self.rule_id,
            "title":            self.title,
            "cwe_id":           self.cwe_id,
            "cwe_name":         self.cwe_name,
            "owasp_category":   self.owasp_category,
            "severity":         self.severity,
            "severity_score":   self.severity_score,
            "language":         self.language,
            "line_number":      self.line_number,
            "column_number":    self.column_number,
            "snippet":          self.snippet,
            "source_path":      self.source_path,
            "recommendation":   self.recommendation,
            "ml_severity":            self.ml_severity,
            "ml_severity_confidence": self.ml_severity_confidence,
            "ml_confidence":          self.ml_confidence,
            "source":           self.source,
            "confidence":       self.confidence,
            "fp_flag":          bool(self.fp_flag),
            "fp_label":         self.fp_label,
            "llm_fix":          self.llm_fix or "",
        }


class LLMRequest(Base):
    __tablename__ = "llm_requests"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    user_id      = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    endpoint     = Column(String(32), nullable=False, default="")
    requested_at = Column(String(40), nullable=False)

    user = relationship("User", back_populates="llm_requests")
