"""Load CWE data from the mapping dataset CSVs and tree_structure.json. Exposes
get_enrichment_text() for ML feature strings and get_parent() for OWASP fallback."""

import csv
import json
import re
import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

#  Internal stores 

# cwe_key → enrichment text string for ML features
_CWE_ENRICHMENT: Dict[str, str] = {}

# numeric string → numeric string, e.g. "242" → "1228"
_PARENT_OF: Dict[str, str] = {}

_loaded = False


#  Parsing helpers 

def _clean(text: str, max_chars: int = 200) -> str:
    """Strip CWE structured-text delimiters and truncate."""
    cleaned = re.sub(r"::", " ", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:max_chars]


def _extract_consequence_tokens(consequences: str) -> str:
    """
    Pull IMPACT values out of the Common Consequences field and return
    them as space-separated tokens the TF-IDF can learn from.

    Example input:  '::SCOPE:Integrity:IMPACT:Execute Unauthorized Code::'
    Example output: 'impact_execute_unauthorized_code'
    """
    impacts = re.findall(r"IMPACT:([^:]+)", consequences)
    tokens = []
    for raw in impacts:
        tok = raw.lower().strip()
        tok = re.sub(r"[^a-z0-9]+", "_", tok).strip("_")
        if tok and tok not in ("varies_by_context", "other", "unknown"):
            tokens.append(f"impact_{tok}")
    return " ".join(tokens)


def _cve_count_token(observed_examples: str) -> str:
    """
    Bucket the number of CVE references in Observed Examples into a
    categorical token so the FP model gets a real-world evidence signal.

    cve_none  → no real-world CVE documented (higher FP risk)
    cve_few   → 1-3 CVEs (moderate evidence)
    cve_many  → 4+ CVEs (well-documented, lower FP risk)
    """
    count = len(re.findall(r"CVE-\d{4}-\d+", observed_examples))
    if count == 0:
        return "cve_none"
    if count <= 3:
        return "cve_few"
    return "cve_many"


def _detection_token(detection_methods: str) -> str:
    """
    If static analysis is listed as a detection method, emit a token so
    the FP model learns these patterns are more reliably detectable.
    """
    if "static analysis" in detection_methods.lower():
        return "detection_static_analysis"
    return ""


#  CSV loader 

def _load_csv(csv_path: Path) -> None:
    if not csv_path.exists():
        logger.debug("CWE CSV not found, skipping: %s", csv_path)
        return
    try:
        with open(csv_path, encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                num = (row.get("CWE-ID") or "").strip()
                if not num:
                    continue
                key = f"CWE-{num}"

                description = _clean(
                    (row.get("Description") or ""), max_chars=150
                )
                consequences = _extract_consequence_tokens(
                    row.get("Common Consequences") or ""
                )
                cve_token = _cve_count_token(
                    row.get("Observed Examples") or ""
                )
                det_token = _detection_token(
                    row.get("Detection Methods") or ""
                )

                parts = [p for p in [description, consequences, cve_token, det_token] if p]
                enrichment = " ".join(parts)

                # First writer wins (SD dataset has priority over RC)
                _CWE_ENRICHMENT.setdefault(key, enrichment)

    except Exception:
        logger.exception("Failed to load CWE CSV: %s", csv_path)


#  Tree loader 

def _walk_tree(node: dict, parent_id: Optional[str]) -> None:
    for child_id, subtree in node.items():
        if parent_id is not None:
            _PARENT_OF.setdefault(child_id, parent_id)
        _walk_tree(subtree, child_id)


def _load_tree(tree_path: Path) -> None:
    if not tree_path.exists():
        logger.debug("CWE tree not found, skipping: %s", tree_path)
        return
    try:
        with open(tree_path, encoding="utf-8") as f:
            tree = json.load(f)
        _walk_tree(tree, None)
    except Exception:
        logger.exception("Failed to load CWE tree: %s", tree_path)


#  Public init 

def load(datasets_root: Path) -> None:
    global _loaded
    if _loaded:
        return

    base = datasets_root / "CWE mapping Dataset"
    sd = base / "Software Development"
    rc = base / "Research Concept"

    # Software Development first (most relevant for SAST)
    _load_csv(sd / "SD_CWEs.csv")
    _load_tree(sd / "tree_structure.json")

    # Research Concept fills in gaps
    _load_csv(rc / "RC_CWEs.csv")
    _load_tree(rc / "tree_structure.json")

    _loaded = True
    logger.info(
        "CWE dataset loaded - enrichment: %d entries, hierarchy: %d parent links",
        len(_CWE_ENRICHMENT),
        len(_PARENT_OF),
    )


def _ensure_loaded() -> None:
    if not _loaded:
        from .config import DATASETS_ROOT
        load(DATASETS_ROOT)


#  Public API 

def get_enrichment_text(cwe_key: str) -> str:
    """
    Return semantic CWE text for ML feature enrichment.

    This string is appended to the ML input at both training and inference
    time, giving the TF-IDF vectorizer real signal about what the CWE means:
      - description text (what the weakness is)
      - consequence tokens (what the attacker can achieve → severity signal)
      - CVE count token (real-world evidence → FP signal)
      - detection method token (static-analysis reliability → FP signal)

    Returns empty string if the CWE is unknown (safe - models degrade
    gracefully to code-only features).
    """
    _ensure_loaded()
    return _CWE_ENRICHMENT.get(cwe_key, "")


def get_parent(cwe_key: str) -> Optional[str]:
    """
    Return the parent CWE key (e.g. 'CWE-1228') for OWASP hierarchy lookup.
    Returns None if no parent is known.
    """
    _ensure_loaded()
    num = cwe_key.removeprefix("CWE-")
    parent_num = _PARENT_OF.get(num)
    return f"CWE-{parent_num}" if parent_num else None
