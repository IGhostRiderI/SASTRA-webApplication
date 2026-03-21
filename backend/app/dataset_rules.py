import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from .config import JULIET_TESTCASES_DIR, LANGUAGE_TO_CSV, RULES_CACHE_PATH
from .mappings import map_cwe_to_owasp, normalize_cwe, severity_for_cwe

csv.field_size_limit(100000000)

CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
CWE_RE = re.compile(r"CWE[-_]?([0-9]+)", re.IGNORECASE)

ALLOWED_CALLS = {
    "python": {
        "eval", "exec", "compile", "input", "open", "loads", "load", "system", "popen", "Popen", "run",
        "call", "check_output", "mktemp", "chmod", "pickle", "yaml", "literal_eval", "subprocess",
    },
    "java": {
        "exec", "loadClass", "newInstance", "getRuntime", "setAccessible", "forName", "readObject", "writeObject",
        "getConnection", "prepareStatement", "createStatement", "evaluate", "setProperty", "deserialize", "parse",
    },
    "cpp": {
        "strcpy", "strncpy", "strcat", "strncat", "sprintf", "vsprintf", "gets", "scanf", "fscanf", "sscanf",
        "memcpy", "memmove", "system", "popen", "realpath", "wcscpy", "wcsncpy", "recv", "strtok",
    },
}

BASE_SEED_RULES = [
    # ── existing rules ─────────────────────────────────────────────────────────
    {"language": "python", "pattern": r"\beval\s*\(", "title": "Dangerous dynamic evaluation", "cwe_id": "CWE-94", "cwe_name": "Code Injection"},
    {"language": "python", "pattern": r"\bexec\s*\(", "title": "Unsafe exec usage", "cwe_id": "CWE-94", "cwe_name": "Code Injection"},
    {"language": "python", "pattern": r"\bpickle\.loads\s*\(", "title": "Unsafe deserialization", "cwe_id": "CWE-502", "cwe_name": "Deserialization of Untrusted Data"},
    {"language": "python", "pattern": r"\byaml\.load\s*\(", "title": "Unsafe YAML load", "cwe_id": "CWE-20", "cwe_name": "Improper Input Validation"},
    {"language": "python", "pattern": r"\bos\.system\s*\(", "title": "OS command execution sink", "cwe_id": "CWE-78", "cwe_name": "OS Command Injection"},
    {"language": "java", "pattern": r"Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(", "title": "Command execution sink", "cwe_id": "CWE-78", "cwe_name": "OS Command Injection"},
    {"language": "java", "pattern": r"ObjectInputStream\s*\(", "title": "Potential unsafe deserialization", "cwe_id": "CWE-502", "cwe_name": "Deserialization of Untrusted Data"},
    {"language": "java", "pattern": r"Statement\s*\.\s*execute(Query|Update)?\s*\(", "title": "Potential SQL injection sink", "cwe_id": "CWE-89", "cwe_name": "SQL Injection"},
    {"language": "cpp", "pattern": r"\bstrcpy\s*\(", "title": "Unbounded copy", "cwe_id": "CWE-120", "cwe_name": "Buffer Copy without Checking Size of Input"},
    {"language": "cpp", "pattern": r"\bsprintf\s*\(", "title": "Unbounded format write", "cwe_id": "CWE-120", "cwe_name": "Buffer Copy without Checking Size of Input"},
    {"language": "cpp", "pattern": r"\bgets\s*\(", "title": "Unsafe input API", "cwe_id": "CWE-242", "cwe_name": "Use of Inherently Dangerous Function"},
    {"language": "cpp", "pattern": r"\bsystem\s*\(", "title": "Command execution sink", "cwe_id": "CWE-78", "cwe_name": "OS Command Injection"},

    # ── FR-9: missing input validation patterns (CWE-20) ───────────────────────
    # Python — untrusted input sources used without validation
    {"language": "python", "pattern": r"\bsys\.argv\b",
     "title": "Unvalidated command-line argument access",
     "cwe_id": "CWE-20", "cwe_name": "Improper Input Validation"},
    {"language": "python", "pattern": r"\brequest\.(args|form|json|data|values|files)\b",
     "title": "Unvalidated web request input accessed directly",
     "cwe_id": "CWE-20", "cwe_name": "Improper Input Validation"},
    {"language": "python", "pattern": r"\bos\.environ\b",
     "title": "Unvalidated environment variable access",
     "cwe_id": "CWE-20", "cwe_name": "Improper Input Validation"},
    {"language": "python", "pattern": r"\binput\s*\(",
     "title": "Unvalidated user input via input()",
     "cwe_id": "CWE-20", "cwe_name": "Improper Input Validation"},

    # Java — HTTP request input sources without explicit validation
    {"language": "java", "pattern": r"\bgetParameter\s*\(",
     "title": "Unvalidated HTTP request parameter",
     "cwe_id": "CWE-20", "cwe_name": "Improper Input Validation"},
    {"language": "java", "pattern": r"\bgetHeader\s*\(",
     "title": "Unvalidated HTTP request header access",
     "cwe_id": "CWE-20", "cwe_name": "Improper Input Validation"},
    {"language": "java", "pattern": r"\bgetQueryString\s*\(",
     "title": "Unvalidated query string access",
     "cwe_id": "CWE-20", "cwe_name": "Improper Input Validation"},
    {"language": "java", "pattern": r"\bgetInputStream\s*\(",
     "title": "Unvalidated raw request body access",
     "cwe_id": "CWE-20", "cwe_name": "Improper Input Validation"},

    # C++ — external input sources without validation
    {"language": "cpp", "pattern": r"\bgetenv\s*\(",
     "title": "Unvalidated environment variable access",
     "cwe_id": "CWE-20", "cwe_name": "Improper Input Validation"},
    {"language": "cpp", "pattern": r"\batoi\s*\(",
     "title": "Unvalidated string-to-integer conversion (atoi does not detect errors)",
     "cwe_id": "CWE-20", "cwe_name": "Improper Input Validation"},
    {"language": "cpp", "pattern": r"\batof\s*\(",
     "title": "Unvalidated string-to-float conversion (atof does not detect errors)",
     "cwe_id": "CWE-20", "cwe_name": "Improper Input Validation"},
    {"language": "cpp", "pattern": r"\bscanf\s*\(",
     "title": "Unvalidated user input via scanf",
     "cwe_id": "CWE-20", "cwe_name": "Improper Input Validation"},
]


@dataclass
class Rule:
    id: str
    language: str
    title: str
    pattern: str
    cwe_id: str
    cwe_name: str
    severity: str
    owasp_category: str
    source: str
    confidence: float


def _extract_calls(snippet: str) -> Iterable[str]:
    if not snippet:
        return []
    return CALL_RE.findall(snippet)


def _extract_cwe(parts: Iterable[str]) -> str:
    for part in parts:
        m = CWE_RE.search(part)
        if m:
            return f"CWE-{m.group(1)}"
    return ""


def _generate_csv_rules(language: str, csv_path: Path) -> Tuple[List[Rule], Dict[str, Dict[str, object]]]:
    rules: List[Rule] = []
    cwe_catalog: Dict[str, Dict[str, object]] = {}
    if not csv_path.exists():
        return rules, cwe_catalog

    counts: Counter[Tuple[str, str]] = Counter()
    cwe_names: Dict[str, str] = {}
    cwe_occurrences: Counter[str] = Counter()

    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            cwe = normalize_cwe(row.get("cwe_id", ""))
            if cwe == "CWE-000":
                continue
            cwe_name = row.get("cwe_name", "") or "Unknown CWE"
            cwe_names[cwe] = cwe_name
            cwe_occurrences[cwe] += 1
            for token in _extract_calls(row.get("vul_code", "")):
                if token in ALLOWED_CALLS[language]:
                    counts[(cwe, token)] += 1

    threshold = 3
    for (cwe, token), freq in sorted(counts.items(), key=lambda item: item[1], reverse=True):
        if freq < threshold:
            continue
        cwe_name = cwe_names.get(cwe, "Unknown CWE")
        rules.append(
            Rule(
                id=f"csv-{language}-{cwe.lower()}-{token.lower()}",
                language=language,
                title=f"Dataset-derived risky call: {token}",
                pattern=rf"\b{re.escape(token)}\s*\(",
                cwe_id=cwe,
                cwe_name=cwe_name,
                severity=severity_for_cwe(cwe, cwe_name),
                owasp_category=map_cwe_to_owasp(cwe, cwe_name),
                source="dataset:13870382",
                confidence=min(0.98, 0.50 + freq / 50),
            )
        )

    for cwe, count in cwe_occurrences.items():
        cwe_name = cwe_names.get(cwe, "Unknown CWE")
        cwe_catalog[cwe] = {
            "cwe_name": cwe_name,
            "severity": severity_for_cwe(cwe, cwe_name),
            "owasp_category": map_cwe_to_owasp(cwe, cwe_name),
            "samples": int(count),
            "source": "dataset:13870382",
        }

    return rules, cwe_catalog


def _generate_juliet_cpp_rules() -> Tuple[List[Rule], Dict[str, Dict[str, object]]]:
    rules: List[Rule] = []
    cwe_catalog: Dict[str, Dict[str, object]] = {}

    if not JULIET_TESTCASES_DIR.exists():
        return rules, cwe_catalog

    counts: Counter[Tuple[str, str]] = Counter()
    cwe_file_count: Counter[str] = Counter()

    max_files_per_cwe = 30
    for path in JULIET_TESTCASES_DIR.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}:
            continue
        if "bad" not in path.stem.lower():
            continue

        cwe = _extract_cwe(path.parts)
        if not cwe:
            continue
        if cwe_file_count[cwe] >= max_files_per_cwe:
            continue

        cwe_file_count[cwe] += 1
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for token in _extract_calls(content):
            if token in ALLOWED_CALLS["cpp"]:
                counts[(cwe, token)] += 1

    threshold = 2
    for (cwe, token), freq in sorted(counts.items(), key=lambda item: item[1], reverse=True):
        if freq < threshold:
            continue
        rules.append(
            Rule(
                id=f"juliet-cpp-{cwe.lower()}-{token.lower()}",
                language="cpp",
                title=f"Juliet-derived risky call: {token}",
                pattern=rf"\b{re.escape(token)}\s*\(",
                cwe_id=cwe,
                cwe_name="Juliet CWE pattern",
                severity=severity_for_cwe(cwe, ""),
                owasp_category=map_cwe_to_owasp(cwe, ""),
                source="dataset:juliet-cpp",
                confidence=min(0.95, 0.45 + freq / 25),
            )
        )

    for cwe, count in cwe_file_count.items():
        cwe_catalog[cwe] = {
            "cwe_name": "Juliet testcases",
            "severity": severity_for_cwe(cwe, ""),
            "owasp_category": map_cwe_to_owasp(cwe, ""),
            "samples": int(count),
            "source": "dataset:juliet-cpp",
        }

    return rules, cwe_catalog


def _seed_rules() -> List[Rule]:
    seeded: List[Rule] = []
    for item in BASE_SEED_RULES:
        cwe = normalize_cwe(item["cwe_id"])
        seeded.append(
            Rule(
                id=f"seed-{item['language']}-{cwe.lower()}-{abs(hash(item['pattern'])) % 100000}",
                language=item["language"],
                title=item["title"],
                pattern=item["pattern"],
                cwe_id=cwe,
                cwe_name=item["cwe_name"],
                severity=severity_for_cwe(cwe, item["cwe_name"]),
                owasp_category=map_cwe_to_owasp(cwe, item["cwe_name"]),
                source="seed",
                confidence=0.99,
            )
        )
    return seeded


def _merge_rules(rule_sets: Iterable[List[Rule]]) -> List[Rule]:
    merged: Dict[Tuple[str, str, str], Rule] = {}
    for rules in rule_sets:
        for rule in rules:
            key = (rule.language, rule.pattern, rule.cwe_id)
            current = merged.get(key)
            if current is None or rule.confidence > current.confidence:
                merged[key] = rule
    return sorted(merged.values(), key=lambda r: (r.language, r.cwe_id, r.id))


def generate_rules_catalog() -> Dict[str, object]:
    seed = _seed_rules()

    csv_rule_sets: List[List[Rule]] = []
    csv_catalogs: List[Dict[str, Dict[str, object]]] = []
    for language, csv_path in LANGUAGE_TO_CSV.items():
        rules, catalog = _generate_csv_rules(language, csv_path)
        csv_rule_sets.append(rules)
        csv_catalogs.append(catalog)

    juliet_rules, juliet_catalog = _generate_juliet_cpp_rules()

    all_rules = _merge_rules([seed, *csv_rule_sets, juliet_rules])

    cwe_catalog: Dict[str, Dict[str, object]] = {}
    for catalog in [*csv_catalogs, juliet_catalog]:
        for cwe, payload in catalog.items():
            if cwe not in cwe_catalog:
                cwe_catalog[cwe] = payload
                continue
            cwe_catalog[cwe]["samples"] = int(cwe_catalog[cwe].get("samples", 0)) + int(payload.get("samples", 0))
            if cwe_catalog[cwe].get("source") != payload.get("source"):
                cwe_catalog[cwe]["source"] = "multiple"

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rule_count": len(all_rules),
        "rules": [asdict(rule) for rule in all_rules],
        "cwe_catalog": cwe_catalog,
    }
    return payload


def load_or_generate_rules(force: bool = False) -> Dict[str, object]:
    if RULES_CACHE_PATH.exists() and not force:
        with RULES_CACHE_PATH.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    payload = generate_rules_catalog()
    RULES_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with RULES_CACHE_PATH.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    return payload
