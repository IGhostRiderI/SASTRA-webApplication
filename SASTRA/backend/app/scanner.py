import re
import logging
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional

from .ast_scanner import (
    JAVALANG_AVAILABLE, CLANG_AVAILABLE, is_clang_runtime_ready,
    ast_scan_java, ast_scan_python, ast_scan_cpp,
)
from .config import MAX_FINDINGS_PER_SCAN
from .mappings import severity_score
from .preprocessor import preprocess


logger = logging.getLogger("sast.scanner")


@dataclass
class CompiledRule:
    id: str
    language: str
    title: str
    regex: re.Pattern
    cwe_id: str
    cwe_name: str
    severity: str
    owasp_category: str
    source: str
    confidence: float


def recommendation_for_cwe(cwe_id: str) -> str:
    if cwe_id in {"CWE-78", "CWE-77", "CWE-94"}:
        return "Avoid executing dynamic commands/code from untrusted input; use strict allowlists."
    if cwe_id in {"CWE-918"}:
        return "For outbound requests, use strict URL allowlists, block private/internal IP ranges, and disable unsafe redirects."
    if cwe_id in {"CWE-79", "CWE-80", "CWE-83"}:
        return "Apply context-aware output encoding and input validation to prevent script injection."
    if cwe_id in {"CWE-89", "CWE-90"}:
        return "Use parameterized queries/prepared statements and avoid string-concatenated queries."
    if cwe_id in {"CWE-611"}:
        return "Disable external entities/DTD processing in XML parsers and use secure parser defaults."
    if cwe_id in {"CWE-120", "CWE-121", "CWE-122", "CWE-787"}:
        return "Use bounded APIs and validate lengths before copy/write operations."
    if cwe_id in {"CWE-22", "CWE-23", "CWE-36", "CWE-73"}:
        return "Canonicalize paths and enforce restricted base directories before file access."
    if cwe_id in {"CWE-502"}:
        return "Never deserialize untrusted data without strict type and signature checks."
    if cwe_id in {"CWE-20"}:
        return "Validate and sanitize all external input before use; enforce type, length, format, and range constraints."
    return "Validate untrusted input and apply language-specific secure coding controls for this sink."


class ScannerEngine:
    def __init__(self, rules_payload: Dict[str, object]):
        self.rules_payload = rules_payload
        self.rules_by_language: Dict[str, List[CompiledRule]] = {}
        self._compile_rules()

    def _compile_rules(self) -> None:
        bucket: Dict[str, List[CompiledRule]] = {}
        for item in self.rules_payload.get("rules", []):
            try:
                compiled = re.compile(item["pattern"])
            except re.error:
                continue
            rule = CompiledRule(
                id=item["id"],
                language=item["language"],
                title=item["title"],
                regex=compiled,
                cwe_id=item["cwe_id"],
                cwe_name=item["cwe_name"],
                severity=item["severity"],
                owasp_category=item["owasp_category"],
                source=item["source"],
                confidence=float(item.get("confidence", 0.5)),
            )
            bucket.setdefault(rule.language, []).append(rule)
        self.rules_by_language = bucket

    def _build_summary(
        self,
        findings: List[Dict[str, object]],
        filename: str,
        language: str,
        files_scanned: int,
    ) -> Dict[str, object]:
        severity_counts: Counter = Counter()
        cwe_counts: Counter = Counter()
        owasp_counts: Counter = Counter()
        for finding in findings:
            severity_counts[finding["severity"]] += 1
            cwe_counts[finding["cwe_id"]] += 1
            owasp_counts[finding["owasp_category"]] += 1

        total = len(findings)
        weighted = sum(f["severity_score"] for f in findings)
        risk_score = round(weighted / total, 2) if total else 0

        return {
            "total_findings": total,
            "risk_score": risk_score,
            "files_scanned": files_scanned,
            "severity": {
                "Critical": severity_counts.get("Critical", 0),
                "High":     severity_counts.get("High", 0),
                "Medium":   severity_counts.get("Medium", 0),
                "Low":      severity_counts.get("Low", 0),
            },
            "top_cwe":   cwe_counts.most_common(8),
            "top_owasp": owasp_counts.most_common(8),
            "filename":  filename,
            "language":  language,
        }

    #  regex scan 

    def _regex_scan(
        self,
        clean_lines: List[str],
        original_lines: List[str],
        language: str,
        path_value: str,
    ) -> List[Dict[str, object]]:
        """
        Run all compiled regex rules against the preprocessed lines.
        Snippets are taken from the original lines so analysts see real
        code rather than stripped text.
        """
        findings: List[Dict[str, object]] = []
        seen: set = set()
        language_rules = self.rules_by_language.get(language, [])

        for line_number, clean_line in enumerate(clean_lines, start=1):
            if not clean_line.strip():
                continue

            original_line = (
                original_lines[line_number - 1]
                if line_number - 1 < len(original_lines)
                else clean_line
            )

            for rule in language_rules:
                for match in rule.regex.finditer(clean_line):
                    key = (line_number, rule.id, match.start())
                    if key in seen:
                        continue
                    seen.add(key)

                    # Capture surrounding lines for ML context (matches
                    # the function-body scale used during training).
                    ctx_start = max(0, line_number - 3)
                    ctx_end   = min(len(original_lines), line_number + 15)
                    ml_context = "\n".join(
                        original_lines[ctx_start:ctx_end]
                    )[:600]

                    findings.append(
                        {
                            "rule_id":          rule.id,
                            "title":            rule.title,
                            "cwe_id":           rule.cwe_id,
                            "cwe_name":         rule.cwe_name,
                            "owasp_category":   rule.owasp_category,
                            "severity":         rule.severity,
                            "severity_score":   severity_score(rule.severity),
                            "language":         language,
                            "line_number":      line_number,
                            "column_number":    match.start() + 1,
                            "snippet":          original_line[:300],
                            "ml_context":       ml_context,
                            "source_path":      path_value,
                            "recommendation":   recommendation_for_cwe(rule.cwe_id),
                            "source":           rule.source,
                            "confidence":       round(rule.confidence, 2),
                            "ml_severity":            "",
                            "ml_severity_confidence": 0.0,
                            "ml_confidence":          0.0,
                        }
                    )

        return findings

    #  AST merge 

    @staticmethod
    def _merge_ast_findings(
        regex_findings: List[Dict[str, object]],
        ast_findings: List[Dict[str, object]],
        path_value: str,
    ) -> List[Dict[str, object]]:
        """
        Add AST findings not already covered by a regex finding.

        Deduplication key: (line_number, cwe_id).

        If a regex finding already reported the same CWE on the same
        line the AST finding is suppressed.  AST findings that cover
        CWEs absent from the regex ruleset (e.g. CWE-798 hardcoded
        secrets, CWE-330 weak RNG, CWE-295 certificate validation) are
        always kept.

        Each AST finding is stamped with the correct source_path before
        being added to the merged list.
        """
        covered: set = {
            (f["line_number"], f["cwe_id"])
            for f in regex_findings
        }

        merged = list(regex_findings)
        for ast_finding in ast_findings:
            key = (ast_finding["line_number"], ast_finding["cwe_id"])
            if key in covered:
                continue
            ast_finding["source_path"] = path_value
            merged.append(ast_finding)
            covered.add(key)

        return merged

    #  public scan API 

    def scan(
        self,
        content: str,
        language: str,
        filename: str,
        source_path: Optional[str] = None,
    ) -> Dict[str, object]:
        """
        Scan a single source file.

        Detection passes per language:

            Python - regex on preprocessed source
                   + AST walk on original source (built-in ast module)

            Java - regex on preprocessed source
                   + AST walk on original source (javalang, if installed)
                     Falls back to regex-only if javalang is unavailable.

            C/C++ - regex on preprocessed source only.
        """
        # FR-7: preprocess before regex scanning
        clean_content  = preprocess(content, language)
        clean_lines    = clean_content.splitlines()
        original_lines = content.splitlines()
        path_value     = source_path or filename

        # Pass 1: regex
        regex_findings = self._regex_scan(
            clean_lines, original_lines, language, path_value
        )

        # Pass 2: AST
        ast_findings: List[Dict[str, object]] = []
        ast_mode = "disabled"

        if language == "python":
            # Built-in ast module - always available
            ast_findings = ast_scan_python(content, original_lines)
            ast_mode = "enabled"
            all_findings = self._merge_ast_findings(
                regex_findings, ast_findings, path_value
            )

        elif language == "java" and JAVALANG_AVAILABLE:
            # javalang - optional; degrades gracefully if not installed
            ast_findings = ast_scan_java(content, original_lines)
            ast_mode = "enabled"
            all_findings = self._merge_ast_findings(
                regex_findings, ast_findings, path_value
            )

        elif language == "cpp" and CLANG_AVAILABLE and is_clang_runtime_ready():
            # C/C++ AST path runs only when libclang is importable and
            # runtime-probed as usable in this environment.
            ast_findings = ast_scan_cpp(content, original_lines, filename=path_value)
            ast_mode = "enabled"
            all_findings = self._merge_ast_findings(
                regex_findings, ast_findings, path_value
            )

        else:
            # Fallback - regex only (Java without javalang, or C/C++ without libclang)
            ast_mode = "regex-only"
            all_findings = regex_findings

        ast_added = max(0, len(all_findings) - len(regex_findings))
        logger.info(
            "Scan composition - language=%s file=%s regex=%d ast_mode=%s ast_raw=%d ast_added=%d total=%d",
            language,
            path_value,
            len(regex_findings),
            ast_mode,
            len(ast_findings),
            ast_added,
            len(all_findings),
        )

        # Sort: highest severity first, then by line number ascending
        all_findings.sort(
            key=lambda f: (-f["severity_score"], f["line_number"])
        )

        summary = self._build_summary(
            findings=all_findings,
            filename=filename,
            language=language,
            files_scanned=1,
        )
        return {"summary": summary, "findings": all_findings}

    def scan_many(
        self,
        sources: List[Dict[str, str]],
        archive_name: str,
    ) -> Dict[str, object]:
        """
        Scan all source files extracted from a ZIP archive.
        Each file is passed through scan() individually so both regex
        and AST passes run per file.
        """
        all_findings: List[Dict[str, object]] = []
        languages: set = set()

        for source in sources:
            content     = source["content"]
            language    = source["language"]
            source_path = source["source_path"]
            languages.add(language)
            result = self.scan(
                content=content,
                language=language,
                filename=archive_name,
                source_path=source_path,
            )
            all_findings.extend(result["findings"])

        all_findings.sort(
            key=lambda item: (item["severity_score"], item["source_path"], item["line_number"]),
            reverse=True,
        )

        language_label = (
            "mixed" if len(languages) > 1
            else (next(iter(languages)) if languages else "unknown")
        )
        summary = self._build_summary(
            findings=all_findings,
            filename=archive_name,
            language=language_label,
            files_scanned=len(sources),
        )
        return {"summary": summary, "findings": all_findings}
