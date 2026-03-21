import re
from typing import Dict

OWASP_BY_CWE: Dict[str, str] = {
    "CWE-22": "A01:2021 - Broken Access Control",
    "CWE-23": "A01:2021 - Broken Access Control",
    "CWE-36": "A01:2021 - Broken Access Control",
    "CWE-73": "A01:2021 - Broken Access Control",
    "CWE-74": "A03:2021 - Injection",
    "CWE-77": "A03:2021 - Injection",
    "CWE-78": "A03:2021 - Injection",
    "CWE-79": "A03:2021 - Injection",
    "CWE-80": "A03:2021 - Injection",
    "CWE-83": "A03:2021 - Injection",
    "CWE-89": "A03:2021 - Injection",
    "CWE-90": "A03:2021 - Injection",
    "CWE-94": "A03:2021 - Injection",
    "CWE-95": "A03:2021 - Injection",
    "CWE-352": "A01:2021 - Broken Access Control",
    "CWE-287": "A07:2021 - Identification and Authentication Failures",
    "CWE-306": "A07:2021 - Identification and Authentication Failures",
    "CWE-307": "A07:2021 - Identification and Authentication Failures",
    "CWE-384": "A07:2021 - Identification and Authentication Failures",
    "CWE-502": "A08:2021 - Software and Data Integrity Failures",
    "CWE-494": "A08:2021 - Software and Data Integrity Failures",
    "CWE-611": "A05:2021 - Security Misconfiguration",
    "CWE-918": "A10:2021 - Server-Side Request Forgery (SSRF)",
    "CWE-862": "A01:2021 - Broken Access Control",
    "CWE-863": "A01:2021 - Broken Access Control",
    "CWE-269": "A01:2021 - Broken Access Control",
    "CWE-732": "A01:2021 - Broken Access Control",
    "CWE-319": "A02:2021 - Cryptographic Failures",
    "CWE-327": "A02:2021 - Cryptographic Failures",
    "CWE-326": "A02:2021 - Cryptographic Failures",
    "CWE-328": "A02:2021 - Cryptographic Failures",
    "CWE-522": "A02:2021 - Cryptographic Failures",
    "CWE-798": "A07:2021 - Identification and Authentication Failures",
    "CWE-200": "A01:2021 - Broken Access Control",
    "CWE-201": "A01:2021 - Broken Access Control",
    "CWE-209": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-312": "A02:2021 - Cryptographic Failures",
    "CWE-327": "A02:2021 - Cryptographic Failures",
    "CWE-601": "A01:2021 - Broken Access Control",
    "CWE-125": "A03:2021 - Injection",
    "CWE-119": "A03:2021 - Injection",
    "CWE-120": "A03:2021 - Injection",
    "CWE-121": "A03:2021 - Injection",
    "CWE-122": "A03:2021 - Injection",
    "CWE-126": "A03:2021 - Injection",
    "CWE-127": "A03:2021 - Injection",
    "CWE-190": "A04:2021 - Insecure Design",
    "CWE-191": "A04:2021 - Insecure Design",
    "CWE-416": "A03:2021 - Injection",
    "CWE-476": "A04:2021 - Insecure Design",
    "CWE-787": "A03:2021 - Injection",
    "CWE-20":  "A03:2021 - Injection",
}

SEVERITY_BY_CWE: Dict[str, str] = {
    "CWE-78": "Critical",
    "CWE-89": "Critical",
    "CWE-77": "Critical",
    "CWE-94": "Critical",
    "CWE-502": "Critical",
    "CWE-918": "Critical",
    "CWE-798": "Critical",
    "CWE-79": "High",
    "CWE-22": "High",
    "CWE-119": "High",
    "CWE-120": "High",
    "CWE-121": "High",
    "CWE-122": "High",
    "CWE-125": "High",
    "CWE-126": "High",
    "CWE-127": "High",
    "CWE-190": "High",
    "CWE-191": "High",
    "CWE-416": "High",
    "CWE-787": "High",
    "CWE-200": "Medium",
    "CWE-201": "Medium",
    "CWE-295": "High",
    "CWE-352": "High",
    "CWE-611": "High",
    "CWE-327": "Medium",
    "CWE-326": "Medium",
    "CWE-287": "High",
    "CWE-522": "Medium",
    "CWE-209": "Low",
    "CWE-476": "Medium",
    "CWE-20":  "Medium",
}

SEVERITY_SCORE = {"Critical": 9, "High": 7, "Medium": 5, "Low": 3}


def normalize_cwe(cwe_id: str) -> str:
    if not cwe_id:
        return "CWE-000"
    cleaned = cwe_id.strip().upper().replace("_", "-")
    if cleaned.startswith("CWE") and not cleaned.startswith("CWE-"):
        cleaned = cleaned.replace("CWE", "CWE-", 1)
    if not cleaned.startswith("CWE-"):
        digits = re.sub(r"\D", "", cleaned)
        if digits:
            return f"CWE-{digits}"
        return "CWE-000"
    return cleaned


def map_cwe_to_owasp(cwe_id: str, cwe_name: str = "") -> str:
    cwe = normalize_cwe(cwe_id)
    direct = OWASP_BY_CWE.get(cwe)
    if direct:
        return direct

    name = (cwe_name or "").lower()
    if any(k in name for k in ["xss", "sql", "inject", "command", "deserialize"]):
        return "A03:2021 - Injection"
    if any(k in name for k in ["path traversal", "authorization", "access control", "privilege"]):
        return "A01:2021 - Broken Access Control"
    if any(k in name for k in ["crypto", "cipher", "certificate", "tls", "ssl"]):
        return "A02:2021 - Cryptographic Failures"
    if any(k in name for k in ["authentication", "password", "session"]):
        return "A07:2021 - Identification and Authentication Failures"
    if any(k in name for k in ["ssrf", "server-side request"]):
        return "A10:2021 - Server-Side Request Forgery (SSRF)"
    return "A05:2021 - Security Misconfiguration"


def severity_for_cwe(cwe_id: str, cwe_name: str = "") -> str:
    cwe = normalize_cwe(cwe_id)
    direct = SEVERITY_BY_CWE.get(cwe)
    if direct:
        return direct

    name = (cwe_name or "").lower()
    if any(k in name for k in ["remote code", "code execution", "command", "sql", "injection"]):
        return "Critical"
    if any(k in name for k in ["overflow", "out-of-bounds", "use after free", "path traversal", "xss"]):
        return "High"
    if any(k in name for k in ["information", "disclosure", "leak", "weak crypto"]):
        return "Medium"
    if any(k in name for k in ["log", "debug", "unchecked return"]):
        return "Low"
    return "Medium"


def severity_score(severity: str) -> int:
    return SEVERITY_SCORE.get(severity, 3)
