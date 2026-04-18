import re
from typing import Dict
from . import cwe_dataset_loader  # CWE hierarchy for OWASP fallback

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
    #  Injection (A03) 
    "CWE-88":   "A03:2021 - Injection",
    "CWE-91":   "A03:2021 - Injection",
    "CWE-93":   "A03:2021 - Injection",
    "CWE-96":   "A03:2021 - Injection",
    "CWE-98":   "A03:2021 - Injection",
    "CWE-99":   "A03:2021 - Injection",
    "CWE-117":  "A03:2021 - Injection",
    "CWE-643":  "A03:2021 - Injection",
    "CWE-644":  "A03:2021 - Injection",
    "CWE-829":  "A03:2021 - Injection",
    "CWE-917":  "A03:2021 - Injection",
    "CWE-1336": "A03:2021 - Injection",
    #  Broken Access Control (A01) 
    "CWE-250":  "A01:2021 - Broken Access Control",
    "CWE-266":  "A01:2021 - Broken Access Control",
    "CWE-277":  "A01:2021 - Broken Access Control",
    "CWE-283":  "A01:2021 - Broken Access Control",
    "CWE-288":  "A07:2021 - Identification and Authentication Failures",
    "CWE-290":  "A07:2021 - Identification and Authentication Failures",
    "CWE-346":  "A01:2021 - Broken Access Control",
    "CWE-403":  "A01:2021 - Broken Access Control",
    "CWE-420":  "A01:2021 - Broken Access Control",
    "CWE-425":  "A01:2021 - Broken Access Control",
    "CWE-441":  "A01:2021 - Broken Access Control",
    "CWE-472":  "A01:2021 - Broken Access Control",
    "CWE-530":  "A01:2021 - Broken Access Control",
    "CWE-539":  "A02:2021 - Cryptographic Failures",
    "CWE-552":  "A01:2021 - Broken Access Control",
    "CWE-598":  "A01:2021 - Broken Access Control",
    "CWE-650":  "A01:2021 - Broken Access Control",
    "CWE-668":  "A01:2021 - Broken Access Control",
    #  Cryptographic Failures (A02) 
    "CWE-311":  "A02:2021 - Cryptographic Failures",
    "CWE-322":  "A02:2021 - Cryptographic Failures",
    "CWE-329":  "A02:2021 - Cryptographic Failures",
    "CWE-331":  "A02:2021 - Cryptographic Failures",
    "CWE-332":  "A02:2021 - Cryptographic Failures",
    "CWE-334":  "A02:2021 - Cryptographic Failures",
    "CWE-335":  "A02:2021 - Cryptographic Failures",
    "CWE-336":  "A02:2021 - Cryptographic Failures",
    "CWE-337":  "A02:2021 - Cryptographic Failures",
    "CWE-345":  "A08:2021 - Software and Data Integrity Failures",
    "CWE-347":  "A02:2021 - Cryptographic Failures",
    "CWE-354":  "A02:2021 - Cryptographic Failures",
    "CWE-523":  "A02:2021 - Cryptographic Failures",
    "CWE-525":  "A02:2021 - Cryptographic Failures",
    "CWE-760":  "A02:2021 - Cryptographic Failures",
    #  Identification and Authentication Failures (A07) 
    "CWE-255":  "A07:2021 - Identification and Authentication Failures",
    "CWE-263":  "A07:2021 - Identification and Authentication Failures",
    "CWE-549":  "A07:2021 - Identification and Authentication Failures",
    "CWE-613":  "A07:2021 - Identification and Authentication Failures",
    "CWE-640":  "A07:2021 - Identification and Authentication Failures",
    #  Insecure Design - Memory/Buffer (A04) 
    "CWE-123":  "A04:2021 - Insecure Design",
    "CWE-128":  "A04:2021 - Insecure Design",
    "CWE-129":  "A04:2021 - Insecure Design",
    "CWE-131":  "A04:2021 - Insecure Design",
    "CWE-170":  "A04:2021 - Insecure Design",
    "CWE-193":  "A04:2021 - Insecure Design",
    "CWE-196":  "A04:2021 - Insecure Design",
    "CWE-680":  "A04:2021 - Insecure Design",
    "CWE-786":  "A04:2021 - Insecure Design",
    "CWE-788":  "A04:2021 - Insecure Design",
    "CWE-824":  "A04:2021 - Insecure Design",
    "CWE-843":  "A04:2021 - Insecure Design",
    #  Insecure Design - Concurrency/Race (A04) 
    "CWE-363":  "A04:2021 - Insecure Design",
    "CWE-366":  "A04:2021 - Insecure Design",
    "CWE-379":  "A04:2021 - Insecure Design",
    "CWE-412":  "A04:2021 - Insecure Design",
    "CWE-413":  "A04:2021 - Insecure Design",
    "CWE-567":  "A04:2021 - Insecure Design",
    #  Insecure Design - Resource/DoS (A04) 
    "CWE-405":  "A04:2021 - Insecure Design",
    "CWE-407":  "A04:2021 - Insecure Design",
    "CWE-409":  "A04:2021 - Insecure Design",
    "CWE-410":  "A04:2021 - Insecure Design",
    "CWE-664":  "A04:2021 - Insecure Design",
    "CWE-665":  "A04:2021 - Insecure Design",
    "CWE-667":  "A04:2021 - Insecure Design",
    "CWE-672":  "A04:2021 - Insecure Design",
    "CWE-674":  "A04:2021 - Insecure Design",
    "CWE-695":  "A04:2021 - Insecure Design",
    "CWE-730":  "A04:2021 - Insecure Design",
    "CWE-754":  "A04:2021 - Insecure Design",
    "CWE-755":  "A04:2021 - Insecure Design",
    #  Insecure Design - Code Quality/Logic (A04) 
    "CWE-248":  "A04:2021 - Insecure Design",
    "CWE-390":  "A04:2021 - Insecure Design",
    "CWE-398":  "A04:2021 - Insecure Design",
    "CWE-477":  "A04:2021 - Insecure Design",
    "CWE-563":  "A04:2021 - Insecure Design",
    "CWE-570":  "A04:2021 - Insecure Design",
    "CWE-571":  "A04:2021 - Insecure Design",
    "CWE-580":  "A04:2021 - Insecure Design",
    "CWE-583":  "A04:2021 - Insecure Design",
    "CWE-584":  "A04:2021 - Insecure Design",
    "CWE-585":  "A04:2021 - Insecure Design",
    "CWE-586":  "A04:2021 - Insecure Design",
    "CWE-587":  "A04:2021 - Insecure Design",
    "CWE-595":  "A04:2021 - Insecure Design",
    "CWE-597":  "A04:2021 - Insecure Design",
    "CWE-624":  "A04:2021 - Insecure Design",
    "CWE-625":  "A04:2021 - Insecure Design",
    #  Security Misconfiguration (A05) 
    "CWE-645":  "A05:2021 - Security Misconfiguration",
    "CWE-651":  "A05:2021 - Security Misconfiguration",
    "CWE-560":  "A05:2021 - Security Misconfiguration",
    "CWE-600":  "A05:2021 - Security Misconfiguration",
    "CWE-579":  "A05:2021 - Security Misconfiguration",
    #  Security Logging and Monitoring Failures (A09) 
    "CWE-392":  "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-393":  "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-532":  "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-544":  "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-778":  "A09:2021 - Security Logging and Monitoring Failures",
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
    #  Injection (A03) 
    "CWE-88":   "High",
    "CWE-91":   "Medium",
    "CWE-93":   "Medium",
    "CWE-96":   "High",
    "CWE-98":   "Critical",
    "CWE-99":   "Medium",
    "CWE-117":  "Medium",
    "CWE-643":  "High",
    "CWE-644":  "Medium",
    "CWE-829":  "High",
    "CWE-917":  "Critical",
    "CWE-1336": "Critical",
    #  Broken Access Control (A01) 
    "CWE-250":  "High",
    "CWE-266":  "High",
    "CWE-277":  "Medium",
    "CWE-283":  "Medium",
    "CWE-288":  "High",
    "CWE-290":  "High",
    "CWE-346":  "High",
    "CWE-403":  "Medium",
    "CWE-420":  "Medium",
    "CWE-425":  "Medium",
    "CWE-441":  "Medium",
    "CWE-472":  "High",
    "CWE-530":  "Medium",
    "CWE-539":  "Medium",
    "CWE-552":  "Medium",
    "CWE-598":  "Medium",
    "CWE-650":  "Medium",
    "CWE-668":  "Medium",
    #  Cryptographic Failures (A02) 
    "CWE-311":  "High",
    "CWE-322":  "High",
    "CWE-329":  "High",
    "CWE-331":  "Medium",
    "CWE-332":  "Medium",
    "CWE-334":  "Medium",
    "CWE-335":  "Medium",
    "CWE-336":  "High",
    "CWE-337":  "High",
    "CWE-345":  "High",
    "CWE-347":  "High",
    "CWE-354":  "Medium",
    "CWE-523":  "High",
    "CWE-525":  "Low",
    "CWE-760":  "High",
    #  Identification and Authentication Failures (A07) 
    "CWE-255":  "Medium",
    "CWE-263":  "Low",
    "CWE-549":  "Low",
    "CWE-613":  "Medium",
    "CWE-640":  "High",
    #  Insecure Design - Memory/Buffer (A04) 
    "CWE-123":  "Critical",
    "CWE-128":  "High",
    "CWE-129":  "High",
    "CWE-131":  "High",
    "CWE-170":  "Medium",
    "CWE-193":  "Medium",
    "CWE-196":  "High",
    "CWE-680":  "High",
    "CWE-786":  "High",
    "CWE-788":  "High",
    "CWE-824":  "High",
    "CWE-843":  "High",
    #  Insecure Design - Concurrency/Race (A04) 
    "CWE-363":  "Medium",
    "CWE-366":  "Medium",
    "CWE-379":  "Medium",
    "CWE-412":  "Medium",
    "CWE-413":  "Medium",
    "CWE-567":  "Medium",
    #  Insecure Design - Resource/DoS (A04) 
    "CWE-405":  "Medium",
    "CWE-407":  "Low",
    "CWE-409":  "Medium",
    "CWE-410":  "Medium",
    "CWE-664":  "Medium",
    "CWE-665":  "Medium",
    "CWE-667":  "Medium",
    "CWE-672":  "High",
    "CWE-674":  "Medium",
    "CWE-695":  "Low",
    "CWE-730":  "Medium",
    "CWE-754":  "Medium",
    "CWE-755":  "Medium",
    #  Insecure Design - Code Quality/Logic (A04) 
    "CWE-248":  "Low",
    "CWE-390":  "Low",
    "CWE-398":  "Low",
    "CWE-477":  "Medium",
    "CWE-563":  "Low",
    "CWE-570":  "Low",
    "CWE-571":  "Low",
    "CWE-580":  "Low",
    "CWE-583":  "Low",
    "CWE-584":  "Low",
    "CWE-585":  "Low",
    "CWE-586":  "Low",
    "CWE-587":  "Medium",
    "CWE-595":  "Low",
    "CWE-597":  "Low",
    "CWE-624":  "Medium",
    "CWE-625":  "Low",
    #  Security Misconfiguration (A05) 
    "CWE-645":  "Low",
    "CWE-651":  "Low",
    "CWE-560":  "Medium",
    "CWE-600":  "Low",
    "CWE-579":  "Low",
    #  Security Logging and Monitoring Failures (A09) 
    "CWE-392":  "Low",
    "CWE-393":  "Low",
    "CWE-532":  "Medium",
    "CWE-544":  "Low",
    "CWE-778":  "Low",
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

    # 1. Check the CWE itself and walk up the hierarchy using the dataset's
    #    parent-child tree until we find an ancestor that has a known 2021 mapping.
    current = cwe
    visited: set = set()
    while current and current not in visited:
        direct = OWASP_BY_CWE.get(current)
        if direct:
            return direct
        visited.add(current)
        current = cwe_dataset_loader.get_parent(current)

    # 2. Name-based heuristic (last resort for CWEs with no hierarchy path)
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
