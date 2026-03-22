"""
AST-based vulnerability scanner for Python, Java, and C/C++ source code.
(FR-7, Tools section)

Python scanner
--------------
Uses Python's built-in ``ast`` module — no extra dependencies required.

Java scanner
------------
Uses the ``javalang`` third-party library.  The import is wrapped in a
try/except so the application starts and runs normally even when
javalang is not installed — Java files simply fall back to regex-only
scanning in that case.

Install javalang to enable Java AST scanning:
    pip install javalang

Why AST alongside regex
-----------------------
Regex rules match text patterns and can miss or misfire depending on
whitespace, string quoting, or comment placement.  The AST scanner
operates on the parsed syntax tree, so it is immune to those issues:

  * It never fires on commented-out code (comments are stripped by the
    parser before the tree is built).
  * It correctly resolves method chains and qualified names.
  * It detects hardcoded password / secret assignments that regex
    patterns struggle with.

Findings produced here use ``source="ast"`` so analysts and reports
can distinguish them from regex-derived findings.

Deduplication
-------------
The scanner returns findings keyed by ``(line_number, cwe_id)``.
``ScannerEngine`` uses the same key to skip any AST finding whose
(line, CWE) pair is already covered by a regex finding, so the same
vulnerability is never reported twice.
"""

import ast
from typing import Dict, List, Optional, Tuple

from .mappings import map_cwe_to_owasp, severity_for_cwe, severity_score

# ── optional javalang import ───────────────────────────────────────────────────
try:
    import javalang
    JAVALANG_AVAILABLE = True
except ImportError:
    JAVALANG_AVAILABLE = False

# ── optional libclang import ───────────────────────────────────────────────────
try:
    import clang.cindex as _clang_cindex
    CLANG_AVAILABLE = True
except Exception:
    _clang_cindex = None  # type: ignore
    CLANG_AVAILABLE = False

_CLANG_INDEX = None  # created lazily on first use


def _get_clang_index():
    global _CLANG_INDEX
    if _CLANG_INDEX is None and CLANG_AVAILABLE:
        _CLANG_INDEX = _clang_cindex.Index.create()
    return _CLANG_INDEX


# ══════════════════════════════════════════════════════════════════════════════
# SHARED HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _make_finding(
    line_number: int,
    col_offset: int,
    cwe_id: str,
    cwe_name: str,
    title: str,
    snippet: str,
    language: str,
    ml_context: str = "",
) -> Dict[str, object]:
    """Build a finding dict in the same shape as regex-scanner findings."""
    sev = severity_for_cwe(cwe_id, cwe_name)
    return {
        "rule_id":          f"ast-{language}-{cwe_id.lower().replace('-', '')}",
        "title":            title,
        "cwe_id":           cwe_id,
        "cwe_name":         cwe_name,
        "owasp_category":   map_cwe_to_owasp(cwe_id, cwe_name),
        "severity":         sev,
        "severity_score":   severity_score(sev),
        "language":         language,
        "line_number":      line_number,
        "column_number":    col_offset + 1,
        "snippet":          snippet[:300],
        "ml_context":       ml_context or snippet[:600],
        "source_path":      "",          # stamped by scanner.py
        "recommendation":   _recommendation(cwe_id),
        "source":           "ast",
        "confidence":       0.92,        # AST matches are high-confidence
        "ml_severity":            "",
        "ml_severity_confidence": 0.0,
        "ml_confidence":          0.0,
    }


def _recommendation(cwe_id: str) -> str:
    mapping = {
        "CWE-89":  "Use PreparedStatement with parameterized queries; never build SQL strings from user input.",
        "CWE-78":  "Avoid shell execution of user input; use ProcessBuilder with a fixed argument list and no shell.",
        "CWE-94":  "Replace eval/exec/compile with strict typed parsers or allowlisted operations.",
        "CWE-502": "Do not deserialize untrusted data; use schema-validated formats such as JSON with strict typing.",
        "CWE-20":  "Validate and sanitize all input before use; prefer safe_load() for YAML.",
        "CWE-22":  "Canonicalize file paths and enforce an allowlisted base directory before opening files.",
        "CWE-330": "Use SecureRandom instead of java.util.Random for security-sensitive random values.",
        "CWE-327": "Replace MD5/SHA-1 with SHA-256 or stronger for security-sensitive hashing.",
        "CWE-798": "Do not hardcode credentials; load secrets from environment variables or a secrets manager.",
        "CWE-295": "Enable certificate validation; do not implement empty or permissive TrustManagers.",
        "CWE-611": "Disable external entities and DTD processing in the XML parser before parsing untrusted documents.",
        "CWE-918": "Allowlist outbound URLs/hosts, block private IP ranges, and disable unsafe redirects.",
    }
    return mapping.get(
        cwe_id,
        "Apply the principle of least privilege and validate all untrusted input.",
    )


def _safe_snippet(source_lines: List[str], lineno: int) -> str:
    idx = lineno - 1
    return source_lines[idx] if 0 <= idx < len(source_lines) else ""


def _ml_context(source_lines: List[str], lineno: int) -> str:
    """Return surrounding lines for ML inference (matches training scale)."""
    start = max(0, lineno - 4)
    end   = min(len(source_lines), lineno + 15)
    return "\n".join(source_lines[start:end])[:600]


# ══════════════════════════════════════════════════════════════════════════════
# PYTHON AST SCANNER
# ══════════════════════════════════════════════════════════════════════════════

# Maps (module_or_None, function_name) → (cwe_id, cwe_name, title)
_PY_CALL_RULES: Dict[Tuple[Optional[str], str], Tuple[str, str, str]] = {
    # Bare dangerous builtins
    (None, "eval"):    ("CWE-94",  "Code Injection",                        "Dangerous dynamic evaluation via eval()"),
    (None, "exec"):    ("CWE-94",  "Code Injection",                        "Unsafe exec() usage"),
    (None, "compile"): ("CWE-94",  "Code Injection",                        "Dynamic code compilation via compile()"),
    (None, "input"):   ("CWE-20",  "Improper Input Validation",             "Unvalidated user input via input()"),
    (None, "open"):    ("CWE-22",  "Path Traversal",                        "Unvalidated file path passed to open()"),
    # os module
    ("os", "system"):  ("CWE-78",  "OS Command Injection",                  "OS command execution via os.system()"),
    ("os", "popen"):   ("CWE-78",  "OS Command Injection",                  "OS command execution via os.popen()"),
    # subprocess module
    ("subprocess", "Popen"):        ("CWE-78", "OS Command Injection",      "Command execution via subprocess.Popen()"),
    ("subprocess", "call"):         ("CWE-78", "OS Command Injection",      "Command execution via subprocess.call()"),
    ("subprocess", "run"):          ("CWE-78", "OS Command Injection",      "Command execution via subprocess.run()"),
    ("subprocess", "check_output"): ("CWE-78", "OS Command Injection",      "Command execution via subprocess.check_output()"),
    ("subprocess", "check_call"):   ("CWE-78", "OS Command Injection",      "Command execution via subprocess.check_call()"),
    # pickle / marshal / shelve
    ("pickle",     "loads"):   ("CWE-502", "Deserialization of Untrusted Data", "Unsafe deserialization via pickle.loads()"),
    ("pickle",     "load"):    ("CWE-502", "Deserialization of Untrusted Data", "Unsafe deserialization via pickle.load()"),
    ("marshal",    "loads"):   ("CWE-502", "Deserialization of Untrusted Data", "Unsafe deserialization via marshal.loads()"),
    ("marshal",    "load"):    ("CWE-502", "Deserialization of Untrusted Data", "Unsafe deserialization via marshal.load()"),
    ("shelve",     "open"):    ("CWE-502", "Deserialization of Untrusted Data", "Potential unsafe deserialization via shelve.open()"),
    ("jsonpickle", "decode"):  ("CWE-502", "Deserialization of Untrusted Data", "Unsafe deserialization via jsonpickle.decode()"),
    # yaml
    ("yaml", "load"):          ("CWE-20",  "Improper Input Validation",        "Unsafe YAML load() — use safe_load()"),
    # hashlib weak algorithms
    ("hashlib", "md5"):        ("CWE-327", "Use of a Broken Cryptographic Algorithm", "Weak hash algorithm MD5"),
    ("hashlib", "sha1"):       ("CWE-327", "Use of a Broken Cryptographic Algorithm", "Weak hash algorithm SHA-1"),
    # random
    ("random", "random"):      ("CWE-330", "Use of Insufficiently Random Values", "Non-cryptographic RNG via random.random()"),
    ("random", "randint"):     ("CWE-330", "Use of Insufficiently Random Values", "Non-cryptographic RNG via random.randint()"),
    ("random", "choice"):      ("CWE-330", "Use of Insufficiently Random Values", "Non-cryptographic RNG via random.choice()"),
    ("random", "seed"):        ("CWE-330", "Use of Insufficiently Random Values", "Predictable RNG seed via random.seed()"),
    # tempfile
    ("tempfile", "mktemp"):    ("CWE-377", "Insecure Temporary File",  "Insecure temp file creation via tempfile.mktemp()"),
    # SQL
    (None, "execute"):         ("CWE-89",  "SQL Injection", "Potential SQL injection via execute()"),
    (None, "executemany"):     ("CWE-89",  "SQL Injection", "Potential SQL injection via executemany()"),
}

_PY_SECRET_KWARG_NAMES = frozenset({
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "token", "auth_token", "access_token", "private_key", "credentials",
})

_PY_SECRET_VAR_NAMES = frozenset({
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "token", "auth_token", "access_token", "private_key", "secret_key",
    "credentials", "db_password", "database_password",
})


def _py_resolve_call(node: ast.Call) -> Tuple[Optional[str], str]:
    func = node.func
    if isinstance(func, ast.Name):
        return None, func.id
    if isinstance(func, ast.Attribute):
        method = func.attr
        if isinstance(func.value, ast.Name):
            return func.value.id, method
        return None, method
    return None, ""


def ast_scan_python(
    content: str,
    source_lines: List[str],
) -> List[Dict[str, object]]:
    """
    Parse *content* as Python source and return a list of vulnerability
    findings.  Returns an empty list if the source cannot be parsed.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    findings: List[Dict[str, object]] = []

    def _snip(lineno: int) -> str:
        return _safe_snippet(source_lines, lineno)

    def _ctx(lineno: int) -> str:
        return _ml_context(source_lines, lineno)

    for node in ast.walk(tree):

        # 1. Dangerous function calls
        if isinstance(node, ast.Call):
            module, func_name = _py_resolve_call(node)
            lineno = getattr(node, "lineno", 0)
            col    = getattr(node, "col_offset", 0)

            rule = _PY_CALL_RULES.get((module, func_name)) or _PY_CALL_RULES.get((None, func_name))
            if rule:
                cwe_id, cwe_name, title = rule
                findings.append(_make_finding(lineno, col, cwe_id, cwe_name, title, _snip(lineno), "python", _ctx(lineno)))

            # 1a. Keyword argument secrets
            for kw in node.keywords:
                if (
                    kw.arg
                    and kw.arg.lower() in _PY_SECRET_KWARG_NAMES
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                    and kw.value.value.strip()
                ):
                    kw_line = getattr(kw.value, "lineno", lineno)
                    findings.append(_make_finding(
                        kw_line, 0,
                        "CWE-798", "Use of Hard-coded Credentials",
                        f"Hardcoded credential passed as keyword argument '{kw.arg}'",
                        _snip(kw_line), "python", _ctx(kw_line),
                    ))

        # 2. Hardcoded credential assignments  (password = "secret123")
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                name = None
                if isinstance(target, ast.Name):
                    name = target.id
                elif isinstance(target, ast.Attribute):
                    name = target.attr
                if (
                    name
                    and name.lower() in _PY_SECRET_VAR_NAMES
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                    and node.value.value.strip()
                ):
                    lineno = getattr(node, "lineno", 0)
                    findings.append(_make_finding(
                        lineno, 0,
                        "CWE-798", "Use of Hard-coded Credentials",
                        f"Hardcoded credential assigned to variable '{name}'",
                        _snip(lineno), "python", _ctx(lineno),
                    ))

        # 3. Annotated assignments  (password: str = "secret")
        elif isinstance(node, ast.AnnAssign):
            target = node.target
            name = None
            if isinstance(target, ast.Name):
                name = target.id
            elif isinstance(target, ast.Attribute):
                name = target.attr
            if (
                name
                and name.lower() in _PY_SECRET_VAR_NAMES
                and node.value
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and node.value.value.strip()
            ):
                lineno = getattr(node, "lineno", 0)
                findings.append(_make_finding(
                    lineno, 0,
                    "CWE-798", "Use of Hard-coded Credentials",
                    f"Hardcoded credential in annotated assignment '{name}'",
                    _snip(lineno), "python", _ctx(lineno),
                ))

        # 4. Security assertions stripped in optimised builds
        elif isinstance(node, ast.Assert):
            lineno = getattr(node, "lineno", 0)
            test_src = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
            if any(kw in test_src.lower() for kw in ("auth", "permission", "is_admin", "is_staff", "logged_in")):
                findings.append(_make_finding(
                    lineno, 0,
                    "CWE-617", "Reachable Assertion",
                    "Security check implemented via assert — removed in optimised builds",
                    _snip(lineno), "python", _ctx(lineno),
                ))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# JAVA AST SCANNER  (requires javalang)
# ══════════════════════════════════════════════════════════════════════════════

# Method invocations to flag: method_name → (cwe_id, cwe_name, title)
# These are matched on the method name alone because javalang does not
# always resolve the fully-qualified class name at parse time.
_JAVA_METHOD_RULES: Dict[str, Tuple[str, str, str]] = {
    # Command execution
    "exec":              ("CWE-78",  "OS Command Injection",                  "Command execution via Runtime.exec()"),
    # Reflection — dynamic class / method loading
    "forName":           ("CWE-470", "Use of Externally-Controlled Input to Select Classes",
                                                                              "Dynamic class loading via Class.forName()"),
    "loadClass":         ("CWE-470", "Use of Externally-Controlled Input to Select Classes",
                                                                              "Dynamic class loading via loadClass()"),
    "newInstance":       ("CWE-470", "Use of Externally-Controlled Input to Select Classes",
                                                                              "Dynamic object instantiation via newInstance()"),
    "setAccessible":     ("CWE-284", "Improper Access Control",              "Reflection bypasses access control via setAccessible()"),
    # SQL
    "executeQuery":      ("CWE-89",  "SQL Injection",                        "Potential SQL injection via executeQuery()"),
    "executeUpdate":     ("CWE-89",  "SQL Injection",                        "Potential SQL injection via executeUpdate()"),
    "execute":           ("CWE-89",  "SQL Injection",                        "Potential SQL injection via execute()"),
    # Deserialization
    "readObject":        ("CWE-502", "Deserialization of Untrusted Data",    "Unsafe deserialization via readObject()"),
    "readUnshared":      ("CWE-502", "Deserialization of Untrusted Data",    "Unsafe deserialization via readUnshared()"),
    # Cryptography
    "getInstance":       ("CWE-327", "Use of a Broken Cryptographic Algorithm",
                                                                              "Potential weak algorithm via getInstance() — verify algorithm argument"),
    # XML external entity
    "parse":             ("CWE-611", "XML External Entity",                  "Potential XXE via XML parse() — ensure external entities disabled"),
    "newDocumentBuilder":("CWE-611", "XML External Entity",                  "Potential XXE via DocumentBuilder — ensure external entities disabled"),
    # SSRF
    "openConnection":    ("CWE-918", "Server-Side Request Forgery",          "Potential SSRF via openConnection() — validate target URL"),
    "openStream":        ("CWE-918", "Server-Side Request Forgery",          "Potential SSRF via openStream() — validate target URL"),
}

# Field / variable names that suggest a hardcoded credential
_JAVA_SECRET_VAR_NAMES = frozenset({
    "password", "passwd", "pwd", "secret", "apiKey", "api_key",
    "token", "authToken", "accessToken", "privateKey", "secretKey",
    "credentials", "dbPassword", "databasePassword",
})

# Weak algorithm string literals passed to MessageDigest.getInstance() etc.
_JAVA_WEAK_ALGORITHMS = frozenset({"MD5", "SHA-1", "SHA1", "DES", "RC4", "RC2"})

# java.util.Random method names (non-secure RNG)
_JAVA_RANDOM_METHODS = frozenset({
    "nextInt", "nextLong", "nextDouble", "nextFloat", "nextBoolean", "nextBytes",
})


def _java_position(node) -> int:
    """Extract line number from a javalang node's position, returning 0 on failure."""
    try:
        pos = node.position
        return pos.line if pos else 0
    except AttributeError:
        return 0


def ast_scan_java(
    content: str,
    source_lines: List[str],
) -> List[Dict[str, object]]:
    """
    Parse *content* as Java source using javalang and return a list of
    vulnerability findings.

    Returns an empty list if:
      - javalang is not installed (graceful degradation to regex-only)
      - the source cannot be parsed (syntax errors are silently swallowed)
    """
    if not JAVALANG_AVAILABLE:
        return []

    try:
        tree = javalang.parse.parse(content)
    except Exception:
        # javalang raises various exceptions for invalid / partial Java source
        return []

    findings: List[Dict[str, object]] = []

    def _snip(lineno: int) -> str:
        return _safe_snippet(source_lines, lineno)

    def _ctx(lineno: int) -> str:
        return _ml_context(source_lines, lineno)

    # ── 1. Method invocations ──────────────────────────────────────────────────
    for _, node in tree.filter(javalang.tree.MethodInvocation):
        method_name = node.member
        lineno = _java_position(node)

        rule = _JAVA_METHOD_RULES.get(method_name)
        if rule:
            cwe_id, cwe_name, title = rule

            # Refine getInstance() — only flag if a known-weak algorithm
            # literal is passed as the first argument.
            if method_name == "getInstance":
                args = node.arguments or []
                if args and isinstance(args[0], javalang.tree.Literal):
                    algo = str(args[0].value).strip('"\'')
                    if algo.upper() not in _JAVA_WEAK_ALGORITHMS:
                        continue   # not a known-weak algorithm — skip
                    title = f"Weak cryptographic algorithm '{algo}' passed to getInstance()"
                else:
                    continue       # no literal argument — skip to avoid noise

            findings.append(_make_finding(lineno, 0, cwe_id, cwe_name, title, _snip(lineno), "java", _ctx(lineno)))

        # 1a. java.util.Random non-secure RNG usage
        if method_name in _JAVA_RANDOM_METHODS:
            # Check whether the invocation is on a Random object by looking
            # at the qualifier — this is a best-effort heuristic.
            qualifier = str(node.qualifier or "").lower()
            if "random" in qualifier or not qualifier:
                findings.append(_make_finding(
                    lineno, 0,
                    "CWE-330", "Use of Insufficiently Random Values",
                    f"Non-cryptographic RNG via Random.{method_name}() — use SecureRandom",
                    _snip(lineno), "java", _ctx(lineno),
                ))

    # ── 2. Object creation — detect new Random() and new ObjectInputStream() ──
    for _, node in tree.filter(javalang.tree.ClassCreator):
        type_name = node.type.name if node.type else ""
        lineno = _java_position(node)

        if type_name == "Random":
            findings.append(_make_finding(
                lineno, 0,
                "CWE-330", "Use of Insufficiently Random Values",
                "Non-cryptographic RNG: new Random() — use SecureRandom for security-sensitive values",
                _snip(lineno), "java", _ctx(lineno),
            ))

        elif type_name == "ObjectInputStream":
            findings.append(_make_finding(
                lineno, 0,
                "CWE-502", "Deserialization of Untrusted Data",
                "Unsafe deserialization: new ObjectInputStream() wraps untrusted data",
                _snip(lineno), "java", _ctx(lineno),
            ))

    # ── 3. Hardcoded credential field declarations ─────────────────────────────
    # Catches:  private String password = "secret";
    for _, node in tree.filter(javalang.tree.VariableDeclarator):
        var_name = (node.name or "").lower()
        if var_name not in _JAVA_SECRET_VAR_NAMES:
            continue

        # Check that the initialiser is a string literal
        initializer = node.initializer
        if (
            initializer is not None
            and isinstance(initializer, javalang.tree.Literal)
            and str(initializer.value).startswith('"')
            and len(str(initializer.value)) > 2   # not an empty string ""
        ):
            lineno = _java_position(node)
            findings.append(_make_finding(
                lineno, 0,
                "CWE-798", "Use of Hard-coded Credentials",
                f"Hardcoded credential in variable declaration '{node.name}'",
                _snip(lineno), "java", _ctx(lineno),
            ))

    # ── 4. Empty / permissive TrustManager (certificate validation disabled) ──
    # Heuristic: look for a class that implements X509TrustManager and
    # contains a method named checkServerTrusted or checkClientTrusted
    # that has an empty body (no statements).
    for _, cls_node in tree.filter(javalang.tree.ClassDeclaration):
        implements = [str(i.name) for i in (cls_node.implements or [])]
        if "X509TrustManager" not in implements:
            continue

        for method in (cls_node.body or []):
            if not isinstance(method, javalang.tree.MethodDeclaration):
                continue
            if method.name not in ("checkServerTrusted", "checkClientTrusted", "checkValidity"):
                continue
            # An empty body means the method does nothing — certificate
            # validation is effectively disabled.
            if not method.body:
                lineno = _java_position(method)
                findings.append(_make_finding(
                    lineno, 0,
                    "CWE-295", "Improper Certificate Validation",
                    f"Empty {method.name}() in X509TrustManager disables certificate validation",
                    _snip(lineno), "java", _ctx(lineno),
                ))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# C / C++ AST SCANNER  (requires libclang — pip install libclang)
# ══════════════════════════════════════════════════════════════════════════════
#
# libclang ships its own libclang.so/dylib inside the PyPI wheel so no
# system-level clang installation is required.  The package works identically
# on macOS (development) and Linux (production).
#
# Strategy
# --------
# We write the source to a temporary file and ask libclang to parse it with
# minimal compiler flags so it never needs real system headers.  We walk the
# cursor tree looking for:
#   - Dangerous function calls (system, popen, gets, strcpy, printf family …)
#   - Hardcoded credential variable declarations
#   - Weak / broken cryptographic API usage (MD5_Init, DES_*, RC4 …)
#   - Insecure random (rand, srand)
# ══════════════════════════════════════════════════════════════════════════════

import tempfile
import os

# Dangerous C/C++ call names → (cwe_id, cwe_name, recommendation)
_CPP_CALL_RULES: Dict[str, Tuple[str, str, str]] = {
    # OS command injection
    "system":          ("CWE-78",  "OS Command Injection",
                        "Replace system() with execv() using a fixed argument list with no shell."),
    "popen":           ("CWE-78",  "OS Command Injection",
                        "Validate all input before passing to popen(); prefer execv() family."),
    "execl":           ("CWE-78",  "OS Command Injection",
                        "Ensure exec arguments are not user-controlled."),
    "execle":          ("CWE-78",  "OS Command Injection",
                        "Ensure exec arguments are not user-controlled."),
    "execlp":          ("CWE-78",  "OS Command Injection",
                        "Ensure exec arguments are not user-controlled."),
    "execv":           ("CWE-78",  "OS Command Injection",
                        "Ensure exec arguments are not user-controlled."),
    "execvp":          ("CWE-78",  "OS Command Injection",
                        "Ensure exec arguments are not user-controlled."),
    "execve":          ("CWE-78",  "OS Command Injection",
                        "Ensure exec arguments are not user-controlled."),
    # Buffer overflow — banned functions
    "gets":            ("CWE-121", "Stack-based Buffer Overflow",
                        "gets() has no bounds checking — replace with fgets()."),
    "strcpy":          ("CWE-120", "Buffer Copy Without Checking Size",
                        "strcpy() is unsafe — use strncpy() or strlcpy()."),
    "strcat":          ("CWE-120", "Buffer Copy Without Checking Size",
                        "strcat() is unsafe — use strncat() or strlcat()."),
    "sprintf":         ("CWE-134", "Use of Externally-Controlled Format String",
                        "sprintf() has no bounds checking — use snprintf()."),
    "vsprintf":        ("CWE-134", "Use of Externally-Controlled Format String",
                        "vsprintf() has no bounds checking — use vsnprintf()."),
    "scanf":           ("CWE-120", "Buffer Copy Without Checking Size",
                        "scanf() with %%s has no bounds — specify a field width or use fgets()."),
    "printf":          ("CWE-134", "Use of Externally-Controlled Format String",
                        "Ensure the printf format string is a literal, not user-controlled."),
    "fprintf":         ("CWE-134", "Use of Externally-Controlled Format String",
                        "Ensure the fprintf format string is a literal, not user-controlled."),
    # Weak crypto
    "MD5_Init":        ("CWE-327", "Use of a Broken Cryptographic Algorithm",
                        "MD5 is cryptographically broken — use SHA-256 or stronger."),
    "MD5_Update":      ("CWE-327", "Use of a Broken Cryptographic Algorithm",
                        "MD5 is cryptographically broken — use SHA-256 or stronger."),
    "MD5_Final":       ("CWE-327", "Use of a Broken Cryptographic Algorithm",
                        "MD5 is cryptographically broken — use SHA-256 or stronger."),
    "SHA1_Init":       ("CWE-327", "Use of a Broken Cryptographic Algorithm",
                        "SHA-1 is cryptographically broken — use SHA-256 or stronger."),
    "SHA1_Update":     ("CWE-327", "Use of a Broken Cryptographic Algorithm",
                        "SHA-1 is cryptographically broken — use SHA-256 or stronger."),
    "SHA1_Final":      ("CWE-327", "Use of a Broken Cryptographic Algorithm",
                        "SHA-1 is cryptographically broken — use SHA-256 or stronger."),
    "DES_ecb_encrypt": ("CWE-327", "Use of a Broken Cryptographic Algorithm",
                        "DES is cryptographically broken — use AES-256-GCM."),
    # Insecure random
    "rand":            ("CWE-330", "Use of Insufficiently Random Values",
                        "rand() is not cryptographically secure — use getrandom() or /dev/urandom."),
    "srand":           ("CWE-330", "Use of Insufficiently Random Values",
                        "srand() seeds a non-cryptographic RNG — avoid for security-sensitive code."),
    # Unsafe memory
    "alloca":          ("CWE-770", "Allocation of Resources Without Limits or Throttling",
                        "alloca() allocates on the stack with no bounds — use malloc() with size checks."),
}

# Variable name fragments that suggest a hardcoded credential
_CPP_SECRET_FRAGMENTS = frozenset({
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "token", "auth_token", "access_token", "private_key", "secret_key",
    "credentials", "db_password",
})


def _cpp_is_secret_var(name: str) -> bool:
    low = name.lower()
    return any(frag in low for frag in _CPP_SECRET_FRAGMENTS)


def ast_scan_cpp(
    content: str,
    source_lines: List[str],
    filename: str = "input.cpp",
) -> List[Dict[str, object]]:
    """
    Parse *content* as C/C++ source using libclang and return vulnerability
    findings.

    ``pip install libclang`` ships its own libclang shared library — no system
    clang is required.  Works identically on macOS and Linux.

    Returns an empty list if libclang is unavailable or the source cannot
    be parsed (graceful degradation to regex-only scanning).
    """
    if not CLANG_AVAILABLE:
        return []

    suffix = ".cpp" if filename.endswith((".cpp", ".cc", ".cxx", ".hpp")) else ".c"
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        args = [
            "-x", "c++" if suffix == ".cpp" else "c",
            "-std=c++17" if suffix == ".cpp" else "-std=c11",
            "-w",               # suppress all warnings
            "-ferror-limit=0",  # don't stop on errors (missing headers etc.)
        ]
        tu = _get_clang_index().parse(
            tmp_path,
            args=args,
            options=_clang_cindex.TranslationUnit.PARSE_INCOMPLETE,
        )
    except Exception:
        return []
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    findings: List[Dict[str, object]] = []

    def _snip(lineno: int) -> str:
        return _safe_snippet(source_lines, lineno)

    def _ctx(lineno: int) -> str:
        return _ml_context(source_lines, lineno)

    def _walk(cursor) -> None:
        loc = cursor.location
        # Skip nodes from system headers — only analyse our file
        if loc.file and loc.file.name != tmp_path:
            for child in cursor.get_children():
                _walk(child)
            return

        lineno = loc.line or 0
        col    = max((loc.column or 1) - 1, 0)
        kind   = cursor.kind

        # ── 1. Dangerous function calls ────────────────────────────────────
        if kind == _clang_cindex.CursorKind.CALL_EXPR:
            func_name = cursor.spelling or ""
            rule = _CPP_CALL_RULES.get(func_name)
            if rule and lineno:
                cwe_id, cwe_name, rec = rule
                f = _make_finding(
                    lineno, col, cwe_id, cwe_name,
                    f"Unsafe call to {func_name}()",
                    _snip(lineno), "cpp", _ctx(lineno),
                )
                f["recommendation"] = rec
                findings.append(f)

        # ── 2. Hardcoded credential variable declarations ──────────────────
        elif kind in (
            _clang_cindex.CursorKind.VAR_DECL,
            _clang_cindex.CursorKind.FIELD_DECL,
        ):
            var_name = cursor.spelling or ""
            if lineno and _cpp_is_secret_var(var_name):
                tokens = list(cursor.get_tokens())
                has_string_literal = any(
                    t.kind == _clang_cindex.TokenKind.LITERAL
                    and t.spelling.startswith('"')
                    and len(t.spelling) > 2   # not empty string ""
                    for t in tokens
                )
                if has_string_literal:
                    f = _make_finding(
                        lineno, col,
                        "CWE-798", "Use of Hard-coded Credentials",
                        f"Hardcoded credential in variable '{var_name}'",
                        _snip(lineno), "cpp", _ctx(lineno),
                    )
                    f["recommendation"] = (
                        "Do not hardcode credentials — load secrets from "
                        "environment variables or a secrets manager."
                    )
                    findings.append(f)

        for child in cursor.get_children():
            _walk(child)

    _walk(tu.cursor)
    return findings
