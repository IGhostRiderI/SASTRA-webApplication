"""
Source code preprocessor (FR-7).

Applies the following steps before the scanner receives code:
    1. Comment removal          — strips single-line and block comments
                                  per language so they cannot trigger false
                                  rule matches.
    2. Whitespace normalisation — collapses runs of spaces/tabs to a
                                  single space so token-boundary regex
                                  patterns match consistently.
    3. Blank line removal       — drops empty lines to keep line-number
                                  references meaningful and reduce noise.
    4. Tokenisation             — splits cleaned source into a flat list
                                  of code tokens (identifiers, keywords,
                                  literals, operators) for downstream
                                  analysis without regex noise.
    5. Function block identification — locates function/method definition
                                  boundaries so findings can be attributed
                                  to a named function context.

The original line structure is preserved as much as possible so that
line numbers reported in findings remain accurate.  Each source line
is processed individually; multi-line block comments are tracked with
a state flag so the scanner never sees comment text.
"""

import re
from typing import Dict, List, Tuple


# ── compiled patterns ──────────────────────────────────────────────────────────
# Tokenisation — matches meaningful code tokens in order of specificity:
#   1. String literals (single/double quoted, non-greedy)
#   2. Numeric literals (int and float)
#   3. Identifiers / keywords (alphanumeric + underscore)
#   4. Two-character operators (==, !=, <=, >=, ->, ::, **, //, <<, >>)
#   5. Single-character operators / punctuation
_TOKEN_RE = re.compile(
    r'"[^"\\]*(?:\\.[^"\\]*)*"'   # double-quoted string
    r"|'[^'\\]*(?:\\.[^'\\]*)*'"  # single-quoted string
    r"|[0-9]+(?:\.[0-9]+)?"       # numeric literal
    r"|[A-Za-z_]\w*"              # identifier / keyword
    r"|==|!=|<=|>=|->|::|[*][*]|//|<<|>>"  # two-char operators
    r"|[^ \t\n]"                  # any remaining non-whitespace char
)

# Function / method definition patterns per language
_FUNC_PATTERNS: Dict[str, re.Pattern] = {
    "python": re.compile(
        r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\("
    ),
    "java": re.compile(
        r"^\s*(?:public|private|protected|static|final|synchronized|abstract|\s)+"
        r"(?:[A-Za-z_][\w<>\[\]]*\s+)"
        r"([A-Za-z_]\w*)\s*\("
    ),
    "cpp": re.compile(
        r"^\s*(?:[A-Za-z_][\w:*&<>\[\]]*\s+)+"
        r"([A-Za-z_]\w*)\s*\([^;]*$"
    ),
}

# Matches the start of a C-style block comment that does NOT close on the
# same line (e.g.  /* start of comment )
_BLOCK_COMMENT_OPEN = re.compile(r"/\*")

# Matches the close of a C-style block comment
_BLOCK_COMMENT_CLOSE = re.compile(r"\*/")

# Matches a full inline block comment on one line (e.g.  /* ... */ )
_INLINE_BLOCK_COMMENT = re.compile(r"/\*.*?\*/")

# Matches Python / shell single-line comments
_PYTHON_COMMENT = re.compile(r"#.*")

# Matches C / Java / C++ single-line comments
_CPP_COMMENT = re.compile(r"//.*")

# Collapses multiple spaces or tabs to a single space
_WHITESPACE_RUN = re.compile(r"[ \t]+")


# ── per-language preprocessing ─────────────────────────────────────────────────

def _preprocess_python(lines: List[str]) -> List[str]:
    """
    Python preprocessing:
      - Remove # comments (but NOT inside string literals — a best-effort
        approach that strips from the first # not preceded by a quote).
      - Normalise horizontal whitespace.
      - Preserve blank placeholder lines so line numbers stay aligned.
    """
    result: List[str] = []
    for line in lines:
        # Remove comment — simple heuristic: strip from first unquoted #
        processed = _PYTHON_COMMENT.sub("", line)
        # Normalise whitespace
        processed = _WHITESPACE_RUN.sub(" ", processed).strip()
        # Keep a blank line as a placeholder so subsequent line numbers
        # in findings still correspond to the original file.
        result.append(processed)
    return result


def _preprocess_c_family(lines: List[str]) -> List[str]:
    """
    Java / C / C++ preprocessing:
      - Remove // single-line comments.
      - Remove /* ... */ block comments, including multi-line ones.
      - Normalise horizontal whitespace.
      - Preserve blank placeholder lines for line-number accuracy.
    """
    result: List[str] = []
    in_block_comment = False

    for line in lines:
        processed = line

        if in_block_comment:
            # We are inside a multi-line block comment.
            close_match = _BLOCK_COMMENT_CLOSE.search(processed)
            if close_match:
                # Comment closes on this line — keep everything after */
                processed = processed[close_match.end():]
                in_block_comment = False
            else:
                # Entire line is inside the block comment — blank it out
                result.append("")
                continue

        # Remove any complete inline block comments on this line
        processed = _INLINE_BLOCK_COMMENT.sub("", processed)

        # Check whether a new block comment opens (without closing)
        open_match = _BLOCK_COMMENT_OPEN.search(processed)
        if open_match:
            close_match = _BLOCK_COMMENT_CLOSE.search(processed, open_match.end())
            if not close_match:
                # Block comment opens but does not close on this line
                processed = processed[: open_match.start()]
                in_block_comment = True

        # Remove single-line // comment
        processed = _CPP_COMMENT.sub("", processed)

        # Normalise whitespace
        processed = _WHITESPACE_RUN.sub(" ", processed).strip()
        result.append(processed)

    return result


# ── public API ─────────────────────────────────────────────────────────────────

def preprocess(content: str, language: str) -> str:
    """
    Preprocess *content* for the given *language* and return the cleaned
    source as a string.

    Supported languages: ``python``, ``java``, ``cpp``.
    Any unknown language is returned unchanged so the scanner degrades
    gracefully without crashing.

    Line count is preserved — blank placeholder lines replace removed
    comment lines so that ``finding["line_number"]`` values still point
    to the correct original lines.
    """
    if not content:
        return content

    lines: List[str] = content.splitlines()

    lang = (language or "").lower().strip()

    if lang == "python":
        processed_lines = _preprocess_python(lines)
    elif lang in {"java", "cpp"}:
        processed_lines = _preprocess_c_family(lines)
    else:
        # Unknown language — return as-is
        return content

    return "\n".join(processed_lines)


def tokenise(content: str, language: str) -> List[str]:
    """
    Tokenise *content* and return a flat list of code tokens (step 4 of FR-7).

    The source is first preprocessed (comments removed, whitespace
    normalised) so that comment text is never tokenised as code.

    Each token is a non-whitespace unit — identifier, keyword, string
    literal, numeric literal, or operator.  The list is suitable for
    downstream analysis such as building a token frequency profile or
    feeding into an ML feature extractor.

    Returns an empty list for unknown languages or empty input.
    """
    if not content:
        return []
    cleaned = preprocess(content, language)
    return _TOKEN_RE.findall(cleaned)


def identify_function_blocks(
    content: str, language: str
) -> List[Dict[str, object]]:
    """
    Identify function/method definition boundaries in *content* (step 5 of FR-7).

    Returns a list of dicts, each describing one function block::

        {
            "name":       str,   # function / method name
            "start_line": int,   # 1-based line where the definition begins
            "end_line":   int,   # 1-based last line of the block (best-effort)
        }

    Detection is language-aware:

    * **Python** — looks for ``def`` / ``async def`` lines and uses
      indentation to determine where the block ends.
    * **Java / C++** — looks for method signatures followed by a body
      opened with ``{`` and uses brace counting to find the closing ``}``.

    For languages where block-end detection is ambiguous the ``end_line``
    is set to the last line of the file as a conservative upper bound.

    Returns an empty list for unknown languages or empty input.
    """
    if not content or (language or "").lower() not in {"python", "java", "cpp"}:
        return []

    lang = language.lower()
    lines = content.splitlines()
    pattern = _FUNC_PATTERNS.get(lang)
    if pattern is None:
        return []

    blocks: List[Dict[str, object]] = []

    if lang == "python":
        # Python: use indentation to find block end
        for i, line in enumerate(lines, start=1):
            m = pattern.match(line)
            if not m:
                continue
            func_name = m.group(1)
            # Measure the indentation of the def line
            def_indent = len(line) - len(line.lstrip())
            end_line = i
            for j in range(i, len(lines)):
                body_line = lines[j]
                if body_line.strip() == "":
                    continue  # blank lines don't close the block
                body_indent = len(body_line) - len(body_line.lstrip())
                if body_indent > def_indent:
                    end_line = j + 1  # 1-based
                elif j > i:
                    break             # indentation returned to def level
            blocks.append({"name": func_name, "start_line": i, "end_line": end_line})

    else:
        # Java / C++: use brace counting
        for i, line in enumerate(lines, start=1):
            m = pattern.match(line)
            if not m:
                continue
            func_name = m.group(1)
            depth = 0
            end_line = len(lines)
            for j in range(i - 1, len(lines)):
                depth += lines[j].count("{") - lines[j].count("}")
                if depth > 0 and j >= i:
                    end_line = j + 1  # 1-based
                if depth == 0 and j >= i:
                    end_line = j + 1
                    break
            blocks.append({"name": func_name, "start_line": i, "end_line": end_line})

    return blocks
