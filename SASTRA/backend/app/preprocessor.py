"""Source code preprocessor: strip comments, normalise whitespace, tokenise, and
locate function boundaries. Line numbers are preserved so findings remain accurate."""

import re
from typing import Dict, List, Tuple


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


#  per-language preprocessing 

def _preprocess_python(lines: List[str]) -> List[str]:
    result: List[str] = []
    for line in lines:
        processed = _PYTHON_COMMENT.sub("", line)
        processed = _WHITESPACE_RUN.sub(" ", processed).strip()
        result.append(processed)
    return result


def _preprocess_c_family(lines: List[str]) -> List[str]:
    result: List[str] = []
    in_block_comment = False

    for line in lines:
        processed = line

        if in_block_comment:
            close_match = _BLOCK_COMMENT_CLOSE.search(processed)
            if close_match:
                processed = processed[close_match.end():]
                in_block_comment = False
            else:
                result.append("")
                continue

        processed = _INLINE_BLOCK_COMMENT.sub("", processed)

        open_match = _BLOCK_COMMENT_OPEN.search(processed)
        if open_match:
            close_match = _BLOCK_COMMENT_CLOSE.search(processed, open_match.end())
            if not close_match:
                processed = processed[: open_match.start()]
                in_block_comment = True

        processed = _CPP_COMMENT.sub("", processed)
        processed = _WHITESPACE_RUN.sub(" ", processed).strip()
        result.append(processed)

    return result


def preprocess(content: str, language: str) -> str:
    """Strip comments and normalise whitespace. Supported: python, java, cpp.
    Unknown languages pass through unchanged."""
    if not content:
        return content

    lines: List[str] = content.splitlines()

    lang = (language or "").lower().strip()

    if lang == "python":
        processed_lines = _preprocess_python(lines)
    elif lang in {"java", "cpp"}:
        processed_lines = _preprocess_c_family(lines)
    else:
        return content

    return "\n".join(processed_lines)


def tokenise(content: str, language: str) -> List[str]:
    """Return a flat list of code tokens for the given language."""
    if not content:
        return []
    cleaned = preprocess(content, language)
    return _TOKEN_RE.findall(cleaned)


def identify_function_blocks(
    content: str, language: str
) -> List[Dict[str, object]]:
    """Return function/method boundaries as dicts with name, start_line, end_line."""
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
