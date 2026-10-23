"""Minimal YAML loader for Sigma rules.

Uses PyYAML when it is installed. Otherwise falls back to a small parser that
covers the subset Sigma rules actually use: nested mappings, block lists,
plain / single-quoted / double-quoted scalars, and comments. Flow collections
([a, b]), anchors, and multi-line block scalars are not supported by the
fallback and raise an error instead of being silently misread.
"""

import re

try:  # pragma: no cover - depends on the environment
    import yaml as _pyyaml
except ImportError:  # pragma: no cover
    _pyyaml = None


class YamlLiteError(ValueError):
    pass


def load(text):
    if _pyyaml is not None:
        return _pyyaml.safe_load(text)
    lines = _prepare(text)
    if not lines:
        return None
    value, rest = _parse_block(lines, lines[0][0])
    if rest:
        raise YamlLiteError(f"unexpected content at line: {rest[0][1]!r}")
    return value


def _strip_comment(line):
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
    return line


def _prepare(text):
    out = []
    for raw in text.splitlines():
        if raw.strip() in ("---", "..."):
            continue
        line = _strip_comment(raw).rstrip()
        if not line.strip():
            continue
        if "\t" in line[: len(line) - len(line.lstrip())]:
            raise YamlLiteError("tabs are not allowed for indentation")
        indent = len(line) - len(line.lstrip(" "))
        out.append((indent, line.strip()))
    return out


def _parse_block(lines, indent):
    if lines[0][1].startswith("- ") or lines[0][1] == "-":
        return _parse_list(lines, indent)
    return _parse_map(lines, indent)


_KEY_RE = re.compile(r"""^(?P<key>'[^']*'|"[^"]*"|[^:'"][^:]*?)\s*:(?:\s+(?P<val>.*))?$""")


def _split_key(text):
    m = _KEY_RE.match(text)
    if not m:
        return None
    return _scalar(m.group("key")), m.group("val")


def _parse_map(lines, indent):
    result = {}
    while lines and lines[0][0] == indent and not lines[0][1].startswith("- "):
        text = lines[0][1]
        kv = _split_key(text)
        if kv is None:
            raise YamlLiteError(f"expected 'key: value', got {text!r}")
        key, val = kv
        lines = lines[1:]
        if val in ("|", "|-", ">", ">-"):
            result[key], lines = _block_scalar(lines, indent, folded=val.startswith(">"))
        elif val is not None and val != "":
            _reject_unsupported(val)
            result[key] = _scalar(val)
        elif lines and (lines[0][0] > indent or (lines[0][0] == indent and lines[0][1].startswith("- "))):
            result[key], lines = _parse_block(lines, lines[0][0])
        else:
            result[key] = None
    if lines and lines[0][0] > indent:
        raise YamlLiteError(f"bad indentation at {lines[0][1]!r}")
    return result, lines


def _parse_list(lines, indent):
    result = []
    while lines and lines[0][0] == indent and (lines[0][1].startswith("- ") or lines[0][1] == "-"):
        item = lines[0][1][1:].strip()
        lines = lines[1:]
        if not item:
            if lines and lines[0][0] > indent:
                value, lines = _parse_block(lines, lines[0][0])
            else:
                value = None
            result.append(value)
            continue
        kv = _split_key(item) if not item[0] in "'\"" else None
        if kv is None:
            _reject_unsupported(item)
            result.append(_scalar(item))
            continue
        # "- key: value" starts a mapping whose other keys sit at indent + 2.
        child_indent = indent + 2
        synthetic = [(child_indent, item)] + lines
        value, lines = _parse_map(synthetic, child_indent)
        result.append(value)
    return result, lines


def _block_scalar(lines, parent_indent, folded):
    """Literal (|) or folded (>) block. Blank lines inside the block are not preserved."""
    body = []
    while lines and lines[0][0] > parent_indent:
        body.append(lines[0])
        lines = lines[1:]
    if not body:
        return "", lines
    base = min(ind for ind, _ in body)
    if folded:
        return " ".join(text for _, text in body), lines
    return "\n".join(" " * (ind - base) + text for ind, text in body), lines


def _reject_unsupported(val):
    if val[0] in "[{&*!|>":
        raise YamlLiteError(
            f"yaml_lite does not support {val[0]!r} syntax ({val!r}); install PyYAML or rewrite the value"
        )


def _scalar(text):
    if len(text) >= 2 and text[0] == text[-1] == "'":
        return text[1:-1].replace("''", "'")
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return text[1:-1].encode("latin-1", "backslashreplace").decode("unicode_escape")
    lowered = text.lower()
    if lowered in ("null", "~"):
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    return text
