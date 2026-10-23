"""A small, dependency-free Sigma rule evaluator for testing rules locally.

It covers the parts of the Sigma specification that most process-creation
rules use, so a rule can be checked against synthetic events before it is
converted to a SIEM query with pySigma / sigma-cli:

  * detection items as maps (AND of fields), lists of maps (OR), and
    keyword lists
  * value lists (OR by default, AND with |all) and null values
  * modifiers: contains, startswith, endswith, all, windash, cased,
    re (with the i / m / s sub-modifiers)
  * plain-string wildcards * and ?, escaped with a backslash
  * conditions: and / or / not, parentheses, "1 of x*", "all of x*",
    "1 of them", "all of them"

Anything outside that subset (base64offset, cidr, field references,
aggregations, correlation rules ...) raises UnsupportedSigma rather than
being silently ignored, so a passing test always means the rule was really
evaluated.
"""

import fnmatch
import itertools
import re

import yaml_lite

DASHES = ["-", "/", "–", "—", "―"]  # hyphen, slash, en, em, horizontal bar
SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "windash", "cased", "re", "i", "m", "s"}


class UnsupportedSigma(ValueError):
    pass


class SigmaRule:
    def __init__(self, data):
        if not isinstance(data, dict) or "detection" not in data:
            raise UnsupportedSigma("rule has no detection section")
        self.data = data
        self.title = data.get("title", "<untitled>")
        detection = dict(data["detection"])
        condition = detection.pop("condition", None)
        detection.pop("timeframe", None)
        if condition is None:
            raise UnsupportedSigma("rule has no condition")
        if isinstance(condition, list):
            condition = " or ".join(f"({c})" for c in condition)
        if "|" in condition:
            raise UnsupportedSigma("aggregation conditions are not supported")
        self.searches = {name: _compile_search(name, body) for name, body in detection.items()}
        self.condition_text = condition
        self.condition = _ConditionParser(condition, list(self.searches)).parse()

    @classmethod
    def from_file(cls, path):
        with open(path, encoding="utf-8") as fh:
            return cls(yaml_lite.load(fh.read()))

    def matches(self, event):
        return self.condition(lambda name: self.searches[name](event))

    def explain(self, event):
        """Return {search_name: bool} for every named search, to show why an event (didn't) match."""
        return {name: search(event) for name, search in self.searches.items()}


# --- detection items -----------------------------------------------------

def _compile_search(name, body):
    if isinstance(body, dict):
        return _compile_map(name, body)
    if isinstance(body, list):
        if all(isinstance(item, dict) for item in body):
            maps = [_compile_map(name, item) for item in body]
            return lambda event: any(m(event) for m in maps)
        if all(not isinstance(item, (dict, list)) for item in body):
            return _compile_keywords(body)
    raise UnsupportedSigma(f"search {name!r} has an unsupported shape")


def _compile_keywords(values):
    matchers = [_compile_value(str(v), ["contains"]) for v in values]

    def keyword_search(event):
        haystack = [str(v) for v in event.values() if v is not None]
        return any(m(h) for m in matchers for h in haystack)

    return keyword_search


def _compile_map(name, body):
    fields = [_compile_field(name, key, value) for key, value in body.items()]
    return lambda event: all(f(event) for f in fields)


def _compile_field(search_name, key, value):
    field, *modifiers = str(key).split("|")
    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise UnsupportedSigma(f"{search_name}.{key}: unsupported modifier(s) {sorted(unknown)}")
    values = value if isinstance(value, list) else [value]
    require_all = "all" in modifiers
    matchers = [_compile_value(v, modifiers) for v in values]

    def field_match(event):
        actual = event.get(field)
        results = (m(actual) for m in matchers)
        return all(results) if require_all else any(results)

    return field_match


def _compile_value(value, modifiers):
    if value is None:
        return lambda actual: actual is None or actual == ""
    if "re" in modifiers:
        flags = 0
        flags |= re.IGNORECASE if "i" in modifiers else 0
        flags |= re.MULTILINE if "m" in modifiers else 0
        flags |= re.DOTALL if "s" in modifiers else 0
        pattern = re.compile(str(value), flags)
        return lambda actual: actual is not None and pattern.search(str(actual)) is not None

    variants = _windash_variants(str(value)) if "windash" in modifiers else [str(value)]
    flags = 0 if "cased" in modifiers else re.IGNORECASE
    patterns = []
    for v in variants:
        body = _wildcard_to_regex(v)
        if "contains" in modifiers:
            body = ".*" + body + ".*"
        elif "startswith" in modifiers:
            body = body + ".*"
        elif "endswith" in modifiers:
            body = ".*" + body
        patterns.append(re.compile(body, flags | re.DOTALL))

    def value_match(actual):
        if actual is None:
            return False
        text = str(actual)
        return any(p.fullmatch(text) for p in patterns)

    return value_match


def _windash_variants(value):
    """Every combination of replacing each '-' with -, /, en dash, em dash, horizontal bar."""
    parts = value.split("-")
    if len(parts) == 1:
        return [value]
    variants = []
    for combo in itertools.product(DASHES, repeat=len(parts) - 1):
        out = parts[0]
        for dash, part in zip(combo, parts[1:]):
            out += dash + part
        variants.append(out)
    return variants


def _wildcard_to_regex(value):
    out = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


# --- condition -----------------------------------------------------------

_TOKEN_RE = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


class _ConditionParser:
    """Recursive-descent parser. Precedence: not > and > or."""

    def __init__(self, text, names):
        self.names = names
        self.tokens = []
        pos = 0
        text = text.strip()
        while pos < len(text):
            m = _TOKEN_RE.match(text, pos)
            if not m:
                raise UnsupportedSigma(f"cannot parse condition near {text[pos:]!r}")
            self.tokens.append(m.group(1))
            pos = m.end()
            while pos < len(text) and text[pos].isspace():
                pos += 1
        self.pos = 0

    def parse(self):
        node = self._or()
        if self.pos != len(self.tokens):
            raise UnsupportedSigma(f"unexpected token {self.tokens[self.pos]!r} in condition")
        return node

    def _peek(self):
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _take(self):
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def _or(self):
        left = self._and()
        while self._peek() == "or":
            self._take()
            right = self._and()
            left = (lambda a, b: lambda ev: a(ev) or b(ev))(left, right)
        return left

    def _and(self):
        left = self._not()
        while self._peek() == "and":
            self._take()
            right = self._not()
            left = (lambda a, b: lambda ev: a(ev) and b(ev))(left, right)
        return left

    def _not(self):
        if self._peek() == "not":
            self._take()
            inner = self._not()
            return lambda ev: not inner(ev)
        return self._atom()

    def _atom(self):
        tok = self._peek()
        if tok is None:
            raise UnsupportedSigma("condition ended unexpectedly")
        if tok == "(":
            self._take()
            node = self._or()
            if self._peek() != ")":
                raise UnsupportedSigma("missing ')' in condition")
            self._take()
            return node
        if tok in ("1", "all") and self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1].lower() == "of":
            quantifier = self._take().lower()
            self._take()  # "of"
            target = self._take()
            selected = self._expand(target)
            if quantifier == "all":
                return lambda ev: all(ev(n) for n in selected)
            return lambda ev: any(ev(n) for n in selected)
        name = self._take()
        if name not in self.names:
            raise UnsupportedSigma(f"condition references unknown search {name!r}")
        return lambda ev: ev(name)

    def _expand(self, target):
        if target.lower() == "them":
            selected = [n for n in self.names if not n.startswith("_")]
        else:
            selected = [n for n in self.names if fnmatch.fnmatchcase(n, target)]
        if not selected:
            raise UnsupportedSigma(f"'{target}' matches no search identifiers")
        return selected
