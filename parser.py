#!/usr/bin/env python3
"""Reference parser for AIPREF usage-preference statements.

Implements the processing model from the paper (§3.2).

Serialization inherits RFC 9651 Structured Fields Dictionary semantics
EXACTLY (AIPREF §6):
  - Dictionary labels are case-sensitive. `Train-AI=n` is an invalid
    dictionary (uppercase key); `train-ai=N` parses successfully but is
    unknown (N is a Token other than y/n).
  - Only Token y / Token n map to allow / disallow. Any other value
    (other Tokens, Strings, Booleans, numbers, ...) -> unknown for that
    category. Parameters are parsed and disregarded (AIPREF §6.5).
  - Duplicate keys within one dictionary: LAST value wins (RFC 9651
    §4.2.2: "when duplicate Dictionary keys are encountered, all but
    the last instance are ignored").
  - Any dictionary parse failure (trailing comma, space around `=`,
    uppercase key, unterminated string, ...) -> the whole statement
    yields unknown for every category (no per-key salvage).

Statement combination follows AIPREF §5.1, applied per usage category
across SEPARATE statements (robots.txt Content-Usage rules, HTTP
Content-Usage header, HTML meta elements) -- never within one
dictionary:
  - if any statement disallows the usage -> disallow
  - else, if any statement allows the usage -> allow
  - else -> unknown

HTML binding: the normative processing model is defined in §3.2 of the
paper (operate on the parsed document tree; candidate statements are
meta elements that are descendants of the document's head element).
This parser is a NON-NORMATIVE reference implementation and
executable conformance aid: it uses Python's stdlib HTMLParser (a
source-token scanner, not WHATWG tree construction) to approximate
the tree model -- implied head, after-head mode, template exclusion,
character-reference resolution -- with the divergences documented in
_HeadMetaParser. The element/attribute name match is ASCII
case-insensitive (HTML semantics); the DOM content-attribute value
(UTF-8) is passed to the RFC 9651 dictionary parser with no further
normalization. Each meta element is parsed independently; a failed
parse yields an all-unknown statement.

Three-carrier evaluation (AIPREF attachment draft §3):
  1. Acquisition check under RFC 9309 Allow/Disallow. Disallowed ->
     no usage preferences are evaluated at all.
  2. If allowed: Content-Usage rules from the combined matching
     robots.txt group(s) (RFC 9309 §2.2.1: all matching groups'
     rules are combined; "*" only when nothing else matches).
     Longest path-prefix match, like Allow/Disallow; ties on path
     length each contribute a separate statement.
  3. Content-Usage HTTP header.
  4. All valid HTML <meta name="content-usage"> statements.
  5. The separate AIPREF statements are combined per §5.1.

Preference outcomes: "y" = preference to allow, "n" = preference to
disallow, "u" = unknown (no assertion). AIPREF takes no position on
application-level defaults for unknown; this parser reports "u" and
stops there.

Stdlib only. `python3 parser.py --self-test` runs the conformance suite.
"""

import re
import sys
from html.parser import HTMLParser

# ---------------------------------------------------------------------------
# RFC 9651 Structured Fields: Dictionary parser (§4.2.2)
# ---------------------------------------------------------------------------

_KEY_START = frozenset("abcdefghijklmnopqrstuvwxyz*")
_KEY_CHAR = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-.*")
_TOKEN_START = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*"
)
_TOKEN_CHAR = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "!#$%&'*+-.^_`|~:/"
)


class _Cursor:
    __slots__ = ("s", "pos")

    def __init__(self, s):
        self.s = s
        self.pos = 0

    def eof(self):
        return self.pos >= len(self.s)

    def peek(self):
        return self.s[self.pos] if not self.eof() else ""

    def skip_sp(self):
        while not self.eof() and self.s[self.pos] == " ":
            self.pos += 1

    def skip_ows(self):
        while not self.eof() and self.s[self.pos] in " \t":
            self.pos += 1


def _parse_key(c):
    """RFC 9651 §4.2.3.3 Parsing a Key. Returns key or None."""
    if c.eof() or c.peek() not in _KEY_START:
        return None
    start = c.pos
    c.pos += 1
    while not c.eof() and c.peek() in _KEY_CHAR:
        c.pos += 1
    return c.s[start:c.pos]


def _parse_bare_item(c):
    """RFC 9651 §4.2.3.1. Returns (vtype, value) or None on failure.

    vtype in {'integer','decimal','string','token','bytes','boolean',
    'date','dispstr'}. Only the type matters to the caller (and the
    token's text); numbers/dates are validated, not interpreted.
    """
    if c.eof():
        return None
    ch = c.peek()
    # Integer or Decimal
    if ch.isdigit() or ch == "-":
        start = c.pos
        if ch == "-":
            c.pos += 1
            if c.eof() or not c.peek().isdigit():
                return None
        while not c.eof() and c.peek().isdigit():
            c.pos += 1
        vtype = "integer"
        if not c.eof() and c.peek() == ".":
            # decimal: need 1-3 fractional digits
            c.pos += 1
            fstart = c.pos
            while not c.eof() and c.peek().isdigit():
                c.pos += 1
            frac = c.pos - fstart
            if frac == 0 or frac > 3:
                return None
            vtype = "decimal"
        return (vtype, c.s[start:c.pos])
    # String
    if ch == '"':
        c.pos += 1
        out = []
        while not c.eof():
            ch2 = c.peek()
            if ch2 == "\\":
                c.pos += 1
                if c.eof():
                    return None
                out.append(c.peek())
                c.pos += 1
            elif ch2 == '"':
                c.pos += 1
                return ("string", "".join(out))
            elif ch2 in ' \t!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~':
                out.append(ch2)
                c.pos += 1
            else:
                return None
        return None  # unterminated
    # Token
    if ch in _TOKEN_START:
        start = c.pos
        c.pos += 1
        while not c.eof() and c.peek() in _TOKEN_CHAR:
            c.pos += 1
        return ("token", c.s[start:c.pos])
    # Byte sequence
    if ch == ":":
        c.pos += 1
        start = c.pos
        while not c.eof() and c.peek() != ":":
            c.pos += 1
        if c.eof():
            return None
        c.pos += 1
        return ("bytes", c.s[start:c.pos - 1])
    # Boolean
    if ch == "?":
        c.pos += 1
        if c.eof() or c.peek() not in "01":
            return None
        val = c.peek() == "1"
        c.pos += 1
        return ("boolean", val)
    # Date
    if ch == "@":
        c.pos += 1
        start = c.pos
        if ch == "-":
            pass
        while not c.eof() and c.peek().isdigit():
            c.pos += 1
        if c.pos == start:
            return None
        return ("date", c.s[start:c.pos])
    # Display string
    if ch == "%":
        c.pos += 1
        if c.eof() or c.peek() != '"':
            return None
        c.pos += 1
        while not c.eof() and c.peek() != '"':
            # simplified: accept any char except bare DQUOTE/CTL
            if ord(c.peek()) < 0x20 or ord(c.peek()) == 0x7F:
                return None
            c.pos += 1
        if c.eof():
            return None
        c.pos += 1
        return ("dispstr", None)
    return None


def _parse_parameters(c):
    """RFC 9651 §4.2.3.2. Parse (and discard) parameters. Returns True/False."""
    while not c.eof() and c.peek() == ";":
        c.pos += 1
        c.skip_sp()
        if _parse_key(c) is None:
            return False
        if not c.eof() and c.peek() == "=":
            c.pos += 1
            if _parse_bare_item(c) is None:
                return False
    return True


def _parse_item_or_inner_list(c):
    """RFC 9651 §4.2.1.1. Returns (vtype, value) or None.

    Inner lists are parsed for correctness but reported as vtype
    'inner-list' (never a Token y/n, hence unknown downstream).
    """
    if c.eof():
        return None
    if c.peek() == "(":
        # Inner list: "(" *SP [ (item-or-inner-list) *( SP (item-or-inner-list) ) *SP ] ")"
        c.pos += 1
        while True:
            while not c.eof() and c.peek() == " ":
                c.pos += 1
            if c.eof():
                return None
            if c.peek() == ")":
                c.pos += 1
                break
            # member: item or nested inner list
            if c.peek() == "(":
                if _parse_item_or_inner_list(c) is None:
                    return None
            else:
                if _parse_bare_item(c) is None:
                    return None
                if not _parse_parameters(c):
                    return None
            # after member: SP or ")"
            if c.eof():
                return None
            if c.peek() == ")":
                continue  # loop will consume it
            if c.peek() != " ":
                return None
        if not _parse_parameters(c):
            return None
        return ("inner-list", None)
    v = _parse_bare_item(c)
    if v is None:
        return None
    if not _parse_parameters(c):
        return None
    return v


def parse_sf_dictionary(s):
    """Parse an RFC 9651 Dictionary (§4.2.2).

    Returns an ordered dict {key: (vtype, value)} with last-wins
    duplicate handling, or None if parsing fails. Parameters are
    parsed and discarded (AIPREF §6.5: disregarded).
    """
    c = _Cursor(s)
    c.skip_sp()  # leading SP discarded
    result = {}
    if c.eof():
        return result  # empty dictionary is valid
    while True:
        key = _parse_key(c)
        if key is None:
            return None
        if not c.eof() and c.peek() == "=":
            c.pos += 1
            item = _parse_item_or_inner_list(c)
            if item is None:
                return None
        else:
            # Bare member: Boolean true, then parameters
            if not _parse_parameters(c):
                return None
            item = ("boolean", True)
        result[key] = item  # last wins
        c.skip_ows()
        if c.eof():
            return result
        if c.peek() != ",":
            return None
        c.pos += 1
        c.skip_ows()
        if c.eof():
            return None  # trailing comma: fail parsing


# ---------------------------------------------------------------------------
# AIPREF statement evaluation (§6.5)
# ---------------------------------------------------------------------------

def statement_prefs(serialization):
    """Evaluate one AIPREF serialization into {key: 'y'/'n'/'u'}.

    Token y -> 'y' (preference to allow); Token n -> 'n' (preference to
    disallow); anything else (other Tokens, Strings, Booleans, numbers,
    absent keys) -> 'u' (unknown). A failed dictionary parse -> {}
    (no assertions; every category unknown). Extension keys are kept;
    parameters were already disregarded by the dictionary parser.
    """
    if serialization is None:
        return {}
    d = parse_sf_dictionary(serialization)
    if d is None:
        return {}
    out = {}
    for key, (vtype, value) in d.items():
        if vtype == "token" and value == "y":
            out[key] = "y"
        elif vtype == "token" and value == "n":
            out[key] = "n"
        else:
            out[key] = "u"
    return out


def combine_statements(statements):
    """AIPREF §5.1 combination across separate statements, per category.

    For each category: if any statement disallows -> 'n'; else if any
    statement allows -> 'y'; else -> 'u' (unknown).
    """
    keys = set()
    for st in statements:
        keys.update(st.keys())
    out = {}
    for key in keys:
        vals = [st[key] for st in statements if key in st]
        if "n" in vals:
            out[key] = "n"
        elif "y" in vals:
            out[key] = "y"
        else:
            out[key] = "u"
    return out


# ---------------------------------------------------------------------------
# HTML binding: <meta name="content-usage"> extraction
# ---------------------------------------------------------------------------

class _HeadMetaParser(HTMLParser):
    """Collect content="..." from <meta name="content-usage"> in <head>.

    IMPLEMENTATION NOTE (honesty about conformance): this reference
    implementation uses Python's stdlib HTMLParser, which is a
    source-token scanner -- NOT WHATWG tree construction. It
    approximates the normative tree-based model (§3.2 of the paper)
    for well-formed documents:

    Handled like the tree model:
    - Implied <head>: meta elements before any <body>/<frameset>
      count, because the HTML parser creates the head element even
      when the tags are omitted.
    - "After head" mode: a meta between </head> and <body> counts
      (WHATWG processes it under "in head" rules).
    - <template> contents: ignored (separate template fragment).
    - Comments: never reported as tags. Scripting disabled: the raw
      source is parsed; JS-inserted tags do not exist in the source.
    - Character references in attribute values are resolved
      (convert_charrefs=True), matching the DOM attribute value.
    - <iframe>/<object> embedded documents are separate documents;
      their markup is attribute/text content here, never parsed.

    Known divergences from WHATWG tree construction (documented, not
    hidden): foster parenting inside <table> (a meta misnested in
    table markup is reparented by the tree builder; this scanner may
    misclassify it), badly misnested tags generally, and <noscript>
    with scripting enabled (out of scope: scripting is disabled).
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        # head_status: "none" (before head/body: implied head),
        # "open", "closed" (after </head>, before body: "after head"
        # mode -- meta still processed under in-head rules), "body".
        self.head_status = "none"
        self.template_depth = 0
        self.contents = []

    def _meta_qualifies(self):
        return (
            self.template_depth == 0
            and self.head_status in ("none", "open", "closed")
        )

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        if t == "template":
            self.template_depth += 1
        elif t == "head":
            self.head_status = "open"
        elif t in ("body", "frameset"):
            self.head_status = "body"
        elif t == "table" and self.head_status != "body":
            # WHATWG "in head"/"after head": a <table> start tag pops
            # the head element and switches to body. Approximate: once
            # a table opens outside body, subsequent content is in body.
            self.head_status = "body"
        elif t == "meta" and self._meta_qualifies():
            name = None
            content = None
            for aname, aval in attrs:
                al = aname.lower()
                # HTML: first occurrence of a duplicate attribute wins
                if al == "name" and name is None:
                    name = aval
                elif al == "content" and content is None:
                    content = aval
            if name is not None and name.lower() == "content-usage":
                # content may be None (missing attribute) -> no assertion
                self.contents.append(content)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        t = tag.lower()
        if t == "template" and self.template_depth > 0:
            self.template_depth -= 1
        elif t == "head" and self.head_status in ("none", "open"):
            self.head_status = "closed"


def extract_meta_contents(html):
    """Return the list of content="..." values from qualifying meta tags.

    Each element is evaluated as an independent statement downstream.
    Missing content attribute -> None (contributes no assertions).
    """
    p = _HeadMetaParser()
    try:
        p.feed(html)
    except Exception:
        return []
    return p.contents


# ---------------------------------------------------------------------------
# robots.txt: RFC 9309 groups + AIPREF Content-Usage rules
# ---------------------------------------------------------------------------

def parse_robots_txt(text):
    """Parse robots.txt into groups.

    Returns [{'agents': [lowercased tokens], 'rules': [(allow: bool, path)],
    'content_usage': [(path_or_None, serialization)]}].
    Lines the parser does not understand are skipped (RFC 9309 §2.2.4:
    "crawlers MUST ignore rules they do not understand"... actually
    unknown lines are ignored per the spec's tolerance rules).
    """
    groups = []
    current = None  # list of groups sharing accumulated agent lines

    def new_group():
        return {"agents": [], "rules": [], "content_usage": []}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if field == "user-agent":
            token = value.lower()
            if current is None or current[0].get("has_rules"):
                # start a new group run
                g = new_group()
                groups.append(g)
                current = [g]
            else:
                # agent lines accumulate into the current run
                pass
            for g in current:
                if token not in g["agents"]:
                    g["agents"].append(token)
        elif field in ("allow", "disallow"):
            if current is None:
                continue
            for g in current:
                g["has_rules"] = True
                # Empty Disallow = allow all (RFC 9309); record as allow-all
                if field == "disallow" and value == "":
                    g["rules"].append((True, "/"))
                else:
                    g["rules"].append((field == "allow", value))
        elif field == "content-usage":
            if current is None:
                continue
            for g in current:
                g["has_rules"] = True
                # content-usage = *WS "content-usage" *WS ":" *WS
                #                [ path-pattern 1*WS ] usage-pref EOL
                # Split on the first run of SP/HTAB: optional path-pattern,
                # then the usage-preference serialization.
                m = re.match(r"(\S+)[ \t]+(.*)$", value, re.DOTALL)
                if m and re.fullmatch(r"[ -~]*", m.group(2) or ""):
                    # Heuristic: if the remainder parses as (or looks like)
                    # a preference serialization, treat group(1) as path.
                    # A path-pattern never contains '=' or ','.
                    first, rest = m.group(1), m.group(2)
                    if "=" not in first and "," not in first:
                        g["content_usage"].append((first, rest))
                    else:
                        g["content_usage"].append((None, value))
                else:
                    g["content_usage"].append((None, value))
    for g in groups:
        g.pop("has_rules", None)
    return groups


def _groups_for_agent(groups, user_agent):
    """RFC 9309 §2.2.1: combine the rules of ALL matching groups.

    Matching is case-insensitive; a group matches when one of its
    user-agent tokens is a prefix of the crawler's product token (the
    conventional interpretation; the RFC requires case-insensitive
    matching of the product token against the group). When more than
    one group matches, their rules MUST be combined into a single
    group. The "*" group is used ONLY when no specific group matches.
    Longest-match applies to URL paths (§2.2.2), NOT to group
    selection -- there is no "most specific group wins" rule.

    Returns a synthetic merged group dict, or None if nothing matches.
    """
    ua = user_agent.lower()
    named = []
    star = []
    for g in groups:
        matched = False
        is_star = False
        for token in g["agents"]:
            if token == "*":
                is_star = True
            elif ua.startswith(token):
                matched = True
        if matched:
            named.append(g)
        elif is_star:
            star.append(g)
    use = named if named else star
    if not use:
        return None
    merged = {"agents": [], "rules": [], "content_usage": []}
    for g in use:
        for a in g["agents"]:
            if a not in merged["agents"]:
                merged["agents"].append(a)
        merged["rules"].extend(g["rules"])
        merged["content_usage"].extend(g["content_usage"])
    return merged


def robots_allows(group, path):
    """RFC 9309 §2.2.2 acquisition check. Returns True if crawlable."""
    if group is None:
        return True
    best = None  # (octets, allow)
    for allow, rule_path in group["rules"]:
        if path.startswith(rule_path):
            if best is None or len(rule_path) > best[0]:
                best = (len(rule_path), allow)
            elif len(rule_path) == best[0] and allow:
                best = (len(rule_path), True)  # tie: Allow wins
    if best is None:
        return True
    return best[1]


def robots_content_usage(group, path):
    """AIPREF attachment draft §3: usage preferences for a crawlable path.

    Among Content-Usage rules whose path-pattern is a prefix of `path`,
    the longest-matching path wins (same prefix rule as Allow/Disallow);
    rules tied on path length each contribute a separate statement.
    """
    if group is None:
        return []
    best_len = -1
    winners = []
    for rule_path, serial in group["content_usage"]:
        rp = rule_path if rule_path is not None else "/"
        if path.startswith(rp):
            if len(rp) > best_len:
                best_len = len(rp)
                winners = [serial]
            elif len(rp) == best_len:
                winners.append(serial)
    return [statement_prefs(s) for s in winners]


def evaluate(user_agent, path, robots_txt=None, http_header=None, html=None):
    """Three-carrier evaluation for one (crawler, resource).

    Returns (crawlable: bool, prefs: {key: 'y'/'n'/'u'}).

    http_header may be a single field value or a list of field values;
    multiple Content-Usage field lines are combined per RFC 9651 §4.2
    (concatenate with commas) and parsed as ONE dictionary.
    """
    statements = []
    if robots_txt is not None:
        groups = parse_robots_txt(robots_txt)
        group = _groups_for_agent(groups, user_agent)
        if not robots_allows(group, path):
            return (False, {})
        statements.extend(robots_content_usage(group, path))
    if http_header is not None:
        if isinstance(http_header, (list, tuple)):
            # RFC 9651 §4.2: combine field lines before parsing.
            combined = ", ".join(h for h in http_header)
        else:
            combined = http_header
        statements.append(statement_prefs(combined))
    if html is not None:
        for content in extract_meta_contents(html):
            statements.append(statement_prefs(content))
    return (True, combine_statements(statements))

# ---------------------------------------------------------------------------
# Conformance test vectors
# Each: (description, kind, input, expected)
# kind "stmt": statement_prefs(input) == expected
# kind "eval": evaluate(...) == expected  (input is a dict of kwargs)
# ---------------------------------------------------------------------------
VECTORS = [
    # --- AIPREF serialization: valid dictionaries ---
    ("valid: train-ai=n, search=y",
     "stmt", "train-ai=n, search=y",
     {"train-ai": "n", "search": "y"}),
    ("valid: all three keys",
     "stmt", "train-ai=n, ai-use=n, search=y",
     {"train-ai": "n", "ai-use": "n", "search": "y"}),
    ("valid: OWS around comma",
     "stmt", "train-ai=n ,\t search=y",
     {"train-ai": "n", "search": "y"}),
    ("valid: empty dictionary asserts nothing",
     "stmt", "",
     {}),
    ("valid: whitespace-only dictionary asserts nothing",
     "stmt", "   ",
     {}),
    # --- Case sensitivity (RFC 9651 keys are lowercase-only) ---
    ("invalid: uppercase key -> whole statement unknown",
     "stmt", "Train-AI=n",
     {}),
    ("invalid: uppercase key among valid -> whole statement unknown",
     "stmt", "train-ai=n, Search=y",
     {}),
    ("valid dict, uppercase TOKEN value -> unknown (not y/n token)",
     "stmt", "train-ai=N",
     {"train-ai": "u"}),
    ("valid dict, uppercase TOKEN value alongside valid",
     "stmt", "train-ai=N, search=y",
     {"train-ai": "u", "search": "y"}),
    # --- Strict separators ---
    ("invalid: spaces around '=' -> whole statement unknown",
     "stmt", "train-ai = n",
     {}),
    ("invalid: space before '=' -> whole statement unknown",
     "stmt", "train-ai =n, search=y",
     {}),
    ("invalid: trailing comma -> whole statement unknown",
     "stmt", "train-ai=n,",
     {}),
    ("invalid: trailing comma with space -> whole statement unknown",
     "stmt", "train-ai=n, ",
     {}),
    ("invalid: leading comma -> whole statement unknown",
     "stmt", ",train-ai=n",
     {}),
    ("invalid: double comma -> whole statement unknown",
     "stmt", "train-ai=n,,search=y",
     {}),
    # --- Duplicate keys: LAST wins (RFC 9651), never most-restrictive ---
    ("duplicate keys: last wins (n then y -> y)",
     "stmt", "train-ai=n, train-ai=y",
     {"train-ai": "y"}),
    ("duplicate keys: last wins (y then n -> n)",
     "stmt", "train-ai=y, train-ai=n",
     {"train-ai": "n"}),
    ("duplicate keys, three occurrences: last wins",
     "stmt", "train-ai=n, train-ai=y, train-ai=n",
     {"train-ai": "n"}),
    # --- Non-token values -> unknown (AIPREF §6.5) ---
    ("quoted string value -> unknown (not a Token)",
     "stmt", 'train-ai="n"',
     {"train-ai": "u"}),
    ("bare key (Boolean true) -> unknown",
     "stmt", "train-ai",
     {"train-ai": "u"}),
    ("bare key alongside valid pair",
     "stmt", "train-ai, search=y",
     {"train-ai": "u", "search": "y"}),
    ("integer value -> unknown",
     "stmt", "train-ai=1",
     {"train-ai": "u"}),
    ("other token value -> unknown",
     "stmt", "train-ai=maybe",
     {"train-ai": "u"}),
    ("other token value alongside valid",
     "stmt", "train-ai=maybe, search=y",
     {"train-ai": "u", "search": "y"}),
    ("boolean ?1 value -> unknown",
     "stmt", "train-ai=?1",
     {"train-ai": "u"}),
    ("parameters disregarded: token value still applies",
     "stmt", "train-ai=n;foo=bar",
     {"train-ai": "n"}),
    ("parameters disregarded: non-token still unknown",
     "stmt", "train-ai;foo=bar",
     {"train-ai": "u"}),
    # --- Extension keys ---
    ("extension key with n -> recorded",
     "stmt", "train-ai=n, x-custom=n",
     {"train-ai": "n", "x-custom": "n"}),
    ("extension key with string -> unknown",
     "stmt", 'x-custom="yes"',
     {"x-custom": "u"}),
    # --- Malformed dictionaries: no per-key salvage ---
    ("invalid: unterminated string -> whole statement unknown",
     "stmt", 'train-ai="n, search=y',
     {}),
    ("invalid: key starting with digit -> whole statement unknown",
     "stmt", "9lives=n",
     {}),
    ("invalid: missing value after '=' -> whole statement unknown",
     "stmt", "train-ai=",
     {}),
    ("invalid: garbage -> whole statement unknown",
     "stmt", "!!!",
     {}),
    # --- AIPREF §6.5.1 example: duplicates resolve per RFC 9651 ---
    ("AIPREF 6.5.1 example: train-ai=y,train-ai,search=n,search=\"n\"",
     "stmt", 'train-ai=y, train-ai, search=n, search="n"',
     {"train-ai": "u", "search": "u"}),

    # --- HTML binding ---
    ("html: single head meta",
     "eval",
     {"html": '<html><head><meta name="content-usage" content="train-ai=n, search=y"></head></html>'},
     (True, {"train-ai": "n", "search": "y"})),
    ("html: name match is ASCII case-insensitive",
     "eval",
     {"html": '<html><head><META NAME="Content-Usage" CONTENT="train-ai=n"></head></html>'},
     (True, {"train-ai": "n"})),
    ("html: content serialization NOT normalized (uppercase key fails)",
     "eval",
     {"html": '<html><head><meta name="content-usage" content="Train-AI=n"></head></html>'},
     (True, {})),
    ("html: content serialization NOT normalized (spaces around = fail)",
     "eval",
     {"html": '<html><head><meta name="content-usage" content="train-ai = n"></head></html>'},
     (True, {})),
    ("html: tag in body ignored",
     "eval",
     {"html": '<html><head><title>t</title></head><body><meta name="content-usage" content="train-ai=n"></body></html>'},
     (True, {})),
    ("html: implied head (omitted <head> tags) counts",
     "eval",
     {"html": '<html><meta name="content-usage" content="train-ai=n"><body><p>x</p></body></html>'},
     (True, {"train-ai": "n"})),
    ("html: meta between </head> and <body> counts (after-head mode)",
     "eval",
     {"html": '<html><head><title>t</title></head><meta name="content-usage" content="train-ai=n"><body></body></html>'},
     (True, {"train-ai": "n"})),
    ("html: meta inside <template> ignored (separate fragment)",
     "eval",
     {"html": '<html><head><template><meta name="content-usage" content="train-ai=n"></template></head></html>'},
     (True, {})),
    ("html: iframe srcdoc markup is a separate document, not parsed",
     "eval",
     {"html": '<html><head></head><body><iframe srcdoc="<meta name=\'content-usage\' content=\'train-ai=n\'>"></iframe></body></html>'},
     (True, {})),
    ("html: character reference in content resolved to DOM value",
     "eval",
     {"html": '<html><head><meta name="content-usage" content="train-ai&#61;n"></head></html>'},
     (True, {"train-ai": "n"})),
    ("html: table in head forces body (foster-parenting approximation)",
     "eval",
     {"html": '<html><head><table><meta name="content-usage" content="train-ai=n"></table></head></html>'},
     (True, {})),
    ("html: empty content asserts nothing",
     "eval",
     {"html": '<html><head><meta name="content-usage" content=""></head></html>'},
     (True, {})),
    ("html: tag after </html> ignored",
     "eval",
     {"html": '<html><head><title>t</title></head><body></body></html><meta name="content-usage" content="train-ai=n">'},
     (True, {})),
    ("html: commented-out tag ignored",
     "eval",
     {"html": '<html><head><!-- <meta name="content-usage" content="train-ai=n"> --></head></html>'},
     (True, {})),
    ("html: no head element -> no statements",
     "eval",
     {"html": '<html><body><p>hi</p></body></html>'},
     (True, {})),
    ("html: missing content attribute -> no assertions",
     "eval",
     {"html": '<html><head><meta name="content-usage"></head></html>'},
     (True, {})),
    ("html: unquoted attributes",
     "eval",
     {"html": "<html><head><meta name=content-usage content=train-ai=n></head></html>"},
     (True, {"train-ai": "n"})),
    ("html: two meta elements combine via AIPREF 5.1 (n wins)",
     "eval",
     {"html": '<html><head><meta name="content-usage" content="train-ai=y"><meta name="content-usage" content="train-ai=n, search=y"></head></html>'},
     (True, {"train-ai": "n", "search": "y"})),
    ("html: two meta elements combine via AIPREF 5.1 (y survives u)",
     "eval",
     {"html": '<html><head><meta name="content-usage" content="train-ai=y"><meta name="content-usage" content="search=y"></head></html>'},
     (True, {"train-ai": "y", "search": "y"})),
    ("html: failed statement does not erase explicit allow",
     "eval",
     {"html": '<html><head><meta name="content-usage" content="train-ai=y"><meta name="content-usage" content="Train-AI=n"></head></html>'},
     (True, {"train-ai": "y"})),

    # --- HTTP header carrier ---
    ("header: alone",
     "eval",
     {"http_header": "train-ai=n, search=y"},
     (True, {"train-ai": "n", "search": "y"})),
    ("header + meta: disallow wins per AIPREF 5.1",
     "eval",
     {"html": '<html><head><meta name="content-usage" content="train-ai=y"></head></html>',
      "http_header": "train-ai=n"},
     (True, {"train-ai": "n"})),
    ("header + meta: allow stands when other is silent",
     "eval",
     {"html": '<html><head><meta name="content-usage" content="train-ai=y"></head></html>',
      "http_header": "search=n"},
     (True, {"train-ai": "y", "search": "n"})),
    ("header: multiple field lines combine to one dictionary (RFC 9651 4.2); "
     "last-wins, not two statements",
     "eval",
     {"http_header": ["train-ai=n", "train-ai=y"]},
     (True, {"train-ai": "y"})),

    # --- robots.txt: RFC 9309 acquisition + Content-Usage rules ---
    ("robots: disallow blocks acquisition; no prefs evaluated",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/private/page",
      "robots_txt": "User-agent: TestBot\nDisallow: /private/\nContent-Usage: train-ai=n\n"},
     (False, {})),
    ("robots: allowed path; group Content-Usage applies",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/blog/post",
      "robots_txt": "User-agent: *\nAllow: /\nContent-Usage: train-ai=n\n"},
     (True, {"train-ai": "n"})),
    ("robots: Content-Usage with path pattern, longest match",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/blog/draft/x",
      "robots_txt": "User-agent: *\nAllow: /\nContent-Usage: / train-ai=y\nContent-Usage: /blog/ train-ai=n\n"},
     (True, {"train-ai": "n"})),
    ("robots: Content-Usage with path pattern, shorter path falls back",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/about",
      "robots_txt": "User-agent: *\nAllow: /\nContent-Usage: / train-ai=y\nContent-Usage: /blog/ train-ai=n\n"},
     (True, {"train-ai": "y"})),
    ("robots: identical paths, conflicting prefs -> separate statements (5.1)",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/x",
      "robots_txt": "User-agent: *\nAllow: /\nContent-Usage: train-ai=y\nContent-Usage: train-ai=n\n"},
     (True, {"train-ai": "n"})),
    # --- RFC 9309 §2.2.1: matching groups COMBINE; "*" only if none match ---
    ("robots: two matching named groups both contribute (combined)",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/x",
      "robots_txt": "User-agent: TestBot\nAllow: /\nContent-Usage: train-ai=n\n\nUser-agent: TestBot\nAllow: /\nContent-Usage: search=y\n"},
     (True, {"train-ai": "n", "search": "y"})),
    ("robots: named + wildcard groups; wildcard ignored when named matches",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/x",
      "robots_txt": "User-agent: *\nAllow: /\nContent-Usage: train-ai=y\n\nUser-agent: TestBot\nAllow: /\nContent-Usage: train-ai=n\n"},
     (True, {"train-ai": "n"})),
    ("robots: wildcard used only when no named group matches",
     "eval",
     {"user_agent": "OtherBot/1.0", "path": "/x",
      "robots_txt": "User-agent: *\nAllow: /\nContent-Usage: train-ai=y\n\nUser-agent: TestBot\nAllow: /\nContent-Usage: train-ai=n\n"},
     (True, {"train-ai": "y"})),
    ("robots: product-token matching is case-insensitive",
     "eval",
     {"user_agent": "testbot/1.0", "path": "/x",
      "robots_txt": "User-agent: TESTBOT\nAllow: /\nContent-Usage: train-ai=n\n"},
     (True, {"train-ai": "n"})),
    ("robots: no matching group and no wildcard -> crawlable, no statements",
     "eval",
     {"user_agent": "OtherBot/1.0", "path": "/x",
      "robots_txt": "User-agent: TestBot\nDisallow: /\nContent-Usage: train-ai=n\n"},
     (True, {})),
    ("robots: acquisition rules also combine across matching groups",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/private/x",
      "robots_txt": "User-agent: TestBot\nAllow: /\n\nUser-agent: TestBot\nDisallow: /private/\n"},
     (False, {})),
    ("robots: three carriers combined via 5.1",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/x",
      "robots_txt": "User-agent: *\nAllow: /\nContent-Usage: ai-use=n\n",
      "http_header": "search=y",
      "html": '<html><head><meta name="content-usage" content="train-ai=n"></head></html>'},
     (True, {"train-ai": "n", "ai-use": "n", "search": "y"})),
    ("robots: no robots.txt -> crawlable, no statements",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/x",
      "html": '<html><head><title>t</title></head></html>'},
     (True, {})),
]


def run_self_test():
    failures = 0
    for desc, kind, inp, expected in VECTORS:
        if kind == "stmt":
            got = statement_prefs(inp)
        else:
            got = evaluate(
                inp.get("user_agent", "TestBot/1.0"),
                inp.get("path", "/"),
                robots_txt=inp.get("robots_txt"),
                http_header=inp.get("http_header"),
                html=inp.get("html"),
            )
        if got != expected:
            failures += 1
            print(f"FAIL: {desc}\n  expected {expected!r}\n  got      {got!r}")
        else:
            print(f"ok: {desc}")
    print(f"\n{len(VECTORS) - failures}/{len(VECTORS)} vectors passed")
    return 1 if failures else 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(run_self_test())
    print("Usage: python3 parser.py --self-test")
