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
import base64
from html.parser import HTMLParser

# ---------------------------------------------------------------------------
# Resource limits (DoS hardening for untrusted input)
# ---------------------------------------------------------------------------
# The parser handles attacker-controlled bytes (crawled HTML, robots.txt,
# header values). These caps keep worst-case work linear and bounded;
# oversized input fails closed (statement -> unknown, no assertions).
# (robots.txt has its own RFC 9309 section 2.3 cap: ROBOTS_TXT_MAX_BYTES.)
MAX_STATEMENT_LEN = 16_384     # 16 KiB: one dictionary serialization
MAX_HTML_BYTES = 10_000_000    # 10 MiB: one HTML document

# ---------------------------------------------------------------------------
# Base32 decoding (HTTPWG JSON "binary" type interop)
# ---------------------------------------------------------------------------
# RFC 9651 byte sequences use Base64 (RFC 4648 §4). However, the HTTPWG
# JSON serialization of Structured Fields maps the "binary" type using
# Base32 (RFC 4648 §6) in some contexts, as Base32 avoids case-sensitivity
# and padding issues in JSON string contexts. This helper decodes
# Base32-encoded byte sequences for interop with such JSON mappings.
# It is not used by the RFC 9651 parser itself (which uses Base64).

def decode_base32(s):
    """Decode RFC 4648 Base32 (no lowercase, padding optional).

    Returns bytes on success, None on invalid input.
    """
    # Normalize: uppercase, strip whitespace
    normalized = re.sub(r"\s", "", s).upper()
    # Base32 alphabet: A-Z, 2-7; padding with =
    if not re.fullmatch(r"[A-Z2-7]*={0,7}", normalized):
        return None
    # Add padding if needed (length must be multiple of 8)
    pad_len = (-len(normalized.rstrip("="))) % 8
    # Only strip existing padding, then re-pad
    stripped = normalized.rstrip("=")
    padded = stripped + ("=" * ((-len(stripped)) % 8))
    try:
        return base64.b32decode(padded, casefold=False)
    except Exception:
        return None

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
    # Integer or Decimal (RFC 9651 §4.2.4)
    # Integer range: -999,999,999,999,999 to 999,999,999,999,999
    # Decimal: max 3 fractional digits; integer part within same range
    if ch.isdigit() or ch == "-":
        start = c.pos
        if ch == "-":
            c.pos += 1
            if c.eof() or not c.peek().isdigit():
                return None
        int_start = c.pos
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
        # Validate integer part is within RFC 9651 range
        # (±999,999,999,999,999 = max 15 digits)
        if vtype == "decimal":
            dot_pos = c.s.find(".", int_start)
            int_digits = c.s[int_start:dot_pos]
        else:
            int_digits = c.s[int_start:c.pos]
        # Remove leading zeros for range check (but keep at least one digit)
        int_digits_stripped = int_digits.lstrip("0") or "0"
        if len(int_digits_stripped) > 15:
            return None
        if len(int_digits_stripped) == 15 and int_digits_stripped > "999999999999999":
            return None
        return (vtype, c.s[start:c.pos])
    # String (RFC 9651 §4.2.6: only \" and \\ are valid escapes)
    if ch == '"':
        c.pos += 1
        out = []
        while not c.eof():
            ch2 = c.peek()
            if ch2 == "\\":
                c.pos += 1
                if c.eof():
                    return None
                esc = c.peek()
                # RFC 9651 §4.2.6: only DQUOTE and backslash may be escaped
                if esc not in ('"', "\\"):
                    return None
                out.append(esc)
                c.pos += 1
            elif ch2 == '"':
                c.pos += 1
                return ("string", "".join(out))
            elif ch2 in ' \t!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~':
                # Note: backslash and DQUOTE excluded; must use escapes
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
    # Byte sequence (RFC 9651 §4.2.7: content MUST be valid Base64 per RFC 4648)
    if ch == ":":
        c.pos += 1
        start = c.pos
        while not c.eof() and c.peek() != ":":
            c.pos += 1
        if c.eof():
            return None
        b64_content = c.s[start:c.pos]
        c.pos += 1
        # Validate RFC 4648 Base64 alphabet (no whitespace allowed in content)
        if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", b64_content):
            return None
        # Validate proper Base64 structure (length multiple of 4, valid padding)
        if len(b64_content) % 4 != 0:
            return None
        # Padding must only appear at end, max 2 chars
        if "=" in b64_content:
            pad_idx = b64_content.index("=")
            if not re.fullmatch(r"={1,2}", b64_content[pad_idx:]):
                return None
        return ("bytes", b64_content)
    # Boolean
    if ch == "?":
        c.pos += 1
        if c.eof() or c.peek() not in "01":
            return None
        val = c.peek() == "1"
        c.pos += 1
        return ("boolean", val)
    # Date (RFC 9651 §4.2.7: "@" followed by non-negative integer)
    if ch == "@":
        c.pos += 1
        # Negative dates are invalid (dates are non-negative per §3.3.7)
        if not c.eof() and c.peek() == "-":
            return None
        start = c.pos
        while not c.eof() and c.peek().isdigit():
            c.pos += 1
        if c.pos == start:
            return None
        return ("date", c.s[start:c.pos])
    # Display string (RFC 9651 §4.2.8)
    # Format: %"..." with \" and \\ escapes, %XX pct-encoding for
    # non-ASCII/unprintable bytes. Decoded output must be valid UTF-8.
    if ch == "%":
        c.pos += 1
        if c.eof() or c.peek() != '"':
            return None
        c.pos += 1
        out_bytes = bytearray()
        while not c.eof():
            ch2 = c.peek()
            if ch2 == '"':
                c.pos += 1
                # Validate the accumulated bytes are valid UTF-8
                try:
                    decoded = bytes(out_bytes).decode("utf-8")
                except UnicodeDecodeError:
                    return None
                return ("dispstr", decoded)
            elif ch2 == "\\":
                c.pos += 1
                if c.eof():
                    return None
                esc = c.peek()
                # Only \" and \\ are valid escapes (same as strings)
                if esc not in ('"', "\\"):
                    return None
                out_bytes.extend(esc.encode("utf-8"))
                c.pos += 1
            elif ch2 == "%":
                # Pct-encoded byte: % followed by 2 hex digits
                c.pos += 1
                if c.pos + 1 >= len(c.s):
                    return None
                hex_digits = c.s[c.pos:c.pos + 2]
                if not re.fullmatch(r"[0-9A-Fa-f]{2}", hex_digits):
                    return None
                out_bytes.append(int(hex_digits, 16))
                c.pos += 2
            elif 0x20 <= ord(ch2) <= 0x7E:
                # Printable ASCII (except " and \ handled above)
                out_bytes.extend(ch2.encode("utf-8"))
                c.pos += 1
            else:
                # CTLs, DEL, and non-ASCII must use pct-encoding
                return None
        return None  # unterminated
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
            # member: item only (RFC 9651 §4.2.1.2: inner lists
            # MUST NOT contain nested inner lists)
            if c.peek() == "(":
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

    Resource limit: serializations longer than MAX_STATEMENT_LEN fail
    closed (None -> unknown downstream).
    """
    if len(s) > MAX_STATEMENT_LEN:
        return None
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

    Resource limit: documents larger than MAX_HTML_BYTES yield no
    statements (fail closed).
    """
    if len(html) > MAX_HTML_BYTES:
        return []
    p = _HeadMetaParser()
    try:
        p.feed(html)
    except Exception:
        return []
    return p.contents


# ---------------------------------------------------------------------------
# robots.txt: RFC 9309 groups + AIPREF Content-Usage rules
# ---------------------------------------------------------------------------

# RFC 9309 §2.3: "crawlers MUST" parse at most 500 kibibytes of robots.txt.
ROBOTS_TXT_MAX_BYTES = 500 * 1024


def _norm_pattern(pattern):
    """Canonicalize %XX triplets in a rule pattern to uppercase hex.

    Lets webmaster-written lowercase encodings (e.g. %2f) compare equal
    to the normalized request path (see _encode_path).
    """
    return re.sub(r"%[0-9a-fA-F]{2}", lambda m: m.group(0).upper(), pattern)


def _pattern_to_regex(pattern):
    """Compile an RFC 9309 §2.2.2 path pattern to a regex.

    '*' matches zero or more characters; a trailing '$' anchors the
    match at the end of the path. A '$' anywhere else is literal.
    Every other character matches literally.
    """
    anchored = pattern.endswith("$")
    body = pattern[:-1] if anchored else pattern
    rx = ".*".join(re.escape(part) for part in body.split("*"))
    return re.compile("^" + rx + ("$" if anchored else ""))


def _encode_path(path):
    """Percent-encode a URL path for robots.txt matching (RFC 9309 §2.2.2).

    Matching is performed on the percent-encoded form: existing %XX
    triplets are preserved (hex normalized to uppercase), characters
    legal unencoded in a path (RFC 3986 pchar plus '/') pass through
    unchanged, and everything else is UTF-8 percent-encoded with
    uppercase hex.
    """
    out = []
    i, n = 0, len(path)
    while i < n:
        c = path[i]
        if (c == "%" and i + 2 < n
                and all(ch in "0123456789abcdefABCDEF"
                        for ch in path[i + 1:i + 3])):
            out.append("%" + path[i + 1:i + 3].upper())
            i += 3
        elif c.isascii() and (c.isalnum() or c in "-._~!$&'()*+,;=:@/"):
            out.append(c)
            i += 1
        else:
            out.extend("%%%02X" % b for b in c.encode("utf-8"))
            i += 1
    return "".join(out)


def _best_rule_match(rules, enc_path):
    """Longest-match rule selection per RFC 9309 §2.2.2.

    `rules` is an iterable of (allow: bool, pattern: str); `enc_path`
    is the percent-encoded request path. Returns (allow, octets) of the
    winning rule, or None when nothing matches. Specificity is measured
    in octets of the pattern; ties resolve to Allow.
    """
    best = None
    for allow, pattern in rules:
        if _pattern_to_regex(pattern).match(enc_path):
            octets = len(pattern.encode("utf-8"))
            if best is None or octets > best[1]:
                best = (allow, octets)
            elif octets == best[1] and allow:
                best = (True, octets)  # tie: Allow wins
    return best


def parse_robots_txt(text):
    """Parse robots.txt into groups.

    Returns [{'agents': [lowercased tokens], 'rules': [(allow: bool, path)],
    'content_usage': [(path_or_None, serialization)]}].

    RFC 9309 handling:
    - §2.3: at most 500 KiB are parsed (input truncated at a line
      boundary; rules past the limit are ignored).
    - §2.4: '#' starts a comment anywhere on the line, including after
      a field value.
    - §2.2.2: empty Disallow means "allow all"; empty Allow matches
      nothing and is ignored.
    Unknown lines are ignored per the spec's tolerance rules.
    """
    if len(text.encode("utf-8")) > ROBOTS_TXT_MAX_BYTES:
        cut = (text.encode("utf-8")[:ROBOTS_TXT_MAX_BYTES]
               .decode("utf-8", "ignore"))
        text = cut.rsplit("\n", 1)[0]  # avoid a torn final line
    groups = []
    current = None  # list of groups sharing accumulated agent lines

    def new_group():
        return {"agents": [], "rules": [], "content_usage": []}

    for raw_line in text.splitlines():
        # RFC 9309 §2.4: '#' begins a comment running to end of line.
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if field == "user-agent":
            token = value.lower()
            if not token:
                continue
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
            if field == "allow" and value == "":
                # Empty Allow matches nothing (RFC 9309 §2.2.2); ignore.
                continue
            for g in current:
                g["has_rules"] = True
                # Empty Disallow = allow all (RFC 9309); record as allow-all
                if field == "disallow" and value == "":
                    g["rules"].append((True, "/"))
                else:
                    g["rules"].append((field == "allow",
                                       _norm_pattern(value)))
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
                        g["content_usage"].append((_norm_pattern(first),
                                                   rest))
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
    """RFC 9309 §2.2.2 acquisition check. Returns True if crawlable.

    Path patterns support '*' (zero or more characters) and a trailing
    '$' (end-of-path anchor). Matching is performed on the
    percent-encoded path; the most specific (longest, in octets)
    matching rule wins, with Allow winning ties.
    """
    if group is None:
        return True
    best = _best_rule_match(group["rules"], _encode_path(path))
    if best is None:
        return True
    return best[0]


def robots_content_usage(group, path):
    """AIPREF attachment draft §3: usage preferences for a crawlable path.

    Among Content-Usage rules whose path-pattern matches `path` under
    RFC 9309 §2.2.2 semantics ('*' wildcard, trailing '$' anchor,
    percent-encoded comparison), the longest-matching pattern in octets
    wins; rules tied on pattern length each contribute a separate
    statement.
    """
    if group is None:
        return []
    enc_path = _encode_path(path)
    best_octets = -1
    winners = []
    for rule_path, serial in group["content_usage"]:
        rp = rule_path if rule_path is not None else "/"
        if _pattern_to_regex(rp).match(enc_path):
            octets = len(rp.encode("utf-8"))
            if octets > best_octets:
                best_octets = octets
                winners = [serial]
            elif octets == best_octets:
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

    # --- RFC 9309 §2.2.2: '*' wildcard and '$' end anchor ---
    ("robots: '*' wildcard matches across path segments",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/a/b/c",
      "robots_txt": "User-agent: *\nDisallow: /a/*\n"},
     (False, {})),
    ("robots: '*' matches zero characters",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/a/",
      "robots_txt": "User-agent: *\nDisallow: /a/*\n"},
     (False, {})),
    ("robots: '$' anchors at end of path",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/x.php",
      "robots_txt": "User-agent: *\nDisallow: /*.php$\n"},
     (False, {})),
    ("robots: '$' does not match a longer path",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/x.php2",
      "robots_txt": "User-agent: *\nDisallow: /*.php$\n"},
     (True, {})),
    ("robots: '$' mid-pattern is a literal character",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/a$b",
      "robots_txt": "User-agent: *\nDisallow: /a$b\n"},
     (False, {})),
    ("robots: longer wildcard pattern beats shorter literal (octets)",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/fish.php",
      "robots_txt": "User-agent: *\nDisallow: /fish\nAllow: /fish*\n"},
     (True, {})),
    ("robots: equal-length patterns -> Allow wins the tie",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/x",
      "robots_txt": "User-agent: *\nDisallow: /x\nAllow: /x\n"},
     (True, {})),

    # --- RFC 9309 §2.2.2: percent-encoded comparison ---
    ("robots: encoded rule matches encoded path",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/foo%2fbar",
      "robots_txt": "User-agent: *\nDisallow: /foo%2fbar\n"},
     (False, {})),
    ("robots: plain rule does not match differently-encoded path",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/foo%2Fbar",
      "robots_txt": "User-agent: *\nDisallow: /foo/bar\n"},
     (True, {})),
    ("robots: wildcard works on percent-encoded paths",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/caf%C3%A9/x",
      "robots_txt": "User-agent: *\nDisallow: /caf%C3%A9/*\n"},
     (False, {})),

    # --- RFC 9309 §2.4: comments; §2.2.2: empty rules ---
    ("robots: trailing comment after Disallow value is ignored",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/private/x",
      "robots_txt": "User-agent: *\nDisallow: /private/ # keep out\n"},
     (False, {})),
    ("robots: trailing comment after User-agent/Allow is ignored",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/x",
      "robots_txt": "# top comment\nUser-agent: * # bots\nAllow: / # all\n"},
     (True, {})),
    ("robots: empty Disallow allows everything",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/anything",
      "robots_txt": "User-agent: *\nDisallow:\n"},
     (True, {})),
    ("robots: empty Allow matches nothing (does not allow-all)",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/private/x",
      "robots_txt": "User-agent: *\nDisallow: /private/\nAllow:\n"},
     (False, {})),

    # --- RFC 9309 §2.3: 500 KiB parse limit ---
    ("robots: rules past 500 KiB are ignored",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/late",
      "robots_txt": ("User-agent: *\nAllow: /\n" + "#pad\n" * 200000
                     + "Disallow: /late\n")},
     (True, {})),
    ("robots: rules within 500 KiB still apply in a large file",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/early",
      "robots_txt": ("User-agent: *\nDisallow: /early\n" + "#pad\n" * 200000)},
     (False, {})),

    # --- RFC 9309 §2.2.1: group selection (lock in combined behavior) ---
    ("robots: several matching named groups combine (prefix match)",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/p",
      "robots_txt": ("User-agent: Test\nAllow: /\n\n"
                     "User-agent: TestBot\nDisallow: /p\n")},
     (False, {})),
    ("robots: group with '*' plus non-matching name falls back to '*'",
     "eval",
     {"user_agent": "OtherBot/1.0", "path": "/s",
      "robots_txt": "User-agent: TestBot\nUser-agent: *\nDisallow: /s\n"},
     (False, {})),

    # --- Content-Usage path-patterns share RFC 9309 matching ---
    ("robots: Content-Usage path-pattern supports '*'",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/blog/2024/x",
      "robots_txt": ("User-agent: *\nAllow: /\n"
                     "Content-Usage: /blog/* train-ai=n\n")},
     (True, {"train-ai": "n"})),
    ("robots: Content-Usage '$' anchor selects exact path only",
     "eval",
     {"user_agent": "TestBot/1.0", "path": "/exact",
      "robots_txt": ("User-agent: *\nAllow: /\n"
                     "Content-Usage: /exact$ train-ai=n\n"
                     "Content-Usage: / train-ai=y\n")},
     (True, {"train-ai": "n"})),

    # --- RFC 9651 strictness fixes ---
    # Quoted-string escapes (§4.2.6): only \" and \\ are valid
    ("string: escaped DQUOTE is valid",
     "stmt", 'x-custom="a\\"b"',
     {"x-custom": "u"}),
    ("string: escaped backslash is valid",
     "stmt", 'x-custom="a\\\\b"',
     {"x-custom": "u"}),
    ("string: invalid escape (\\n) -> whole statement unknown",
     "stmt", 'x-custom="a\\nb"',
     {}),
    ("string: invalid escape (\\t) -> whole statement unknown",
     "stmt", 'train-ai="n", x-custom="a\\tb"',
     {}),
    ("string: bare backslash -> whole statement unknown",
     "stmt", 'x-custom="a\\b"',
     {}),
    # Byte sequence Base64 validation (RFC 4648)
    ("bytes: valid Base64 -> unknown (not a token)",
     "stmt", "x-custom=:aGVsbG8=:",
     {"x-custom": "u"}),
    ("bytes: unpadded Base64 (length not multiple of 4) -> whole statement unknown",
     "stmt", "x-custom=:aGVsbG8:",
     {}),
    ("bytes: invalid Base64 chars -> whole statement unknown",
     "stmt", "x-custom=:aGVsbG8!@:",
     {}),
    ("bytes: bad padding -> whole statement unknown",
     "stmt", "x-custom=:aGVsbG8===:",
     {}),
    ("bytes: length not multiple of 4 -> whole statement unknown",
     "stmt", "x-custom=:abc:",
     {}),
    # Integer range limits (§4.2.4: ±999,999,999,999,999)
    ("integer: max valid (999999999999999) -> unknown",
     "stmt", "x-custom=999999999999999",
     {"x-custom": "u"}),
    ("integer: min valid (-999999999999999) -> unknown",
     "stmt", "x-custom=-999999999999999",
     {"x-custom": "u"}),
    ("integer: too large (1000000000000000) -> whole statement unknown",
     "stmt", "x-custom=1000000000000000",
     {}),
    ("integer: too small (-1000000000000000) -> whole statement unknown",
     "stmt", "x-custom=-1000000000000000",
     {}),
    ("decimal: max 3 fractional digits ok",
     "stmt", "x-custom=1.234",
     {"x-custom": "u"}),
    ("decimal: 4 fractional digits -> whole statement unknown",
     "stmt", "x-custom=1.2345",
     {}),
    ("decimal: integer part too large -> whole statement unknown",
     "stmt", "x-custom=1000000000000000.5",
     {}),
    # Negative dates rejected (§3.3.7: dates are non-negative)
    ("date: negative date -> whole statement unknown",
     "stmt", "x-custom=@-123",
     {}),
    ("date: valid date -> unknown (not a token)",
     "stmt", "x-custom=@1234567890",
     {"x-custom": "u"}),
    # Display strings (§4.2.8)
    ("dispstr: simple ASCII -> unknown (not a token)",
     "stmt", 'x-custom=%"hello"',
     {"x-custom": "u"}),
    ("dispstr: pct-encoded UTF-8 (Hello) -> unknown",
     "stmt", 'x-custom=%"%48%65%6c%6c%6f"',
     {"x-custom": "u"}),
    ("dispstr: escaped DQUOTE -> unknown",
     "stmt", 'x-custom=%"a\\"b"',
     {"x-custom": "u"}),
    ("dispstr: invalid pct-encoding -> whole statement unknown",
     "stmt", 'x-custom=%"a%zzb"',
     {}),
    ("dispstr: bare non-ASCII -> whole statement unknown",
     "stmt", 'x-custom=%"caf\xc3\xa9"',
     {}),
    # Nested inner lists rejected (§4.2.1.2)
    ("inner-list: nested inner list -> whole statement unknown",
     "stmt", "x-custom=((a b))",
     {}),
    ("inner-list: simple inner list -> unknown (not a token)",
     "stmt", "x-custom=(a b)",
     {"x-custom": "u"}),
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
