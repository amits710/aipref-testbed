#!/usr/bin/env python3
"""Normative-reference implementation of the HTML binding's meta extraction.

Uses html5lib (a WHATWG-conforming HTML tree builder) to implement the
normative processing model from the paper (§3.2) directly:

  - Parse the representation with the WHATWG HTML parsing algorithm,
    scripting disabled (html5lib's default: no script execution).
  - Candidate statements are <meta> elements that are DESCENDANTS of the
    document's head element.
  - Element and attribute NAME matching is ASCII case-insensitive
    (html5lib lowercases tag/attribute names per HTML semantics; the
    name attribute VALUE is compared ASCII case-insensitively here).
  - The statement is the DOM value of the `content` attribute
    (character references already resolved by the tree builder),
    encoded as UTF-8 and parsed as an RFC 9651 Dictionary.
  - <template> contents live in a separate template fragment, not in
    the head subtree, and do not qualify. <iframe> documents are
    separate documents. Foster-parented content (e.g. <meta> before
    <table>) lands outside the head and does not qualify.

This module reuses the RFC 9651 dictionary parser, AIPREF value mapping,
and statement combination from parser.py -- only the HTML *extraction*
layer differs (tree-based here vs. source-token scanner there).

Requires: pip install html5lib
"""

import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])

import html5lib  # noqa: E402
from parser import statement_prefs, combine_statements  # noqa: E402


def _ascii_lower(s):
    """ASCII-only case folding (HTML ASCII case-insensitive matching)."""
    return "".join(
        chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s
    )


def extract_meta_contents_html5lib(html):
    """Return content="..." values of qualifying meta tags via html5lib.

    Each element is evaluated as an independent statement downstream.
    Missing content attribute -> None (contributes no assertions).
    """
    try:
        doc = html5lib.parse(
            html, treebuilder="etree", namespaceHTMLElements=False
        )
    except Exception:
        return []
    # Find the head element (html5lib always creates one per the spec).
    head = None
    for el in doc.iter():
        if el.tag == "head":
            head = el
            break
    if head is None:
        return []
    contents = []
    for meta in head.iter("meta"):
        # html5lib lowercases attribute NAMES; compare the name VALUE
        # ASCII case-insensitively per the normative model.
        name_val = None
        content_val = None
        # NB: html5lib keeps only the first occurrence of duplicate
        # attributes, matching the HTML specification.
        for aname, aval in meta.attrib.items():
            if _ascii_lower(aname) == "name" and name_val is None:
                name_val = aval
            elif _ascii_lower(aname) == "content" and content_val is None:
                content_val = aval
        if name_val is not None and _ascii_lower(name_val) == "content-usage":
            contents.append(content_val)
    return contents


def evaluate_html5lib(html):
    """Evaluate all meta statements in `html` via the tree-based model.

    Returns the combined preference dict {key: 'y'/'n'/'u'}.
    """
    statements = [
        statement_prefs(c) for c in extract_meta_contents_html5lib(html)
    ]
    return combine_statements(statements)


# ---------------------------------------------------------------------------
# Differential runner: compare scanner (parser.py) vs tree (this module)
# on every HTML-bearing vector from parser.VECTORS, plus malformed cases.
# ---------------------------------------------------------------------------

# Additional malformed-document vectors targeting tree-vs-scanner
# divergences. Format matches parser.VECTORS: (desc, kind, input, expected)
# where expected is the NORMATIVE (tree-based) outcome.
MALFORMED_VECTORS = [
    # Foster parenting: <meta> before <table> is foster-parented ahead
    # of the table element -- outside the head. No statement.
    ("malformed: meta foster-parented before table -> outside head",
     "html-meta",
     "<html><head><title>t</title></head><body><table>"
     '<meta name="content-usage" content="train-ai=n">'
     "<tr><td>x</td></tr></table></body></html>",
     []),
    # Misnested: </head> closed early by <body>-implying content; a
    # later <meta> after body content started is in the body.
    ("malformed: meta after body started -> not in head",
     "html-meta",
     "<html><head><title>t</title></head><body><p>text</p>"
     '<meta name="content-usage" content="train-ai=n"></body></html>',
     []),
    # <noscript> in head: the normative model specifies scripting
    # DISABLED, under which noscript content parses as markup, so an
    # eligible <meta> inside a conforming <noscript> in <head> is a real
    # element and qualifies. html5lib parses noscript content as markup
    # (scripting-disabled behavior), matching the normative model here.
    ("malformed: meta inside noscript (scripting disabled) -> qualifies",
     "html-meta",
     '<html><head><noscript><meta name="content-usage" '
     'content="train-ai=n"></noscript></head></html>',
     ["train-ai=n"]),
    # Template fragment: meta inside <template> is not in the head
    # subtree (separate DocumentFragment). No statement.
    ("malformed: meta inside template -> separate fragment",
     "html-meta",
     '<html><head><template><meta name="content-usage" '
     'content="train-ai=n"></template></head></html>',
     []),
    # Character reference in attribute value resolves before parsing.
    ("malformed: charref in content value resolves (&equals;)",
     "html-meta",
     '<html><head><meta name="content-usage" '
     'content="train-ai&#x3d;n"></head></html>',
     ["train-ai=n"]),
    # Duplicate content attributes: first wins per HTML spec.
    ("malformed: duplicate content attribute -> first wins",
     "html-meta",
     '<html><head><meta name="content-usage" content="train-ai=n" '
     'content="train-ai=y"></head></html>',
     ["train-ai=n"]),
    # Unquoted + uppercase element/attribute names.
    ("malformed: uppercase META/NAME/CONTENT",
     "html-meta",
     '<HTML><HEAD><META NAME=content-usage CONTENT=train-ai=n>'
     "</HEAD></HTML>",
     ["train-ai=n"]),
    # Meta before <html>: implied html/head; still qualifies.
    ("malformed: meta before html tag -> implied head",
     "html-meta",
     '<meta name="content-usage" content="train-ai=n">'
     "<html><head><title>t</title></head></html>",
     ["train-ai=n"]),
    # Commented-out meta is not an element.
    ("malformed: commented-out meta ignored",
     "html-meta",
     '<html><head><!-- <meta name="content-usage" '
     'content="train-ai=n"> --></head></html>',
     []),
    # Two metas, one in head one in body: only the head one counts.
    ("malformed: head meta counts, body meta does not",
     "html-meta",
     '<html><head><meta name="content-usage" content="train-ai=n">'
     '</head><body><meta name="content-usage" content="train-ai=y">'
     "</body></html>",
     ["train-ai=n"]),
]


def run_differential():
    """Compare scanner vs tree extraction on HTML vectors + malformed."""
    from parser import VECTORS, extract_meta_contents

    total = 0
    agreed = 0
    divergences = []

    def check(desc, html, normative):
        nonlocal total, agreed
        total += 1
        scanner = extract_meta_contents(html)
        tree = extract_meta_contents_html5lib(html)
        if scanner == tree == normative:
            agreed += 1
            print(f"ok (agree): {desc}")
        else:
            divergences.append((desc, html, scanner, tree, normative))
            print(f"DIVERGE: {desc}")
            print(f"  normative: {normative!r}")
            print(f"  scanner:   {scanner!r}")
            print(f"  tree:      {tree!r}")

    # HTML-bearing vectors from the main suite (kind "eval" with html,
    # or explicit html-meta checks below).
    for desc, kind, inp, expected in VECTORS:
        if kind == "eval" and isinstance(inp, dict) and "html" in inp:
            html = inp["html"]
            # normative expectation: derive from the tree implementation
            # only where the vector's expected outcome constrains it.
            # We compare scanner-vs-tree directly here.
            total += 1
            scanner = extract_meta_contents(html)
            tree = extract_meta_contents_html5lib(html)
            if scanner == tree:
                agreed += 1
                print(f"ok (agree): {desc}")
            else:
                divergences.append((desc, html, scanner, tree, None))
                print(f"DIVERGE: {desc}")
                print(f"  scanner: {scanner!r}")
                print(f"  tree:    {tree!r}")

    for desc, kind, html, normative in MALFORMED_VECTORS:
        assert kind == "html-meta"
        check(desc, html, normative)

    print(f"\n{agreed}/{total} extraction cases agree "
          f"({len(divergences)} divergences)")
    return divergences


if __name__ == "__main__":
    if "--differential" in sys.argv:
        divs = run_differential()
        sys.exit(1 if divs else 0)
    if "--self-test" in sys.argv:
        # The malformed vectors double as a self-test of the normative
        # implementation: every one must match its normative expectation.
        fails = 0
        for desc, kind, html, normative in MALFORMED_VECTORS:
            got = extract_meta_contents_html5lib(html)
            status = "ok" if got == normative else "FAIL"
            if got != normative:
                fails += 1
            print(f"{status}: {desc} (got {got!r})")
        print(f"\n{len(MALFORMED_VECTORS) - fails}/"
              f"{len(MALFORMED_VECTORS)} malformed vectors pass")
        sys.exit(1 if fails else 0)
    print("Usage: python3 html5lib_reference.py [--differential|--self-test]")
