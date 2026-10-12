# RFC 9309 robots.txt Fixes — Summary

**Date:** 2026-10-11
**File:** `~/workspace/aipref-testbed/parser.py`
**Tests:** 117/117 passing (97 pre-existing + 20 new)

## Fixes Applied

### 1. `*` wildcard and `$` end-anchor (RFC 9309 §2.2.2)
**Problem:** Path matching was a plain `str.startswith` — `*` and `$` in
rule patterns were treated as literal characters.
**Fix:** New `_pattern_to_regex()` compiles each rule pattern: `*` becomes
`.*`, a trailing `$` becomes an end-of-path anchor, a `$` anywhere else
stays literal, and all other characters are regex-escaped. Applied to
both `robots_allows()` (Allow/Disallow) and `robots_content_usage()`
(AIPREF path-patterns).
**Tests:** 7 new vectors (wildcard across segments, `*` matching zero
chars, `$` anchor hit/miss, mid-pattern `$` literal, longer wildcard
pattern beating a shorter literal, tie → Allow wins).

### 2. Percent-encoded comparison (RFC 9309 §2.2.2)
**Problem:** Matching compared raw strings; an encoded request path
would not match its encoded rule (and vice versa), and case variants
of `%XX` hex (`%2f` vs `%2F`) never matched.
**Fix:** New `_encode_path()` normalizes the request path before
matching: existing `%XX` triplets are preserved with uppercase hex,
RFC 3986 pchar characters pass through, everything else is UTF-8
percent-encoded. New `_norm_pattern()` uppercases `%XX` triplets in
rule patterns at parse time so both sides compare canonically.
**Tests:** 3 new vectors (encoded rule ↔ encoded path, plain rule does
not match differently-encoded path, wildcard over encoded path) plus
a manual check that a raw-Unicode request path (`/café`) matches an
encoded rule (`/caf%C3%A9`).

### 3. Octet-based specificity (RFC 9309 §2.2.2)
**Problem:** "Most specific match" was measured with `len()` on the
Python string (characters), not octets.
**Fix:** Specificity now uses `len(pattern.encode("utf-8"))`. New
`_best_rule_match()` helper centralizes longest-match selection with
the Allow-wins-ties rule.
**Tests:** Manual check — `Allow: /éx` (4 octets) beats
`Disallow: /é` (3 octets) for path `/éx`.

### 4. Inline comments and empty rules (RFC 9309 §2.4, §2.2.2)
**Problem:** Only full-line `#` comments were skipped; a trailing
comment (`Disallow: /private/ # keep out`) became part of the rule
path. An empty `Allow:` recorded `(True, "")`, which `startswith`
matched against every path (accidental allow-all).
**Fix:** `#` now starts a comment anywhere on the line (stripped before
field parsing). Empty `Allow:` is ignored (matches nothing); empty
`User-agent:` tokens are skipped. Empty `Disallow:` still means
allow-all (unchanged).
**Tests:** 4 new vectors (trailing comments on Disallow/User-agent/Allow
lines, empty Disallow allows all, empty Allow does not allow-all).

### 5. User-agent group selection — verified, no change (RFC 9309 §2.2.1)
**Finding:** The existing implementation is already RFC-correct: all
groups whose token case-insensitively prefix-matches the crawler's
product token are combined; `*` groups apply only when no named group
matches; ties/longest-match apply to paths, not to group selection
("most specific wins" is a path rule, §2.2.2). No behavior change was
needed; the task's "most specific UA match wins" phrasing describes the
named-over-`*` fallback, which was already implemented.
**Tests:** 2 new vectors locking this in (multiple matching named groups
combine via prefix match; a group holding `*` plus a non-matching name
still serves as the `*` fallback).

### 6. Crawlability gating — verified, no change
**Finding:** `evaluate()` already returns `(False, {})` when
`robots_allows()` fails, so no usage preferences are evaluated for
disallowed URLs. Empty or comments-only robots.txt correctly yields
crawlable with no statements.
**Tests:** Manual checks (gated disallow, empty file, comments-only file).

### 7. 500 KiB parse limit (RFC 9309 §2.3)
**Problem:** No size limit; an unbounded robots.txt was fully parsed.
**Fix:** `parse_robots_txt()` truncates input to 500 KiB
(`ROBOTS_TXT_MAX_BYTES`), backing up to the last complete line so a
torn rule is dropped rather than half-parsed. Rules past the limit are
ignored.
**Tests:** 2 new vectors (a `Disallow` pushed past 500 KiB by padding is
ignored → crawlable; a `Disallow` before 500 KiB in a large file still
applies).

## Notes
- `server.py` has a pre-existing, unrelated `NameError`
  (`_rsl_head` referenced but not defined) that breaks `import server`;
  it exists in the working tree independent of these changes and was
  left untouched.
- Content-Usage path-patterns share the same RFC 9309 matching
  semantics as Allow/Disallow (wildcard, `$`, encoding, octet
  longest-match), verified by 2 new vectors.
